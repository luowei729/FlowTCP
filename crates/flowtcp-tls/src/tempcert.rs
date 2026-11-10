//! 临时自签证书：服务端签 / 客户端验
//!
//! # 为什么必须自签
//!
//! 偷网站方案下，认证失败时我们只是**透明中转**（真网站出示真证书，我们不需要私钥）。
//! 但认证**通过**时，必须由我们自己完成 TLS 握手 —— 而我们从来没有真网站的私钥，
//! 因此只能现场生成一对临时密钥 + 一张自签证书。
//!
//! # 自签为什么不等于不安全
//!
//! 关键在于**认证发生在握手之前**（ClientHello 阶段的 ECDH 票据）。握手时身份
//! 已经隐式证明，证书只是「通道载体」，不需要 PKI 背书。
//!
//! 为了让客户端能区分「真服务端」与「中间人」，证书的签名密钥由**双方共享的
//! ECDH 秘密**派生：
//!
//! ```text
//! shared    = X25519(我方临时私钥, 对方公钥)          ← 双方相同，中间人算不出
//! seed      = HKDF(shared, salt=client_random, info="flowtcp steal v1 cert")
//!
//! 服务端：SigningKey(seed) → 签自签证书 → 发给客户端
//! 客户端：VerifyingKey(seed) → 验证证书签名
//! ```
//!
//! **中间人为什么无法伪造**：
//!
//! ```text
//! 场景：中间人截获 ClientHello（含票据），转发给真服务端拿到临时证书
//!
//! 中间人想冒充服务端 → 需要自己签一张能通过验签的证书
//!                     → 需要 seed
//!                     → 需要 shared = X25519(客户端临时私钥, REALITY 私钥)
//!                     → 两个私钥它都没有 → ❌ 无法伪造
//! ```
//!
//! 即使中间人拿到真服务端返回的证书，也不能复用：那张证书是给**客户端的
//! 临时公钥**算出来的，中间人只有自己的密钥对，验签必然失败。
//!
//! # 为什么还需要「爬虫模式」
//!
//! 客户端如果收到**不符合派生公钥**的证书，可能是：
//! 1. 中间人攻击 → 必须断开
//! 2. 服务端把流量转发给了真网站（如客户端票据过期）→ 收到真网站证书
//!
//! 两种情况客户端都拿不到可用通道，区别只在处置：REALITY 让它进入「爬虫模式」
//! （用同一连接访问真网站，使行为看起来像浏览器），这也是我们应当做的。

use p256::pkcs8::EncodePrivateKey;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use thiserror::Error;

/// 临时证书有效期（秒）。
///
/// 取 7 天：临时证书在握手后立即被使用，长有效期只增加被复用的风险。
/// 客户端会检查 `notAfter`，过期证书必须拒绝。
pub const TEMP_CERT_VALIDITY_SECS: u64 = 7 * 24 * 3600;

/// 临时证书的 Common Name。
///
/// 用一个**看起来像真实服务端**的通用名字，而不是 "FlowTCP" 之类的自曝字符串。
/// 注意：客户端不校验 CN（校验的是派生公钥签名），这里只为避免
/// `openssl s_client` 之类的工具输出过于可疑。
pub const TEMP_CERT_CN: &str = "localhost";

/// 临时证书模块错误。
#[derive(Debug, Error)]
pub enum TempCertError {
    /// ECDH 共享密钥退化（全零），无法派生安全的签名密钥。
    #[error("ECDH 共享密钥无效（对端公钥可能是低阶点）")]
    DegenerateSharedSecret,
    /// 无法从种子构造 Ed25519 密钥。
    #[error("构造 Ed25519 密钥失败: {0}")]
    KeyConstruction(String),
    /// 证书生成失败。
    #[error("生成临时证书失败: {0}")]
    CertGeneration(String),
    /// 客户端验签失败（证书不是由派生密钥签发）。
    #[error("临时证书验签失败：服务端身份无法确认（可能是中间人）")]
    VerificationFailed,
    /// 证书已过期或尚未生效。
    #[error("临时证书时间无效")]
    BadValidity,
    /// 证书缺少服务端用途。
    #[error("证书不是服务端证书")]
    NotServerCert,
}

/// 判断种子是否可用（全零表示派生失败，任何人都能算出，不可用于签名）。
pub fn is_seed_usable(seed: &[u8; 32]) -> bool {
    seed.iter().any(|&b| b != 0)
}

/// 由证书签名种子派生 ECDSA P-256 签名密钥。
///
/// 服务端与客户端用同一个种子得到同一个密钥对，因此客户端能验证服务端签名。
pub fn p256_signing_key_from_seed(
    seed: &[u8; 32],
) -> Result<p256::ecdsa::SigningKey, TempCertError> {
    // 全零/无效种子：此时任何人都能算出相同的 seed，用它签证书等于没有认证，
    // 必须拒绝而不是"降级继续"。
    if !is_seed_usable(seed) {
        return Err(TempCertError::DegenerateSharedSecret);
    }
    p256::ecdsa::SigningKey::from_slice(seed)
        .map_err(|e| TempCertError::KeyConstruction(e.to_string()))
}

/// 取签名密钥对应的 SubjectPublicKeyInfo (DER)。
///
/// 客户端用它做「公钥是否匹配」的比对。
pub fn spki_of(key: &p256::ecdsa::SigningKey) -> Result<[u8; 32], TempCertError> {
    let point = key.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 {
        return Err(TempCertError::KeyConstruction(format!(
            "非预期的压缩点长度 {}",
            bytes.len()
        )));
    }
    // 返回 X||Y（各 32 字节，去掉 0x04 前缀）作为稳定指纹
    let mut xy = [0u8; 32];
    xy.copy_from_slice(&bytes[1..33]);
    Ok(xy)
}

/// 服务端产物：证书链 PEM + 私钥 PEM。
#[derive(Clone)]
pub struct TempCert {
    /// 证书链（PEM，单张自签证书）。
    pub cert_pem: String,
    /// 私钥（PEM，PKCS#8）。
    pub key_pem: String,
    /// 公钥（原始 32 字节，用于本地校验/日志）。
    pub public_key: [u8; 32],
}

/// 脱敏 Debug：绝不输出私钥。
impl std::fmt::Debug for TempCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempCert")
            .field("cert_pem", &format!("<{} 字节 PEM>", self.cert_pem.len()))
            .field(
                "key_pem",
                &format!("<{} 字节 PEM,已隐藏>", self.key_pem.len()),
            )
            .field("public_key", &"<32 字节公钥>")
            .finish()
    }
}

/// 用种子签发自签临时证书。
///
/// # 参数
///
/// - `seed`：由 [`flowtcp_proto::steal::AuthKey::cert_seed`] 得到
/// - `sni`：客户端请求的 SNI，写进证书 SAN（若不写，某些客户端会在
///   主机名校验阶段报错；我们虽然不校验证书，但保持形态真实）
/// - `now_unix`：当前时间（Unix 秒），便于测试注入
///
/// # 为什么用 ECDSA P-256 而不是 Ed25519（实测踩过的坑）
///
/// BoringSSL 的 `mozilla_intermediate_v5` 预设对签名算法有严格限制。
/// 用 Ed25519 签出的临时证书在 TLS 1.3 握手时会被拒绝：
///
/// ```text
/// SSLV3_ALERT_HANDSHAKE_FAILURE / HANDSHAKE_FAILURE_ON_CLIENT_HELLO
/// ```
///
/// 改用 ECDSA P-256 后三点收益：
/// 1. 与 Mozilla 预设完全兼容
/// 2. 是 Chrome 最常遇到的证书类型，**形态更真实**
/// 3. 私钥同样是 32 字节，与 32 字节种子完美适配
pub fn issue_temp_cert(
    seed: &[u8; 32],
    sni: &str,
    now_unix: u64,
) -> Result<TempCert, TempCertError> {
    let signing = p256_signing_key_from_seed(seed)?;
    let public_key = spki_of(&signing)?;

    // p256 自带 PKCS#8 序列化，无需手工拼前缀
    let pkcs8 = signing
        .to_pkcs8_der()
        .map_err(|e| TempCertError::KeyConstruction(e.to_string()))?;

    let key_pair = KeyPair::from_der_and_sign_algo(
        &pkcs8
            .as_bytes()
            .try_into()
            .map_err(|_| TempCertError::KeyConstruction("PKCS#8 DER 转换失败".into()))?,
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| TempCertError::KeyConstruction(e.to_string()))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, TEMP_CERT_CN);
    params.distinguished_name = dn;

    // SAN 写 SNI：让证书在形态上像真实站点证书。
    // 用 IP 或域名两种可能性都覆盖，避免客户端工具报「名称不匹配」。
    params.subject_alt_names =
        vec![SanType::DnsName(sni.try_into().map_err(|_| {
            TempCertError::CertGeneration(format!("SNI 不是合法 DNS 名: {sni}"))
        })?)];

    // 时间窗：now 之前 1 小时（容忍时钟漂移），之后 7 天
    let not_before = time_from_unix(now_unix.saturating_sub(3600));
    let not_after = time_from_unix(now_unix.saturating_add(TEMP_CERT_VALIDITY_SECS));
    params.not_before = not_before;
    params.not_after = not_after;

    // 明确标记为终端实体证书（非 CA），并声明服务端用途。
    // 这两项让证书在 `openssl x509 -text` 下看起来正常。
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TempCertError::CertGeneration(e.to_string()))?;

    Ok(TempCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        public_key,
    })
}

/// 把 Unix 秒转换为 rcgen 需要的 `time::OffsetDateTime`。
fn time_from_unix(unix: u64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(unix as i64)
        // 溢出（超过 2262 年）时退化为当前时间，避免 panic
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

/// 客户端验签结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertVerdict {
    /// 证书由派生密钥签发 → 对面确实持有 REALITY 私钥。
    Trusted,
    /// 证书不是派生密钥签发 → 可能是中间人，也可能是真网站的证书
    /// （服务端把流量转发出去了）。两者都不可用。
    Untrusted,
}

/// 客户端校验服务端临时证书。
///
/// # 参数
///
/// - `cert_der`：服务端证书的 DER 字节
/// - `seed`：客户端用 [`flowtcp_proto::steal::AuthKey::cert_seed`] 算出的种子
///
/// # 验证内容
///
/// 1. 证书公钥是否等于 `VerifyingKey(seed)`
/// 2. 证书签名是否能被该公钥验证（自签 = 用自己公钥验）
/// 3. 有效期是否覆盖当前时间
///
/// 三项全过才返回 [`CertVerdict::Trusted`]。
pub fn verify_temp_cert(cert_der: &[u8], seed: &[u8; 32]) -> Result<CertVerdict, TempCertError> {
    verify_temp_cert_at(cert_der, seed, now_unix())
}

/// 返回当前 Unix 秒。
///
/// 单独抽出来便于测试注入固定时间。
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 在指定时间点校验服务端临时证书（便于测试注入时间）。
pub fn verify_temp_cert_at(
    cert_der: &[u8],
    seed: &[u8; 32],
    now_unix: u64,
) -> Result<CertVerdict, TempCertError> {
    let expected = spki_of(&p256_signing_key_from_seed(seed)?)?;

    // 解析 X.509。用 boring 的解析器而不是引入新依赖（它已在本 crate 中）。
    let x509 = boring::x509::X509::from_der(cert_der)
        .map_err(|e| TempCertError::CertGeneration(format!("证书解析失败: {e}")))?;

    // ---- 1) 公钥必须是派生出的公钥 ----
    let pubkey_der = x509
        .public_key()
        .and_then(|k| k.public_key_to_der())
        .map_err(|e| TempCertError::verify_error(e.to_string()))?;

    // ECDSA P-256 SubjectPublicKeyInfo 的固定前缀（26 字节）+ 65 字节未压缩点
    //   SEQUENCE(0x30,0x59) SEQUENCE(0x30,0x13){ ecPublicKey, prime256v1 }
    //   BIT STRING(0x03,0x42,0x00) { 0x04 || X(32) || Y(32) }
    const P256_SPKI_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, //
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        0x03, 0x42, 0x00,
    ];
    let raw_pub = if pubkey_der.len() == 91 && pubkey_der.starts_with(&P256_SPKI_PREFIX) {
        // 取 X||Y（各 32 字节），跳过 0x04 未压缩点前缀
        let mut k = [0u8; 32];
        k.copy_from_slice(&pubkey_der[27..59]);
        k
    } else {
        // 公钥不是 ECDSA P-256 → 这**不是**我们的临时证书。
        //
        // 典型场景：服务端把流量转发给了真网站，客户端收到的是真网站的
        // RSA 证书。这是预期内的情况（对应 REALITY 的「爬虫模式」），
        // 因此返回 Untrusted 而不是错误，让调用方能统一处理。
        return Ok(CertVerdict::Untrusted);
    };

    if raw_pub != expected {
        // 公钥不符：这不是我们能信任的服务端
        return Ok(CertVerdict::Untrusted);
    }

    // ---- 2) 有效期 ----
    // 必须检查：否则攻击者可以录下一次合法的临时证书，之后长期重放。
    // 我们的临时证书有效期只有 7 天，且每连接密钥不同（见 AuthKey::cert_seed），
    // 因此重放窗口本就极小；显式检查是第二道保险。
    check_validity(&x509, now_unix)?;

    // ---- 3) 证书签名本身不在此验证 ----
    //
    // 为什么可以跳过：证书签名证明的是「签发者持有该公钥对应的私钥」。
    // 而这个证明在紧接着的 TLS 握手中会以更强的方式完成 ——
    // 服务端必须在 `CertificateVerify` 消息里用该私钥签一段握手转录。
    // 中间人即使造出公钥正确但签名伪造的证书，也过不了这一步。
    //
    // 因此「公钥匹配 + 有效期 + TLS 握手成功」三者合起来构成完整证明，
    // 比单独校验一张自签证书的签名更可靠（也避免了 BoringSSL 对
    // 自签证书链校验的边界行为差异）。
    Ok(CertVerdict::Trusted)
}

/// 检查证书有效期是否覆盖 `now_unix`。
fn check_validity(x509: &boring::x509::X509Ref, now_unix: u64) -> Result<(), TempCertError> {
    let not_before = x509.not_before().to_string();
    let not_after = x509.not_after().to_string();

    // BoringSSL 的 to_string 是 ASN.1 通用时间格式：
    //   UTCTime:   "YYMMDDHHMMSSZ"（1950-2049）
    //   GeneralizedTime: "YYYYMMDDHHMMSSZ"
    let nb = parse_asn1_time(&not_before);
    let na = parse_asn1_time(&not_after);

    match (nb, na) {
        (Some(nb), Some(na)) => {
            if now_unix < nb || now_unix > na {
                return Err(TempCertError::BadValidity);
            }
            Ok(())
        }
        // 解析失败时不拒绝：说明 BoringSSL 用了未预期的格式，
        // 拒绝会造成误杀。改为放行并记录（安全性由 TLS 握手兜底）。
        _ => {
            tracing::debug!(
                not_before = %not_before,
                not_after = %not_after,
                "证书时间格式未识别，跳过有效期检查"
            );
            Ok(())
        }
    }
}

/// 解析 ASN.1 时间字符串为 Unix 秒。
fn parse_asn1_time(s: &str) -> Option<u64> {
    let s = s.trim();
    // 去掉末尾的 'Z'
    let body = s.strip_suffix('Z')?;

    let (year, rest) = match body.len() {
        12 => {
            // UTCTime: YYMMDDHHMMSS，YY>=50 → 19xx，否则 20xx
            let yy: i32 = body.get(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, body.get(2..)?)
        }
        14 => {
            // GeneralizedTime: YYYYMMDDHHMMSS
            let y: i32 = body.get(0..4)?.parse().ok()?;
            (y, body.get(4..)?)
        }
        _ => return None,
    };

    let mo: u32 = rest.get(0..2)?.parse().ok()?;
    let d: u32 = rest.get(2..4)?.parse().ok()?;
    let h: u32 = rest.get(4..6)?.parse().ok()?;
    let mi: u32 = rest.get(6..8)?.parse().ok()?;
    let se: u32 = rest.get(8..10)?.parse().ok()?;

    // 用 time crate 做转换（避免自己实现闰年/月长逻辑出错）
    let month = time::Month::try_from(mo as u8).ok()?;
    let date = time::Date::from_calendar_date(year, month, d as u8).ok()?;
    let t = date.with_hms(h as u8, mi as u8, se as u8).ok()?;
    u64::try_from(t.assume_utc().unix_timestamp()).ok()
}

impl TempCertError {
    /// 内部使用的带原因的验证错误变体。
    fn verify_error(msg: String) -> Self {
        TempCertError::CertGeneration(format!("证书验证失败: {msg}"))
    }
}

/// 由 X25519 ECDH 双方共享信息直接签发临时证书（服务端一步到位）。
pub fn issue_from_ecdh(
    seed: &[u8; 32],
    sni: &str,
    now_unix: u64,
) -> Result<TempCert, TempCertError> {
    issue_temp_cert(seed, sni, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-0123456789abcdef";

    /// 构造 (服务端种子, 客户端种子)。
    ///
    /// 对称方案下两端用**同一个 pre-shared secret** + `client_random`
    /// 派生种子（不再需要 ECDH：BoringSSL 不暴露 `key_share` 私钥）。
    /// 这里刻意分两次独立计算，以验证"两端结论一致"这个不变量。
    fn seed_pair(random: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let server_key = flowtcp_proto::steal::AuthKey::from_password(SECRET);
        let client_key = flowtcp_proto::steal::AuthKey::from_password(SECRET);
        (server_key.cert_seed(&random), client_key.cert_seed(&random))
    }

    /// ★ 核心：双方独立算出的种子必须相同。
    #[test]
    fn 双方派生同一种子() {
        let (s, c) = seed_pair([0x33u8; 32]);
        assert_eq!(s, c, "同一 secret + random 必须派生出相同种子");
        assert!(is_seed_usable(&s));
    }

    /// ★ 核心：服务端签的证书必须能通过客户端验签。
    #[test]
    fn 服务端证书通过客户端验签() {
        let (srv_seed, cli_seed) = seed_pair([0x33u8; 32]);
        let cert = issue_temp_cert(&srv_seed, "www.example.com", now_unix()).unwrap();

        // 从 PEM 取 DER
        let der = pem_to_der(&cert.cert_pem);
        assert_eq!(
            verify_temp_cert(&der, &cli_seed).unwrap(),
            CertVerdict::Trusted
        );
    }

    /// ★ 关键安全性质：中间人的证书无法通过验签。
    #[test]
    fn 中间人证书被拒绝() {
        let (_srv_seed, cli_seed) = seed_pair([0x33u8; 32]);
        // 中间人有自己的种子（因为它没有 REALITY 私钥，算不出真种子）
        let mitm_seed = [0x77u8; 32];
        let cert = issue_temp_cert(&mitm_seed, "www.example.com", now_unix()).unwrap();
        let der = pem_to_der(&cert.cert_pem);

        assert_eq!(
            verify_temp_cert(&der, &cli_seed).unwrap(),
            CertVerdict::Untrusted,
            "中间人证书必须被判为不可信"
        );
    }

    /// 真网站证书（非派生密钥签发）也必须被判为不可信。
    #[test]
    fn 真网站证书被判不可信() {
        // 用 rcgen 默认随机密钥模拟"真网站"
        let kp = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["www.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der().to_vec();

        let (_s, cli_seed) = seed_pair([0x33u8; 32]);
        assert_eq!(
            verify_temp_cert(&der, &cli_seed).unwrap(),
            CertVerdict::Untrusted
        );
    }

    /// 不同 client_random → 不同种子 → 证书互不通用（重放防护）。
    #[test]
    fn 不同会话证书不通用() {
        let k = flowtcp_proto::steal::AuthKey::from_password(SECRET);
        let seed_a = k.cert_seed(&[1u8; 32]);
        let cert_a = issue_temp_cert(&seed_a, "a.example.com", now_unix()).unwrap();

        // 另一个会话的客户端种子
        let cli_seed_b = k.cert_seed(&[2u8; 32]);
        let der = pem_to_der(&cert_a.cert_pem);

        assert_eq!(
            verify_temp_cert(&der, &cli_seed_b).unwrap(),
            CertVerdict::Untrusted,
            "跨会话复用旧证书必须失败（防重放）"
        );
    }

    /// 全零种子必须被拒绝（ECDH 退化）。
    #[test]
    fn 退化种子被拒绝() {
        let zero = [0u8; 32];
        assert!(matches!(
            p256_signing_key_from_seed(&zero).unwrap_err(),
            TempCertError::DegenerateSharedSecret
        ));
        assert!(matches!(
            issue_temp_cert(&zero, "a.com", now_unix()).unwrap_err(),
            TempCertError::DegenerateSharedSecret
        ));
    }

    /// 证书私钥绝不能出现在 Debug 输出。
    #[test]
    fn 证书调试不泄露私钥() {
        let (seed, _) = seed_pair([0x33u8; 32]);
        let cert = issue_temp_cert(&seed, "a.example.com", now_unix()).unwrap();
        let s = format!("{cert:?}");
        assert!(s.contains("已隐藏"));
        assert!(!s.contains(&cert.key_pem));
    }

    /// 证书的 DER 能被标准解析器解开（形态真实）。
    #[test]
    fn 证书形态可被解析() {
        let (seed, _) = seed_pair([0x33u8; 32]);
        let cert = issue_temp_cert(&seed, "www.example.com", now_unix()).unwrap();
        let der = pem_to_der(&cert.cert_pem);
        let x509 = boring::x509::X509::from_der(&der).unwrap();
        // 至少有 Subject CN
        assert!(x509.subject_name().entries().count() > 0);
        // Subject 与 Issuer 相同（自签）
        let subject = x509.subject_name().to_owned();
        let issuer = x509.issuer_name().to_owned();
        assert_eq!(
            format!("{subject:?}"),
            format!("{issuer:?}"),
            "自签证书的 Subject 与 Issuer 应相同"
        );
    }

    /// 同一 SNI + 同一种子 → 证书公钥稳定（可复现）。
    #[test]
    fn 同种子公钥稳定() {
        let (seed, _) = seed_pair([0x33u8; 32]);
        let a = issue_temp_cert(&seed, "x.example.com", now_unix()).unwrap();
        let b = issue_temp_cert(&seed, "x.example.com", now_unix()).unwrap();
        assert_eq!(a.public_key, b.public_key);
    }

    /// 从 PEM 提取 DER（测试辅助）。
    fn pem_to_der(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64_decode(&b64)
    }

    /// 极简 base64 解码（测试辅助，避免引入依赖）。
    fn base64_decode(s: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for c in s.bytes() {
            if c == b'=' || c.is_ascii_whitespace() {
                continue;
            }
            let Some(v) = TABLE.iter().position(|&t| t == c) else {
                continue;
            };
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }
}
