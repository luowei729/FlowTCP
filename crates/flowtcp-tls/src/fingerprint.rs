//! Chrome 级 TLS 指纹配置
//!
//! # 为什么用 BoringSSL 而不是自己构造 ClientHello
//!
//! ClientHello 指纹包含 **十几个维度**，任何一处与真实 Chrome 不同都可被统计识别：
//!
//! | 维度 | 示例 |
//! |------|------|
//! | cipher suites 及顺序 | 顺序本身就是指纹 |
//! | extension 集合与顺序 | Chrome 106+ 会随机化顺序（`permute_extensions`） |
//! | 曲线列表 | X25519 / P-256 / P-384 |
//! | 签名算法列表 | 7~9 项，顺序固定 |
//! | GREASE 值 | Chrome 每版本更换插入位置与数值 |
//! | record 层分片方式 | ClientHello 是否被拆成两个 TCP 段 |
//! | 压缩方法 | null only |
//! | ALPN | `h2` / `http/1.1` |
//! | SNI 编码细节 | 是否带尾部点、大小写 |
//!
//! **BoringSSL 正是 Chrome 使用的 TLS 实现**（Google 自研，Chrome/Android/Google
//! 服务端共用）。因此它的扩展集合、GREASE 插入逻辑、分片行为天然与 Chrome 一致。
//!
//! 我们只需调几个开关（GREASE / permute / cipher 列表 / 曲线 / sigalgs），
//! 就能得到与真实 Chrome 几乎无法区分的 ClientHello —— 且**随 BoringSSL 升级自动跟进**。
//!
//! # 不用自研方案的理由
//!
//! 自研 ClientHello 构造器等于自己维护一份 Chrome 指纹数据库：
//! - Chrome 每 6 周发一次新版，指纹至少每季度变动
//! - 指纹偏差的后果是「被识别 → 被封」，而不是「性能下降」
//! - 这类偏差**无法通过自己的测试发现**，只能靠外部对抗检验
//!
//! 这是典型的「不要自己造轮子」场景。

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

/// Chrome 的 TLS 1.2 及以下 cipher suite 列表（顺序即指纹）。
///
/// # 为什么是这个顺序
///
/// Chrome 优先 ECDSA（证书通常更小更快），然后 RSA；每组内 AES-GCM 优先于
/// ChaCha20 —— 因为大多数设备有 AES-NI 硬件加速。仅当无 AES 加速时才回落到 ChaCha20。
///
/// TLS 1.3 的 cipher suite（`TLS_AES_128_GCM_SHA256` 等）由 BoringSSL 内部固定顺序，
/// 不受此列表影响，也不需要设置。
pub const CHROME_CIPHER_LIST: &str = "\
ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-RSA-AES128-SHA:\
ECDHE-RSA-AES256-SHA:\
AES128-GCM-SHA256:\
AES256-GCM-SHA384:\
AES128-SHA:\
AES256-SHA";

/// Chrome 的分组（曲线）列表，顺序即优先级。
///
/// `X25519` 优先（最快、最安全），然后 P-256、P-384。
///
/// # 注意：后量子
///
/// Chrome 131+ 默认在首位插入 `X25519MLKEM768`（ML-KEM 混合密钥交换）。
/// 这与**是否被识别**无关（普通站点也会收到该 group），但会改变 ClientHello 大小。
/// 若目标网络存在对「ClientHello 长度」的统计，可考虑开启；
/// 当前默认关闭，因为老版本 BoringSSL 与部分中间设备可能不兼容。
pub const CHROME_CURVES: &str = "X25519:P-256:P-384";

/// Chrome 的签名算法列表，顺序即优先级。
///
/// 顺序含义：ECDSA-P256 优先 → RSA-PSS（现代）→ RSA-PKCS1（兼容）→ 更大的曲线/哈希。
/// 这个顺序对**服务端选证书**有实际影响，因此也是重要指纹。
pub const CHROME_SIGALGS: &str = "\
ECDSA+SHA256:\
rsa_pss_rsae_sha256:\
RSA+SHA256:\
ECDSA+SHA384:\
rsa_pss_rsae_sha384:\
RSA+SHA384:\
ECDSA+SHA512:\
rsa_pss_rsae_sha512:\
RSA+SHA512";

/// ALPN 协议列表（线格式：长度前缀）。
///
/// 必须是 `h2` + `http/1.1` 且**顺序不能反** —— Chrome 永远优先 h2。
/// 这个字段对伪装至关重要：缺 h2 会被立即识别为「非浏览器」。
pub const CHROME_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// 指纹严格程度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintProfile {
    /// 完整 Chrome 模拟（GREASE + extension 随机化 + 全量列表）。
    ///
    /// 用于**对外连接**（客户端 → 服务端），因为要抗主动探测。
    #[default]
    Chrome,
    /// 简化配置，仅保证 TLS 1.3 + ALPN 正确。
    ///
    /// 用于**内部测试**或性能敏感场景（少一次 extension 随机化的开销）。
    Plain,
}

/// 客户端 TLS 配置器。
///
/// 封装「如何把 `SslConnector` 配置成 Chrome 的样子」。
pub struct FingerprintConfig {
    profile: FingerprintProfile,
    /// 是否校验服务端证书。
    ///
    /// 默认 `true`。仅当使用自签证书做本地测试时才应设为 `false`，
    /// 生产环境关闭校验等于放弃抗中间人攻击能力。
    verify_cert: bool,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        FingerprintConfig {
            profile: FingerprintProfile::Chrome,
            verify_cert: true,
        }
    }
}

impl FingerprintConfig {
    /// 使用完整 Chrome 指纹。
    pub fn chrome() -> Self {
        Self::default()
    }

    /// 使用简化指纹（测试用）。
    pub fn plain() -> Self {
        FingerprintConfig {
            profile: FingerprintProfile::Plain,
            verify_cert: true,
        }
    }

    /// 关闭证书校验（**仅本地测试**）。
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.verify_cert = false;
        self
    }

    /// 当前严格程度。
    pub fn profile(&self) -> FingerprintProfile {
        self.profile
    }

    /// 是否启用证书校验。
    ///
    /// 供握手层决定是否同时校验主机名：证书校验与主机名校验必须成对开关，
    /// 只关其一会造成「证书通过但域名不匹配」的隐蔽漏洞。
    pub fn verify_enabled(&self) -> bool {
        self.verify_cert
    }

    /// 构造配置好的 `SslConnector`。
    pub fn build_connector(&self) -> Result<SslConnector, boring::error::ErrorStack> {
        let mut b = SslConnector::builder(SslMethod::tls())?;

        // ★ 关键：不要设置 min_proto_version = TLS1_3
        //
        // 真实 Chrome 的 ClientHello 是 **TLS 1.2 兼容格式**：它同时发送
        // `supported_versions = [GREASE, 1.3, 1.2]`，并附带一批 TLS 1.2 时代的扩展
        // （`ec_point_formats`、`extended_master_secret`、`renegotiation_info` 等）。
        //
        // 若设 `set_min_proto_version(TLS1_3)`，BoringSSL 会认为「不需要兼容 1.2」，
        // 从而**省略这些扩展** —— 扩展数量骤减（实测从 15 个降到 7 个），
        // JA4 哈希随之偏离 Chrome，反而更容易被识别。
        //
        // 正确做法：使用默认版本范围（1.2 ~ 1.3），由服务端强制要求 1.3。
        // 我们的服务端会设 min = TLS1.3，因此最终一定协商 1.3。

        // 证书校验：默认开启，且必须校验主机名
        if self.verify_cert {
            b.set_verify(SslVerifyMode::PEER);
        } else {
            b.set_verify(SslVerifyMode::NONE);
        }

        // ALPN 是必设项（任何合法 HTTPS 客户端都会发）
        b.set_alpn_protos(CHROME_ALPN)?;

        if self.profile == FingerprintProfile::Chrome {
            // ---- 以下是「像 Chrome」的关键项 ----
            b.set_cipher_list(CHROME_CIPHER_LIST)?;
            b.set_curves_list(CHROME_CURVES)?;
            b.set_sigalgs_list(CHROME_SIGALGS)?;
            // GREASE：插入保留值让中间设备无法硬编码解析
            // 缺失 GREASE 是最常被用来识别「非浏览器」的特征之一
            b.set_grease_enabled(true);
            // extension 顺序随机化（Chrome 106+ 行为）
            // 不开启则 extension 顺序恒定，可被长期观察建立指纹
            b.set_permute_extensions(true);
            // OCSP stapling 请求（extension 5, status_request）
            // 真实浏览器都请求 OCSP，缺失是明显特征
            b.enable_ocsp_stapling();
            // 证书透明度签名请求（extension 18, signed_certificate_timestamp）
            // Chrome 自 2018 起强制要求 SCT，不发此项几乎可断定非 Chrome
            b.enable_signed_cert_timestamps();
        }

        Ok(b.build())
    }
}

/// 服务端证书来源。
///
/// # 为什么需要两种来源
///
/// - **文件**：自有证书模式（`OwnCert`），证书由 CA 签发、长期有效
/// - **内存**：偷网站模式（`Steal`），每连接现场生成临时自签证书
///
/// 临时证书是逐连接变化的（种子含 `client_random`），无法落盘复用，
/// 必须直接从内存加载。若只支持文件路径，每连接都要写临时文件 ——
/// 高并发下会成为磁盘 IO 瓶颈，且留下可被审计的痕迹。
///
/// # 为什么需要 `Clone`
///
/// 客户端 HTTPS 入口要为**每条本地连接**构造一个 acceptor，
/// 而 acceptor 需要持有配置的拷贝（不能共享 `SslAcceptor`，
/// 因为它内部有可变状态且构建成本低）。
#[derive(Clone)]
pub enum CertSource {
    /// 证书链与私钥的 PEM 文件路径。
    Files {
        /// 证书链 PEM 路径。
        cert_path: std::path::PathBuf,
        /// 私钥 PEM 路径。
        key_path: std::path::PathBuf,
    },
    /// 内存中的 PEM 字符串。
    Pem {
        /// 证书链 PEM。
        cert_pem: String,
        /// 私钥 PEM。
        key_pem: String,
    },
}

/// 脱敏 Debug：内存 PEM 含私钥，绝不能输出。
impl std::fmt::Debug for CertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertSource::Files {
                cert_path,
                key_path,
            } => f
                .debug_struct("CertSource::Files")
                .field("cert_path", cert_path)
                .field("key_path", key_path)
                .finish(),
            CertSource::Pem { cert_pem, key_pem } => f
                .debug_struct("CertSource::Pem")
                .field("cert_pem", &format!("<{} 字节 PEM>", cert_pem.len()))
                .field("key_pem", &format!("<{} 字节 PEM,已隐藏>", key_pem.len()))
                .finish(),
        }
    }
}

/// 服务端 TLS 配置器。
///
/// 服务端**不需要**模拟指纹（服务端特征由证书 + ServerHello 决定）。
#[derive(Clone)]
pub struct ServerTlsConfig {
    /// 证书来源。
    pub source: CertSource,
    /// 是否接受客户端证书（双向认证）。默认关闭。
    pub require_client_cert: bool,
}

impl ServerTlsConfig {
    /// 用证书与私钥**文件路径**构造（自有证书模式）。
    pub fn new(
        cert_path: impl Into<std::path::PathBuf>,
        key_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        ServerTlsConfig {
            source: CertSource::Files {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
            },
            require_client_cert: false,
        }
    }

    /// 用内存 PEM 构造（临时证书模式）。
    ///
    /// 每连接调用一次，`cert_pem` / `key_pem` 来自
    /// [`crate::tempcert::issue_temp_cert`]。
    pub fn from_pem(cert_pem: impl Into<String>, key_pem: impl Into<String>) -> Self {
        ServerTlsConfig {
            source: CertSource::Pem {
                cert_pem: cert_pem.into(),
                key_pem: key_pem.into(),
            },
            require_client_cert: false,
        }
    }

    /// 构造配置好的 `SslAcceptor`。
    pub fn build_acceptor(&self) -> Result<boring::ssl::SslAcceptor, boring::error::ErrorStack> {
        let mut b = boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

        match &self.source {
            CertSource::Files {
                cert_path,
                key_path,
            } => {
                b.set_certificate_chain_file(cert_path)?;
                b.set_private_key_file(key_path, boring::ssl::SslFiletype::PEM)?;
            }
            CertSource::Pem { cert_pem, key_pem } => {
                // 证书链用 stack_from_pem 解析：支持"叶证书 + 中间证书"的多段 PEM
                let chain = boring::x509::X509::stack_from_pem(cert_pem.as_bytes())?;
                let leaf = chain.first().ok_or_else(|| {
                    boring::error::ErrorStack::get() // 空链时取当前错误栈
                })?;
                b.set_certificate(leaf)?;
                // 中间证书必须一并交给客户端，否则部分客户端会构建不出完整链
                for extra in chain.iter().skip(1) {
                    b.add_extra_chain_cert(extra.to_owned())?;
                }
                let pkey = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes())?;
                b.set_private_key(&pkey)?;
            }
        }

        // 最低 TLS 1.3：与客户端要求对齐，避免协议降级
        b.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        // 必须声明 h2/http1.1 才能完成 ALPN 协商；
        // 缺省会导致 Chrome 侧 ALPN 协商失败，浏览器报 ERR_SSL_PROTOCOL_ERROR
        b.set_alpn_protos(CHROME_ALPN)?;
        if self.require_client_cert {
            b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        Ok(b.build())
    }
}

impl std::fmt::Debug for ServerTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTlsConfig")
            .field("source", &self.source)
            .field("require_client_cert", &self.require_client_cert)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome指纹配置可构造() {
        let cfg = FingerprintConfig::chrome();
        let conn = cfg.build_connector().expect("Chrome 指纹配置应可构造");
        // 能构造即说明所有参数被 BoringSSL 接受（不合法参数会返回 Err）
        drop(conn);
    }

    #[test]
    fn 简化指纹可构造() {
        let cfg = FingerprintConfig::plain();
        assert_eq!(cfg.profile(), FingerprintProfile::Plain);
        assert!(cfg.build_connector().is_ok());
    }

    #[test]
    fn 默认开启证书校验() {
        assert!(FingerprintConfig::default().verify_cert);
        assert!(
            !FingerprintConfig::chrome()
                .danger_accept_invalid_certs()
                .verify_cert
        );
    }

    /// ALPN 必须是 h2 优先，且线格式正确（长度前缀）。
    #[test]
    fn alpn线格式正确() {
        // b"\x02h2\x08http/1.1"
        //  ^ len=2  ^"h2"  ^len=8   ^"http/1.1"
        assert_eq!(CHROME_ALPN[0], 2);
        assert_eq!(&CHROME_ALPN[1..3], b"h2");
        assert_eq!(CHROME_ALPN[3], 8);
        assert_eq!(&CHROME_ALPN[4..12], b"http/1.1");
        assert_eq!(CHROME_ALPN.len(), 12);
    }

    /// cipher 列表必须以 ECDSA-AES128-GCM 开头（Chrome 顺序）。
    #[test]
    fn cipher列表顺序符合chrome() {
        let first = CHROME_CIPHER_LIST.split(':').next().unwrap();
        assert_eq!(first, "ECDHE-ECDSA-AES128-GCM-SHA256");
        // 必须包含 ChaCha20（无 AES-NI 设备的兜底）
        assert!(CHROME_CIPHER_LIST.contains("CHACHA20-POLY1305"));
    }

    /// 曲线列表必须以 X25519 开头。
    #[test]
    fn 曲线列表顺序符合chrome() {
        assert!(CHROME_CURVES.starts_with("X25519"));
        assert!(CHROME_CURVES.contains("P-256"));
        assert!(CHROME_CURVES.contains("P-384"));
    }

    /// sigalgs 必须以 ECDSA+SHA256 开头，且包含 RSA-PSS（现代 RSA）。
    #[test]
    fn 签名算法顺序符合chrome() {
        assert!(CHROME_SIGALGS.starts_with("ECDSA+SHA256"));
        assert!(CHROME_SIGALGS.contains("rsa_pss_rsae_sha256"));
        assert!(CHROME_SIGALGS.contains("RSA+SHA256"));
    }

    /// 服务端 acceptor 用不存在的证书必须报错而非 panic。
    #[test]
    fn 服务端缺证书报错() {
        let cfg = ServerTlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(cfg.build_acceptor().is_err());
    }
}
