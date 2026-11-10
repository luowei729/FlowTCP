//! 自研 TLS 1.3 ClientHello 构造器
//!
//! # 为什么必须自研（方案 G 的核心）
//!
//! 前面实测排除了两条路：
//!
//! | 方案 | 结果 |
//! |------|------|
//! | 客户端字节流层改写 `session_id` | ❌ TLS 1.3 转录包含 ClientHello 全部字节，改了就 `BAD_DECRYPT` |
//! | 用 `SSL_SESSION` 注入 `session_id` | ❌ BoringSSL 源码里 TLS 1.3 永远不走 `kID` 分支 |
//!
//! 根因是同一个：**BoringSSL 不给我们控制 ClientHello 字节的能力**。
//! REALITY 能解决，是因为它的客户端是 uTLS（fork 的 Go crypto/tls），
//! 可以直接改 ClientHello 结构体字段、再从最终字节计算转录。
//!
//! Rust 生态（`rustls` / `boring` / `boring2`）都没有这个能力。因此
//! **客户端必须自己构造 ClientHello 并自己算转录** —— 这就是本模块。
//!
//! # 服务端不需要改
//!
//! 服务端只是把收到的原始字节喂给 BoringSSL（`PrebufferedStream` 已实现），
//! 转录天然一致。**只有客户端需要自研。**
//!
//! # 指纹基准（实测自 BoringSSL）
//!
//! 用 `set_grease_enabled` + `set_permute_extensions` + OCSP + SCT 配置的
//! BoringSSL 生成的 ClientHello，JA4 为 `t13d1513h2_8daaf6152771_...`，
//! 第二段哈希 `8daaf6152771` **与 Chrome 桌面版一致**。
//!
//! 本构造器复刻该结构（扩展集合、GREASE 位置、各扩展内容），
//! 并额外补上 Chrome 有而我们之前缺的三个扩展：
//!
//! - `21` padding
//! - `27` compress_certificate
//! - `17513` application_settings (ALPS，Chrome 特有)
//!
//! # 与 BoringSSL 的字节级差异（有意为之）
//!
//! - `session_id`：填入我们的认证票据（32 字节），而非随机值
//! - 扩展顺序：固定为 Chrome 常见顺序，而非每次随机
//!   （随机顺序对 JA4 无影响 —— JA4 的扩展哈希基于**排序后**的列表）

use rand::TryRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// TLS 握手记录的内容类型。
pub const TLS_HANDSHAKE: u8 = 0x16;
/// TLS 1.0 记录版本（ClientHello 首条记录惯例值）。
pub const TLS_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
/// legacy_version：TLS 1.2（TLS 1.3 的 ClientHello 必须写此值）。
pub const LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
/// ClientHello 的握手消息类型。
pub const HS_CLIENT_HELLO: u8 = 0x01;

/// GREASE 值表（RFC 8701）。
///
/// 必须是 `0x?a?a` 形式，且首尾字节相同。
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// TLS 1.3 cipher suite 常量。
mod cipher {
    /// `TLS_AES_128_GCM_SHA256`
    pub const AES_128_GCM: u16 = 0x1301;
    /// `TLS_AES_256_GCM_SHA384`
    pub const AES_256_GCM: u16 = 0x1302;
    /// `TLS_CHACHA20_POLY1305_SHA256`
    pub const CHACHA20: u16 = 0x1303;
}

/// 扩展类型常量。
mod ext {
    /// server_name
    pub const SERVER_NAME: u16 = 0x0000;
    /// status_request（OCSP）
    pub const STATUS_REQUEST: u16 = 0x0005;
    /// supported_groups
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// ec_point_formats
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    /// signature_algorithms
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// application_layer_protocol_negotiation
    pub const ALPN: u16 = 0x0010;
    /// signed_certificate_timestamp
    pub const SCT: u16 = 0x0012;
    /// padding
    pub const PADDING: u16 = 0x0015;
    /// extended_master_secret
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    /// compress_certificate
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    /// session_ticket
    pub const SESSION_TICKET: u16 = 0x0023;
    /// supported_versions
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// psk_key_exchange_modes
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    /// key_share
    pub const KEY_SHARE: u16 = 0x0033;
    /// application_settings（ALPS，Chrome 特有）
    pub const APPLICATION_SETTINGS: u16 = 0x4469;
    /// renegotiation_info
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// 命名组常量。
mod group {
    /// x25519
    pub const X25519: u16 = 0x001d;
    /// secp256r1 (P-256)
    pub const P256: u16 = 0x0017;
    /// secp384r1 (P-384)
    pub const P384: u16 = 0x0018;
}

/// 签名算法常量（TLS 1.3 常用）。
mod sigalg {
    /// ecdsa_secp256r1_sha256
    pub const ECDSA_P256_SHA256: u16 = 0x0403;
    /// rsa_pss_rsae_sha256
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// rsa_pkcs1_sha256
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /// ecdsa_secp384r1_sha384
    pub const ECDSA_P384_SHA384: u16 = 0x0503;
    /// rsa_pss_rsae_sha384
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /// rsa_pkcs1_sha384
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    /// ecdsa_secp521r1_sha512
    pub const ECDSA_P521_SHA512: u16 = 0x0603;
    /// rsa_pss_rsae_sha512
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    /// rsa_pkcs1_sha512
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
}

/// 构造 ClientHello 的参数。
pub struct ClientHelloParams {
    /// SNI（服务端名称）。
    pub sni: String,
    /// `session_id`（32 字节）。**这是我们的认证票据载体。**
    ///
    /// 自研构造器的核心价值就在这里：可以自由填入任意 32 字节，
    /// 且因为转录由我们自己计算，不会有 `BAD_DECRYPT`。
    pub session_id: [u8; 32],
    /// X25519 临时公钥（用于 key_share）。
    pub key_share_public: [u8; 32],
    /// 客户端随机数（32 字节）。
    pub random: [u8; 32],
    /// GREASE 值。`None` 表示不插入 GREASE（不推荐，易被识别）。
    pub grease: Option<u16>,
}

impl ClientHelloParams {
    /// 生成完整的随机参数（除 `session_id` 由调用方填入）。
    pub fn new(sni: impl Into<String>, session_id: [u8; 32], seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let key_share_public = PublicKey::from(&secret).to_bytes();

        let mut random = [0u8; 32];
        // rand 0.9：OsRng 实现 TryRngCore（可能失败），需显式处理
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .expect("系统 CSPRNG 不可用");
        let grease = Some(GREASE_VALUES[(random[0] as usize) % GREASE_VALUES.len()]);

        ClientHelloParams {
            sni: sni.into(),
            session_id,
            key_share_public,
            random,
            grease,
        }
    }

    /// 由种子生成 X25519 临时私钥（调用方需保存以完成 ECDHE）。
    pub fn ephemeral_secret(seed: [u8; 32]) -> StaticSecret {
        StaticSecret::from(seed)
    }

    /// **客户端实际使用的构造入口**：自动把认证票据写进 `session_id`。
    ///
    /// # 为什么必须这样（不能先给 session_id）
    ///
    /// 票据 = `HMAC(secret, "ticket" || client_random || window)`，
    /// 依赖 `client_random`。而 `client_random` 是 ClientHello 的一部分，
    /// 因此顺序必须是：**先定 random → 再算 ticket → 再拼 ClientHello**。
    ///
    /// 早期 API 让调用方直接传 `session_id`，导致无法先算票据；
    /// 这个构造把 random 的生成暴露出来，与票据计算串成一条链。
    ///
    /// `random` 传 `None` 时自动用系统 CSPRNG 生成。
    pub fn authed(
        sni: impl Into<String>,
        seed: [u8; 32],
        auth: &flowtcp_proto::steal::AuthKey,
        random: Option<[u8; 32]>,
        now_unix: u64,
    ) -> Self {
        let random = random.unwrap_or_else(|| {
            let mut r = [0u8; 32];
            use rand::TryRngCore;
            rand::rngs::OsRng
                .try_fill_bytes(&mut r)
                .expect("系统 CSPRNG 不可用");
            r
        });

        // 票据时间窗口：与服务端 `judge()` 用同一套算法
        let window = now_unix / flowtcp_proto::steal::TIME_WINDOW_SECS;
        let session_id = auth.ticket(&random, window);

        let secret = StaticSecret::from(seed);
        let key_share_public = PublicKey::from(&secret).to_bytes();
        // GREASE 值由 random 首字节决定，与 Chrome 行为一致（同一连接内固定）
        let grease = Some(GREASE_VALUES[(random[0] as usize) % GREASE_VALUES.len()]);

        ClientHelloParams {
            sni: sni.into(),
            session_id,
            key_share_public,
            random,
            grease,
        }
    }
}

/// 构造完整的 ClientHello（含 TLS 记录头）。
///
/// 返回的字节可直接写入 TCP 流。
pub fn build_client_hello(p: &ClientHelloParams) -> Vec<u8> {
    let body = build_handshake_body(p);

    // 握手头：type(1) + length(3)
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(HS_CLIENT_HELLO);
    hs.push(((body.len() >> 16) & 0xff) as u8);
    hs.push(((body.len() >> 8) & 0xff) as u8);
    hs.push((body.len() & 0xff) as u8);
    hs.extend_from_slice(&body);

    // 记录头：type(1) + version(2) + length(2)
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(TLS_HANDSHAKE);
    rec.extend_from_slice(&TLS_RECORD_VERSION);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// 构造 ClientHello 的握手体（不含记录头与握手头）。
fn build_handshake_body(p: &ClientHelloParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    // ---- legacy_version ----
    out.extend_from_slice(&LEGACY_VERSION);
    // ---- random ----
    out.extend_from_slice(&p.random);
    // ---- legacy_session_id ----
    out.push(32);
    out.extend_from_slice(&p.session_id);

    // ---- cipher_suites ----
    let mut ciphers: Vec<u16> = Vec::with_capacity(12);
    if let Some(g) = p.grease {
        ciphers.push(g);
    }
    // ★ cipher 列表必须与 `fingerprint.rs::CHROME_CIPHER_LIST` **完全一致**。
    //
    // 实测证明：`tls.peet.ws` 报的 JA4 B 段（`8daaf6152771`）就是
    // `sha256(排序后的 cipher 4hex 列表)[0..12]`。因此只要 cipher 集合与
    // Chrome 相同，该哈希必然一致。少一个都会导致指纹不匹配。
    ciphers.extend_from_slice(&[
        // TLS 1.3 三个（RFC 8446 §9.1 强制）
        cipher::AES_128_GCM, // 0x1301
        cipher::AES_256_GCM, // 0x1302
        cipher::CHACHA20,    // 0x1303
        // TLS 1.2 十二个（Chrome 顺序：ECDHE-GCM → ECDHE-CBC → RSA-GCM → RSA-CBC）
        0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
        0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
        0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
        0xc030, // ECDHE-RSA-AES256-GCM-SHA384
        0xcca9, // ECDHE-ECDSA-CHACHA20-POLY1305
        0xcca8, // ECDHE-RSA-CHACHA20-POLY1305
        0xc013, // ECDHE-RSA-AES128-SHA
        0xc014, // ECDHE-RSA-AES256-SHA
        0x009c, // AES128-GCM-SHA256
        0x009d, // AES256-GCM-SHA384
        0x002f, // AES128-SHA
        0x0035, // AES256-SHA
    ]);
    out.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in &ciphers {
        out.extend_from_slice(&c.to_be_bytes());
    }

    // ---- compression_methods ----
    out.push(1);
    out.push(0); // null

    // ---- extensions ----
    let exts = build_extensions(p);
    out.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    out.extend_from_slice(&exts);

    out
}

/// 构造扩展列表。
///
/// # 顺序说明
///
/// 按 Chrome 常见顺序排列。JA4 的扩展哈希基于**排序后**的 ID 列表，
/// 因此顺序不影响指纹；但保持与 Chrome 一致可降低被非常规检测识别的概率。
fn build_extensions(p: &ClientHelloParams) -> Vec<u8> {
    let mut exts = Vec::with_capacity(320);

    // 1) GREASE 扩展（Chrome 固定放第一个，空内容）
    if let Some(g) = p.grease {
        push_ext(&mut exts, g, &[]);
    }

    // 2) server_name
    {
        let name = p.sni.as_bytes();
        let mut d = Vec::with_capacity(5 + name.len());
        d.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list_len
        d.push(0); // host_name
        d.extend_from_slice(&(name.len() as u16).to_be_bytes());
        d.extend_from_slice(name);
        push_ext(&mut exts, ext::SERVER_NAME, &d);
    }

    // 3) extended_master_secret（空，TLS 1.2 兼容性要求）
    push_ext(&mut exts, ext::EXTENDED_MASTER_SECRET, &[]);

    // 4) renegotiation_info（空 renegotiated_connection）
    push_ext(&mut exts, ext::RENEGOTIATION_INFO, &[0x00]);

    // 5) supported_groups
    {
        let mut d = Vec::new();
        let mut groups: Vec<u16> = Vec::new();
        if let Some(g) = p.grease {
            groups.push(g);
        }
        groups.extend_from_slice(&[group::X25519, group::P256, group::P384]);
        d.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in &groups {
            d.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, ext::SUPPORTED_GROUPS, &d);
    }

    // 6) signature_algorithms
    {
        let algs = [
            sigalg::ECDSA_P256_SHA256,
            sigalg::RSA_PSS_RSAE_SHA256,
            sigalg::RSA_PKCS1_SHA256,
            sigalg::ECDSA_P384_SHA384,
            sigalg::RSA_PSS_RSAE_SHA384,
            sigalg::RSA_PKCS1_SHA384,
            sigalg::ECDSA_P521_SHA512,
            sigalg::RSA_PSS_RSAE_SHA512,
            sigalg::RSA_PKCS1_SHA512,
        ];
        let mut d = Vec::with_capacity(2 + algs.len() * 2);
        d.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
        for a in &algs {
            d.extend_from_slice(&a.to_be_bytes());
        }
        push_ext(&mut exts, ext::SIGNATURE_ALGORITHMS, &d);
    }

    // 7) signed_certificate_timestamp（空，Chrome 2018 起强制）
    push_ext(&mut exts, ext::SCT, &[]);

    // 8) key_share
    {
        let mut entry = Vec::with_capacity(36);
        // GREASE 的 key_share 条目（1 字节 key）
        let mut d = Vec::new();
        let mut shares: Vec<(u16, Vec<u8>)> = Vec::new();
        if let Some(g) = p.grease {
            shares.push((g, vec![0x00]));
        }
        shares.push((group::X25519, p.key_share_public.to_vec()));
        let total: usize = shares.iter().map(|(_, k)| 4 + k.len()).sum();
        d.extend_from_slice(&(total as u16).to_be_bytes());
        for (g, k) in &shares {
            d.extend_from_slice(&g.to_be_bytes());
            d.extend_from_slice(&(k.len() as u16).to_be_bytes());
            d.extend_from_slice(k);
        }
        entry.extend_from_slice(&d);
        push_ext(&mut exts, ext::KEY_SHARE, &entry);
    }

    // 9) psk_key_exchange_modes（仅 psk_dhe_ke）
    push_ext(&mut exts, ext::PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01]);

    // 10) supported_versions
    {
        let mut d = Vec::new();
        let mut vers: Vec<u16> = Vec::new();
        if let Some(g) = p.grease {
            vers.push(g);
        }
        vers.push(0x0304); // TLS 1.3
        vers.push(0x0303); // TLS 1.2
        d.push((vers.len() * 2) as u8);
        for v in &vers {
            d.extend_from_slice(&v.to_be_bytes());
        }
        push_ext(&mut exts, ext::SUPPORTED_VERSIONS, &d);
    }

    // 11) ec_point_formats（uncompressed）
    push_ext(&mut exts, ext::EC_POINT_FORMATS, &[0x01, 0x00]);

    // 12) session_ticket（空，Chrome 会带）
    push_ext(&mut exts, ext::SESSION_TICKET, &[]);

    // 13) ALPN（h2 优先，必须与真实浏览器一致）
    {
        let d = b"\x00\x0c\x02h2\x08http/1.1";
        push_ext(&mut exts, ext::ALPN, d);
    }

    // 14) status_request（OCSP stapling，Chrome 必带）
    push_ext(
        &mut exts,
        ext::STATUS_REQUEST,
        &[0x01, 0x00, 0x00, 0x00, 0x00],
    );

    // 15) compress_certificate（Chrome 有：brotli / zlib / zstd）
    {
        let algs: [u16; 3] = [0x0002, 0x0001, 0x0003];
        let mut d = Vec::with_capacity(1 + algs.len() * 2);
        d.push((algs.len() * 2) as u8);
        for a in &algs {
            d.extend_from_slice(&a.to_be_bytes());
        }
        push_ext(&mut exts, ext::COMPRESS_CERTIFICATE, &d);
    }

    // 16) application_settings（ALPS，Chrome 特有）
    {
        // ALPS 内容：ALPN 列表（h2 的 settings）
        // 真实 Chrome 发的是 h2 的应用层设置序列化，这里用最小的合法形态
        let d = b"\x00\x03\x02h2";
        push_ext(&mut exts, ext::APPLICATION_SETTINGS, d);
    }

    // 17) padding —— 必须放最后
    //
    // 作用：把整个 ClientHello 填充到固定长度（Chrome 常见 0x0000-0x00ff 区间），
    // 避免"扩展长度恰好是多少"成为指纹。
    //
    // 这里填充到 512 字节对齐（含记录头 5 + 握手头 4）。
    {
        const TARGET: usize = 512;
        let current = exts.len();
        if current < TARGET {
            // padding 扩展自身占 4 字节
            let pad_len = TARGET.saturating_sub(current + 4);
            let pad = vec![0u8; pad_len];
            push_ext(&mut exts, ext::PADDING, &pad);
        }
    }

    exts
}

/// 追加一个扩展（type(2) + len(2) + data）。
fn push_ext(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ClientHelloParams {
        ClientHelloParams::new("flowtcp.test", [0xAB; 32], [0x11; 32])
    }

    /// 构造的 ClientHello 必须是合法 TLS 记录结构。
    #[test]
    fn 结构合法() {
        let ch = build_client_hello(&params());
        assert_eq!(ch[0], TLS_HANDSHAKE, "记录类型");
        assert_eq!(&ch[1..3], &TLS_RECORD_VERSION, "记录版本");
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(rec_len, ch.len() - 5, "记录长度必须与总长一致");
        assert_eq!(ch[5], HS_CLIENT_HELLO, "握手类型");
        let hs_len = ((ch[6] as usize) << 16) | ((ch[7] as usize) << 8) | ch[8] as usize;
        assert_eq!(hs_len, ch.len() - 9, "握手长度必须与剩余一致");
    }

    /// 各字段偏移必须与 RFC 8446 一致（供 server 解析器复用）。
    #[test]
    fn 字段偏移正确() {
        let p = params();
        let ch = build_client_hello(&p);
        assert_eq!(&ch[9..11], &LEGACY_VERSION, "legacy_version 在偏移 9");
        assert_eq!(&ch[11..43], &p.random, "random 在偏移 11");
        assert_eq!(ch[43], 32, "session_id 长度在偏移 43");
        assert_eq!(&ch[44..76], &p.session_id, "session_id 在偏移 44");
    }

    /// ★ 核心：session_id 必须能承载我们指定的 32 字节票据。
    #[test]
    fn 票据可嵌入session_id() {
        let ticket = [0x5Au8; 32];
        let p = ClientHelloParams::new("flowtcp.test", ticket, [0x22; 32]);
        let ch = build_client_hello(&p);
        assert_eq!(&ch[44..76], &ticket);
    }

    /// 服务端解析器必须能解析我们构造的 ClientHello（双向兼容）。
    #[test]
    fn 服务端解析器可解析() {
        let p = params();
        let ch = build_client_hello(&p);
        let info = flowtcp_proto::steal::parse_client_hello(&ch)
            .expect("解析不应报错")
            .expect("应能完整解析");
        assert_eq!(info.sni.as_deref(), Some("flowtcp.test"));
        assert_eq!(info.session_id, p.session_id.to_vec());
        assert_eq!(info.random, p.random);
        assert_eq!(info.key_share_x25519, Some(p.key_share_public));
        assert_eq!(info.wire_len, ch.len());
    }

    /// 必须包含 Chrome 的关键扩展。
    #[test]
    fn 包含chrome关键扩展() {
        let ch = build_client_hello(&params());
        let types = ext_types(&ch);
        for (name, ty) in [
            ("server_name", ext::SERVER_NAME),
            ("status_request", ext::STATUS_REQUEST),
            ("supported_groups", ext::SUPPORTED_GROUPS),
            ("sigalgs", ext::SIGNATURE_ALGORITHMS),
            ("ALPN", ext::ALPN),
            ("SCT", ext::SCT),
            ("extended_master_secret", ext::EXTENDED_MASTER_SECRET),
            ("session_ticket", ext::SESSION_TICKET),
            ("supported_versions", ext::SUPPORTED_VERSIONS),
            ("psk_modes", ext::PSK_KEY_EXCHANGE_MODES),
            ("key_share", ext::KEY_SHARE),
            ("renegotiation_info", ext::RENEGOTIATION_INFO),
            ("ec_point_formats", ext::EC_POINT_FORMATS),
            ("compress_certificate", ext::COMPRESS_CERTIFICATE),
            ("ALPS", ext::APPLICATION_SETTINGS),
        ] {
            assert!(types.contains(&ty), "缺少扩展 {name} (0x{ty:04x})");
        }
    }

    /// GREASE 必须出现在正确位置（cipher[0]、扩展、group、version、key_share）。
    #[test]
    fn grease位置正确() {
        let mut p = params();
        p.grease = Some(0x1a1a);
        let ch = build_client_hello(&p);

        // cipher[0] 是 GREASE
        // 布局：legacy_version(9..11) random(11..43) sid_len(43) sid(44..76)
        //       → cipher_suites 长度字段在 76
        let cs_off = 76usize;
        let cs_len = u16::from_be_bytes([ch[cs_off], ch[cs_off + 1]]) as usize;
        let first_cipher = u16::from_be_bytes([ch[cs_off + 2], ch[cs_off + 3]]);
        assert_eq!(first_cipher, 0x1a1a, "cipher[0] 应为 GREASE");
        // GREASE(1) + TLS1.3 三个 + TLS1.2 十二个 = 16 个
        assert_eq!(cs_len, 16 * 2, "应有 16 个 cipher（含 GREASE）");

        // 扩展列表含 GREASE
        let types = ext_types(&ch);
        assert!(types.contains(&0x1a1a), "扩展列表应含 GREASE");

        // supported_groups[0] 是 GREASE
        let (gs, gl) = find_ext(&ch, ext::SUPPORTED_GROUPS).expect("应有 supported_groups");
        let first_group = u16::from_be_bytes([ch[gs + 2], ch[gs + 3]]);
        assert_eq!(first_group, 0x1a1a, "groups[0] 应为 GREASE");
        let _ = gl;

        // supported_versions[0] 是 GREASE
        let (vs, _) = find_ext(&ch, ext::SUPPORTED_VERSIONS).expect("应有 supported_versions");
        let first_ver = u16::from_be_bytes([ch[vs + 1], ch[vs + 2]]);
        assert_eq!(first_ver, 0x1a1a, "versions[0] 应为 GREASE");

        // key_share[0] 是 GREASE
        let (ks, _) = find_ext(&ch, ext::KEY_SHARE).expect("应有 key_share");
        let first_ks_group = u16::from_be_bytes([ch[ks + 2], ch[ks + 3]]);
        assert_eq!(first_ks_group, 0x1a1a, "key_share[0] 应为 GREASE");
    }

    /// 不插 GREASE 时也必须合法（仅用于测试对照）。
    #[test]
    fn 无grease也可构造() {
        let mut p = params();
        p.grease = None;
        let ch = build_client_hello(&p);
        let info = flowtcp_proto::steal::parse_client_hello(&ch)
            .unwrap()
            .unwrap();
        assert_eq!(info.sni.as_deref(), Some("flowtcp.test"));
        let types = ext_types(&ch);
        assert!(!types.iter().any(|t| GREASE_VALUES.contains(t)));
    }

    /// ALPN 必须是 h2 优先（缺了会被判为非浏览器）。
    #[test]
    fn alpn为h2优先() {
        let ch = build_client_hello(&params());
        let (d, l) = find_ext(&ch, ext::ALPN).expect("应有 ALPN");
        let body = &ch[d..d + l];
        // ALPN 格式：list_len(2) || proto_len(1) || proto
        assert_eq!(body[2], 2, "首个协议名长度应为 2");
        assert_eq!(&body[3..5], b"h2", "首个协议必须是 h2");
    }

    /// 构造长度应稳定在合理范围（Chrome 典型 300~600 字节）。
    #[test]
    fn 长度在chrome范围() {
        let ch = build_client_hello(&params());
        assert!(
            (400..=800).contains(&ch.len()),
            "长度 {} 不在 Chrome 典型范围内（含 padding）",
            ch.len()
        );
    }

    /// 相同参数（含固定 random）必须产生完全相同的字节（可复现）。
    #[test]
    fn 构造可复现() {
        let p = params();
        assert_eq!(build_client_hello(&p), build_client_hello(&p));
    }

    /// 不同票据 → 不同 ClientHello（但仅 session_id 区域不同）。
    #[test]
    fn 不同票据仅影响session_id() {
        let a = ClientHelloParams::new("x.test", [0x01; 32], [0x33; 32]);
        let b = ClientHelloParams::new("x.test", [0x02; 32], [0x33; 32]);
        let ca = build_client_hello(&a);
        let cb = build_client_hello(&b);
        assert_eq!(ca.len(), cb.len(), "长度应相同");
        // 除 44..76 外，其余应相同（random 因 new() 内部随机而不同，
        // 因此这里只比较 session_id 区段确实不同）
        assert_ne!(&ca[44..76], &cb[44..76]);
    }

    // ---- 测试辅助：解析扩展 ----

    fn ext_types(ch: &[u8]) -> Vec<u16> {
        let mut v = Vec::new();
        let mut p = 9 + 2 + 32;
        let sl = ch[p] as usize;
        p += 1 + sl;
        let cl = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
        p += 2 + cl;
        let ml = ch[p] as usize;
        p += 1 + ml;
        let tl = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
        p += 2;
        let end = (p + tl).min(ch.len());
        while p + 4 <= end {
            let t = u16::from_be_bytes([ch[p], ch[p + 1]]);
            let l = u16::from_be_bytes([ch[p + 2], ch[p + 3]]) as usize;
            v.push(t);
            p += 4 + l;
        }
        v
    }

    /// 返回 (数据偏移, 数据长度)。
    fn find_ext(ch: &[u8], want: u16) -> Option<(usize, usize)> {
        let mut p = 9 + 2 + 32;
        let sl = ch[p] as usize;
        p += 1 + sl;
        let cl = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
        p += 2 + cl;
        let ml = ch[p] as usize;
        p += 1 + ml;
        let tl = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
        p += 2;
        let end = (p + tl).min(ch.len());
        while p + 4 <= end {
            let t = u16::from_be_bytes([ch[p], ch[p + 1]]);
            let l = u16::from_be_bytes([ch[p + 2], ch[p + 3]]) as usize;
            if t == want {
                return Some((p + 4, l));
            }
            p += 4 + l;
        }
        None
    }
}
