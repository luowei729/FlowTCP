//! 偷网站（REALITY 式）：从 ClientHello 认证，失败则透传给真实网站
//!
//! # 为什么这条路能免掉 nginx 和证书
//!
//! 传统方案要自己有域名 + 证书 + nginx 来"扮演一个网站"。但真正的网站
//! 已经存在了，我们只需要在**认证失败时把 TCP 字节流原样转发给它**：
//!
//! ```text
//! 探测者/浏览器 ──TCP──> FlowTCP 服务端 ──TCP──> 真实网站 (如 www.microsoft.com:443)
//!                              ↑                        │
//!                              └────── 字节流透传 ──────┘
//! ```
//!
//! 探测者看到的是**真实网站完整、无误的 TLS 会话**：真证书、真 ServerHello、
//! 真证书链、真 OCSP。我们从未参与 TLS，因此不可能露出破绽。
//!
//! 这比"自己扮演网站"强得多 —— 扮演总有细节差异，转发则没有。
//!
//! # 认证载体：ClientHello.session_id
//!
//! TLS 1.3 的 `session_id` 是 **32 字节、内容不受约束** 的兼容性字段
//! （RFC 8446 §4.1.2 明确它是"兼容性字段"，TLS 1.3 不使用它做会话恢复）。
//! 真实 Chrome 也会填它（为中间设备兼容），因此"非空 + 随机内容"完全不异常。
//!
//! # ★ 为什么用对称派生而不是 REALITY 的 ECDH
//!
//! REALITY 用 X25519 `key_share` 做 ECDH，因为它的客户端是 **fork 过的
//! crypto/tls**（uTLS），能拿到自己生成的临时私钥。
//!
//! 我们用 BoringSSL，**它不暴露 `key_share` 的临时私钥**（也没有
//! `SSL_CTX_set_client_hello_cb` 这样的回调）。这意味着客户端**无法**算出
//! ECDH 共享密钥 —— 除非我们自己 fork BoringSSL，那是不可接受的工程量。
//!
//! 因此改用**对称密钥派生**，安全性等价（都是基于预共享秘密），
//! 但客户端可用**完全标准**的 BoringSSL，只需在字节流层改写 session_id：
//!
//! ```text
//! ticket    = HMAC-SHA256(secret, "flowtcp v1 ticket" || client_random || window)
//! cert_seed = HMAC-SHA256(secret, "flowtcp v1 cert"   || client_random)
//! ```
//!
//! - `ticket` 正好 32 字节 → 直接填入 `session_id`
//! - `cert_seed` 派生 Ed25519 密钥 → 服务端签临时证书，客户端验签
//! - `window = now / 30` → 服务端接受当前窗口及前后各 1 个（±30 秒容错）
//!
//! **抗重放**：`client_random` 每连接唯一，同一票据无法用于另一条连接。
//! **抗中间人**：没有 `secret` 就算不出合法 ticket，也伪造不出能通过验签的证书。
//!
//! # 裁决与处置
//!
//! | 认证结果 | 处置 | 探测者看到 |
//! |---------|------|-----------|
//! | ticket 匹配 + SNI 在允许列表 | 自行完成 TLS 握手（临时证书） | 我们的服务 |
//! | 任一环节失败 | **原样透传到真实网站** | 真实网站的完整 TLS 会话 |

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// session_id 固定长度（TLS 1.3 要求 ≤32，Chrome 桌面版恒为 32）。
pub const SESSION_ID_LEN: usize = 32;
/// 票据长度（正好填满 session_id）。
pub const TICKET_LEN: usize = 32;
/// 用户标识长度（仅用于日志区分，不参与认证）。
pub const USER_TAG_LEN: usize = 8;
/// 时间窗口长度（秒）。
///
/// 取 30 秒：与 REALITY 默认一致。太小会因客户端时钟漂移误拒，
/// 太大则扩大重放窗口（尽管 `client_random` 已使跨连接重放无效）。
pub const TIME_WINDOW_SECS: u64 = 30;
/// 接受的时间窗口容差（前后各几个窗口）。
///
/// 取 1 → 服务端接受 `window-1 / window / window+1`，即 ±30 秒容错，
/// 总有效窗口 90 秒。足以覆盖网络延迟与时钟漂移。
pub const TIME_WINDOW_TOLERANCE: u64 = 1;
/// x25519 公钥长度（仅用于解析 `key_share`，本方案不再用它做密钥交换）。
pub const X25519_LEN: usize = 32;

/// 票据派生标签。
const LABEL_TICKET: &[u8] = b"flowtcp v1 ticket";
/// 证书种子派生标签。
const LABEL_CERT: &[u8] = b"flowtcp v1 cert";
/// 用户标识派生标签。
const LABEL_TAG: &[u8] = b"flowtcp v1 tag";

/// TLS 握手记录的内容类型。
const TLS_HANDSHAKE: u8 = 0x16;
/// ClientHello 的握手消息类型。
const HS_CLIENT_HELLO: u8 = 0x01;
/// extension: server_name。
const EXT_SERVER_NAME: u16 = 0x0000;
/// extension: key_share。
const EXT_KEY_SHARE: u16 = 0x0033;
/// 命名组: x25519。
const GROUP_X25519: u16 = 0x001D;

/// 预共享认证密钥。
///
/// # 客户端与服务端都需要它
///
/// - 服务端：验票据、派生证书种子
/// - 客户端：算票据、算证书种子（验服务端证书）
///
/// 通常由用户配置的"密码"派生：`AuthKey::from_password("my-password")`。
/// 对密码做 SHA-256 而不是直接使用，是为了：
/// 1. 支持任意长度密码
/// 2. 避免弱密码直接作为 HMAC 密钥
#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey([u8; 32]);

impl AuthKey {
    /// 从 32 字节原始密钥构造。
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        AuthKey(secret)
    }

    /// 从人类可读密码派生。
    ///
    /// 用 SHA-256（而非慢哈希如 Argon2）的理由：这个密钥用于
    /// **每条连接的 HMAC**，必须在握手路径上足够快。密码强度应由
    /// 用户选择足够随机的字符串来保证（推荐 32 字节随机值的 base64）。
    pub fn from_password(password: &str) -> Self {
        AuthKey(sha256(password.as_bytes()))
    }

    /// 生成随机密钥（服务端初始化时使用）。
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        use rand::TryRngCore;
        rand::rngs::OsRng
            .try_fill_bytes(&mut seed)
            .expect("系统 CSPRNG 不可用");
        AuthKey(seed)
    }

    /// 计算某个时间窗口的票据。
    ///
    /// `session_id` 直接填这 32 字节。
    pub fn ticket(&self, client_random: &[u8; 32], window: u64) -> [u8; TICKET_LEN] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC 接受任意长度密钥");
        mac.update(LABEL_TICKET);
        mac.update(client_random);
        mac.update(&window.to_be_bytes());
        let out = mac.finalize().into_bytes();
        let mut t = [0u8; TICKET_LEN];
        t.copy_from_slice(&out);
        t
    }

    /// 派生临时证书的签名种子。
    ///
    /// 服务端用它签自签证书，客户端用同一颗种子派生公钥来验签。
    ///
    /// **安全关键**：标签与 [`Self::ticket`] 不同。若相同，攻击者拿到
    /// 证书签名密钥就能反推出票据密钥，从而伪造 session_id 绕过认证。
    pub fn cert_seed(&self, client_random: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC 接受任意长度密钥");
        mac.update(LABEL_CERT);
        mac.update(client_random);
        let out = mac.finalize().into_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&out);
        seed
    }

    /// 用户标识：由密钥派生，仅用于日志/统计区分，**不参与认证**。
    pub fn user_tag(&self) -> [u8; USER_TAG_LEN] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC 接受任意长度密钥");
        mac.update(LABEL_TAG);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; USER_TAG_LEN];
        tag.copy_from_slice(&out[..USER_TAG_LEN]);
        tag
    }

    /// 常量时间比较票据。
    ///
    /// 必须用常量时间：普通 `==` 会在首个不同字节处提前返回，
    /// 攻击者可通过测量握手耗时逐字节暴力破解票据。
    fn ticket_matches(&self, got: &[u8], expect: &[u8; TICKET_LEN]) -> bool {
        if got.len() != TICKET_LEN {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..TICKET_LEN {
            diff |= got[i] ^ expect[i];
        }
        diff == 0
    }
}

/// 脱敏 Debug：绝不输出密钥。
impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthKey").field(&"<32 字节,已隐藏>").finish()
    }
}

/// 偷网站配置（服务端）。
#[derive(Clone, Debug)]
pub struct StealConfig {
    /// 被"偷"的真实网站，形如 `www.microsoft.com:443`。
    ///
    /// 选择标准（REALITY 作者建议）：
    /// - 国外网站、支持 TLS 1.3 与 h2
    /// - **IP 与服务器相近**（更像，且延迟低）
    /// - 证书链完整、有 OCSP Stapling
    /// - 不要用有跳转的裸域名（如 `example.com` → `www.example.com`）
    pub target: String,
    /// 允许的 SNI 列表。客户端必须使用其中之一。
    ///
    /// 必须是 `target` 域名本身（或 target 也认的别名），
    /// 否则转发过去会因 SNI 不匹配而拿到错误证书。
    pub server_names: Vec<String>,
    /// 预共享认证密钥。
    pub auth: AuthKey,
}

impl StealConfig {
    /// 用目标站点、允许的 SNI 与密钥构造。
    pub fn new(target: impl Into<String>, server_names: Vec<String>, auth: AuthKey) -> Self {
        StealConfig {
            target: target.into(),
            server_names,
            auth,
        }
    }

    /// 便捷构造：从密码派生密钥。
    pub fn from_password(
        target: impl Into<String>,
        server_names: Vec<String>,
        password: &str,
    ) -> Self {
        Self::new(target, server_names, AuthKey::from_password(password))
    }

    /// 面向单个 ClientHello 的裁决。
    pub fn judge(&self, ch: &ClientHelloInfo, now_unix: u64) -> Verdict {
        // ---- 1) SNI 必须在允许列表 ----
        match ch.sni.as_deref() {
            Some(sni) if self.server_names.iter().any(|s| s == sni) => {}
            other => {
                return Verdict::Forward {
                    reason: ForwardReason::SniNotAllowed(other.map(|s| s.to_string())),
                }
            }
        }

        // ---- 2) session_id 必须是 32 字节 ----
        if ch.session_id.len() != SESSION_ID_LEN {
            return Verdict::Forward {
                reason: ForwardReason::BadSessionIdLen(ch.session_id.len()),
            };
        }

        // ---- 3) 票据比对：接受当前窗口及前后各 N 个 ----
        let window = now_unix / TIME_WINDOW_SECS;
        let mut matched: Option<u64> = None;
        for delta in 0..=TIME_WINDOW_TOLERANCE {
            // 先试当前与之后窗口，再试之前窗口（普通客户端的时钟通常不慢于服务端）
            let candidates: [Option<u64>; 2] =
                [window.checked_add(delta), window.checked_sub(delta)];
            for w in candidates.into_iter().flatten() {
                let expect = self.auth.ticket(&ch.random, w);
                if self.auth.ticket_matches(&ch.session_id, &expect) {
                    matched = Some(w);
                    break;
                }
            }
            if matched.is_some() {
                break;
            }
        }

        match matched {
            Some(_) => Verdict::Accept {
                user_tag: self.auth.user_tag(),
            },
            None => Verdict::Forward {
                reason: ForwardReason::TicketMismatch,
            },
        }
    }

    /// 派生本连接临时证书的签名种子。
    pub fn cert_seed(&self, client_random: &[u8; 32]) -> [u8; 32] {
        self.auth.cert_seed(client_random)
    }
}

/// 从 ClientHello 解析出的关键字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// `session_id`（认证票据载体）。
    pub session_id: Vec<u8>,
    /// SNI。
    pub sni: Option<String>,
    /// X25519 `key_share` 的客户端临时公钥。
    ///
    /// **本方案不使用它做密钥交换**（BoringSSL 不暴露对应私钥），
    /// 仅保留用于诊断与将来可能的扩展。
    pub key_share_x25519: Option<[u8; X25519_LEN]>,
    /// `ClientHello.random`（票据与证书种子的派生输入之一）。
    pub random: [u8; 32],
    /// 这条 ClientHello 在字节流中占用的**总长度**（含 TLS 记录头）。
    ///
    /// 转发时需要知道"已经吞掉了多少字节"，以便把它们原样重放给真实网站。
    pub wire_len: usize,
}

/// 裁决结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 认证通过，由我们自己完成 TLS 握手。
    Accept {
        /// 用户标识（由密钥派生，仅用于日志区分）。
        user_tag: [u8; USER_TAG_LEN],
    },
    /// 认证失败，**必须原样转发**到真实网站。
    Forward {
        /// 失败原因（仅用于日志，绝不回给客户端）。
        reason: ForwardReason,
    },
}

impl Verdict {
    /// 是否应转发到真实网站。
    pub fn should_forward(&self) -> bool {
        matches!(self, Verdict::Forward { .. })
    }

    /// 是否应自行处理。
    pub fn should_accept(&self) -> bool {
        matches!(self, Verdict::Accept { .. })
    }
}

/// 转发原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardReason {
    /// SNI 不在允许列表（含未提供 SNI）。
    SniNotAllowed(Option<String>),
    /// session_id 长度不是 32。
    BadSessionIdLen(usize),
    /// 票据不匹配（最常见：对方不是我们的客户端）。
    TicketMismatch,
}

impl std::fmt::Display for ForwardReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardReason::SniNotAllowed(s) => write!(f, "SNI 不在允许列表: {s:?}"),
            ForwardReason::BadSessionIdLen(n) => {
                write!(f, "session_id 长度为 {n}（应为 32）")
            }
            ForwardReason::TicketMismatch => write!(f, "票据不匹配"),
        }
    }
}

/// 解析 ClientHello。
///
/// # 返回值
///
/// - `Ok(Some(info))`：解析成功
/// - `Ok(None)`：数据不足（TCP 分片），调用方应继续读取
/// - `Err(e)`：不是合法的 TLS ClientHello（应转发或关闭）
///
/// # 为什么要自己解析而不交给 TLS 库
///
/// 我们必须在**建立 TLS 上下文之前**判断"这是不是我们的客户端"，
/// 因为判断结果决定这条连接是走 BoringSSL 还是纯字节转发。
/// 一旦先建 TLS 上下文，再想"改成转发"就已经太晚了。
pub fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHelloInfo>, StealError> {
    // ---- TLS 记录头 (5 字节) ----
    if buf.len() < 5 {
        return Ok(None);
    }
    if buf[0] != TLS_HANDSHAKE {
        // 首个记录不是 handshake：可能是 HTTP、或探针
        return Err(StealError::NotTls(buf[0]));
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let rec_end = 5usize.saturating_add(rec_len);
    if buf.len() < rec_end {
        return Ok(None); // 记录未收全
    }

    // ---- 握手头 (4 字节) ----
    let hs = &buf[5..rec_end];
    if hs.len() < 4 {
        return Err(StealError::Truncated);
    }
    if hs[0] != HS_CLIENT_HELLO {
        return Err(StealError::NotClientHello(hs[0]));
    }
    let hs_len = u24(&hs[1..4]);
    let hs_end = 4usize.saturating_add(hs_len);
    if hs.len() < hs_end {
        // 握手消息跨多个 TLS 记录：向调用方报告"需要更多数据"。
        // 真实 Chrome 的 ClientHello 常达 500+ 字节，一定会跨记录。
        return Ok(None);
    }
    let body = &hs[4..hs_end];
    let wire_len = 5 + hs_end;

    // ---- ClientHello 主体 ----
    if body.len() < 2 + 32 + 1 {
        return Err(StealError::Truncated);
    }
    let mut off = 2; // legacy_version

    let mut random = [0u8; 32];
    random.copy_from_slice(&body[off..off + 32]);
    off += 32;

    let sid_len = body[off] as usize;
    off += 1;
    if sid_len > 32 {
        return Err(StealError::BadSessionIdLen(sid_len));
    }
    if body.len() < off + sid_len {
        return Err(StealError::Truncated);
    }
    let session_id = body[off..off + sid_len].to_vec();
    off += sid_len;

    // cipher_suites
    if body.len() < off + 2 {
        return Err(StealError::Truncated);
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;
    if body.len() < off + 1 {
        return Err(StealError::Truncated);
    }

    // compression_methods
    let cm_len = body[off] as usize;
    off += 1 + cm_len;
    if body.len() < off + 2 {
        // 没有 extensions（老客户端），允许但无 SNI/key_share
        return Ok(Some(ClientHelloInfo {
            session_id,
            sni: None,
            key_share_x25519: None,
            random,
            wire_len,
        }));
    }

    // extensions
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    let ext_end = off.saturating_add(ext_total).min(body.len());

    let mut sni: Option<String> = None;
    let mut key_share_x25519: Option<[u8; X25519_LEN]> = None;

    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[off], body[off + 1]]);
        let elen = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        off += 4;
        if off + elen > ext_end {
            break;
        }
        let edata = &body[off..off + elen];

        match etype {
            EXT_SERVER_NAME => {
                // server_name_list: list_len(u16) + [type(u8) + len(u16) + name]
                if edata.len() >= 5 {
                    let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
                    let available = edata.len() - 2;
                    if list_len <= available && list_len >= 3 {
                        let name_type = edata[2];
                        let nlen = u16::from_be_bytes([edata[3], edata[4]]) as usize;
                        if name_type == 0 && edata.len() >= 5 + nlen {
                            if let Ok(s) = std::str::from_utf8(&edata[5..5 + nlen]) {
                                sni = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            EXT_KEY_SHARE if edata.len() >= 2 => {
                // client_shares: total_len(u16) + [group(u16) + key_len(u16) + key]
                let mut p = 2usize;
                while p + 4 <= edata.len() {
                    let group = u16::from_be_bytes([edata[p], edata[p + 1]]);
                    let klen = u16::from_be_bytes([edata[p + 2], edata[p + 3]]) as usize;
                    p += 4;
                    if p + klen > edata.len() {
                        break;
                    }
                    if group == GROUP_X25519 && klen == X25519_LEN {
                        let mut pk = [0u8; X25519_LEN];
                        pk.copy_from_slice(&edata[p..p + klen]);
                        key_share_x25519 = Some(pk);
                    }
                    p += klen;
                }
            }
            _ => {}
        }
        off += elen;
    }

    Ok(Some(ClientHelloInfo {
        session_id,
        sni,
        key_share_x25519,
        random,
        wire_len,
    }))
}

/// 读 3 字节大端整数。
fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

/// 偷网站模块错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StealError {
    /// 首个记录不是 TLS handshake。
    #[error("首包不是 TLS handshake（content_type=0x{0:02X}）")]
    NotTls(u8),
    /// 不是 ClientHello。
    #[error("不是 ClientHello（handshake_type=0x{0:02X}）")]
    NotClientHello(u8),
    /// 数据不足。
    #[error("数据不足")]
    Truncated,
    /// session_id 长度异常。
    #[error("session_id 长度异常: {0}（应为 32）")]
    BadSessionIdLen(usize),
}

/// 计算 SHA-256（导出给上层做 short_id 派生等用途）。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 把票据写入 ClientHello 的 `session_id` 字段。
///
/// # 为什么用「改写」而不是「构造」
///
/// 客户端必须让 ClientHello 与真实 Chrome **逐字节一致**才能抗指纹识别
/// （我们的 JA4 已实测匹配 `8daaf6152771`）。如果自己从头构造 ClientHello，
/// 就得维护一份随 Chrome 版本变化的指纹数据库。
///
/// 正确做法：**让 BoringSSL 生成**（指纹天然正确），然后只替换 `session_id`
/// 这 32 字节。因为 `session_id` 本来就是 32 字节的随机值，替换后：
///
/// - 总长度不变
/// - 字段偏移不变
/// - 其他所有字段（cipher 顺序、扩展集合、GREASE）全不变
///
/// 因此指纹**完全不受影响**。
///
/// # 参数
///
/// - `client_hello`：完整的 TLS 记录（含 5 字节记录头），必须正好是一条握手记录
/// - `session_id`：新的 32 字节会话 ID
///
/// # 返回
///
/// 改写后的字节；`session_id` 字段定位失败时返回原始字节的副本（不报错）——
/// 因为这种情况说明 BoringSSL 没有填 session_id（理论上不会发生），
/// 此时保持原样比中断连接更安全。
pub fn rewrite_session_id(client_hello: &[u8], session_id: &[u8; SESSION_ID_LEN]) -> Vec<u8> {
    let mut out = client_hello.to_vec();

    // 定位 session_id 的偏移：
    // TLS 记录头 5 字节 + 握手头 4 字节 + legacy_version 2 字节 + random 32 字节
    // = 43，然后是 session_id_len(1) + session_id
    const SID_LEN_OFFSET: usize = 5 + 4 + 2 + 32;
    const SID_OFFSET: usize = SID_LEN_OFFSET + 1;

    if out.len() < SID_OFFSET + SESSION_ID_LEN {
        return out; // 数据不足，原样返回
    }
    if out[SID_LEN_OFFSET] as usize != SESSION_ID_LEN {
        // BoringSSL 没填 32 字节 session_id（例如发的是空 session_id）。
        // 此时不能改长度（会破坏整个消息），只能原样返回。
        return out;
    }
    out[SID_OFFSET..SID_OFFSET + SESSION_ID_LEN].copy_from_slice(session_id);
    out
}

/// 从 ClientHello 中取出 `(client_random, session_id 偏移)`。
///
/// 客户端在拦截到 BoringSSL 生成的 ClientHello 后调用它，
/// 以便用 `client_random` 计算票据再把票据写回 `session_id`。
pub fn extract_hello_params(client_hello: &[u8]) -> Option<([u8; 32], usize)> {
    const RANDOM_OFFSET: usize = 5 + 4 + 2;
    const SID_LEN_OFFSET: usize = RANDOM_OFFSET + 32;
    const SID_OFFSET: usize = SID_LEN_OFFSET + 1;

    if client_hello.len() < SID_OFFSET + SESSION_ID_LEN {
        return None;
    }
    if client_hello[SID_LEN_OFFSET] as usize != SESSION_ID_LEN {
        return None;
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[RANDOM_OFFSET..SID_LEN_OFFSET]);
    Some((random, SID_OFFSET))
}

/// 定位 ServerHello 中 `session_id` 的偏移。
///
/// # 为什么需要它
///
/// TLS 1.3 规定服务端必须在 `ServerHello` 中**回显客户端的 `session_id`**
/// （RFC 8446 §4.1.3，为中间设备兼容）。客户端会校验这一项。
///
/// 但我们的客户端改写了发出的 `session_id`（填入票据），BoringSSL 内部
/// 仍记着它自己生成的原始值。服务端回显票据 → 客户端比对不一致 →
/// 报 `DECODE_ERROR` 握手失败。
///
/// 因此客户端必须**双向改写**：发出时改票据，收到 `ServerHello` 时改回原值。
///
/// # 返回
///
/// `Some((session_id 偏移, session_id 长度))`；数据不足或不是 ServerHello 时返回 `None`。
pub fn locate_server_hello_session_id(data: &[u8]) -> Option<(usize, usize)> {
    // 记录头 5 字节
    if data.len() < 5 {
        return None;
    }
    if data[0] != TLS_HANDSHAKE {
        return None;
    }
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let rec_end = 5usize.saturating_add(rec_len);
    if data.len() < rec_end {
        return None; // 记录未收全
    }

    // 握手头 4 字节；ServerHello 的 type = 0x02
    if data.len() < 9 {
        return None;
    }
    if data[5] != 0x02 {
        return None;
    }

    // 记录头(5) + 握手头(4) + legacy_version(2) + random(32) + sid_len(1)
    const SID_LEN_OFFSET: usize = 5 + 4 + 2 + 32;
    if data.len() < SID_LEN_OFFSET + 1 {
        return None;
    }
    let sid_len = data[SID_LEN_OFFSET] as usize;
    let sid_off = SID_LEN_OFFSET + 1;
    if data.len() < sid_off + sid_len {
        return None;
    }
    Some((sid_off, sid_len))
}

/// 把 `ServerHello` 的 `session_id` 改写为指定值。
///
/// 客户端用于把服务端回显的票据还原成 BoringSSL 期望的原始值。
///
/// # 长度必须匹配
///
/// 若 `original` 长度与 ServerHello 中的 `sid_len` 不同则不做任何改动
/// （长度变化会破坏整条消息）。实际场景中两边都是 32 字节。
pub fn rewrite_server_hello_session_id(data: &[u8], original: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    match locate_server_hello_session_id(data) {
        Some((off, len)) if len == original.len() => {
            out[off..off + len].copy_from_slice(original);
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "www.microsoft.com";
    const SNI: &str = "www.microsoft.com";
    const PASSWORD: &str = "test-password-0123456789abcdef";

    fn config() -> StealConfig {
        StealConfig::from_password(format!("{TARGET}:443"), vec![SNI.to_string()], PASSWORD)
    }

    /// 构造结构合法的 ClientHello（用于测试）。
    fn build_hello(
        sni: &str,
        session_id: &[u8],
        random: [u8; 32],
        key_share: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut exts = Vec::new();

        // server_name
        let name = sni.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sn);

        // key_share
        if let Some(pk) = key_share {
            let mut ks = Vec::new();
            ks.extend_from_slice(&((4 + 32) as u16).to_be_bytes());
            ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
            ks.extend_from_slice(&32u16.to_be_bytes());
            ks.extend_from_slice(&pk);
            exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
            exts.extend_from_slice(&(ks.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ks);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HS_CLIENT_HELLO];
        hs.extend_from_slice(&[
            ((body.len() >> 16) & 0xFF) as u8,
            ((body.len() >> 8) & 0xFF) as u8,
            (body.len() & 0xFF) as u8,
        ]);
        hs.extend_from_slice(&body);

        let mut rec = vec![TLS_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    // ---------- AuthKey 基础 ----------

    /// 同一密码必须派生出同一密钥（双方可复现）。
    #[test]
    fn 密码派生可复现() {
        let a = AuthKey::from_password(PASSWORD);
        let b = AuthKey::from_password(PASSWORD);
        assert_eq!(a, b);
        assert_eq!(a.ticket(&[7u8; 32], 100), b.ticket(&[7u8; 32], 100));
    }

    /// 不同密码必须派生出不同密钥。
    #[test]
    fn 不同密码不同密钥() {
        let a = AuthKey::from_password("password-a");
        let b = AuthKey::from_password("password-b");
        assert_ne!(a, b);
        assert_ne!(a.ticket(&[7u8; 32], 100), b.ticket(&[7u8; 32], 100));
    }

    /// 票据必须随窗口变化（否则无法用时间窗口防重放）。
    #[test]
    fn 票据随窗口变化() {
        let k = AuthKey::from_password(PASSWORD);
        let t1 = k.ticket(&[1u8; 32], 100);
        let t2 = k.ticket(&[1u8; 32], 101);
        assert_ne!(t1, t2);
    }

    /// 票据必须随 client_random 变化（防跨连接重放）。
    #[test]
    fn 票据随random变化() {
        let k = AuthKey::from_password(PASSWORD);
        assert_ne!(k.ticket(&[1u8; 32], 100), k.ticket(&[2u8; 32], 100));
    }

    /// ★ 安全关键：证书种子与票据必须不同（否则拿到证书密钥就能伪造票据）。
    #[test]
    fn 证书种子与票据不同() {
        let k = AuthKey::from_password(PASSWORD);
        let random = [5u8; 32];
        let seed = k.cert_seed(&random);
        // 票据在每个窗口都不同，全都不能等于证书种子
        for w in [0u64, 100, 1000] {
            assert_ne!(
                seed,
                k.ticket(&random, w),
                "证书种子不得等于票据（窗口 {w}）"
            );
        }
    }

    /// 证书种子必须随 random 变化（每连接不同证书）。
    #[test]
    fn 证书种子随random变化() {
        let k = AuthKey::from_password(PASSWORD);
        assert_ne!(k.cert_seed(&[1u8; 32]), k.cert_seed(&[2u8; 32]));
    }

    /// 证书种子不得全零（Ed25519 会拒绝）。
    #[test]
    fn 证书种子可用() {
        let k = AuthKey::from_password(PASSWORD);
        assert!(k.cert_seed(&[0u8; 32]).iter().any(|&b| b != 0));
    }

    /// 用户标识必须稳定且不泄露密钥。
    #[test]
    fn 用户标识稳定() {
        let k = AuthKey::from_password(PASSWORD);
        assert_eq!(k.user_tag(), k.user_tag());
        assert_ne!(k.user_tag(), [0u8; USER_TAG_LEN]);
    }

    /// 空密码也必须可用（不能 panic）。
    #[test]
    fn 空密码可用() {
        let k = AuthKey::from_password("");
        assert_eq!(k.ticket(&[0u8; 32], 0).len(), TICKET_LEN);
    }

    /// 密钥不得出现在 Debug 输出中。
    #[test]
    fn 密钥调试不泄露() {
        let k = AuthKey::from_password(PASSWORD);
        let s = format!("{k:?}");
        assert!(s.contains("已隐藏"));
        // 不该出现任何 32 字节十六进制串
        assert!(!s.contains(&format!("{:02x}", k.0[0])));
    }

    // ---------- 裁决 ----------

    /// 当前窗口的票据必须通过。
    #[test]
    fn 当前窗口票据通过() {
        let cfg = config();
        let random = [0x11u8; 32];
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;
        let sid = cfg.auth.ticket(&random, window);

        let hello = build_hello(SNI, &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        let v = cfg.judge(&info, now);
        assert!(v.should_accept(), "应通过，实际: {v:?}");
    }

    /// 上一窗口的票据也必须通过（时钟容差）。
    #[test]
    fn 上一窗口票据通过() {
        let cfg = config();
        let random = [0x22u8; 32];
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;
        let sid = cfg.auth.ticket(&random, window - 1);

        let hello = build_hello(SNI, &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert!(cfg.judge(&info, now).should_accept());
    }

    /// 下一窗口的票据也必须通过。
    #[test]
    fn 下一窗口票据通过() {
        let cfg = config();
        let random = [0x33u8; 32];
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;
        let sid = cfg.auth.ticket(&random, window + 1);

        let hello = build_hello(SNI, &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert!(cfg.judge(&info, now).should_accept());
    }

    /// 超出容差的窗口必须被拒绝。
    #[test]
    fn 超窗票据被拒绝() {
        let cfg = config();
        let random = [0x44u8; 32];
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;
        let sid = cfg.auth.ticket(&random, window + 5);

        let hello = build_hello(SNI, &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert_eq!(
            cfg.judge(&info, now),
            Verdict::Forward {
                reason: ForwardReason::TicketMismatch
            }
        );
    }

    /// ★ 普通浏览器（随机 session_id）必须被转发。
    #[test]
    fn 普通浏览器被转发() {
        let cfg = config();
        let hello = build_hello(SNI, &[0xABu8; 32], [0x55u8; 32], None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        let v = cfg.judge(&info, 1_700_000_000);
        assert!(v.should_forward(), "普通浏览器必须转发");
        assert_eq!(
            v,
            Verdict::Forward {
                reason: ForwardReason::TicketMismatch
            }
        );
    }

    /// 错误 SNI 必须被转发（即使票据正确）。
    #[test]
    fn 错误sni被转发() {
        let cfg = config();
        let random = [0x66u8; 32];
        let now = 1_700_000_000u64;
        let sid = cfg.auth.ticket(&random, now / TIME_WINDOW_SECS);

        let hello = build_hello("evil.example.com", &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert_eq!(
            cfg.judge(&info, now),
            Verdict::Forward {
                reason: ForwardReason::SniNotAllowed(Some("evil.example.com".into()))
            }
        );
    }

    /// session_id 长度不是 32 时直接转发。
    #[test]
    fn 非法session长度被转发() {
        let cfg = config();
        let hello = build_hello(SNI, &[0u8; 16], [0u8; 32], None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert_eq!(
            cfg.judge(&info, 1_700_000_000),
            Verdict::Forward {
                reason: ForwardReason::BadSessionIdLen(16)
            }
        );
    }

    /// 用其他密码算出的票据不得通过。
    #[test]
    fn 错误密码票据被拒绝() {
        let cfg = config();
        let other = AuthKey::from_password("wrong-password");
        let random = [0x77u8; 32];
        let now = 1_700_000_000u64;
        let sid = other.ticket(&random, now / TIME_WINDOW_SECS);

        let hello = build_hello(SNI, &sid, random, None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert!(cfg.judge(&info, now).should_forward());
    }

    /// ★ 关键：票据绑定 client_random，换一个 random 就失效（防跨连接重放）。
    #[test]
    fn 票据不能跨连接重放() {
        let cfg = config();
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;

        // 攻击者录下一条合法连接的 session_id
        let real_random = [0x88u8; 32];
        let stolen_sid = cfg.auth.ticket(&real_random, window);

        // 用它配自己的 random 尝试连接 → 必须失败
        let hello = build_hello(SNI, &stolen_sid, [0x99u8; 32], None);
        let info = parse_client_hello(&hello).unwrap().unwrap();
        assert!(
            cfg.judge(&info, now).should_forward(),
            "票据必须绑定 client_random，不能跨连接重放"
        );
    }

    /// 有 key_share 也不影响判定（本方案不依赖它）。
    #[test]
    fn 有无keyshare都能认证() {
        let cfg = config();
        let random = [0xAAu8; 32];
        let now = 1_700_000_000u64;
        let sid = cfg.auth.ticket(&random, now / TIME_WINDOW_SECS);

        for ks in [None, Some([0x12u8; 32])] {
            let hello = build_hello(SNI, &sid, random, ks);
            let info = parse_client_hello(&hello).unwrap().unwrap();
            assert!(
                cfg.judge(&info, now).should_accept(),
                "key_share={ks:?} 时应通过"
            );
        }
    }

    // ---------- ClientHello 解析 ----------

    #[test]
    fn 解析数据不足时等待() {
        assert_eq!(parse_client_hello(&[]).unwrap(), None);
        assert_eq!(parse_client_hello(&[0x16]).unwrap(), None);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x01, 0x00]).unwrap(), None);
    }

    #[test]
    fn 解析非tls报错() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n").unwrap_err(),
            StealError::NotTls(b'G')
        );
    }

    #[test]
    fn 跨记录时等待() {
        let hello = build_hello(SNI, &[0u8; 32], [0u8; 32], None);
        assert_eq!(parse_client_hello(&hello[..9]).unwrap(), None);
        assert_eq!(parse_client_hello(&hello[..hello.len() / 2]).unwrap(), None);
        assert!(parse_client_hello(&hello).unwrap().is_some());
    }

    #[test]
    fn 解析字段准确() {
        let random = [0xCDu8; 32];
        let sid = [0xEFu8; 32];
        let eph = [0x42u8; 32];
        let hello = build_hello(SNI, &sid, random, Some(eph));
        let info = parse_client_hello(&hello).unwrap().unwrap();

        assert_eq!(info.sni.as_deref(), Some(SNI));
        assert_eq!(info.session_id, sid);
        assert_eq!(info.random, random);
        assert_eq!(info.key_share_x25519, Some(eph));
        assert_eq!(info.wire_len, hello.len());
    }

    // ---------- session_id 改写 ----------

    /// 改写后长度不变，且 session_id 被替换。
    #[test]
    fn 改写session_id() {
        let random = [0x11u8; 32];
        let hello = build_hello(SNI, &[0xAAu8; 32], random, None);
        let new_sid = [0xBBu8; 32];
        let out = rewrite_session_id(&hello, &new_sid);

        assert_eq!(out.len(), hello.len(), "长度必须不变");
        let (got_random, sid_off) = extract_hello_params(&out).unwrap();
        assert_eq!(got_random, random, "random 不得被改动");
        assert_eq!(&out[sid_off..sid_off + 32], &new_sid);
    }

    /// 空 session_id 时原样返回（不能破坏消息）。
    #[test]
    fn 空session_id原样返回() {
        let hello = build_hello(SNI, &[], [0u8; 32], None);
        let out = rewrite_session_id(&hello, &[0xFFu8; 32]);
        assert_eq!(out, hello);
    }

    /// extract_hello_params 在数据不足时返回 None。
    #[test]
    fn 提取参数数据不足() {
        assert!(extract_hello_params(&[]).is_none());
        assert!(extract_hello_params(&[0u8; 30]).is_none());
    }

    /// ★ 端到端：客户端改写 → 服务端解析 → 认证通过。
    #[test]
    fn 改写后能被服务端认证() {
        let cfg = config();
        let now = 1_700_000_000u64;
        let window = now / TIME_WINDOW_SECS;
        let random = [0x5Au8; 32];

        // 客户端：先造一个"BoringSSL 生成的" ClientHello（session_id 是随机占位）
        let placeholder = build_hello(SNI, &[0x00u8; 32], random, Some([0x01u8; 32]));

        // 从里面取出 random，算票据，写回
        let (got_random, _) = extract_hello_params(&placeholder).unwrap();
        assert_eq!(got_random, random);
        let sid = cfg.auth.ticket(&got_random, window);
        let injected = rewrite_session_id(&placeholder, &sid);

        // 服务端：解析并裁决
        let info = parse_client_hello(&injected).unwrap().unwrap();
        assert!(
            cfg.judge(&info, now).should_accept(),
            "客户端注入的票据必须被服务端接受"
        );
    }

    /// 证书种子两端一致（客户端与服务端用同一 secret + random）。
    #[test]
    fn 证书种子两端一致() {
        let server = config();
        let client_key = AuthKey::from_password(PASSWORD);
        let random = [0x3Cu8; 32];
        assert_eq!(server.cert_seed(&random), client_key.cert_seed(&random));
    }

    /// 生成密钥应可用且每次不同。
    #[test]
    fn 生成密钥可用() {
        let a = AuthKey::generate();
        let b = AuthKey::generate();
        assert_ne!(a, b);
        assert_ne!(a.ticket(&[0u8; 32], 0), [0u8; TICKET_LEN]);
    }
}
