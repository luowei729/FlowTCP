//! 自研 TLS 1.3 客户端握手（方案 G）
//!
//! # 这个模块解决什么问题
//!
//! BoringSSL 不允许我们控制 `ClientHello.session_id`（见 DEVTIPS §11、§12），
//! 而 REALITY 式认证必须把票据放进那里。唯一的出路是**自己实现客户端 TLS**。
//!
//! 服务端不需要改：它把收到的原始字节喂给 BoringSSL，转录天然一致。
//!
//! # 支持的握手流程（1-RTT，无 PSK）
//!
//! ```text
//!   客户端                                    服务端
//!     │──── ClientHello（我们构造，含票据）────→│
//!     │←─── ServerHello（明文）────────────────│
//!     │     ↓ 计算 ECDHE → handshake_secret     │
//!     │←═══ {EncryptedExtensions} ═════════════│  ← 以下均为密文
//!     │←═══ {Certificate} ═════════════════════│
//!     │←═══ {CertificateVerify} ═══════════════│
//!     │←═══ {Finished} ════════════════════════│
//!     │     ↓ 验证 CV 与 Finished               │
//!     │════ {Finished} ════════════════════════→│
//!     │     ↓ 派生应用密钥（供 FlowTCP 使用）    │
//! ```
//!
//! # 明确不支持的
//!
//! | 特性 | 原因 |
//! |------|------|
//! | HelloRetryRequest | 我们总是发 X25519 key_share，服务端不会要求重试 |
//! | PSK / 会话恢复 | 每条连接都是全新握手（更安全，也避免票据与 PSK 混淆） |
//! | 0-RTT | 同上 |
//! | 客户端证书 | 我们用预共享密钥认证，不需要 |
//! | 证书链校验 | 偷网站模式下服务端是临时自签证书，靠 ECDH 派生公钥验证 |
//! | AES-256-GCM | 只支持 `TLS_AES_128_GCM_SHA256`（Chrome 首选，够用） |
//!
//! # 安全边界
//!
//! 本实现的定位是「**通道载体**」，身份认证由 FlowTCP 的票据机制完成
//! （`session_id` 里的 HMAC）。因此：
//!
//! - 必须验证 `CertificateVerify`（证明对方持有临时私钥）
//! - 必须验证 `Finished`（证明握手未被篡改）
//! - 证书链校验可以跳过（临时自签证书天然无法链到公共 CA）

use std::io;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use flowtcp_proto::steal::AuthKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::PublicKey;

use crate::chbuilder::{build_client_hello, ClientHelloParams};
use crate::key_schedule::{
    constant_time_eq, derive_finished_key, derive_traffic_keys, finished_verify_data,
    transcript_hash, KeySchedule, TrafficKeys, HASH_LEN,
};

/// TLS 握手记录类型。
const CT_HANDSHAKE: u8 = 0x16;
/// TLS 应用数据记录类型（TLS 1.3 中所有密文都用这个）。
const CT_APPLICATION_DATA: u8 = 0x17;
/// ChangeCipherSpec。TLS 1.3 里只在"中间盒兼容模式"下作为假记录出现。
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
/// Alert。`close_notify` 用它表达优雅关闭。
const CT_ALERT: u8 = 0x15;
/// TLS 记录版本（TLS 1.2 值，TLS 1.3 沿用）。
const RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// 握手消息类型。
mod hs {
    /// ClientHello（我们主动发送，不在此处解析，保留常量以便阅读）
    #[allow(dead_code)]
    pub const CLIENT_HELLO: u8 = 1;
    /// ServerHello
    pub const SERVER_HELLO: u8 = 2;
    /// NewSessionTicket
    pub const NEW_SESSION_TICKET: u8 = 4;
    /// EncryptedExtensions
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    /// Certificate
    pub const CERTIFICATE: u8 = 11;
    /// CertificateVerify
    pub const CERTIFICATE_VERIFY: u8 = 15;
    /// Finished
    pub const FINISHED: u8 = 20;
}

/// 扩展类型。
mod ext {
    /// supported_versions
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// key_share
    pub const KEY_SHARE: u16 = 0x0033;
}

/// 客户端握手错误。
#[derive(Debug, thiserror::Error)]
pub enum Tls13Error {
    /// IO 错误。
    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),
    /// 记录层格式错误。
    #[error("记录层错误: {0}")]
    Record(String),
    /// 握手消息格式错误。
    #[error("握手消息错误: {0}")]
    Handshake(String),
    /// 服务端协商了不支持的参数。
    #[error("协商失败: {0}")]
    Negotiation(String),
    /// 密钥派生失败。
    #[error("密钥派生失败: {0}")]
    KeySchedule(String),
    /// 记录解密失败。
    #[error("记录解密失败（序号 {seq}）")]
    Decrypt {
        /// 记录的序号
        seq: u64,
    },
    /// `Finished` 校验失败（握手被篡改或密钥不同步）。
    #[error("Finished 校验失败")]
    FinishedMismatch,
    /// `CertificateVerify` 校验失败（对方不持有临时私钥）。
    #[error("CertificateVerify 校验失败")]
    CertVerifyFailed,
    /// 服务端要求我们未实现的特性。
    #[error("不支持的特性: {0}")]
    Unsupported(String),
}

/// 客户端握手结果。
pub struct HandshakeResult {
    /// FlowTCP 内层密钥（由 TLS exporter 派生）。
    ///
    /// 与 `flowtcp_proto::keyderive::derive` 的输入约定一致：
    /// 直接传给 `flowtcp_proto::derive_keys(&exporter, ctx, key_len)`。
    pub exporter: [u8; HASH_LEN],
    /// exporter 的 context（`ClientHello.random || ServerHello.random`）。
    pub exporter_context: [u8; 64],
    /// 客户端应用流量密钥（若后续要用原生 TLS 记录层）。
    pub client_app_keys: TrafficKeys,
    /// 服务端应用流量密钥。
    pub server_app_keys: TrafficKeys,
    /// 服务端证书（DER）。
    pub server_cert: Vec<u8>,
    /// 协商的 ALPN。
    pub alpn: Option<Vec<u8>>,
}

/// 握手完成后的 TLS 1.3 应用数据流。
///
/// # 用途
///
/// 握手只解决"双方建立共享密钥"。真正的代理数据（内层 Frame）需要
/// 用**应用流量密钥**加密后按 TLS 记录发送。这个类型就是那一层。
///
/// # 为什么单独一个类型而不是复用 `SslStream`
///
/// 服务端用的是 BoringSSL 的 `SslStream`（`flowtcp_tls::accept` 返回），
/// 客户端是自研握手，没有 `SslStream`。两者必须在**记录层**对齐，
/// 因此客户端侧需要自己的加密流。
///
/// # 记录格式
///
/// ```text
/// 0x17 0x03 0x03 | len(2) | AEAD(明文 || 真实内容类型)
/// ```
///
/// 与标准 TLS 1.3 完全一致（这样服务端的 BoringSSL 才能解密）。
pub struct Tls13Stream<S> {
    inner: S,
    /// 客户端→服务端（写）密钥。
    rl: RecordLayer,
    /// 已关闭（避免重复发 close_notify）。
    closed: bool,
}

impl<S> Tls13Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 用握手结果构造应用数据流。
    ///
    /// `hs.client_app_keys` 是本端写密钥，`hs.server_app_keys` 是读密钥。
    pub fn new(inner: S, hs: &HandshakeResult) -> Self {
        let mut rl = RecordLayer::new();
        // 客户端视角：自己发的用 client key 加密，收到的用 server key 解密
        rl.write_keys = Some(TrafficKeys {
            key: hs.client_app_keys.key.clone(),
            iv: hs.client_app_keys.iv,
        });
        rl.read_keys = Some(TrafficKeys {
            key: hs.server_app_keys.key.clone(),
            iv: hs.server_app_keys.iv,
        });
        Tls13Stream {
            inner,
            rl,
            closed: false,
        }
    }

    /// 发送一条应用数据记录（自动分片到 2^14 以内）。
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), Tls13Error> {
        // TLS 1.3 明文上限 2^14 字节
        const MAX_PLAIN: usize = 16384;
        for chunk in data.chunks(MAX_PLAIN) {
            let mut out = Vec::with_capacity(chunk.len() + 22);
            self.rl.seal(CT_APPLICATION_DATA, chunk, &mut out)?;
            self.inner.write_all(&out).await?;
        }
        self.inner.flush().await?;
        Ok(())
    }

    /// 读一条应用数据记录，返回明文。
    ///
    /// 握手期消息（NewSessionTicket、KeyUpdate 之前的旧密钥记录）会被跳过。
    /// 收到 `close_notify` 时返回空 `Vec`（调用方据此判断优雅关闭）。
    pub async fn read_one(&mut self) -> Result<Vec<u8>, Tls13Error> {
        // 用循环而非递归：async fn 递归需要装箱，且这里天然是循环语义
        loop {
            let rec = read_record(&mut self.inner).await?;
            if rec[0] == CT_CHANGE_CIPHER_SPEC {
                // 兼容模式的假 CCS，跳过
                continue;
            }
            let (ct, plain) = self.rl.open(&rec)?;
            match ct {
                // close_notify：description=0
                CT_ALERT => {
                    if plain.len() >= 2 && plain[1] == 0 {
                        self.closed = true;
                    }
                    return Ok(Vec::new());
                }
                // NewSessionTicket 等握手后消息：跳过，继续读
                CT_HANDSHAKE => continue,
                _ => return Ok(plain),
            }
        }
    }

    /// 取回底层流（用于关闭或降级）。
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 底层流的只读引用。
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

/// 握手期的记录层读写器。
///
/// 维护独立的读写序号（TLS 1.3 规定收发各用独立序号空间）。
struct RecordLayer {
    /// 客户端→服务端 的密钥（写）。
    write_keys: Option<TrafficKeys>,
    /// 服务端→客户端 的密钥（读）。
    read_keys: Option<TrafficKeys>,
    /// 写序号。
    write_seq: u64,
    /// 读序号。
    read_seq: u64,
}

impl RecordLayer {
    fn new() -> Self {
        RecordLayer {
            write_keys: None,
            read_keys: None,
            write_seq: 0,
            read_seq: 0,
        }
    }

    /// 计算 AEAD nonce：`nonce = iv XOR (0x00000000 || seq_be_u64)`。
    ///
    /// TLS 1.3 §5.3 规定：nonce 为静态 IV 与「左侧补零到 iv 长度的序号」异或。
    fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
        let mut n = *iv;
        let s = seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    /// 加密一条记录（写入 `out`，含记录头）。
    fn seal(
        &mut self,
        content_type: u8,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Tls13Error> {
        let keys = self
            .write_keys
            .as_ref()
            .ok_or_else(|| Tls13Error::Record("写密钥未就绪".into()))?;

        // 内层明文 = payload || content_type（不含 padding）
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type);

        let total = inner.len() + 16; // + AEAD tag
        let start = out.len();
        out.push(CT_APPLICATION_DATA);
        out.extend_from_slice(&RECORD_VERSION);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        let aad = out[start..start + 5].to_vec();

        let cipher = Aes128Gcm::new_from_slice(&keys.key)
            .map_err(|_| Tls13Error::Record("密钥长度错误".into()))?;
        let nonce = Self::nonce(&keys.iv, self.write_seq);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut inner)
            .map_err(|_| Tls13Error::Record("加密失败".into()))?;
        out.extend_from_slice(&inner);
        out.extend_from_slice(&tag);

        self.write_seq += 1;
        Ok(())
    }

    /// 解密一条记录，返回 `(content_type, 明文)`。
    fn open(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>), Tls13Error> {
        let keys = self
            .read_keys
            .as_ref()
            .ok_or_else(|| Tls13Error::Record("读密钥未就绪".into()))?;

        if record.len() < 5 + 16 {
            return Err(Tls13Error::Record("记录太短".into()));
        }
        if record[0] != CT_APPLICATION_DATA {
            return Err(Tls13Error::Record(format!(
                "期望密文记录(0x17)，实际 0x{:02x}",
                record[0]
            )));
        }
        let ct_len = record.len() - 5;
        let mut body = record[5..].to_vec();
        let aad = record[..5].to_vec();
        let cipher = Aes128Gcm::new_from_slice(&keys.key)
            .map_err(|_| Tls13Error::Record("密钥长度错误".into()))?;
        let nonce = Self::nonce(&keys.iv, self.read_seq);
        let tag_start = ct_len - 16;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&body[tag_start..]);
        body.truncate(tag_start);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                &mut body,
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| Tls13Error::Decrypt { seq: self.read_seq })?;

        self.read_seq += 1;

        // 去掉尾部零填充，最后一个非零字节即真实 content_type
        let ct = body
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| {
                let t = body[i];
                body.truncate(i);
                t
            })
            .ok_or_else(|| Tls13Error::Record("解密后无内容类型".into()))?;

        Ok((ct, body))
    }
}

/// 读取一条完整的 TLS 记录（含头）。
async fn read_record<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>, Tls13Error> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).await?;
    let len = u16::from_be_bytes([head[3], head[4]]) as usize;
    if len > 18432 {
        // 2^14 + 2048，超长记录必须拒绝
        return Err(Tls13Error::Record(format!("记录过长: {len}")));
    }
    let mut buf = vec![0u8; 5 + len];
    buf[..5].copy_from_slice(&head);
    s.read_exact(&mut buf[5..]).await?;
    Ok(buf)
}

/// 解析握手消息（可能一条记录里含多条消息）。
///
/// 返回 `(type, body)` 列表。`body` 不含 4 字节消息头。
fn parse_handshake_messages(buf: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Tls13Error> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 4 <= buf.len() {
        let ty = buf[p];
        let len =
            ((buf[p + 1] as usize) << 16) | ((buf[p + 2] as usize) << 8) | (buf[p + 3] as usize);
        if p + 4 + len > buf.len() {
            return Err(Tls13Error::Handshake(format!(
                "握手消息截断: 需要 {} 字节，仅剩 {}",
                len,
                buf.len() - p - 4
            )));
        }
        out.push((ty, buf[p + 4..p + 4 + len].to_vec()));
        p += 4 + len;
    }
    Ok(out)
}

/// ServerHello 的解析结果。
struct ServerHello {
    random: [u8; 32],
    /// 服务端 x25519 公钥。
    key_share: [u8; 32],
    /// 服务端回显的 session_id（必须与我们的票据一致）。
    session_id_echo: Vec<u8>,
    /// 原始消息字节（保留用于排查问题）。
    #[allow(dead_code)]
    raw: Vec<u8>,
}

/// 解析 ServerHello。
fn parse_server_hello(body: &[u8], raw: Vec<u8>) -> Result<ServerHello, Tls13Error> {
    let mut p = 0usize;
    if body.len() < 2 + 32 + 1 {
        return Err(Tls13Error::Handshake("ServerHello 过短".into()));
    }
    p += 2; // legacy_version
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[p..p + 32]);
    p += 32;

    let sid_len = body[p] as usize;
    p += 1;
    if body.len() < p + sid_len {
        return Err(Tls13Error::Handshake("session_id 截断".into()));
    }
    let session_id_echo = body[p..p + sid_len].to_vec();
    p += sid_len;

    if body.len() < p + 3 {
        return Err(Tls13Error::Handshake("cipher/compression 截断".into()));
    }
    let cipher = u16::from_be_bytes([body[p], body[p + 1]]);
    p += 2;
    if cipher != 0x1301 {
        return Err(Tls13Error::Negotiation(format!(
            "服务端选择的 cipher 0x{cipher:04x} 不是 TLS_AES_128_GCM_SHA256"
        )));
    }
    p += 1; // compression

    if body.len() < p + 2 {
        return Err(Tls13Error::Handshake("缺少 extensions".into()));
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_total).min(body.len());

    let mut key_share: Option<[u8; 32]> = None;
    let mut have_tls13 = false;

    while p + 4 <= end {
        let ty = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            break;
        }
        let d = &body[p..p + len];
        match ty {
            ext::SUPPORTED_VERSIONS => {
                if d.len() >= 2 && u16::from_be_bytes([d[0], d[1]]) == 0x0304 {
                    have_tls13 = true;
                }
            }
            // server_share: group(2) + key_len(2) + key
            // 只接受 x25519(0x001d) 且长度恰好 32 的 share（我们只发这一种）
            ext::KEY_SHARE if d.len() >= 4 + 32 => {
                let g = u16::from_be_bytes([d[0], d[1]]);
                let kl = u16::from_be_bytes([d[2], d[3]]) as usize;
                if g == 0x001d && kl == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&d[4..36]);
                    key_share = Some(k);
                }
            }
            _ => {}
        }
        p += len;
    }

    if !have_tls13 {
        return Err(Tls13Error::Negotiation(
            "服务端未协商 TLS 1.3（可能要求 HelloRetryRequest）".into(),
        ));
    }
    let key_share = key_share.ok_or_else(|| {
        Tls13Error::Negotiation("服务端未提供 x25519 key_share（可能需要 HRR）".into())
    })?;

    Ok(ServerHello {
        random,
        key_share,
        session_id_echo,
        raw,
    })
}

/// 执行完整的客户端 TLS 1.3 握手。
///
/// # 参数
///
/// - `stream`：底层字节流（TCP 或 FakeTCP）
/// - `sni`：服务端名称
/// - `session_id`：32 字节认证票据（会写入 ClientHello）
///
/// # 返回
///
/// 握手结果，含 FlowTCP 内层密钥材料。
pub async fn handshake<S>(
    stream: &mut S,
    sni: &str,
    auth: &AuthKey,
) -> Result<HandshakeResult, Tls13Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- 1) 生成临时密钥并构造 ClientHello ----
    let mut seed = [0u8; 32];
    {
        use rand::TryRngCore;
        rand::rngs::OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| Tls13Error::Record("CSPRNG 不可用".into()))?;
    }
    let our_secret = ClientHelloParams::ephemeral_secret(seed);

    // ★ 顺序关键：先定 random，再由 random 算票据，最后拼 ClientHello。
    //   票据 = HMAC(secret, "ticket" || client_random || window)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let params = ClientHelloParams::authed(sni, seed, auth, None, now);
    // 票据就是从 session_id 读出来的，后面回显校验要用
    let session_id = params.session_id;
    let ch = build_client_hello(&params);

    // 转录从我们**实际发出的字节**开始 —— 这是自研的核心优势
    let ch_hs = ch[5..].to_vec(); // 去掉记录头，只留握手消息
    let mut transcript = ch_hs.clone();

    stream.write_all(&ch).await?;
    stream.flush().await?;

    // ---- 2) 读 ServerHello（明文记录）----
    let rec = read_record(stream).await?;
    if rec[0] != CT_HANDSHAKE {
        return Err(Tls13Error::Record(format!(
            "期望明文握手记录(0x16)，实际 0x{:02x}",
            rec[0]
        )));
    }
    let msgs = parse_handshake_messages(&rec[5..])?;
    let (ty, body) = msgs
        .into_iter()
        .find(|(t, _)| *t == hs::SERVER_HELLO)
        .ok_or_else(|| Tls13Error::Handshake("首条消息不是 ServerHello".into()))?;
    if ty != hs::SERVER_HELLO {
        return Err(Tls13Error::Handshake("意外的握手消息".into()));
    }
    // ServerHello 的原始字节（含 4 字节消息头）必须进转录
    let mut sh_raw = vec![hs::SERVER_HELLO];
    sh_raw.extend_from_slice(&[
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ]);
    sh_raw.extend_from_slice(&body);

    let sh = parse_server_hello(&body, sh_raw.clone())?;
    transcript.extend_from_slice(&sh_raw);

    // ---- 3) 校验服务端回显了我们的票据 ----
    //
    // TLS 1.3 §4.1.3：服务端必须回显 legacy_session_id。
    // 若不一致说明有中间人或服务端实现异常，必须中止。
    if sh.session_id_echo != session_id {
        return Err(Tls13Error::Negotiation(format!(
            "服务端回显的 session_id 与票据不一致（回显 {} 字节）",
            sh.session_id_echo.len()
        )));
    }

    // ---- 4) ECDHE ----
    let server_pub = PublicKey::from(sh.key_share);
    let shared = our_secret.diffie_hellman(&server_pub);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(Tls13Error::Negotiation(
            "ECDHE 共享密钥全零（服务端公钥可能是低阶点）".into(),
        ));
    }

    // ---- 5) 派生握手密钥 ----
    let early = KeySchedule::no_psk();
    let hs_sched = early
        .handshake(shared.as_bytes())
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;

    let server_hs_secret = hs_sched
        .server_handshake_traffic(&transcript)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let client_hs_secret = hs_sched
        .client_handshake_traffic(&transcript)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;

    let mut rl = RecordLayer::new();
    rl.read_keys = Some(
        derive_traffic_keys(&server_hs_secret, 16)
            .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?,
    );
    rl.write_keys = Some(
        derive_traffic_keys(&client_hs_secret, 16)
            .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?,
    );

    // ---- 6) 解密并处理服务端握手消息 ----
    let mut server_cert: Option<Vec<u8>> = None;
    let mut cert_verify: Option<Vec<u8>> = None;
    let mut alpn: Option<Vec<u8>> = None;
    let mut server_finished: Option<[u8; HASH_LEN]> = None;

    // 记录级缓冲：一条记录可能含多条消息，也可能一条消息跨多条记录
    let mut pending: Vec<u8> = Vec::new();
    // 验证服务端 Finished 用：CH..CertificateVerify（不含 Finished）
    let mut transcript_before_finished: Option<Vec<u8>> = None;
    // 验证 CertificateVerify 用：CH..Certificate（不含 CV 本身）
    let mut transcript_before_cv: Option<Vec<u8>> = None;
    // 计算客户端 Finished / 应用密钥用：CH..server Finished（含服务端 Finished）
    let mut transcript_after_server_finished: Option<Vec<u8>> = None;

    while server_finished.is_none() {
        let rec = read_record(stream).await?;

        // ★ 中间盒兼容模式（RFC 8446 §5）：
        //
        // 因为我们在 ClientHello 里带了非空 session_id（TLS 1.2 兼容模式），
        // 服务端会在 ServerHello 之后、第一条加密记录之前插入一条**明文**
        // ChangeCipherSpec 记录（0x14 03 03 00 01 01，只有 6 字节）。
        //
        // 这条记录不参与密钥派生，也不在转录里，纯粹是给中间盒看的"假 CCS"。
        // 必须原样丢弃，否则会被当成密文去解密 → 长度不足 / 解密失败。
        if rec[0] == CT_CHANGE_CIPHER_SPEC {
            if rec.len() != 6 || rec[5] != 0x01 {
                return Err(Tls13Error::Record("非法的 ChangeCipherSpec 记录".into()));
            }
            continue;
        }

        let (ct, plain) = rl.open(&rec)?;
        if ct != CT_HANDSHAKE {
            return Err(Tls13Error::Record(format!(
                "期望握手内容类型，实际 0x{ct:02x}"
            )));
        }
        pending.extend_from_slice(&plain);

        // 逐条消费完整消息
        loop {
            if pending.len() < 4 {
                break;
            }
            let ty = pending[0];
            let len = ((pending[1] as usize) << 16)
                | ((pending[2] as usize) << 8)
                | (pending[3] as usize);
            if pending.len() < 4 + len {
                break;
            }
            let body = pending[4..4 + len].to_vec();
            let full = pending[..4 + len].to_vec();
            pending.drain(..4 + len);

            match ty {
                hs::ENCRYPTED_EXTENSIONS => {
                    alpn = parse_alpn(&body);
                    transcript.extend_from_slice(&full);
                }
                hs::CERTIFICATE => {
                    server_cert = Some(parse_certificate(&body)?);
                    transcript.extend_from_slice(&full);
                }
                hs::CERTIFICATE_VERIFY => {
                    // ★ 签名验证要用「CV 之前」的转录，先存快照再入转录
                    transcript_before_cv = Some(transcript.clone());
                    cert_verify = Some(body.clone());
                    transcript.extend_from_slice(&full);
                }
                hs::FINISHED => {
                    // ★ 两件事必须分清楚（RFC 8446 §4.4.4 / §7.1）：
                    //
                    // (a) **验证服务端 Finished** 用「服务端 Finished 之前」的转录
                    // (b) **服务端 Finished 自身要进转录**，因为客户端的 Finished
                    //     和后续应用流量密钥都是基于「CH..server Finished」计算的。
                    //
                    // 早期实现漏了 (b)，导致服务端报 DIGEST_CHECK_FAILED。
                    transcript_before_finished = Some(transcript.clone());
                    let got = body;
                    if got.len() != HASH_LEN {
                        return Err(Tls13Error::Handshake("Finished 长度错误".into()));
                    }
                    let mut v = [0u8; HASH_LEN];
                    v.copy_from_slice(&got);
                    // 把服务端 Finished 完整消息（含 4 字节头）纳入转录
                    transcript.extend_from_slice(&full);
                    transcript_after_server_finished = Some(transcript.clone());
                    server_finished = Some(v);
                    break;
                }
                hs::NEW_SESSION_TICKET => {
                    // 握手后的票据消息，忽略（我们不使用 PSK）
                }
                other => {
                    return Err(Tls13Error::Unsupported(format!("未知握手消息类型 {other}")));
                }
            }
        }
    }

    let transcript_at_finished =
        transcript_before_finished.ok_or_else(|| Tls13Error::Handshake("缺少转录快照".into()))?;

    // ---- 7) 验证服务端 Finished ----
    let server_finished_key = derive_finished_key(&server_hs_secret)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let expect = finished_verify_data(&server_finished_key, &transcript_at_finished)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let got = server_finished.expect("循环退出条件已保证");
    if !constant_time_eq(&expect, &got) {
        return Err(Tls13Error::FinishedMismatch);
    }

    // ---- 8) 验证 CertificateVerify ----
    //
    // 这证明对方持有证书对应的私钥。证书链本身不校验（临时自签），
    // 但签名必须有效，否则无法排除「中间人转发握手但无对应私钥」。
    let cert = server_cert.ok_or_else(|| Tls13Error::Handshake("服务端未发送证书".into()))?;
    let cv = cert_verify
        .ok_or_else(|| Tls13Error::Handshake("服务端未发送 CertificateVerify".into()))?;
    // 用「CV 之前」的转录做签名验证（CV 自身的字节不能参与）
    let t_before_cv =
        transcript_before_cv.ok_or_else(|| Tls13Error::Handshake("缺少 CV 前转录快照".into()))?;
    verify_certificate_verify(&cert, &cv, &t_before_cv, &sh.random)?;

    // ---- 9) 发送客户端 Finished ----
    //
    // 客户端 Finished = HMAC(finished_key, Transcript-Hash(CH .. server Finished))
    let t_at_client_fin = transcript_after_server_finished
        .ok_or_else(|| Tls13Error::Handshake("缺少服务端 Finished 后转录".into()))?;
    let client_finished_key = derive_finished_key(&client_hs_secret)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let client_verify = finished_verify_data(&client_finished_key, &t_at_client_fin)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;

    let mut fin_msg = vec![hs::FINISHED, 0, 0, HASH_LEN as u8];
    fin_msg.extend_from_slice(&client_verify);

    let mut out = Vec::new();
    rl.seal(CT_HANDSHAKE, &fin_msg, &mut out)?;
    stream.write_all(&out).await?;
    stream.flush().await?;

    // ---- 10) 派生应用密钥与 exporter ----
    //
    // ★ RFC 8446 §7.1：应用流量密钥的转录是「CH .. server Finished」，
    //   **不含客户端的 Finished**。早期实现用了含客户端 Finished 的转录，
    //   导致双端密钥不一致、数据全部解密失败。
    let master = hs_sched
        .master()
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let client_app_secret = master
        .client_app_traffic(&t_at_client_fin)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    let server_app_secret = master
        .server_app_traffic(&t_at_client_fin)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;

    let exp_sched_secret = master
        .exporter_master(&t_at_client_fin)
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;
    // ★ 必须用 from_secret：exporter_master_secret 已经是最终 secret，
    //   再过 early() 会多套一层 HKDF-Extract，exporter 会完全不同。
    let exp_sched = KeySchedule::from_secret(exp_sched_secret);

    // exporter 的 context 约定：ClientHello.random || ServerHello.random
    let mut ctx = [0u8; 64];
    ctx[..32].copy_from_slice(&params.random);
    ctx[32..].copy_from_slice(&sh.random);

    let mut exporter = [0u8; HASH_LEN];
    exp_sched
        .export_keying_material(
            flowtcp_proto::EXPORTER_LABEL.as_bytes(),
            &ctx,
            &mut exporter,
        )
        .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?;

    Ok(HandshakeResult {
        exporter,
        exporter_context: ctx,
        client_app_keys: derive_traffic_keys(&client_app_secret, 16)
            .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?,
        server_app_keys: derive_traffic_keys(&server_app_secret, 16)
            .map_err(|e| Tls13Error::KeySchedule(e.to_string()))?,
        server_cert: cert,
        alpn,
    })
}

/// 从 EncryptedExtensions 里提取 ALPN。
fn parse_alpn(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 2 {
        return None;
    }
    let total = u16::from_be_bytes([body[0], body[1]]) as usize;
    let end = (2 + total).min(body.len());
    let mut p = 2usize;
    while p + 4 <= end {
        let ty = u16::from_be_bytes([body[p], body[p + 1]]);
        let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            break;
        }
        if ty == 0x0010 && len >= 3 {
            // ALPN: list_len(2) + proto_len(1) + proto
            let plen = body[p + 2] as usize;
            if p + 3 + plen <= end {
                return Some(body[p + 3..p + 3 + plen].to_vec());
            }
        }
        p += len;
    }
    None
}

/// 从 Certificate 消息里取出**叶证书** DER。
fn parse_certificate(body: &[u8]) -> Result<Vec<u8>, Tls13Error> {
    // certificate_request_context<0..2^8-1>
    if body.is_empty() {
        return Err(Tls13Error::Handshake("Certificate 为空".into()));
    }
    let ctx_len = body[0] as usize;
    let mut p = 1 + ctx_len;
    if body.len() < p + 3 {
        return Err(Tls13Error::Handshake("Certificate 结构截断".into()));
    }
    let _list_len = u24(&body[p..p + 3]);
    p += 3;
    if body.len() < p + 3 {
        return Err(Tls13Error::Handshake("Certificate 条目截断".into()));
    }
    let cert_len = u24(&body[p..p + 3]);
    p += 3;
    if body.len() < p + cert_len {
        return Err(Tls13Error::Handshake("证书数据截断".into()));
    }
    Ok(body[p..p + cert_len].to_vec())
}

fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

/// 验证 `CertificateVerify`。
///
/// # 待签名内容（TLS 1.3 §4.4.3）
///
/// ```text
/// 64 个 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || Transcript-Hash
/// ```
fn verify_certificate_verify(
    cert_der: &[u8],
    cv_body: &[u8],
    // **CV 之前**的转录（CH..Certificate）。调用方已裁好，此处不得再裁。
    transcript_before_cv: &[u8],
    _server_random: &[u8; 32],
) -> Result<(), Tls13Error> {
    // CV body: algorithm(2) + signature_len(2) + signature
    if cv_body.len() < 4 {
        return Err(Tls13Error::Handshake("CertificateVerify 过短".into()));
    }
    let alg = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() < 4 + sig_len {
        return Err(Tls13Error::Handshake("CV 签名截断".into()));
    }
    let sig = &cv_body[4..4 + sig_len];

    // 构造待签名内容
    let mut to_sign = Vec::with_capacity(64 + 33 + 32);
    to_sign.extend_from_slice(&[0x20u8; 64]);
    to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    to_sign.push(0);
    let th = transcript_hash(transcript_before_cv);
    to_sign.extend_from_slice(&th);

    // 用 boring 解析证书公钥并验签（不自研 ASN.1 与签名验证）
    use boring::x509::X509;
    let cert = X509::from_der(cert_der)
        .map_err(|e| Tls13Error::Handshake(format!("证书解析失败: {e}")))?;
    let pkey = cert
        .public_key()
        .map_err(|e| Tls13Error::Handshake(format!("取公钥失败: {e}")))?;

    // 用 boring 的 Verifier 统一处理 ECDSA 与 RSA-PSS。
    //
    // 只支持 TLS 1.3 的两个主力算法：
    // - 0x0403 = ecdsa_secp256r1_sha256（临时证书用的就是它）
    // - 0x0804 = rsa_pss_rsae_sha256（真实网站证书常见）
    use boring::hash::MessageDigest;
    use boring::sign::Verifier;

    let ok = match alg {
        0x0403 | 0x0804 | 0x0805 | 0x0806 => {
            let md = match alg {
                0x0403 | 0x0804 => MessageDigest::sha256(),
                0x0805 => MessageDigest::sha384(),
                _ => MessageDigest::sha512(),
            };
            let mut v = Verifier::new(md, &pkey).map_err(|_| Tls13Error::CertVerifyFailed)?;
            // rsa_pss_* 必须显式设置 PSS 填充；对 ECDSA 设置会被忽略/报错，
            // 因此只在 RSA 算法上设置。
            if matches!(alg, 0x0804..=0x0806) {
                v.set_rsa_padding(boring::rsa::Padding::PKCS1_PSS)
                    .map_err(|_| Tls13Error::CertVerifyFailed)?;
                v.set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(|_| Tls13Error::CertVerifyFailed)?;
            }
            v.update(&to_sign)
                .map_err(|_| Tls13Error::CertVerifyFailed)?;
            v.verify(sig).map_err(|_| Tls13Error::CertVerifyFailed)?
        }
        other => {
            return Err(Tls13Error::Unsupported(format!(
                "证书签名算法 0x{other:04x} 未实现（需扩展）"
            )));
        }
    };

    if !ok {
        return Err(Tls13Error::CertVerifyFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u24解析正确() {
        assert_eq!(u24(&[0, 0, 5]), 5);
        assert_eq!(u24(&[0, 1, 0]), 256);
        assert_eq!(u24(&[1, 0, 0]), 65536);
    }

    /// AEAD nonce 必须按 TLS 1.3 §5.3 与序号异或。
    #[test]
    fn nonce计算正确() {
        let iv = [0u8; 12];
        let n0 = RecordLayer::nonce(&iv, 0);
        assert_eq!(n0, [0u8; 12], "序号 0 时 nonce 应等于 iv");

        let n1 = RecordLayer::nonce(&iv, 1);
        assert_eq!(&n1[4..], &1u64.to_be_bytes(), "序号 1 应写入低 8 字节");

        let n_ff = RecordLayer::nonce(&iv, 0xff);
        assert_eq!(&n_ff[4..], &0xffu64.to_be_bytes());

        // iv 非零时必须异或
        let iv2 = [0xAAu8; 12];
        let n = RecordLayer::nonce(&iv2, 0);
        assert_eq!(n, iv2);
        let n = RecordLayer::nonce(&iv2, 1);
        assert_eq!(n[11], 0xAA ^ 0x01);
    }

    /// 记录层加解密往返。
    #[test]
    fn 记录层往返() {
        let keys = TrafficKeys {
            key: vec![0x11u8; 16],
            iv: [0x22u8; 12],
        };
        let mut w = RecordLayer::new();
        w.write_keys = Some(keys.clone());
        let mut r = RecordLayer::new();
        r.read_keys = Some(keys);

        let mut out = Vec::new();
        w.seal(CT_HANDSHAKE, b"hello tls13", &mut out).unwrap();
        assert_eq!(out[0], CT_APPLICATION_DATA, "TLS 1.3 密文记录类型");
        assert_eq!(&out[1..3], &RECORD_VERSION);

        let (ct, plain) = r.open(&out).unwrap();
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(plain, b"hello tls13");
    }

    /// 序号递增必须让相同明文产生不同密文。
    #[test]
    fn 序号递增产生不同密文() {
        let keys = TrafficKeys {
            key: vec![0x33u8; 16],
            iv: [0x44u8; 12],
        };
        let mut w = RecordLayer::new();
        w.write_keys = Some(keys);
        let mut a = Vec::new();
        let mut b = Vec::new();
        w.seal(CT_HANDSHAKE, b"same", &mut a).unwrap();
        w.seal(CT_HANDSHAKE, b"same", &mut b).unwrap();
        assert_ne!(a, b, "序号不同 → nonce 不同 → 密文不同");
    }

    /// 篡改密文必须被检测到。
    #[test]
    fn 篡改被检测() {
        let keys = TrafficKeys {
            key: vec![0x55u8; 16],
            iv: [0x66u8; 12],
        };
        let mut w = RecordLayer::new();
        w.write_keys = Some(keys.clone());
        let mut r = RecordLayer::new();
        r.read_keys = Some(keys);

        let mut out = Vec::new();
        w.seal(CT_HANDSHAKE, b"authentic", &mut out).unwrap();
        let last = out.len() - 1;
        out[last] ^= 0x01;
        assert!(matches!(r.open(&out), Err(Tls13Error::Decrypt { .. })));
    }

    /// 序号不匹配时解密必须失败（防止重排攻击）。
    #[test]
    fn 序号错乱无法解密() {
        let keys = TrafficKeys {
            key: vec![0x77u8; 16],
            iv: [0x88u8; 12],
        };
        let mut w = RecordLayer::new();
        w.write_keys = Some(keys.clone());
        let mut r = RecordLayer::new();
        r.read_keys = Some(keys);

        let mut rec0 = Vec::new();
        let mut rec1 = Vec::new();
        w.seal(CT_HANDSHAKE, b"first", &mut rec0).unwrap();
        w.seal(CT_HANDSHAKE, b"second", &mut rec1).unwrap();

        // 先解第二条 → 序号不匹配 → 失败
        assert!(r.open(&rec1).is_err(), "跳过序号必须解密失败");
    }

    /// 多条握手消息可打包在一条记录中。
    #[test]
    fn 解析多条握手消息() {
        let mut buf = vec![8u8, 0, 0, 2, 0xAA, 0xBB]; // type=8, len=2
        buf.extend_from_slice(&[20u8, 0, 0, 1, 0xCC]); // type=20, len=1
        let msgs = parse_handshake_messages(&buf).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].0, 8);
        assert_eq!(msgs[0].1, vec![0xAA, 0xBB]);
        assert_eq!(msgs[1].0, 20);
        assert_eq!(msgs[1].1, vec![0xCC]);
    }

    /// 截断的握手消息必须报错而非 panic。
    #[test]
    fn 截断握手消息报错() {
        let buf = vec![8u8, 0, 0, 10, 0xAA]; // 声明 10 字节但只有 1 字节
        assert!(parse_handshake_messages(&buf).is_err());
    }

    /// Certificate 消息解析必须取到叶证书。
    #[test]
    fn 解析证书消息() {
        // context_len=0, list_len=0x000008, cert_len=0x000005, cert=5 字节
        let mut body = vec![0u8]; // ctx_len = 0
        body.extend_from_slice(&[0, 0, 8]); // list_len
        body.extend_from_slice(&[0, 0, 5]); // cert_len
        body.extend_from_slice(&[1, 2, 3, 4, 5]);
        body.extend_from_slice(&[0, 0, 0]); // extensions_len = 0
        let cert = parse_certificate(&body).unwrap();
        assert_eq!(cert, vec![1, 2, 3, 4, 5]);
    }

    /// ALPN 解析。
    ///
    /// 编码：ext_list_len(2) || [ type(2) || len(2) || (list_len(2) || proto_len(1) || proto) ]
    #[test]
    fn 解析alpn() {
        // 单个扩展：type=0x0010, 内容 = 00 03 | 02 'h' '2'（5 字节）
        // 因此 ext_total = 4 + 5 = 9
        let body = vec![
            0x00, 0x09, // ext_total
            0x00, 0x10, // type = ALPN
            0x00, 0x05, // len = 5
            0x00, 0x03, // list_len = 3
            0x02, b'h', b'2', // proto_len=2, "h2"
        ];
        assert_eq!(parse_alpn(&body).as_deref(), Some(&b"h2"[..]));
    }

    /// 无 ALPN 时返回 None。
    #[test]
    fn 无alpn返回none() {
        // 只有一个 empty extensions 列表
        assert!(parse_alpn(&[0x00, 0x00]).is_none());
        // 有扩展但不是 ALPN
        let body = vec![
            0x00, 0x09, 0x00, 0x2b, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2',
        ];
        assert!(parse_alpn(&body).is_none());
    }

    /// 无 extensions 的 ServerHello 必须报错（需要 key_share）。
    #[test]
    fn 缺keyshare报错() {
        // legacy_version(2) + random(32) + sid_len(0) + cipher(2) + comp(1) + ext_len(2)
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        let r = parse_server_hello(&body, body.clone());
        assert!(matches!(r, Err(Tls13Error::Negotiation(_))));
    }

    /// 不支持的 cipher 必须拒绝。
    #[test]
    fn 不支持的cipher被拒绝() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x02]); // AES-256-GCM，我们不支持
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        let r = parse_server_hello(&body, body.clone());
        assert!(matches!(r, Err(Tls13Error::Negotiation(_))));
    }
}
