//! 单个连接的服务流程：读 ClientHello → 裁决 → 分流处置
//!
//! # 完整时序
//!
//! ```text
//! TCP 连接建立
//!   ↓
//! 读 ClientHello（可能跨多个 TCP 段）
//!   ↓
//! steal::parse_client_hello() → ClientHelloInfo
//!   ↓
//! StealConfig::judge()  ← 7 步校验（SNI/keyshare/session_id/解密/版本/时间/short_id）
//!   ↓
//! ┌──────────────────────┬────────────────────────────┐
//! │ Accept（我们的客户端）│ Forward（探测者/浏览器）    │
//! │                      │                            │
//! │ 派生 cert seed       │ TCP 连真实网站              │
//! │ 签自签临时证书        │ 重放已读 ClientHello        │
//! │ PrebufferedStream    │ 双向 copy                   │
//! │ → BoringSSL 握手     │                            │
//! │ → 读 FTAUTH 首帧     │ 客户端看到真网站的 TLS      │
//! │ → 交给代理路径        │                            │
//! └──────────────────────┴────────────────────────────┘
//! ```
//!
//! # 关键不变量
//!
//! 1. **判定必须先于 TLS 上下文建立** —— 一旦建了 TLS 就无法改成透传
//! 2. **失败原因只能记日志** —— 任何"认证失败"响应都是自曝
//! 3. **已读字节必须完整重放** —— 缺一个字节目标就握手失败

use std::time::Duration;

use flowtcp_proto::steal::{ClientHelloInfo, Verdict};
use flowtcp_tls::mode::{FallbackAction, ServerMode};
use flowtcp_tls::prebuf::PrebufferedStream;
use flowtcp_tls::{ServerTlsConfig, TempCert};
use thiserror::Error;
use tokio::net::TcpStream;

use crate::exit::{self, ExitConfig, ExitStats};
use crate::forward::{self, ProxyProtocol};

/// 读 ClientHello 的超时。
///
/// 取 10 秒：真实客户端在 TCP 建连后立即发 ClientHello（<100ms）。
/// 超时过长会让「只建连不说话」的探测连接长期占用资源。
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// ClientHello 的最大长度。
///
/// TLS 记录上限 16384，但 ClientHello 实际不超过 8KB（Chrome 约 500~600 字节，
/// 带后量子密钥共享时可达 1.5KB）。取 16KB 作为硬上限，防止恶意超长输入。
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// 会话处理错误。
#[derive(Debug, Error)]
pub enum SessionError {
    /// 读 ClientHello 超时。
    #[error("等待 ClientHello 超时（{0:?}）")]
    HelloTimeout(Duration),
    /// 读 ClientHello 失败。
    #[error("读取 ClientHello 失败: {0}")]
    HelloRead(std::io::Error),
    /// ClientHello 超过上限。
    #[error("ClientHello 超过 {MAX_CLIENT_HELLO} 字节上限")]
    HelloTooLarge,
    /// 不是合法的 ClientHello（可能是 HTTP 探测、端口扫描）。
    #[error("首包不是 TLS ClientHello: {0}")]
    NotClientHello(String),
    /// 连接在收到完整 ClientHello 前关闭。
    #[error("连接在 ClientHello 完成前关闭")]
    ClosedDuringHello,
    /// TLS 握手失败。
    #[error("TLS 握手失败: {0}")]
    TlsHandshake(String),
    /// 签发临时证书失败。
    #[error("签发临时证书失败: {0}")]
    TempCert(String),
    /// 透传失败。
    #[error("透传失败: {0}")]
    Forward(String),
    /// 内层出口失败（数据面）。
    #[error("出口失败: {0}")]
    Exit(String),
    /// 模式不支持该操作。
    #[error("当前模式不支持该操作: {0}")]
    Unsupported(String),
}

/// 处理结果（用于统计与日志）。
#[derive(Debug)]
pub enum Outcome {
    /// 认证通过，已完成 TLS 握手与内层数据面。
    Proxied {
        /// 用户标识（由密钥派生，仅用于日志区分）。
        user_tag: [u8; 8],
        /// 协商的 ALPN。
        alpn: Option<Vec<u8>>,
        /// 数据面统计（流数、字节数、拒绝数）。
        stats: ExitStats,
    },
    /// 认证失败，已透传给真实网站。
    Forwarded {
        /// 客户端→目标字节数。
        to_target: u64,
        /// 目标→客户端字节数。
        from_target: u64,
    },
    /// 连接被关闭（无法解析 ClientHello 等）。
    Closed {
        /// 原因（仅用于日志）。
        reason: String,
    },
}

/// 处理一个客户端连接。
///
/// 这是服务端的核心入口：判定 + 分流全在这里完成。
pub async fn handle_connection(
    mut client: TcpStream,
    mode: &ServerMode,
    exit_cfg: &ExitConfig,
    now_unix: u64,
) -> Result<Outcome, SessionError> {
    // 转发与握手都是小包交互，关闭 Nagle 降低 RTT
    let _ = client.set_nodelay(true);

    // ---- 步骤 1：读 ClientHello ----
    let (hello_info, raw_hello) = match read_client_hello(&mut client).await {
        Ok(v) => v,
        Err(e) => {
            // 解析失败说明对端不是 TLS 客户端。
            // 不能返回任何自定义响应（那是自曝），只能关闭。
            return Ok(Outcome::Closed {
                reason: e.to_string(),
            });
        }
    };

    tracing::debug!(
        sni = ?hello_info.sni,
        session_id_len = hello_info.session_id.len(),
        has_keyshare = hello_info.key_share_x25519.is_some(),
        wire_len = hello_info.wire_len,
        "收到 ClientHello"
    );

    // ---- 步骤 2：裁决 ----
    let verdict = match mode {
        ServerMode::Steal { config, .. } => config.judge(&hello_info, now_unix),
        ServerMode::OwnCert { .. } => {
            // 自有证书模式：客户端走标准 CA 校验，不需要 ClientHello 层认证。
            // 这里直接进入 TLS 握手，认证发生在握手后的首帧（FTAUTH）。
            Verdict::Accept { user_tag: [0u8; 8] }
        }
    };

    // ---- 步骤 3：分流 ----
    match verdict {
        Verdict::Accept { user_tag } => {
            serve_ours(client, mode, &hello_info, raw_hello, user_tag, exit_cfg).await
        }
        Verdict::Forward { reason } => {
            // 失败原因只记日志，绝不回给客户端
            tracing::debug!(%reason, "认证未通过，转发到真实网站");
            do_forward(client, mode, &raw_hello).await
        }
    }
}

/// 认证通过：TLS 握手 → 切到 FlowTCP 记录层 → 进入出口数据面。
///
/// # 为什么用 `accept_raw` 而不是 `accept`
///
/// [`flowtcp_tls::accept`] 会在握手后继续用 **TLS 记录层**读首帧做分流判定。
/// 但方案 G（ClientHello.session_id 票据认证）已经把分流决策提前到了
/// 读 ClientHello 的那一刻，认证通过后客户端会**立刻切到 FlowTCP 记录层** ——
/// 此时 TLS 层看到的不是合法 TLS 记录，`accept` 会一直等到 10 秒超时。
///
/// `accept_raw` 用 [`flowtcp_tls::Takeable`] 在握手后取回裸字节流，
/// 正好符合"握手用 TLS、数据不用 TLS"的架构设计。
async fn serve_ours(
    client: TcpStream,
    mode: &ServerMode,
    hello_info: &ClientHelloInfo,
    raw_hello: Vec<u8>,
    user_tag: [u8; 8],
    exit_cfg: &ExitConfig,
) -> Result<Outcome, SessionError> {
    let tls_cfg = build_server_tls(mode, hello_info, user_tag)?;

    // 把已读的 ClientHello 还回去，让 BoringSSL 能完整看到握手首包
    let stream = PrebufferedStream::new(raw_hello, client);

    let hs = flowtcp_tls::accept_raw(stream, &tls_cfg)
        .await
        .map_err(|e| SessionError::TlsHandshake(e.to_string()))?;

    let alpn = hs.alpn.clone();
    let (raw, tx_keys, rx_keys) = hs
        .into_parts()
        .map_err(|e| SessionError::TlsHandshake(e.to_string()))?;

    tracing::info!(
        alpn = ?alpn.as_deref().map(String::from_utf8_lossy),
        policy = ?exit_cfg.policy,
        "认证通过，TLS 握手完成，进入数据面"
    );

    let stats = exit::run(raw, tx_keys, rx_keys, exit_cfg.clone())
        .await
        .map_err(|e| SessionError::Exit(e.to_string()))?;

    tracing::info!(
        opened = stats.streams_opened,
        up = stats.bytes_up,
        down = stats.bytes_down,
        denied = stats.denied,
        failed = stats.connect_failed,
        "会话结束"
    );

    Ok(Outcome::Proxied {
        user_tag,
        alpn,
        stats,
    })
}

/// 为当前连接构造服务端 TLS 配置。
///
/// # 偷网站模式：每连接一张临时证书
///
/// 种子 = `HKDF(X25519(reality_priv, client_keyshare), salt=client_random)`。
/// 客户端能算出同一个种子，因此验证得了这张证书 —— 这就是"自签但仍安全"的原理。
fn build_server_tls(
    mode: &ServerMode,
    hello_info: &ClientHelloInfo,
    _user_tag: [u8; 8],
) -> Result<ServerTlsConfig, SessionError> {
    match mode {
        ServerMode::OwnCert {
            cert_path,
            key_path,
            ..
        } => Ok(ServerTlsConfig::new(cert_path, key_path)),

        ServerMode::Steal { config, .. } => {
            // 对称方案：seed = HMAC(secret, "cert" || client_random)
            // 客户端用同一 secret 算出同一种子，因此能验证这张证书。
            let seed = config.cert_seed(&hello_info.random);

            let sni = hello_info
                .sni
                .as_deref()
                .ok_or_else(|| SessionError::Unsupported("缺少 SNI（内部逻辑错误）".into()))?;

            let cert = flowtcp_tls::issue_temp_cert(&seed, sni, flowtcp_tls::now_unix())
                .map_err(|e| SessionError::TempCert(e.to_string()))?;

            Ok(ServerTlsConfig::from_pem(cert.cert_pem, cert.key_pem))
        }
    }
}

/// 认证失败：透传给真实网站。
async fn do_forward(
    client: TcpStream,
    mode: &ServerMode,
    raw_hello: &[u8],
) -> Result<Outcome, SessionError> {
    match mode.fallback() {
        FallbackAction::ForwardToSite {
            target,
            proxy_protocol,
        } => {
            let pp = proxy_protocol
                .map(ProxyProtocol::from_u8)
                .unwrap_or(ProxyProtocol::None);
            let (to_target, from_target) = forward::forward(client, raw_hello, target, pp)
                .await
                .map_err(|e| SessionError::Forward(e.to_string()))?;
            Ok(Outcome::Forwarded {
                to_target,
                from_target,
            })
        }
        FallbackAction::LocalHttp { addr } => {
            // 自有证书模式下客户端已通过 TLS，这里的 client 是**明文**流。
            // 直接把它接到本地 HTTP 服务。
            let (to_target, from_target) =
                forward::forward(client, raw_hello, addr, ProxyProtocol::None)
                    .await
                    .map_err(|e| SessionError::Forward(e.to_string()))?;
            Ok(Outcome::Forwarded {
                to_target,
                from_target,
            })
        }
        FallbackAction::Close => Ok(Outcome::Closed {
            reason: "配置为直接关闭".into(),
        }),
    }
}

/// 从 TCP 流读取完整的 ClientHello。
///
/// # 返回值
///
/// `(解析结果, 原始字节)`。原始字节**必须**保留：透传时要原样重放给目标网站，
/// 认证通过时要通过 [`PrebufferedStream`] 还回给 BoringSSL。
///
/// # 为什么循环读取
///
/// TLS 允许 ClientHello 跨多个 TCP 段（真实 Chrome 的 ClientHello 常达
/// 500+ 字节，且可能被拆成两个 TCP 段发出 —— 这本身是 Chrome 的已知行为）。
/// `parse_client_hello` 返回 `Ok(None)` 表示数据不足，必须继续读。
async fn read_client_hello(
    client: &mut TcpStream,
) -> Result<(ClientHelloInfo, Vec<u8>), SessionError> {
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + CLIENT_HELLO_TIMEOUT;

    loop {
        let n = tokio::time::timeout_at(deadline, client.read(&mut chunk))
            .await
            .map_err(|_| SessionError::HelloTimeout(CLIENT_HELLO_TIMEOUT))?
            .map_err(SessionError::HelloRead)?;

        if n == 0 {
            return Err(SessionError::ClosedDuringHello);
        }

        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_CLIENT_HELLO {
            return Err(SessionError::HelloTooLarge);
        }

        match flowtcp_proto::steal::parse_client_hello(&buf) {
            Ok(Some(info)) => return Ok((info, buf)),
            // 数据不足，继续读
            Ok(None) => continue,
            // 不是 TLS ClientHello：可能是 HTTP 探测或端口扫描。
            Err(e) => return Err(SessionError::NotClientHello(e.to_string())),
        }
    }
}

/// 便捷函数：签发临时证书（供测试与工具使用）。
pub fn make_temp_cert(
    config: &flowtcp_proto::steal::StealConfig,
    client_random: &[u8; 32],
    sni: &str,
) -> Result<TempCert, SessionError> {
    let seed = config.cert_seed(client_random);
    flowtcp_tls::issue_temp_cert(&seed, sni, flowtcp_tls::now_unix())
        .map_err(|e| SessionError::TempCert(e.to_string()))
}
