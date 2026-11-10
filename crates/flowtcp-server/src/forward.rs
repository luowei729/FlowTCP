//! 透传转发器：把 TCP 字节流原样中转给真实网站
//!
//! # 为什么这是抗主动探测的最强手段
//!
//! 探测者连上来时，我们不扮演任何角色，只是**双向复制字节**：
//!
//! ```text
//! 探测者 ──TCP──> 本模块 ──TCP──> www.microsoft.com:443
//!                  │                    │
//!                  └─── 原样双向复制 ────┘
//! ```
//!
//! 探测者看到的 TLS 会话，其证书、ServerHello、证书链、OCSP、ALPN
//! **全部来自真实网站**。我们从未参与 TLS，因此不可能露出任何破绽 ——
//! 这比「自己扮演一个网站」强得多，扮演总有细节差异。
//!
//! # 已读字节的重放
//!
//! 判定需要先读 ClientHello，这些字节必须**先发给目标**，否则目标会
//! 收到残缺的握手而直接报错。参见 [`crate::Session::serve`] 的调用顺序。
//!
//! # 为什么用 copy_bidirectional 而不是手写循环
//!
//! `tokio::io::copy_bidirectional` 会：
//! - 正确传播半关闭（一方 FIN 时通知另一方，而不是立刻双双关闭）
//! - 使用 vectored IO（若底层支持）
//! - 处理背压（一方读得慢时不会无限缓冲）
//!
//! 手写循环极易在这些细节上出错，导致「大文件传输卡死」或「连接不释放」。

use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// 连接目标的超时。
///
/// 取 10 秒：目标站可能短暂不可达，太长会让探测者的连接一直挂着
/// （反而暴露"这个端口行为异常"）。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 透传错误。
#[derive(Debug, Error)]
pub enum ForwardError {
    /// 无法连接目标网站。
    #[error("连接目标 {target} 失败: {source}")]
    Connect {
        /// 目标地址
        target: String,
        /// 底层错误
        source: std::io::Error,
    },
    /// 连接目标超时。
    #[error("连接目标 {target} 超时（{timeout:?}）")]
    ConnectTimeout {
        /// 目标地址
        target: String,
        /// 超时值
        timeout: Duration,
    },
    /// 重放已读字节失败。
    #[error("重放已读字节失败: {0}")]
    Replay(std::io::Error),
    /// 双向复制过程中出错。
    #[error("双向转发失败: {0}")]
    Relay(std::io::Error),
}

/// PROXY protocol 版本。
///
/// 仅当目标网站**明确支持**时才应开启；否则目标会把协议头当成
/// TLS 记录的开头，握手必然失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    /// 不发送。
    None,
    /// v1（人类可读的单行文本）。
    V1,
    /// v2（二进制）。
    V2,
}

impl ProxyProtocol {
    /// 从配置整数解析（1 → V1，2 → V2，其他 → None）。
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => ProxyProtocol::V1,
            2 => ProxyProtocol::V2,
            _ => ProxyProtocol::None,
        }
    }
}

/// 把客户端连接透传给目标网站。
///
/// # 参数
///
/// - `client`：已建立的客户端连接（可能已读走若干字节）
/// - `already_read`：已从 `client` 读走的字节，必须**先**发给目标
/// - `target`：目标网站，形如 `www.microsoft.com:443`
/// - `proxy_protocol`：是否插入 PROXY protocol 头
///
/// # 返回
///
/// 双向复制结束后的 `(客户端→目标 字节数, 目标→客户端 字节数)`。
/// 「结束」可能是任何一方关闭连接、出错，或目标主动断开 —— 都属于正常情况，
/// 因此**不视为错误**（除了建连与重放阶段的失败）。
pub async fn forward(
    mut client: TcpStream,
    already_read: &[u8],
    target: &str,
    proxy_protocol: ProxyProtocol,
) -> Result<(u64, u64), ForwardError> {
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| ForwardError::ConnectTimeout {
            target: target.to_string(),
            timeout: CONNECT_TIMEOUT,
        })?
        .map_err(|source| ForwardError::Connect {
            target: target.to_string(),
            source,
        })?;

    // 转发场景对延迟敏感（探测者可能在测 RTT），关闭 Nagle
    let _ = upstream.set_nodelay(true);
    let _ = client.set_nodelay(true);

    // ---- 步骤 1：先发 PROXY protocol 头（若启用）----
    if proxy_protocol != ProxyProtocol::None {
        let header = build_proxy_header(proxy_protocol, &client, &upstream);
        upstream
            .write_all(&header)
            .await
            .map_err(ForwardError::Replay)?;
    }

    // ---- 步骤 2：重放已读字节 ----
    //
    // 这些字节是判定阶段从客户端读走的 ClientHello。目标必须收到
    // 完整、连续的 TLS 记录，缺一个字节握手就会失败。
    if !already_read.is_empty() {
        upstream
            .write_all(already_read)
            .await
            .map_err(ForwardError::Replay)?;
        upstream.flush().await.map_err(ForwardError::Replay)?;
    }

    // ---- 步骤 3：双向复制剩余字节 ----
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(ForwardError::Relay)
}

/// 构造 PROXY protocol 头。
///
/// # 关于 v2 的最小实现
///
/// 完整 v2 规范还支持 TLVs（如 PP2_TYPE_AUTHORITY），但目标网站通常
/// 只解析地址字段。这里只生成必需部分，避免引入不必要的复杂度。
fn build_proxy_header(kind: ProxyProtocol, client: &TcpStream, upstream: &TcpStream) -> Vec<u8> {
    let src = client.peer_addr().ok();
    let dst = upstream.peer_addr().ok();

    match kind {
        ProxyProtocol::None => Vec::new(),
        ProxyProtocol::V1 => {
            let (sip, sport) = src
                .map(|a| (a.ip().to_string(), a.port()))
                .unwrap_or_else(|| ("0.0.0.0".into(), 0));
            let (dip, dport) = dst
                .map(|a| (a.ip().to_string(), a.port()))
                .unwrap_or_else(|| ("0.0.0.0".into(), 0));
            let fam = if sip.contains(':') { "TCP6" } else { "TCP4" };
            format!("PROXY {fam} {sip} {dip} {sport} {dport}\r\n").into_bytes()
        }
        ProxyProtocol::V2 => {
            // 固定签名：\r\n\r\n\0\r\nQUIT\n
            const SIG: [u8; 12] = [
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            ];
            let mut out = Vec::with_capacity(28);
            out.extend_from_slice(&SIG);
            // version=2, command=PROXY
            out.push(0x21);
            match (src, dst) {
                (Some(std::net::SocketAddr::V4(s)), Some(std::net::SocketAddr::V4(d))) => {
                    out.push(0x11); // AF_INET + STREAM
                    out.extend_from_slice(&12u16.to_be_bytes());
                    out.extend_from_slice(&s.ip().octets());
                    out.extend_from_slice(&d.ip().octets());
                    out.extend_from_slice(&s.port().to_be_bytes());
                    out.extend_from_slice(&d.port().to_be_bytes());
                }
                (Some(std::net::SocketAddr::V6(s)), Some(std::net::SocketAddr::V6(d))) => {
                    out.push(0x21); // AF_INET6 + STREAM
                    out.extend_from_slice(&36u16.to_be_bytes());
                    out.extend_from_slice(&s.ip().octets());
                    out.extend_from_slice(&d.ip().octets());
                    out.extend_from_slice(&s.port().to_be_bytes());
                    out.extend_from_slice(&d.port().to_be_bytes());
                }
                _ => {
                    // 地址族不一致或取不到 → 发 UNSPEC，让目标按直连处理
                    out.push(0x00);
                    out.extend_from_slice(&0u16.to_be_bytes());
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_protocol解析() {
        assert_eq!(ProxyProtocol::from_u8(0), ProxyProtocol::None);
        assert_eq!(ProxyProtocol::from_u8(1), ProxyProtocol::V1);
        assert_eq!(ProxyProtocol::from_u8(2), ProxyProtocol::V2);
        assert_eq!(ProxyProtocol::from_u8(9), ProxyProtocol::None);
    }

    /// 端到端：把已读字节透传给一个本地监听器，验证目标收到完整内容。
    ///
    /// # 测试拓扑
    ///
    /// ```text
    /// 本测试扮演"客户端" ──> (我们传 as `client`) ──forward──> mock target
    /// ```
    ///
    /// 注意必须用**两对**连接：
    /// - 一对是本测试与 `forward` 之间的（模拟"上游连进来的客户端"）
    /// - 另一对是 `forward` 与 mock target 之间的（真实目标）
    ///
    /// 若误用同一对连接，`forward` 会把数据发到没人 accept 的连接上。
    #[tokio::test]
    async fn 透传重放已读字节() {
        let already_read = b"CLIENT-HELLO-BYTES".to_vec();
        let expect_len = already_read.len();
        let expect = already_read.clone();

        // ---- mock target：收够字节后关闭 ----
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = vec![0u8; expect_len];
            sock.read_exact(&mut buf).await.unwrap();
            drop(sock); // 发 FIN，让 copy_bidirectional 正常结束
            buf
        });

        // ---- 模拟"客户端连接我们"：本测试是客户端，forward 拿到服务端 ----
        let our_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let our_addr = our_listener.local_addr().unwrap();
        let _fake_client = TcpStream::connect(our_addr).await.unwrap();
        let (server_side, _) = our_listener.accept().await.unwrap();

        let target_s = target_addr.to_string();
        let fwd = forward(server_side, &already_read, &target_s, ProxyProtocol::None);
        let _ = tokio::time::timeout(Duration::from_secs(3), fwd).await;

        let received = tokio::time::timeout(Duration::from_secs(2), target_task)
            .await
            .expect("目标应在超时内收到数据")
            .unwrap();
        assert_eq!(received, expect, "目标必须收到完整的已读字节");
    }

    /// 目标不可达时必须返回明确错误，不能静默成功。
    #[tokio::test]
    async fn 目标不可达报错() {
        // 用一个几乎不可能监听的端口
        let client = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            TcpStream::connect(a).await.unwrap()
        };

        let err = forward(client, b"x", "127.0.0.1:1", ProxyProtocol::None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ForwardError::Connect { .. }),
            "应为 Connect 错误，实际: {err:?}"
        );
    }

    /// v1 头格式必须符合规范。
    #[tokio::test]
    async fn proxy_v1格式正确() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = l.accept().await.unwrap();

        let h = build_proxy_header(ProxyProtocol::V1, &client, &accepted);
        let s = String::from_utf8(h).unwrap();
        assert!(s.starts_with("PROXY TCP4 "), "实际: {s}");
        assert!(s.ends_with("\r\n"));
    }

    /// v2 头必须以固定签名开头。
    #[tokio::test]
    async fn proxy_v2签名正确() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = l.accept().await.unwrap();

        let h = build_proxy_header(ProxyProtocol::V2, &client, &accepted);
        assert_eq!(
            &h[..12],
            &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
        );
        assert_eq!(h[12], 0x21, "version=2 command=PROXY");
    }

    /// None 必须产生空头。
    #[tokio::test]
    async fn proxy_none为空() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = l.accept().await.unwrap();
        assert!(build_proxy_header(ProxyProtocol::None, &client, &accepted).is_empty());
    }
}
