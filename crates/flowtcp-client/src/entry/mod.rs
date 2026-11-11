//! 本地入口：把各种代理协议翻译成 FlowTCP 帧
//!
//! # 支持的三种入口
//!
//! | 入口 | 本地协议 | 适合谁 | 证书 |
//! |------|---------|--------|------|
//! | [`socks5`] | SOCKS5（RFC 1928 + 1929 UDP） | 浏览器、Telegram、系统代理、几乎所有客户端 | 无 |
//! | [`http`] | HTTP 代理（CONNECT + 绝对 URI） | curl、老软件、需要明文调试的场合 | 无 |
//! | [`https`] | HTTP 代理 **套 TLS** | 需要加密到本机、或穿越只允许 TLS 的环境 | 默认自签，可指定 |
//!
//! # 为什么三个都要
//!
//! - **SOCKS5** 是唯一原生支持 UDP 的通用协议，游戏/QUIC/DNS 必需
//! - **HTTP** 是兼容性兜底（很多工具只认 `HTTP_PROXY` 环境变量）
//! - **HTTPS** 解决"本地链路也被监控"的场景（例如公司内网 DLP 检查明文 HTTP）
//!
//! # 共同的搬运逻辑
//!
//! 三种入口最终都归约到同一个动作：**本地字节流 ↔ 一条 FlowTCP 流**。
//! 这个搬运写在 [`pump`] 里，避免三份几乎相同的代码各自演化出细微差异。

use std::sync::Arc;

use flowtcp_proto::frame::FrameType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::ClientConfig;
use crate::mux::{Mux, MuxError, StreamHandle};

/// 常量时间字节比较（认证凭据校验专用）。
///
/// # 为什么不能直接用 `==`
///
/// `==` 在第一个不同字节处就返回，攻击者可以通过测量响应时间
/// 逐字节猜出正确凭据（时序侧信道）。认证路径必须用常量时间比较。
///
/// 实现：长度不等直接返回 false（长度本身不是秘密），
/// 否则逐字节异或累加，**不提前返回** —— 耗时只与长度相关。
#[inline]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    let mut i = 0;
    while i < a.len() {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    acc == 0
}

pub mod base64;
pub mod http;
pub mod https;
pub mod socks5;

/// 入口错误。
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// IO 失败。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    /// 复用层失败。
    #[error("复用层错误: {0}")]
    Mux(#[from] MuxError),
    /// 本地协议格式非法。
    #[error("本地协议错误: {0}")]
    Protocol(String),
    /// 本地 TLS 终止失败（仅 HTTPS 入口）。
    #[error("本地 TLS 失败: {0}")]
    Tls(String),
    /// 配置错误。
    #[error("配置错误: {0}")]
    Config(String),
}

/// 启动所有已配置的入口，直到全部退出。
///
/// 任一入口绑定失败会立即返回错误（快速失败比"静默少开一个端口"更好排查）。
pub async fn run_all(mux: Arc<Mux>, config: ClientConfig) -> Result<(), EntryError> {
    let mut tasks = Vec::new();

    // 三个入口共用同一份认证凭据（`--proxy-auth user:pass`）。
    //
    // # 为什么共用一个凭据而不是三个独立参数
    //
    // 用户配置的是"谁能用这个代理"，而不是"谁能用哪个端口的代理"。
    // 三份独立凭据只会增加配置负担和出错概率（改了 socks5 忘了改 http）。
    // 若将来真需要分别控制，再扩展成 `--socks5-auth` / `--http-auth` 即可。
    let auth = config.proxy_auth.clone().map(Arc::new);

    if let Some(addr) = config.entries.socks5 {
        let m = Arc::clone(&mux);
        let a = auth.clone();
        tasks.push(tokio::spawn(async move {
            tracing::info!(%addr, "SOCKS5 入口启动（TCP CONNECT + UDP ASSOCIATE）");
            socks5::serve(addr, m, a).await
        }));
    }

    if let Some(addr) = config.entries.http {
        let m = Arc::clone(&mux);
        let a = auth.clone();
        tasks.push(tokio::spawn(async move {
            tracing::info!(%addr, "HTTP 代理入口启动（CONNECT + 绝对 URI）");
            http::serve(addr, m, a).await
        }));
    }

    if let Some(addr) = config.entries.https {
        let m = Arc::clone(&mux);
        let cert = config.https_cert.clone();
        let a = auth.clone();
        tasks.push(tokio::spawn(async move {
            tracing::info!(%addr, "HTTPS 代理入口启动（HTTP over TLS）");
            https::serve(addr, m, &cert, a).await
        }));
    }

    // 入口任务是长期运行的；任何一个提前结束都说明出了故障
    for t in tasks {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(EntryError::Config(format!("入口任务异常退出: {e}"))),
        }
    }
    Ok(())
}

/// 本地字节流与一条 FlowTCP 流之间的双向搬运。
///
/// 返回 `(上行字节数, 下行字节数)`。
///
/// # 为什么用 `select!` 而不是 `join!`（重要）
///
/// 早期实现用 `tokio::join!` 等两个方向都自然结束，实际会**挂住**：
///
/// ```text
/// 目标服务器关闭 → 下行收到 Close 并结束
/// 但上行仍在 read(本地) 上等待 —— 浏览器保持 keep-alive 不关，于是永远等下去
/// ```
///
/// 结果是本地连接与两条任务泄漏，直到浏览器自己关掉（可能几分钟）。
/// 在代理场景下，"一端结束"就等于"整个会话结束" ——
/// 不存在"服务端已 FIN 但客户端还要继续发"的合法交互
/// （HTTP 的 request body 一定在响应之前发完；WebSocket/SSH 是双向长连，
///   任一端断即全断）。
///
/// 因此改用 `select!`：任一侧结束就取消另一侧。
///
/// # 关闭语义
///
/// - 本地读端 EOF → 发 `Close(FIN)`
/// - 收到 `Close` / `Error` / 发送队列关闭 → 结束并关闭本地写端
pub async fn pump<S>(local: S, handle: StreamHandle) -> Result<(u64, u64), EntryError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut tx, mut rx) = handle.split();
    let (mut local_r, mut local_w) = tokio::io::split(local);

    // 用原子计数而非返回值：select! 取消某一侧后拿不到它的返回值
    let up_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let down_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // ---- 上行：本地 → 隧道 ----
    let up_counter = Arc::clone(&up_bytes);
    let up = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match local_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::trace!(error = %e, "本地读失败，上行结束");
                    // 读错误视为异常关闭，仍发 FIN（让对端能回收流）
                    let _ = tx.close(true).await;
                    return;
                }
            };
            if let Err(e) = tx.send_data(&buf[..n]).await {
                eprintln!("[DBGC] up send 失败: {e}");
                tracing::trace!(error = %e, "隧道写失败，上行结束");
                return;
            }
            up_counter.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        // 本地 EOF：明确告知对端"我不再发数据"
        let _ = tx.close(true).await;
    };

    // ---- 下行：隧道 → 本地 ----
    let down_counter = Arc::clone(&down_bytes);
    let down = async move {
        while let Some(f) = rx.recv().await {
            match f.frame_type {
                FrameType::Data => {
                    if let Err(e) = local_w.write_all(&f.payload).await {
                        tracing::trace!(error = %e, "本地写失败，下行结束");
                        return;
                    }
                    down_counter
                        .fetch_add(f.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
                FrameType::Close => {
                    // 对端关闭：把缓冲刷出去再结束
                    let _ = local_w.flush().await;
                    let _ = local_w.shutdown().await;
                    return;
                }
                FrameType::Error => {
                    // 服务端拒绝/出错：Phase 3 无错误码细分，统一按异常关闭
                    tracing::debug!(stream_id = f.stream_id, "服务端返回错误帧");
                    let _ = local_w.shutdown().await;
                    return;
                }
                // Ping/Pong/Ack 等控制帧：Phase 3 不处理
                _ => {}
            }
        }
        // 通道关闭 = 隧道或该流已结束
        let _ = local_w.shutdown().await;
    };

    // ★ 半关闭语义（TCP 的核心特性，不能省）
    //
    // 早期实现是 `select! { _ = up => {}, _ = down => {} }`，即
    // **任一侧结束就取消另一侧** —— 这是错的：
    //
    // ```text
    // 浏览器发完请求后半关闭写端（HTTP/1.0 的 Connection: close 就是这么做的）
    //   → up 结束 → select! 取消 down
    //   → 响应还没收完就被掐断，文件下载不完整
    // ```
    //
    // 实测症状：16MB 文件只收到 15.4MB，且内容错位。
    //
    // 正确语义：
    // - **上行结束**（本地 EOF）→ 只发 FIN，**继续接收下行**直到对端关闭
    // - **下行结束**（收到 Close / 通道关闭）→ 整个会话结束，可以取消上行
    // 用 pin! 固定两个 future，避免 select! 内借用/移动冲突
    tokio::pin!(up, down);
    tokio::select! {
        // 上行结束：FIN 已发出，继续等下行把剩余数据收完
        _ = &mut up => { (&mut down).await; }
        // 下行结束：会话真正结束（对端已关闭或隧道断了）
        _ = &mut down => {}
    }

    Ok((
        up_bytes.load(std::sync::atomic::Ordering::Relaxed),
        down_bytes.load(std::sync::atomic::Ordering::Relaxed),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tunnel_pair;
    use flowtcp_proto::frame::{Address, OwnedFrame};

    #[tokio::test]
    async fn pump双向搬运() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 8, 1400);

        let handle = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();

        // 本地一侧用 duplex 模拟浏览器
        let (mut browser, local) = tokio::io::duplex(64 * 1024);

        let sid = {
            let open = server.reader.recv().await.unwrap();
            assert_eq!(open.frame_type, FrameType::OpenTcp);
            open.stream_id
        };

        let pump_task = tokio::spawn(async move { pump(local, handle).await });

        // 上行：浏览器 → 隧道
        browser.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let f = server.reader.recv().await.unwrap();
        assert_eq!(f.stream_id, sid);
        assert_eq!(f.payload, b"GET / HTTP/1.1\r\n\r\n");

        // 下行：隧道 → 浏览器
        server
            .writer
            .send(&OwnedFrame::data(sid, b"HTTP/1.1 200 OK\r\n\r\n".to_vec()))
            .await
            .unwrap();
        let mut buf = vec![0u8; 19];
        browser.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200 OK\r\n\r\n");

        // 服务端关闭 → 浏览器应看到 EOF
        server
            .writer
            .send(&OwnedFrame::close(sid, true))
            .await
            .unwrap();
        let mut rest = Vec::new();
        browser.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        let (up, down) = pump_task.await.unwrap().unwrap();
        assert_eq!(up, 18);
        assert_eq!(down, 19);
    }

    #[tokio::test]
    async fn 本地eof时发送fin() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 8, 1400);
        let handle = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();

        let (browser, local) = tokio::io::duplex(4096);
        let _sid = server.reader.recv().await.unwrap().stream_id;
        tokio::spawn(async move { pump(local, handle).await });

        // 浏览器立即关闭写端
        drop(browser);

        // 服务端应收到 FIN
        let mut saw_fin = false;
        for _ in 0..4 {
            match server.reader.recv().await {
                Ok(f) if f.frame_type == FrameType::Close => {
                    assert!(f.is_fin(), "应为正常关闭");
                    saw_fin = true;
                    break;
                }
                Ok(_) => continue,
                Err(e) => panic!("意外错误: {e}"),
            }
        }
        assert!(saw_fin, "本地 EOF 后应收到 FIN");
    }
}
