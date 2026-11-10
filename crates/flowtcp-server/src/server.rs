//! 服务端主循环：监听 + 并发处理连接
//!
//! # 与 [`crate::session::handle_connection`] 的分工
//!
//! `handle_connection` 只管**一条**连接（读 ClientHello → 裁决 → 处置）。
//! 本模块负责进程级的事情：
//!
//! - 绑定端口
//! - 并发 accept（每条连接一个 tokio 任务）
//! - 全局连接计数与优雅退出
//!
//! 这样拆分的好处：单连接逻辑可以在测试里直接调用（不需要真起进程），
//! 而主循环保持极薄，几乎没有可测逻辑。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flowtcp_tls::mode::ServerMode;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::exit::ExitConfig;
use crate::session::{handle_connection, Outcome};

/// 服务端运行配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 监听地址。
    pub listen: SocketAddr,
    /// 认证与伪装模式。
    pub mode: ServerMode,
    /// 内层出口配置（策略、流数上限等）。
    pub exit: ExitConfig,
    /// 单连接空闲超时（0 表示不限制）。
    ///
    /// 注意：这里指的是**整个会话**的空闲时间。数据面本身由 TCP 的
    /// keepalive 与目标连接的关闭驱动，不需要额外超时；
    /// 这个值主要防止"握手完成后什么都不做"的连接长期占用 fd。
    pub idle_timeout: Duration,
}

impl ServerConfig {
    /// 构造。
    pub fn new(listen: SocketAddr, mode: ServerMode) -> Self {
        ServerConfig {
            listen,
            mode,
            exit: ExitConfig::default(),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// 全局统计（进程级）。
#[derive(Debug, Default)]
pub struct ServerStats {
    /// 累计接受的 TCP 连接数。
    pub accepted: AtomicU64,
    /// 认证通过并进入数据面的连接数。
    pub proxied: AtomicU64,
    /// 被透传到真实网站的连接数（探测者/浏览器）。
    pub forwarded: AtomicU64,
    /// 直接关闭的连接数。
    pub closed: AtomicU64,
    /// 处理出错终止的连接数。
    pub errored: AtomicU64,
}

impl ServerStats {
    /// 快照（用于日志输出）。
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.proxied.load(Ordering::Relaxed),
            self.forwarded.load(Ordering::Relaxed),
            self.closed.load(Ordering::Relaxed),
            self.errored.load(Ordering::Relaxed),
        )
    }
}

/// 运行服务端，直到 `shutdown` 收到信号。
///
/// 返回进程级统计。
pub async fn run(
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Arc<ServerStats>, std::io::Error> {
    let listener = TcpListener::bind(config.listen).await?;
    let actual = listener.local_addr()?;
    tracing::info!(
        %actual,
        mode = config.mode.name(),
        policy = ?config.exit.policy,
        max_streams = config.exit.max_streams,
        "FlowTCP 服务端已启动"
    );

    let stats = Arc::new(ServerStats::default());
    let mode = Arc::new(config.mode);
    let exit_cfg = Arc::new(config.exit);
    let idle = config.idle_timeout;

    loop {
        tokio::select! {
            // ---- 收到退出信号 ----
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("收到退出信号，停止接受新连接");
                    break;
                }
            }

            // ---- 接受新连接 ----
            accepted = listener.accept() => {
                let (sock, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        // fd 耗尽、EMFILE 等：记录后继续，不要因为一次失败就退出
                        tracing::warn!(error = %e, "accept 失败");
                        // 轻微退避，避免 accept 失败时空转烧 CPU
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                stats.accepted.fetch_add(1, Ordering::Relaxed);

                let mode = Arc::clone(&mode);
                let exit_cfg = Arc::clone(&exit_cfg);
                let stats2 = Arc::clone(&stats);

                tokio::spawn(async move {
                    serve_one(sock, peer, &mode, &exit_cfg, idle, &stats2).await;
                });
            }
        }
    }

    Ok(stats)
}

/// 处理一条已接受的连接，并更新统计。
async fn serve_one(
    sock: TcpStream,
    peer: SocketAddr,
    mode: &ServerMode,
    exit_cfg: &ExitConfig,
    idle: Duration,
    stats: &ServerStats,
) {
    // 每个连接一个随机用户的票据窗口都由 now 决定，取当前秒即可
    let now = flowtcp_tls::now_unix();

    let fut = handle_connection(sock, mode, exit_cfg, now);

    // 用整体超时兜住"握手完成后什么都不做"的连接。
    // 数据面的长连接不受影响：只要有数据流动，未来会由目标侧的关闭驱动结束；
    // 这里只限制**整条会话**的最长存活时间（0 表示不限）。
    let result = if idle.is_zero() {
        fut.await
    } else {
        // 用空闲超时作为会话上限是保守做法：
        // Phase 4 会改成基于最后活动时间的真实空闲检测。
        match tokio::time::timeout(idle, fut).await {
            Ok(v) => v,
            Err(_) => {
                tracing::debug!(%peer, "会话超时结束");
                stats.errored.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    };

    match result {
        Ok(Outcome::Proxied { stats: s, .. }) => {
            stats.proxied.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                %peer,
                opened = s.streams_opened,
                up = s.bytes_up,
                down = s.bytes_down,
                "代理会话正常结束"
            );
        }
        Ok(Outcome::Forwarded {
            to_target,
            from_target,
        }) => {
            stats.forwarded.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, to_target, from_target, "已透传到真实网站");
        }
        Ok(Outcome::Closed { reason }) => {
            stats.closed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, %reason, "连接被关闭");
        }
        Err(e) => {
            stats.errored.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, error = %e, "会话处理失败");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 统计初始为零() {
        let s = ServerStats::default();
        assert_eq!(s.snapshot(), (0, 0, 0, 0, 0));
    }

    #[test]
    fn 统计可累加() {
        let s = ServerStats::default();
        s.accepted.fetch_add(3, Ordering::Relaxed);
        s.proxied.fetch_add(1, Ordering::Relaxed);
        assert_eq!(s.snapshot(), (3, 1, 0, 0, 0));
    }

    #[tokio::test]
    async fn 收到退出信号后停止() {
        let (tx, rx) = watch::channel(false);
        let cfg = ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            ServerMode::OwnCert {
                cert_path: "/tmp/nonexistent.pem".into(),
                key_path: "/tmp/nonexistent.key".into(),
                fallback: flowtcp_tls::mode::FallbackAction::Close,
            },
        );

        let task = tokio::spawn(async move { run(cfg, rx).await });

        // 给启动一点时间，然后发退出信号
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(true).unwrap();

        let stats = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("应在 5 秒内退出")
            .expect("任务不应 panic")
            .expect("启动应成功");
        assert_eq!(stats.snapshot().0, 0, "没有连接时 accepted 应为 0");
    }
}
