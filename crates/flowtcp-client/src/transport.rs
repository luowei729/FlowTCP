//! 承载层抽象
//!
//! # 为什么要有这一层抽象
//!
//! FlowTCP 的「承载层」可能有两种形态，而**上层（握手、复用、入口）完全不想感知差异**：
//!
//! | 承载 | 何时使用 | 特点 |
//! |------|---------|------|
//! | 真 TCP | 测试、受限网络、WSS 降级 | 内核有序可靠，但**有真 TCP 握手与拥塞控制** |
//! | FakeTCP | 生产（UDP 被 QoS 时） | 伪造 TCP 头、无重传、无流控 → 保留 UDP 低延迟 |
//!
//! Phase 3 先用真 TCP 把**端到端数据面打通并可自动化测试**；
//! Phase 4 把 FakeTCP 接进来时，只需实现本 trait，上层零改动。
//!
//! 这样分阶段的价值：数据面的 Bug（帧边界、半包、流生命周期、UDP 地址切换）
//! 在可靠链路上先被彻底测清，Phase 4 面对的就只剩"丢包与乱序"一个新变量。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 承载层：建立一条到服务端的**字节流**连接。
///
/// 返回的是有序字节流（FakeTCP 由 `flowtcp-faketcp` 的 transport 层负责把
/// 数据报适配成有序流）。上层只依赖 `AsyncRead + AsyncWrite`。
pub trait Transport: Send + Sync + 'static {
    /// 连接产出的流类型。
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// 连接服务端。
    ///
    /// `sni` 目前只用于日志与 FakeTCP 的目标选择（真 TCP 模式用 `addr`）；
    /// TLS 握手会另外拿 SNI，不依赖这里。
    fn connect(
        &self,
        sni: &str,
    ) -> impl std::future::Future<Output = io::Result<Self::Stream>> + Send;
}

/// 真 TCP 承载。
///
/// # 什么时候该用它
///
/// - **测试**：CI 里不能要求 root（TUN + raw socket 需要）
/// - **受限网络降级**：某些网络 UDP 完全被封（不是 QoS 而是 drop），
///   此时 FakeTCP 也活不了，只能退回真 TCP
/// - **对端部署在 CDN/反代后面**：只有 80/443 真 TCP 能进来
///
/// 代价：真 TCP 有自己的三次握手、拥塞控制、重传 —— FlowTCP 的
/// "UDP 低延迟"优势消失，只剩下"TLS 1.3 外观伪装"这一个收益。
#[derive(Debug, Clone)]
pub struct TcpTransport {
    /// 服务端地址。
    pub addr: SocketAddr,
    /// 连接超时。
    pub timeout: Duration,
}

impl TcpTransport {
    /// 构造。
    pub fn new(addr: SocketAddr) -> Self {
        TcpTransport {
            addr,
            timeout: Duration::from_secs(10),
        }
    }

    /// 设置超时。
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

impl Transport for TcpTransport {
    type Stream = TcpStream;

    async fn connect(&self, _sni: &str) -> io::Result<TcpStream> {
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("连接 {} 超时（{:?}）", self.addr, self.timeout),
                )
            })??;

        // 关闭 Nagle：FlowTCP 的帧本身就是消息边界，让内核再攒 40ms 毫无意义。
        // 对交互式流量（SSH、游戏、DNS）这是数量级的延迟差异。
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp承载可连通() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = l.accept().await;
        });

        let t = TcpTransport::new(addr);
        let s = t.connect("example.com").await.expect("应能连上");
        assert!(s.nodelay().unwrap(), "必须关闭 Nagle");
    }

    #[tokio::test]
    async fn 连接被拒时报错() {
        // 绑定后立刻释放，得到一个几乎肯定无监听的端口
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);

        let t = TcpTransport::new(addr).with_timeout(Duration::from_millis(500));
        assert!(t.connect("example.com").await.is_err());
    }
}
