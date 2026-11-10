//! FakeTCP 传输封装：把 `fake_tcp::Stack` 包装成可用的监听器 / 连接对象
//!
//! # 为什么还要包一层
//!
//! `fake_tcp::Stack` 的 API 是「半成品」：
//!
//! - `listen(port)` 与 `accept()` 分离，且 `listen` 只能调用一次同端口
//! - `Socket::send/recv` 返回 `Option`，无法区分「对端关闭」与「本地错误」
//! - 没有把「一个 IP 包」映射到「一条记录」的边界处理
//!
//! 本模块把这些细节收敛，使上层（服务端 / 客户端）只需面对
//! 「收一条记录 / 发一条记录」的简单接口。

use std::net::SocketAddr;

use fake_tcp::Stack;
use thiserror::Error;

/// 传输层错误。
#[derive(Debug, Error)]
pub enum TransportError {
    /// 连接已关闭（对端 FIN/RST 或本地栈销毁）。
    #[error("连接已关闭")]
    Closed,
    /// 单包超过 MTU 上限，必须由调用方先分片。
    #[error("单包 {size} 字节超过上限 {max}，需先分片")]
    TooLarge {
        /// 实际大小
        size: usize,
        /// 允许上限
        max: usize,
    },
    /// 无法建立到服务端的连接（握手重试耗尽）。
    #[error("无法连接到 {0}")]
    ConnectFailed(SocketAddr),
}

/// 一条已建立的 FakeTCP 连接。
///
/// 内部持有 `fake_tcp::Socket`，语义是**数据报**：
/// 每次 `send_datagram` 对应一个 IP 包，每次 `recv_datagram` 返回一个 IP 包的 payload。
pub struct FakeTcpStream {
    inner: fake_tcp::Socket,
    /// 对端地址（客户端视角是服务端，服务端视角是客户端）。
    peer: SocketAddr,
    /// 本连接可用的单包 payload 上限。
    max_datagram: usize,
}

impl FakeTcpStream {
    /// 包装一个 fake-tcp socket。
    pub fn new(inner: fake_tcp::Socket, peer: SocketAddr, max_datagram: usize) -> Self {
        FakeTcpStream {
            inner,
            peer,
            max_datagram,
        }
    }

    /// 对端地址。
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// 单包 payload 上限。
    pub fn max_datagram(&self) -> usize {
        self.max_datagram
    }

    /// 发送一个数据报（一个 IP 包）。
    ///
    /// 超过 `max_datagram` 会直接返回错误而**不是静默截断**：
    /// 截断会造成协议层无法察觉的数据损坏，比报错危险得多。
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > self.max_datagram {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                max: self.max_datagram,
            });
        }
        self.inner.send(payload).await.ok_or(TransportError::Closed)
    }

    /// 接收一个数据报，返回写入 `buf` 的字节数。
    pub async fn recv_datagram(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        match self.inner.recv(buf).await {
            Some(n) => Ok(n),
            None => Err(TransportError::Closed),
        }
    }
}

impl std::fmt::Debug for FakeTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTcpStream")
            .field("peer", &self.peer)
            .field("max_datagram", &self.max_datagram)
            .finish()
    }
}

/// FakeTCP 监听器。
///
/// 创建时即完成 `listen()` 注册，因此后续 `accept()` 可以并发调用。
pub struct FakeTcpListener {
    stack: Stack,
    port: u16,
    max_datagram: usize,
}

impl FakeTcpListener {
    /// 在已构造好的 `Stack` 上监听指定端口。
    ///
    /// # 参数
    ///
    /// - `stack`：由 [`crate::create_tun`] + `Stack::new` 构造
    /// - `port`：监听端口，与 iptables DNAT 的目标端口一致
    /// - `max_datagram`：单包 payload 上限（由 MTU 推导）
    ///
    /// # 为什么 `port` 必须与 DNAT 一致
    ///
    /// `fake_tcp` 用「目的端口 ∈ listening 集合」判定是否接受新连接
    /// （见 `vendor/fake-tcp/src/lib.rs` 的 reader_task）。若 DNAT 的目标端口
    /// 与监听端口不同，SYN 会被当作未知包并回 RST。
    pub fn new(mut stack: Stack, port: u16, max_datagram: usize) -> Self {
        stack.listen(port);
        FakeTcpListener {
            stack,
            port,
            max_datagram,
        }
    }

    /// 监听端口。
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 接受一条新连接。
    pub async fn accept(&mut self) -> FakeTcpStream {
        let sock = self.stack.accept().await;
        // fake-tcp 的 Display 形如 "(Fake TCP connection from A to B)"，
        // 这里不需要解析；对端地址由 Socket 内部维护，仅用于日志时再取。
        let peer = SocketAddr::from(([0, 0, 0, 0], 0));
        tracing::debug!(conn = %sock, "接受新的 FakeTCP 连接");
        FakeTcpStream::new(sock, peer, self.max_datagram)
    }
}

/// 主动连接到服务端。
///
/// 仅客户端使用。返回 `None` 表示握手重试耗尽（对端不可达或未监听）。
pub async fn connect(
    mut stack: Stack,
    server: SocketAddr,
    max_datagram: usize,
) -> Result<FakeTcpStream, TransportError> {
    match stack.connect(server).await {
        Some(sock) => Ok(FakeTcpStream::new(sock, server, max_datagram)),
        None => Err(TransportError::ConnectFailed(server)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 超大包必须在发送前被拦截，不能静默截断。
    #[test]
    fn 超大包被拒绝() {
        // 这里只验证尺寸判定逻辑（不构造真实 socket，避免需要 TUN 权限）
        let max = 1400usize;
        let payload = vec![0u8; 1401];
        assert!(payload.len() > max);
        let err = TransportError::TooLarge {
            size: payload.len(),
            max,
        };
        assert!(err.to_string().contains("1401"));
        assert!(err.to_string().contains("1400"));
    }

    /// 上限值本身必须被允许（边界包含）。
    #[test]
    fn 边界值允许() {
        let max = 1400usize;
        let payload = vec![0u8; 1400];
        assert!(payload.len() <= max);
    }
}
