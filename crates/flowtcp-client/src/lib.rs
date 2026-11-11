//! # flowtcp-client — FlowTCP 客户端
//!
//! 把「本地上网入口」与「FlowTCP 隧道」接起来：
//!
//! ```text
//! 浏览器 / Telegram / 游戏
//!      │ (1) SOCKS5 / HTTP / HTTPS（本 crate 的 entry）
//!      ▼
//!  ┌──────────────┐
//!  │  Entry 入口   │  ← 解析目标地址、建立本地代理协议握手
//!  └──────┬───────┘
//!         │ (2) 申请一条 stream_id
//!         ▼
//!  ┌──────────────┐
//!  │  Mux 复用层   │  ← 多条本地连接共用一条隧道
//!  └──────┬───────┘
//!         │ (3) Frame::encode
//!         ▼
//!  ┌──────────────┐
//!  │  Tunnel 隧道 │  ← 自研 TLS 1.3 握手（方案 G）+ FlowTCP 记录层
//!  └──────┬───────┘
//!         │ (4) RecordEncoder::seal
//!         ▼
//!   Transport（Phase 3 = 真 TCP；Phase 4 = FakeTCP）
//! ```
//!
//! # 为什么一条隧道要复用多条流
//!
//! 浏览器打开一个页面会并发 6+ 条 TCP 连接，视频/游戏还会加 UDP。
//! 若每条本地连接都单独握手：
//!
//! - 每次握手 1~2 RTT + 数 KB 流量 → 首屏明显变慢
//! - 每个连接一个 TLS 指纹 → 活跃连接数是可观测特征（异常高）
//!
//! 复用后：**一次握手，N 条流**，流量形态与一个长连 HTTPS 会话完全一致。
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`config`] | 客户端配置（远端、密码、SNI、各入口监听地址） |
//! | [`transport`] | 承载层抽象（真 TCP / FakeTCP） |
//! | [`tunnel`] | 单条 FlowTCP 隧道（握手 + 记录层 + 帧收发） |
//! | [`mux`] | 流复用（stream_id 分配 + 读写任务分流） |
//! | [`entry`] | 本地入口：SOCKS5 / HTTP / HTTPS |
//!
//! # 已知限制（Phase 3）
//!
//! - **无 ARQ**：依赖承载层可靠有序（真 TCP 满足）。Phase 4 接 FakeTCP 时补。
//! - **无流控**：单流大流量会挤占同隧道其他流。Phase 4 加窗口。
//! - HTTP 入口只处理**首个请求**的绝对 URI 改写；后续 keep-alive 请求
//!   若是 origin-form 可正常工作，若是绝对 URI 则不保证（见 [`entry::http`]）。

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod config;
pub mod entry;
pub mod mux;
pub mod transport;
pub mod tunnel;

#[cfg(test)]
mod testutil;

pub use config::{ClientConfig, EntryAddrs, HttpsCert, ProxyAuth};
pub use mux::{Mux, StreamHandle};
pub use transport::{TcpTransport, Transport};
pub use tunnel::{Tunnel, TunnelError};

/// 客户端统一错误。
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// 隧道建立或收发失败。
    #[error("隧道错误: {0}")]
    Tunnel(#[from] TunnelError),
    /// 入口处理失败。
    #[error("入口错误: {0}")]
    Entry(#[from] entry::EntryError),
    /// 承载层连接失败。
    #[error("承载层连接失败: {0}")]
    Transport(String),
    /// IO 错误。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    /// 配置错误。
    #[error("配置错误: {0}")]
    Config(String),
}
