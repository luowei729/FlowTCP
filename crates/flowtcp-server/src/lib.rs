//! # flowtcp-server — FlowTCP 服务端
//!
//! 把「偷网站认证」「临时证书签发」「透传转发」三块接成一个可运行的服务端。
//!
//! # 核心流程
//!
//! ```text
//! TCP accept
//!   → 读 ClientHello（可能跨多个 TCP 段）
//!   → session_id 票据认证（7 步校验）
//!   ├─ 通过 → ECDH 派生种子 → 签临时证书 → BoringSSL 握手 → 代理路径
//!   └─ 失败 → TCP 字节流原样透传给真实网站
//! ```
//!
//! # 为什么这个设计能抗主动探测
//!
//! 探测者拿到的是**真实网站完整无误的 TLS 会话**。我们从未在那个连接上
//! 参与 TLS，因此不可能露出破绽 —— 这比「自己扮演一个网站」强得多。
//!
//! 而且**不需要域名、不需要证书、不需要 ACME、不需要 nginx**。
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`forward`] | 透传转发（含 PROXY protocol 与已读字节重放） |
//! | [`session`] | 单连接裁决与分流处置 |
//! | [`exit`] | **内层出口**：帧 → 真实 TCP/UDP 连接（数据面） |
//! | [`policy`] | 目标地址访问策略（防 SSRF / 内网扫描） |
//! | [`server`] | 进程级主循环（监听、并发、统计、优雅退出） |

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod exit;
pub mod forward;
pub mod policy;
pub mod server;
pub mod session;

pub use exit::{ExitConfig, ExitError, ExitStats};
pub use forward::{forward, ForwardError, ProxyProtocol, CONNECT_TIMEOUT};
pub use policy::{DenyReason, TargetPolicy};
pub use server::{run, ServerConfig, ServerStats};
pub use session::{
    handle_connection, make_temp_cert, Outcome, SessionError, CLIENT_HELLO_TIMEOUT,
    MAX_CLIENT_HELLO,
};
