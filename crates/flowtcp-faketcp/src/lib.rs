//! # flowtcp-faketcp — FakeTCP 承载层
//!
//! 把 `fake-tcp` 的用户态伪 TCP 栈与 FlowTCP 的记录层衔接起来，并提供
//! **运行时网络自动配置**（TUN + iptables），使服务端一条命令即可就绪。
//!
//! # 在协议栈中的位置
//!
//! ```text
//! flowtcp-proto（帧 / 记录层 / 密钥派生）
//!        ↕  明文记录字节流
//! flowtcp-faketcp（本 crate）—— 把字节流切成「伪 TCP 数据报」发出
//!        ↕
//! TUN 设备 ←→ 内核 netfilter（DNAT/SNAT）←→ 公网
//! ```
//!
//! # 关键语义：数据报而非字节流
//!
//! `fake-tcp::Socket::send()` 每次调用对应**一个 IP 包**，`recv()` 每次返回
//! **一个 IP 包的 payload**。中间不做重组、不保证顺序、丢失就是丢失。
//!
//! 这正是我们需要的：FlowTCP 记录层自身携带显式序号，能容忍乱序与丢包，
//! 因此不需要底层提供可靠流。反过来若用真 TCP，重组与重传会引入
//! 队头阻塞，抵消全部收益。
//!
//! # 单包大小约束
//!
//! 一次 `send()` 的 payload 上限由 MTU 决定（见
//! [`flowtcp_proto::max_payload_for_mtu`]）。超长会被内核丢弃且无任何反馈，
//! 表现为「大包神秘消失」，因此调用方**必须**在发送前分片。

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod netcfg;
pub mod transport;

pub use netcfg::{create_tun, AppliedConfig, NetConfig, NetError};
pub use transport::{FakeTcpListener, FakeTcpStream, TransportError};

/// 与 fake-tcp 一致的单包长度上限。
///
/// 该值来自 `fake_tcp::packet::MAX_PACKET_LEN`（1500），是 IP 层总长上限。
pub const MAX_PACKET_LEN: usize = fake_tcp::packet::MAX_PACKET_LEN;

/// 链路 MTU 假设值。
///
/// 默认按以太网 1500 计算。若链路为 PPPoE（1492）或存在 VLAN 封装，
/// 必须调小，否则会出现「小包通、大包不通」的经典故障。
pub const DEFAULT_MTU: usize = 1500;

/// 单个 FlowTCP 记录在 MTU 1500 下的明文上限（字节）。
///
/// 由 `flowtcp_proto::max_payload_for_mtu` 计算，已含 79 字节协议开销
/// 与 21 字节安全余量。
pub const RECOMMENDED_RECORD_PLAINTEXT: usize = 1400;
