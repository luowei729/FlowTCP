//! # flowtcp-proto — FlowTCP 协议核心
//!
//! 本 crate 是**纯逻辑**实现：只做编解码与密码学运算，**不涉及任何 IO**。
//! 这样设计的三个理由：
//!
//! 1. **可单元测试**：无需网络、无需 TUN 设备、无需 root 权限即可验证协议正确性
//! 2. **可移植**：同一套协议逻辑复用于 Linux/Windows/Android 各平台承载层
//! 3. **可审计**：密码学与线格式集中在一处，便于逐行审查
//!
//! # 模块划分
//!
//! | 模块 | 职责 | 对应协议层 |
//! |------|------|-----------|
//! | [`frame`] | 内层帧编解码、地址编码、MTU 预算 | L4 复用层 |
//! | [`record`] | AEAD 加解密、显式序号、TLS 记录伪装、重放窗口 | L3 记录层 |
//! | [`flow`] | 信用流控（`Window` 帧 + 收发两侧状态机） | L4 复用层 |
//! | [`keyderive`] | 从 TLS exporter 派生方向性密钥 | L2→L3 交界 |
//! | [`slotmap`] | `u16` 流 ID → 状态的无锁定容映射 | L4 复用层 |
//!
//! # 数据流
//!
//! ```text
//!  应用数据 (UDP datagram / TCP chunk)
//!       │
//!       ▼  frame::Frame::encode
//!  内层帧 [type|flags|stream_id|pkt_seq|len|payload]
//!       │
//!       ▼  record::RecordEncoder::seal
//!  记录 [0x17 0x03 0x03|len|masked_seq|ciphertext|tag]
//!       │
//!       ▼  FakeTCP（raw socket，伪造 TCP 头）
//!  公网 IP 包（协议号 6）
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod arq;
pub mod fault;
pub mod flow;
pub mod frame;
pub mod keyderive;
pub mod padding;
pub mod record;
pub mod slotmap;
pub mod steal;

pub use flow::{
    decode_window_credit, encode_window_credit, FlowCounters, FlowError, SendCredit,
    DEFAULT_CONN_WINDOW, DEFAULT_STREAM_WINDOW, WINDOW_PAYLOAD_LEN,
};
pub use frame::{
    max_payload_for_mtu, Address, Flags, Frame, FrameError, FrameIter, FrameType, OwnedFrame,
    FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD,
};
pub use keyderive::{derive as derive_keys, DerivedKeys, KeyDeriveError, EXPORTER_LABEL};
pub use padding::{PaddingError, PaddingScheme, DEFAULT_SCHEME_TEXT};
pub use record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder, RecordError, MAX_RECORD_PLAINTEXT};
pub use slotmap::SlotTable;
pub use steal::{
    extract_hello_params, locate_server_hello_session_id, parse_client_hello,
    rewrite_server_hello_session_id, rewrite_session_id, AuthKey, ClientHelloInfo, ForwardReason,
    StealConfig, StealError, Verdict,
};

/// 协议主版本号。
///
/// 变更规则：任何破坏线格式兼容性的改动都必须递增此值，
/// 且必须同步更新 [`EXPORTER_LABEL`]（标签内含版本号）。
pub const PROTOCOL_VERSION: u8 = 0x01;

/// 认证帧魔数（握手后首帧明文的前 6 字节）。
///
/// 选择依据：
/// - 必须是**非 HTTP** 前缀，以便服务端用"首字节比对"完成分流
/// - 长度 6 字节：足够避免与真实 HTTP 方法碰撞，又不浪费带宽
/// - 全大写字母：与 HTTP 方法（也是大写）同族，即使被看到也不突兀
pub const AUTH_MAGIC: &[u8; 6] = b"FTAUTH";

#[cfg(test)]
mod tests {
    use super::*;

    /// 魔数必须不能与任何 HTTP 方法前缀相同，否则分流会误判。
    #[test]
    fn 魔数不与http方法冲突() {
        let http_methods: [&[u8]; 9] = [
            b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC", b"CONN", b"PRI ",
        ];
        for m in http_methods {
            assert_ne!(&AUTH_MAGIC[..], m);
            // 逐字节前缀也不能相同（分流按首字节匹配）
            assert_ne!(AUTH_MAGIC[0], m[0], "首字节与 {m:?} 冲突");
        }
    }

    /// 协议版本与 exporter 标签中的版本号必须一致。
    #[test]
    fn 版本与exporter标签一致() {
        assert!(EXPORTER_LABEL.ends_with("v1"));
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
