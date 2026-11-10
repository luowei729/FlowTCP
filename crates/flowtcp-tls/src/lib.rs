//! # flowtcp-tls — TLS 1.3 握手层
//!
//! 负责 FlowTCP 的「伪装外壳」：用**真实 Chrome 指纹**完成 TLS 1.3 握手，
//! 在握手后读取首帧明文完成分流判定，并通过 exporter 派生内层密钥。
//!
//! # 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`fingerprint`] | Chrome 级指纹配置（cipher / curves / sigalgs / GREASE / 扩展随机化） |
//! | [`split`] | 首帧分流判定（FlowTCP vs HTTP vs 未知） |
//! | [`handshake`] | 客户端/服务端握手 + exporter 密钥导出 |
//!
//! # 为什么基于 BoringSSL
//!
//! BoringSSL 是 Chrome 使用的 TLS 实现，其扩展集合、GREASE 插入逻辑、
//! 记录层分片行为与 Chrome **天然一致**。我们只需开关几个选项，
//! 就得到与真实 Chrome 无法区分的 ClientHello —— 且随 BoringSSL 升级自动跟进。
//!
//! 自研 ClientHello 构造器需要维护一份随 Chrome 版本变化的指纹数据库，
//! 偏差后果是「被识别并封锁」，且无法通过自测发现。详见 [`fingerprint`] 模块文档。
//!
//! # 在整体架构中的位置
//!
//! ```text
//! flowtcp-faketcp（伪 TCP 数据报）
//!        ↓ 有序字节流适配
//! flowtcp-tls（本 crate）—— TLS 1.3 握手 + 分流 + exporter
//!        ↓ 派生密钥
//! flowtcp-proto::record（自研记录层，容忍乱序与丢包）
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod chbuilder;
pub mod fingerprint;
pub mod handshake;
pub mod inject;
pub mod ja4;
pub mod key_schedule;
pub mod mode;
pub mod prebuf;
pub mod split;
pub mod takeable;
pub mod tempcert;
pub mod tls13_client;

pub use chbuilder::{build_client_hello, ClientHelloParams};
pub use fingerprint::{
    CertSource, FingerprintConfig, FingerprintProfile, ServerTlsConfig, CHROME_ALPN,
    CHROME_CIPHER_LIST, CHROME_CURVES, CHROME_SIGALGS,
};
pub use handshake::{
    accept, accept_raw, aead_algo_of, connect, derive_flow_keys, export_context, record_keys_for,
    ClientHandshake, RawServerHandshake, ServerHandshake, TlsError, FIRST_FRAME_TIMEOUT,
    MAX_FIRST_FRAME,
};
pub use inject::{InjectPlan, InjectingStream};
pub use ja4::{compute_ja4, Ja4, CHROME_JA4_B};
pub use key_schedule::{KeySchedule, TrafficKeys};
pub use mode::{FallbackAction, ServerMode};
pub use prebuf::PrebufferedStream;
pub use split::{classify, Classified, Verdict, MIN_CLASSIFY_LEN};
pub use takeable::Takeable;
pub use tempcert::{
    issue_from_ecdh, issue_temp_cert, now_unix, p256_signing_key_from_seed, spki_of,
    verify_temp_cert, verify_temp_cert_at, CertVerdict, TempCert, TempCertError, TEMP_CERT_CN,
    TEMP_CERT_VALIDITY_SECS,
};
pub use tls13_client::{handshake, HandshakeResult, Tls13Error};
