//! 测试辅助：构造"直连隧道对"，跳过真 TLS 握手
//!
//! # 为什么需要它
//!
//! 真正走一遍 `Tunnel::open()` 需要：承载层连接 + 自研 TLS 1.3 握手 +
//! 服务端 BoringSSL 应答。这套流程在 `flowtcp-server` 的 e2e 测试里已经
//! 覆盖（那才是真正的端到端验证）。
//!
//! 而本 crate 的单元测试关心的是**数据面逻辑**：帧边界、分片、流分发、
//! SOCKS5 编解码。这些与 TLS 无关，用 `tokio::io::duplex` 造一对已建立
//! 的隧道即可，测试跑得快且零端口依赖。
//!
//! 关键点：**必须用同一份密钥、相反的 tx/rx 方向**，否则解密失败。

use std::sync::Arc;

use flowtcp_proto::record::{AeadAlgo, Keys};

use crate::mux::Mux;
use crate::tunnel::{FrameReader, FrameWriter, Tunnel};

/// `duplex` 之上的隧道类型。
pub(crate) type DuplexTunnel = Tunnel<tokio::io::DuplexStream>;

/// 构造一对方向相反的直连隧道（客户端视角在前）。
pub(crate) fn tunnel_pair() -> (DuplexTunnel, DuplexTunnel) {
    // 缓冲给足，避免测试里因为写入阻塞而死锁
    let (a, b) = tokio::io::duplex(512 * 1024);

    // 先 split，再各自构造 —— 注意不能对同一个流 split 两次
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);

    let d = flowtcp_proto::derive_keys(&[0x42u8; 32], &[0x99u8; 64], AeadAlgo::Aes128Gcm.key_len())
        .expect("密钥派生不应失败");

    // 客户端视角：tx = c2s，rx = s2c
    let (tk, tiv, tsn) = d.tx_material(true);
    let (rk, riv, rsn) = d.rx_material(true);
    let client = Tunnel::for_test(
        FrameWriter::new(aw, Keys::new(AeadAlgo::Aes128Gcm, tk, tiv, tsn).unwrap()),
        FrameReader::new(ar, Keys::new(AeadAlgo::Aes128Gcm, rk, riv, rsn).unwrap()),
        [0x42; 32],
        [0x99; 64],
    );

    // 服务端视角：方向对调
    let (tk, tiv, tsn) = d.tx_material(false);
    let (rk, riv, rsn) = d.rx_material(false);
    let server = Tunnel::for_test(
        FrameWriter::new(bw, Keys::new(AeadAlgo::Aes128Gcm, tk, tiv, tsn).unwrap()),
        FrameReader::new(br, Keys::new(AeadAlgo::Aes128Gcm, rk, riv, rsn).unwrap()),
        [0x42; 32],
        [0x99; 64],
    );

    (client, server)
}

/// 构造一个只含客户端侧的 `Mux`（服务端那半被丢弃）。
///
/// 适用于只验证"客户端是否正确发出了某些帧"的测试 —— 服务端隧道丢弃后，
/// 写入会失败，因此只适合测试**读取侧**行为（例如 SOCKS5 协议应答）。
pub(crate) fn mux_for_tests() -> Arc<Mux> {
    let (client, server) = tunnel_pair();
    // 保住服务端那半不被 drop：起一个只读不写的守护任务，
    // 否则对端关闭会让客户端写任务立刻失败。
    let mut r = server.reader;
    let mut w = server.writer;
    tokio::spawn(async move {
        // 持续读并丢弃，同时定期发 Pong 保持连接
        while let Ok(f) = r.recv().await {
            if f.frame_type == flowtcp_proto::frame::FrameType::Close {
                break;
            }
        }
        let _ = w.flush_record().await;
    });
    Arc::new(Mux::spawn(client, 64, 1400))
}
