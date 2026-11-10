//! FlowTCP 统一 CLI 入口
//!
//! # 当前阶段职责
//!
//! Phase 1 之前，本 CLI 只提供**自检**与**协议演示**能力，
//! 用于在目标服务器上验证「协议栈可用 + 链路可达」，
//! 而不需要先实现完整的 SOCKS5 / FakeTCP 数据面。
//!
//! 这样设计的好处：每个 Phase 都有可独立部署验证的产物，
//! 避免"全写完才发现某层假设不成立"。

use std::process::ExitCode;

use flowtcp_proto::frame::{Address, Flags, Frame, FrameType};
use flowtcp_proto::record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder};
use flowtcp_proto::{derive_keys, EXPORTER_LABEL, PROTOCOL_VERSION};

mod args;
mod cli;
mod cmd_client;
mod cmd_server;
mod fpcheck;

/// 主入口。
///
/// 用 `#[tokio::main]` 而非手动建 runtime：`fingerprint` 子命令需要异步 IO，
/// 统一入口可以避免「同步 main 里临时建 runtime」带来的嵌套 runtime panic 风险。
/// 其余子命令（selftest / info）是纯同步计算，跑在 async main 里没有额外开销。
#[tokio::main]
async fn main() -> ExitCode {
    // 日志初始化：默认 info，可用 RUST_LOG 覆盖
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("错误: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 协议自检：不依赖网络，纯本地验证协议核心各环节。
///
/// 返回 `Ok(())` 表示全部通过；任何一项失败都会返回具体错误。
pub fn selftest(verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("FlowTCP 协议自检 (协议版本 0x{PROTOCOL_VERSION:02X})");
    println!("exporter 标签: {EXPORTER_LABEL}");
    println!();

    // ---- 第 1 项：内层帧编解码 ----
    let addr = Address::Domain("example.com".to_string(), 443);
    let mut open_payload = Vec::new();
    addr.encode(&mut open_payload)?;
    let open = Frame::new(FrameType::OpenTcp, Flags::empty(), 1, 0, &open_payload);
    let mut wire = Vec::new();
    open.encode(&mut wire)?;
    let (decoded, used) = Frame::decode(&wire)?;
    assert_eq!(used, wire.len());
    assert_eq!(decoded.stream_id, 1);
    let (decoded_addr, _) = Address::decode(decoded.payload)?;
    assert_eq!(decoded_addr, addr);
    println!("  [1/5] 内层帧编解码 .......... 通过 ({} 字节)", wire.len());

    // ---- 第 2 项：MTU 预算 ----
    let max_payload = flowtcp_proto::max_payload_for_mtu(1500);
    println!("  [2/5] MTU 1500 预算 ......... payload 上限 {max_payload} 字节");
    assert_eq!(max_payload, 1400);

    // ---- 第 3 项：密钥派生 ----
    let exporter = [0x5Au8; 32];
    let context = b"selftest-context";
    let keys = derive_keys(&exporter, context, AeadAlgo::Aes128Gcm.key_len())?;
    println!("  [3/5] TLS exporter 密钥派生 . 通过 (方向隔离已启用)");
    if verbose {
        println!("        密钥材料: {keys:?}");
    }

    // ---- 第 4 项：记录层加解密 ----
    let (ck, civ, csn) = keys.tx_material(true);
    let mut enc = RecordEncoder::new(Keys::new(AeadAlgo::Aes128Gcm, ck, civ, csn)?);
    let (rk, riv, rsn) = keys.rx_material(false);
    let mut dec = RecordDecoder::new(Keys::new(AeadAlgo::Aes128Gcm, rk, riv, rsn)?);

    let mut records = Vec::new();
    for i in 0..8u32 {
        let (_, rec) = enc.seal(&i.to_be_bytes())?;
        records.push(rec);
    }
    let first = &records[0];
    println!(
        "  [4/5] 记录层伪装 ........... 通过 (头 {:#04X} {:#04X} {:#04X}，与真 TLS 1.3 一致)",
        first[0], first[1], first[2]
    );

    // ---- 第 5 项：乱序 + 丢包容忍（这是本项目区别于 TCP 的核心能力）----
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.reverse();
    // 故意只收 6 个，模拟 25% 丢包
    order.truncate(6);
    let mut ok = 0;
    for idx in order {
        let (seq, plain, _) = dec.open(&records[idx])?;
        assert_eq!(seq, idx as u64);
        assert_eq!(plain, (idx as u32).to_be_bytes());
        ok += 1;
    }
    println!("  [5/5] 乱序+丢包容忍 ........ 通过 ({ok}/8 记录全部正确解密)");
    println!();
    println!("全部自检通过。协议栈就绪。");
    Ok(())
}
