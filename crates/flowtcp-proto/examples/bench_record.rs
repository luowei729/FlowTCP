//! 记录层性能基准：量化"每包重建密码学上下文"的开销
//!
//! # 为什么需要这个基准（Phase 4 前置）
//!
//! 用户明确反馈过「流控实现不好 → 隧道带宽低、CPU 占用高」。
//! 在动手改之前必须先量化瓶颈在哪，否则容易优化错地方。
//!
//! 本 example 对比两种实现：
//! - **现状**：`Keys` 每次 `seal_into` 都重建 `Aes128Gcm` / `Aes128` 实例
//! - **缓存**：把 cipher 实例缓存在 `RecordEncoder` 里，只建一次
//!
//! 运行：
//! ```bash
//! cargo run --release -p flowtcp-proto --example bench_record
//! ```

use std::time::Instant;

use flowtcp_proto::record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder, MAX_RECORD_PLAINTEXT};

/// 基准用密钥材料（固定值，避免随机数影响可比性）。
const EXPORTER: [u8; 32] = [0x5A; 32];
const CTX: [u8; 64] = [0x11; 64];

fn make_keys(algo: AeadAlgo) -> Keys {
    let d = flowtcp_proto::derive_keys(&EXPORTER, &CTX, algo.key_len()).unwrap();
    let (k, iv, sn) = d.tx_material(true);
    Keys::new(algo, k, iv, sn).unwrap()
}

fn main() {
    println!("=== FlowTCP 记录层性能基准 ===\n");

    // 三个典型 payload 尺寸
    let cases: [(&str, usize); 4] = [
        ("小包 64B（DNS/游戏）", 64),
        ("中包 512B（交互）", 512),
        ("MTU 包 1400B（FakeTCP 典型）", 1400),
        ("大包 16KB（大流量）", MAX_RECORD_PLAINTEXT),
    ];

    for (name, size) in cases {
        println!("--- {name} ---");
        let payload = vec![0xABu8; size];

        for algo in [AeadAlgo::Aes128Gcm, AeadAlgo::ChaCha20Poly1305] {
            let keys = make_keys(algo);

            // --- 发送 ---
            let iters = if size >= 1400 { 200_000 } else { 500_000 };
            let mut enc = RecordEncoder::new(keys.clone());
            let mut out = Vec::with_capacity(MAX_RECORD_PLAINTEXT + 64);
            // 预热
            for _ in 0..1000 {
                out.clear();
                enc.seal_into(&payload, &mut out).unwrap();
            }

            let t = Instant::now();
            for _ in 0..iters {
                out.clear();
                enc.seal_into(&payload, &mut out).unwrap();
            }
            let send_ns = t.elapsed().as_nanos() as f64 / iters as f64;

            // --- 接收 ---
            let mut dec = RecordDecoder::new(keys.clone());
            let (_, wire) = {
                let mut e = RecordEncoder::new(keys.clone());
                e.seal(&payload).unwrap()
            };
            // 预热
            for _ in 0..1000 {
                let _ = RecordDecoder::new(keys.clone()).open(&wire);
            }
            let t = Instant::now();
            for _ in 0..iters {
                // 每次都换新的 decoder 会破坏重放窗口；这里用同一个
                let _ = dec.open(&wire);
            }
            let recv_ns = t.elapsed().as_nanos() as f64 / iters as f64;

            println!(
                "  {:<22} 加密 {:>7.0} ns/包   解密 {:>7.0} ns/包",
                format!("{algo:?}"),
                send_ns,
                recv_ns
            );
            println!(
                "  {:<22} 理论 {:>6.0} MB/s     上/下行 {:>6.0} MB/s（单核）",
                "",
                size as f64 / send_ns * 1e9 / 1e6,
                size as f64 / send_ns * 1e9 / 1e6,
            );
        }
        println!();
    }

    // ---- AES key expansion 的纯开销 ----
    println!("--- 纯 AES-128 key expansion（每包重建的代价）---");
    {
        use aes_gcm::aead::KeyInit;
        use aes_gcm::Aes128Gcm;
        let key = [0x42u8; 16];
        let iters = 2_000_000;
        // 预热
        for _ in 0..10000 {
            let _ = Aes128Gcm::new_from_slice(&key);
        }
        let t = Instant::now();
        for _ in 0..iters {
            let c = Aes128Gcm::new_from_slice(&key).unwrap();
            std::hint::black_box(&c);
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        println!("  Aes128Gcm::new_from_slice  {ns:.1} ns/次  ← 每包浪费一次");
    }
    {
        use aes::cipher::KeyInit;
        use aes::Aes128;
        let key = [0x42u8; 16];
        let iters = 2_000_000;
        for _ in 0..10000 {
            let _ = Aes128::new_from_slice(&key);
        }
        let t = Instant::now();
        for _ in 0..iters {
            let c = Aes128::new_from_slice(&key).unwrap();
            std::hint::black_box(&c);
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        println!("  Aes128::new_from_slice     {ns:.1} ns/次  ← 每包浪费一次（seq_mask）");
    }
}
