//! 流注册表查找开销基准
//!
//! # 要回答的问题
//!
//! `docs/FLOW_CONTROL.md` §6.6 声称
//! 「读循环每帧抢锁 + HashMap 查找 30~60 ns，与加密开销同量级」。
//! 这个数字必须有实测支撑，否则优化方向可能是错的。
//!
//! 本基准对比四种实现：
//! 1. `Arc<Mutex<HashMap<u16, Sender>>>`（当前实现）
//! 2. `Arc<Mutex<Vec<Option<Sender>>>>`（去掉哈希，保留锁）
//! 3. 开放寻址表 + `Mutex`（小内存 + 无哈希）
//! 4. 独占 `Vec<Option<Sender>>`（读循环独占，无锁）—— 理论最优
//!
//! 运行：
//! ```bash
//! cargo run --release -p flowtcp-client --example bench_registry
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use flowtcp_proto::frame::OwnedFrame;
use tokio::sync::mpsc;

/// 模拟的流数量。
const STREAMS: u16 = 256;

/// 基准迭代次数。
const ITERS: u64 = 5_000_000;

fn main() {
    println!("=== 流注册表查找开销基准 ===");
    println!("流数 = {STREAMS}，迭代 = {ITERS}\n");

    // ---------------------------------------------------------------
    // 1. Arc<Mutex<HashMap>>  (当前实现)
    // ---------------------------------------------------------------
    let map: Arc<Mutex<HashMap<u16, mpsc::Sender<OwnedFrame>>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(STREAMS as usize)));
    {
        let mut m = map.lock().unwrap();
        for id in 0..STREAMS {
            let (tx, rx) = mpsc::channel::<OwnedFrame>(256);
            // 保证 sender 不被 drop（否则 drop 也有成本）
            std::mem::forget(rx);
            m.insert(id, tx);
        }
    }
    // 预热
    for _ in 0..100_000 {
        let tx = map.lock().unwrap().get(&123u16).cloned();
        std::hint::black_box(&tx);
    }
    let t = Instant::now();
    for i in 0..ITERS {
        let id = (i % STREAMS as u64) as u16;
        let tx = map.lock().unwrap().get(&id).cloned();
        std::hint::black_box(&tx);
    }
    let hashmap_ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    println!("1. Arc<Mutex<HashMap>>      {hashmap_ns:>6.1} ns/次");

    // ---------------------------------------------------------------
    // 2. Arc<Mutex<Vec<Option<Sender>>>>  (去掉哈希)
    // ---------------------------------------------------------------
    let vec: Arc<Mutex<Vec<Option<mpsc::Sender<OwnedFrame>>>>> = {
        let mut v: Vec<Option<mpsc::Sender<OwnedFrame>>> = (0..STREAMS).map(|_| None).collect();
        for id in 0..STREAMS {
            let (tx, rx) = mpsc::channel::<OwnedFrame>(256);
            std::mem::forget(rx);
            v[id as usize] = Some(tx);
        }
        Arc::new(Mutex::new(v))
    };
    for _ in 0..100_000 {
        let tx = vec.lock().unwrap()[123].clone();
        std::hint::black_box(&tx);
    }
    let t = Instant::now();
    for i in 0..ITERS {
        let id = (i % STREAMS as u64) as usize;
        let tx = vec.lock().unwrap()[id].clone();
        std::hint::black_box(&tx);
    }
    let vec_mutex_ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    println!("2. Arc<Mutex<Vec<Option>>>  {vec_mutex_ns:>6.1} ns/次");

    // ---------------------------------------------------------------
    // 3. 独占 Vec<Option<Sender>>  (无锁)
    //
    // 这模拟「读循环独占注册表」的设计：注册/注销通过控制通道送达。
    // ---------------------------------------------------------------
    let mut owned: Vec<Option<mpsc::Sender<OwnedFrame>>> = (0..STREAMS).map(|_| None).collect();
    for id in 0..STREAMS {
        let (tx, rx) = mpsc::channel::<OwnedFrame>(256);
        std::mem::forget(rx);
        owned[id as usize] = Some(tx);
    }
    for _ in 0..100_000 {
        std::hint::black_box(&owned[123]);
    }
    let t = Instant::now();
    for i in 0..ITERS {
        let id = (i % STREAMS as u64) as usize;
        std::hint::black_box(&owned[id]);
    }
    let owned_ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    println!("3. 独占 Vec<Option>（无锁） {owned_ns:>6.1} ns/次");

    // ---------------------------------------------------------------
    // 4. 对照：原子 CAS（分配 stream_id 的成本）
    // ---------------------------------------------------------------
    let next = AtomicU16::new(1);
    for _ in 0..100_000 {
        next.fetch_add(1, Ordering::Relaxed);
    }
    let t = Instant::now();
    for _ in 0..ITERS {
        std::hint::black_box(next.fetch_add(1, Ordering::Relaxed));
    }
    let atomic_ns = t.elapsed().as_nanos() as f64 / ITERS as f64;
    println!("4. AtomicU16 fetch_add       {atomic_ns:>6.1} ns/次（对照）");

    println!();
    println!("--- 判读 ---");
    println!(
        "  优化 1→3 的绝对收益 = {:.1} ns/次查找",
        hashmap_ns - owned_ns
    );
    println!(
        "  按 256 流 × 1000 包/秒 = 256k 次/秒 计算，节省 {:.1} ms/秒 CPU",
        (hashmap_ns - owned_ns) * 256_000.0 / 1e6
    );
    println!("  参考：64B 包加密 235 ns。若收益 < 20 ns/次，则此项优化优先级不高。");
}
