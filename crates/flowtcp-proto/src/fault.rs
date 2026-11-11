//! 故障注入（仅用于测试与诊断，生产环境默认全关）。
//!
//! # 为什么需要这个模块
//!
//! `tc netem` 只能模拟**链路**丢包。在真 TCP 承载下，丢掉的包会被内核
//! TCP 重传，应用层（我们的帧层）看不到任何丢失 —— 因此**根本测不出**
//! 流控在真实丢包环境下的行为。
//!
//! FakeTCP 承载（Phase 4.8）没有内核重传，帧会真的丢。本模块在**应用层**
//! 按概率丢弃出站帧，等价模拟 FakeTCP 的丢失，从而验证：
//!
//! 1. `Data` 帧丢失 → 数据能否被发现（无 ARQ 时会静默损坏）
//! 2. `Window` 帧丢失 → 信用能否自愈（**这是最致命的**：
//!    增量语义的信用一旦丢失就永久少掉那一块）
//!
//! # 用法
//!
//! 通过环境变量开启，两侧进程独立配置：
//!
//! ```bash
//! # 丢弃 5% 的 Data 帧（模拟数据丢失）
//! FLOWTCP_DROP_DATA=5 flowtcp server ...
//!
//! # 丢弃 3% 的 Window 帧（模拟信用帧丢失）
//! FLOWTCP_DROP_WINDOW=3 flowtcp client ...
//! ```
//!
//! 值域 `0..=100`（百分比）。非法值按 0 处理并告警一次。
//!
//! # 为什么不丢 `Open` / `Close`
//!
//! 这两类帧丢了会导致流根本建立不起来，测试时无法区分
//! 「开流失败」与「流控死锁」—— 必须让它们始终可靠，
//! 才能把测试聚焦在流控语义上。

use std::cell::Cell;
use std::sync::OnceLock;

use crate::frame::FrameType;

/// 故障注入配置（进程内解析一次）。
#[derive(Debug, Clone, Copy, Default)]
pub struct FaultConfig {
    /// `Data` 帧丢弃概率，`0.0..=1.0`。
    pub drop_data: f64,
    /// `Window` 帧丢弃概率，`0.0..=1.0`。
    pub drop_window: f64,
}

impl FaultConfig {
    /// 是否完全关闭（热路径快速判断）。
    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.drop_data <= 0.0 && self.drop_window <= 0.0
    }

    /// 该类型的帧是否应该被丢弃。
    #[inline]
    pub fn should_drop(&self, ft: FrameType) -> bool {
        let p = match ft {
            FrameType::Data => self.drop_data,
            FrameType::Window => self.drop_window,
            // 其他帧一律不丢：控制帧丢失会让测试失去意义
            _ => return false,
        };
        if p <= 0.0 {
            return false;
        }
        next_f64() < p
    }
}

/// 进程级配置缓存。
///
/// 用 `OnceLock` 而非每次读环境变量：`should_drop` 在热路径上（每帧一次），
/// 读环境变量要走锁且分配，代价远超我们想省下的那点工作。
static CONFIG: OnceLock<FaultConfig> = OnceLock::new();

/// 取当前进程的故障注入配置。
///
/// 首次调用解析环境变量，之后直接返回缓存。未设置任何变量时
/// 返回 `drop_* = 0.0`，`should_drop` 退化为一次两条 `f64` 比较。
pub fn config() -> &'static FaultConfig {
    CONFIG.get_or_init(|| {
        let mut cfg = FaultConfig {
            drop_data: parse_percent("FLOWTCP_DROP_DATA"),
            drop_window: parse_percent("FLOWTCP_DROP_WINDOW"),
        };
        // 上限保护：100% 丢 Data 会让传输彻底停在第一帧，
        // 测不出任何有意义的信息（且容易误判为死锁）。
        // 允许 100，但会打一条醒目告警。
        if cfg.drop_data >= 1.0 {
            tracing_log_warn(
                "FLOWTCP_DROP_DATA=100 会丢弃全部数据帧，传输必然停滞；这是有意的吗？",
            );
        }
        if cfg.drop_window >= 1.0 {
            tracing_log_warn(
                "FLOWTCP_DROP_WINDOW=100 会丢弃全部窗口帧，流控必然死锁；这是有意的吗？",
            );
        }
        if cfg.is_disabled() {
            cfg = FaultConfig::default();
        }
        cfg
    })
}

/// 解析 `0..=100` 的百分比环境变量为 `0.0..=1.0`。
fn parse_percent(name: &str) -> f64 {
    let Ok(raw) = std::env::var(name) else {
        return 0.0;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return 0.0;
    }
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() && (0.0..=100.0).contains(&v) => v / 100.0,
        _ => {
            tracing_log_warn(&format!(
                "{name}={raw} 非法（应为 0..=100 的百分比），已按 0 处理"
            ));
            0.0
        }
    }
}

/// 轻量告警（本 crate 不依赖 `tracing`，用 `eprintln` 保持零依赖）。
fn tracing_log_warn(msg: &str) {
    eprintln!("[flowtcp-proto][fault] {msg}");
}

// ---- 线程本地伪随机数 ----
//
// 不用 `rand` 依赖：这个模块只为测试服务，xorshift32 足够。
// 用 `Cell` 而非 `AtomicU32`：每个 tokio worker 线程各自独立，
// 无竞争、无缓存行弹跳，热路径开销可忽略。

thread_local! {
    static RNG: Cell<u32> = const { Cell::new(0) };
}

/// 返回 `[0.0, 1.0)` 的伪随机数。
#[inline]
fn next_f64() -> f64 {
    RNG.with(|c| {
        let mut x = c.get();
        if x == 0 {
            // 用线程 ID 做种子，避免所有线程产生同一序列
            // （否则「按概率丢」会退化成「全丢」或「全不丢」）
            x = thread_seed();
        }
        // xorshift32
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        c.set(x);
        // 取高位（低位随机性差），映射到 [0,1)
        (x >> 8) as f64 / (1u32 << 24) as f64
    })
}

/// 生成线程种子。
fn thread_seed() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    // RandomState 每次构造都带随机密钥，用它算一个 hash 即可
    let mut h = RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9),
    );
    // 高并发下多个线程可能在同一纳秒取种子，再加线程 id 混合
    h.write_u64(thread_id_hash());
    let v = h.finish() as u32;
    if v == 0 {
        0x1234_5678
    } else {
        v
    }
}

/// 线程标识的哈希（`ThreadId::as_u64` 仍是 unstable，用 Debug 表示求 hash）。
fn thread_id_hash() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 未配置时不丢任何帧() {
        // 注意：`config()` 是进程级缓存，测试里不能依赖它被重新解析。
        // 这里直接构造配置验证逻辑。
        let cfg = FaultConfig::default();
        assert!(cfg.is_disabled());
        assert!(!cfg.should_drop(FrameType::Data));
        assert!(!cfg.should_drop(FrameType::Window));
    }

    #[test]
    fn 只丢配置过的帧类型() {
        let cfg = FaultConfig {
            drop_data: 1.0, // 100% 丢
            drop_window: 0.0,
        };
        // Data 必丢
        for _ in 0..8 {
            assert!(cfg.should_drop(FrameType::Data), "100% 配置应必丢 Data");
        }
        // Window 不丢
        for _ in 0..8 {
            assert!(!cfg.should_drop(FrameType::Window), "未配置的类型不应丢");
        }
        // 控制帧永不丢（否则流建不起来，测试失去意义）
        for ft in [
            FrameType::OpenTcp,
            FrameType::OpenUdp,
            FrameType::Close,
            FrameType::Ping,
            FrameType::Pong,
            FrameType::Ack,
            FrameType::Fec,
            FrameType::Error,
        ] {
            assert!(!cfg.should_drop(ft), "控制帧 {ft:?} 绝不能被丢");
        }
    }

    #[test]
    fn 概率大致符合配置() {
        // 10% 丢包，跑 10000 次，期望落在 8%~12%（xorshift32 足够）
        let cfg = FaultConfig {
            drop_data: 0.1,
            drop_window: 0.0,
        };
        let dropped = (0..10_000)
            .filter(|_| cfg.should_drop(FrameType::Data))
            .count();
        assert!(
            (800..=1200).contains(&dropped),
            "10% 配置实测 {dropped}/10000，偏离过大"
        );
    }

    #[test]
    fn 伪随机数落在零到一之间() {
        for _ in 0..1000 {
            let v = next_f64();
            assert!((0.0..1.0).contains(&v), "越界: {v}");
        }
    }

    #[test]
    fn 伪随机数有足够变化() {
        // 防退化：若种子取错，可能一直返回同一个值
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            seen.insert(next_f64().to_bits());
        }
        assert!(seen.len() > 90, "随机序列变化不足: {} 个不同值", seen.len());
    }
}
