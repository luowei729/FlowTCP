//! 信用流控：`Window` 帧 + 收发两侧状态机
//!
//! # 为什么需要流控（现在没有也能跑满）
//!
//! Phase 3 用真 TCP 承载时，内核 socket 的接收窗口在替我们做流控，
//! 所以 `send().await` 背压就够用（实测 143/154 MB/s）。
//!
//! 但换成 FakeTCP（Phase 4.8）后：
//!
//! - **没有内核接收窗口** → 发送方无法感知接收方容量
//! - 只能靠 `send().await` 阻塞读循环 → **整条隧道队头阻塞（HOL）**
//! - 一个慢目标会卡住所有流
//!
//! 因此流控的价值不是"跑得更快"，而是**用按流窗口代替阻塞，消除跨流 HOL**。
//!
//! # 设计依据（RFC 9000 §4 的三条铁律）
//!
//! 1. **窗口必须 ≥ 2×BDP**，否则流控自己成为吞吐瓶颈
//! 2. **信用帧必须搭便车**，绝不单独发包
//! 3. **信用按「已接收」而非「已交付」计算**，否则丢包造成空洞 → 死锁
//!
//! 详见 `docs/FLOW_CONTROL.md`。
//!
//! # 为什么用「绝对偏移」而不是「增量」
//!
//! | 方案 | 每帧开销 | 丢一帧的后果 |
//! |------|---------|-------------|
//! | 增量（早期实现） | 4 字节 | **那份信用永久蒸发**，累计超过窗口即死锁 |
//! | **绝对偏移（本模块）** | 4 字节 | 下一个信用帧自动修正，**无损失** |
//!
//! 实测证据（`FLOWTCP_DROP_WINDOW=10`，真 TCP 承载，只丢应用层 Window 帧）：
//! 增量语义下传输在 **3.3 MB / 16 MB** 处永久停滞（丢 10% 的信用帧，
//! 每窗漏掉十几 KB，约十几轮后信用彻底漏光）。
//!
//! 绝对语义下同一个测试只需把丢包率提高到 99% 才会停滞，因为任何一个
//! 幸存下来的信用帧都能把状态直接拉回正确值 —— **幂等、可自愈**。
//!
//! 载荷语义：`consumed` 累计值的**低 32 位**。发送方用 `wrapping` 差值
//! 重建完整的 `u64`，自然处理 4 GB 回绕。
//!
//! # 与 ARQ 的关系
//!
//! **流控与 ARQ 正交**：
//! - 流控管「能不能发」（接收方是否有空间）
//! - ARQ 管「要不要重传」（数据是否丢失）
//!
//! 顺序：先拿信用 → 再发/重传。**重传也消耗信用**。
//!
//! 本模块的 [`FlowCounters::on_received`] 语义是「**新增了多少不重复的字节**」——
//! 去重是 ARQ 层的职责（它有 `pkt_seq` 与重放窗口），流控不应重复实现。
//!
//! **无 ARQ 时的必然代价**（Phase 4.6 才能根治）：`Data` 帧真的丢了，
//! 接收方的 `consumed` 就永远少那一块 → 发送方净损失等量信用。
//! 本模块提供 [`SendCredit::recover`] 作为临时兜底（由调用方超时触发），
//! 宁可把「对端缓冲可能被多塞几帧」也不能让隧道永久停死。

use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// `Window` 帧载荷长度：已消费绝对偏移的低 32 位（大端）。
///
/// # 为什么是 32 位绝对偏移而不是 64 位
///
/// 接收方可以把上次收到的值与新值做 `wrapping_sub`，只要差值 < 2^31
/// 就认为是「前进」（并据此重建 64 位累计值）。因为正常情况下两次
/// 信用帧之间不会前进 2 GB 以上，所以 32 位完全够用。
///
/// 这条规则与 QUIC 的 `MAX_DATA` 变长整数思路一致，但固定 4 字节更好解析。
pub const WINDOW_PAYLOAD_LEN: usize = 4;

/// 单次补发信用的上限。
///
/// 取 1 GB：正常补发量是「窗口大小」量级（KB~MB），
/// 1 GB 只是防御性上限，防止实现 bug 导致一次通告天文数字。
pub const MAX_GRANT_CHUNK: u64 = 1 << 30;

/// 默认单流窗口大小（**对齐 Hysteria 2 的 QUIC 默认值**）。
///
/// # 取值依据：直接采用成熟项目的实测结论
///
/// Hysteria 2 官方 `quic.initStreamReceiveWindow` 默认 **8 MB**、
/// `initConnReceiveWindow` 默认 **20 MB**，并明确说明
/// 「We do not recommend changing these values unless you fully understand
/// what you are doing」+「recommend keeping the ratio of stream receive window
/// to connection receive window at 2:5」。
///
/// 这不是拍脑袋的数字，而是 QUIC 生态（quic-go / Chromium / Cloudflare）
/// 在大量高 BDP、高丢包链路上的经验值：
///
/// | 带宽 | RTT | BDP | 8 MB 窗口能否跑满 |
/// |------|-----|-----|------------------|
/// | 1 Gbps | 100 ms | 12.5 MB | 接近（64% 利用率） |
/// | 1 Gbps | 50 ms | 6.25 MB | ✅ 跑满 |
/// | 500 Mbps | 200 ms | 12.5 MB | 接近 |
/// | 100 Mbps | 300 ms | 3.75 MB | ✅ 跑满 |
/// | 20 Mbps | 100 ms | 0.25 MB | ✅ 远超需求 |
///
/// 对比我们早期用的 256 KB：在 RTT 100 ms 链路上单流上限仅
/// `256KB / 0.1s ≈ 2.5 MB/s`（实测 1.5 MB/s），**比 hy2 小 32 倍**，
/// 这是实测发现的硬瓶颈。
///
/// 内存代价：32 MB 的连接级上限下，8 MB 单流最多 4 条同时满载 ——
/// 这正是 2:5 比例 + 连接级上限的意义（见 [`DEFAULT_CONN_WINDOW`]）。
pub const DEFAULT_STREAM_WINDOW: u64 = 8 * 1024 * 1024;

/// 默认连接级窗口（所有流合计）。**对齐 Hysteria 2 的 20 MB**。
///
/// 与 [`DEFAULT_STREAM_WINDOW`] 严格保持 **2:5** 的比例（8:20），
/// 这是 hy2 官方推荐值。
///
/// # 为什么必须有连接级上限
///
/// 若只有流级窗口：256 条流 × 8 MB = **2 GB** 内存 —— 路由器/小内存 VPS 直接 OOM。
/// 连接级上限把「最坏情况」钉死在 20 MB/连接。
///
/// 本机国外服务器可用内存仅 **183 MB**（见 `DEVOPS` 记录），
/// 20 MB/连接意味着理论上最多 ~9 条并发满载连接 —— 实际协作式调度下
/// 远未达到这个数（`poll_grant` 是按需补发，不预分配）。
pub const DEFAULT_CONN_WINDOW: u64 = 20 * 1024 * 1024;

/// 流控错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowError {
    /// 载荷长度不符。
    #[error("Window 帧载荷长度错误：期望 {WINDOW_PAYLOAD_LEN}，实际 {0}")]
    BadPayloadLen(usize),
    /// 超出授信额度。
    ///
    /// 这表示**对端违约或我们有实现 bug**，必须断开而不是继续发 ——
    /// 继续发会让接收方缓冲无限增长（内存耗尽）。
    #[error("超出流控信用：想发 {requested} 字节，仅剩 {available} 字节可用")]
    CreditExceeded {
        /// 本次想发的字节数。
        requested: usize,
        /// 当前可用信用。
        available: u64,
    },
}

/// 把一个信用偏移编码进 `Window` 帧的 payload。
///
/// `offset` 是接收方**已消费的累计字节数的低 32 位**（不是增量！）。
/// 追加到 `out`（便于与帧头一起编码）。
#[inline]
pub fn encode_window_credit(offset: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&offset.to_be_bytes());
}

/// 解析 `Window` 帧的 payload，得到已消费绝对偏移的低 32 位。
#[inline]
pub fn decode_window_credit(payload: &[u8]) -> Result<u32, FlowError> {
    if payload.len() != WINDOW_PAYLOAD_LEN {
        return Err(FlowError::BadPayloadLen(payload.len()));
    }
    Ok(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

// ============================================================================
// 发送侧：信用记账
// ============================================================================

/// 发送侧的信用记账（绝对偏移语义）。
///
/// # 语义
///
/// - `acked`：对端累计已消费的字节数（由 32 位偏移重建为 `u64`，单调递增）
/// - `used`：我已经发出去的累计字节数（单调递增）
/// - 可用信用 = `acked + window - used`（饱和到 0）
///
/// # 为什么用「累计值」而不是「剩余额度」
///
/// - 累计值只用 `u64` 加法，无减法下溢风险
/// - `acked` 是**幂等**的：同一个 `Window` 帧收两次、乱序到达、
///   中间的帧丢了 —— 都不影响最终结果，只要收到**任何一个**较新的偏移就能对正
///
/// # 为什么带 `acked_low` 的 `u32` 镜像
///
/// 协议上用 32 位传（省带宽），本地用 64 位算（免回绕）。
/// 收到新偏移时用 `wrapping_sub` 算差值：差值 < 2³¹ 即视为前进，
/// 忽略倒序的旧帧 —— 这正是 QUIC 处理 `MAX_DATA` 乱序的方式。
pub struct SendCredit {
    /// 对端已消费的累计字节数（`u64`，本端算出）。
    acked: u64,
    /// 上次收到的 32 位偏移原值（算 `wrapping` 差值用）。
    acked_low: u32,
    /// 已发送的累计字节数。
    used: u64,
    /// 窗口大小（对端可以「超前」我多少字节）。
    window: u64,
}

impl SendCredit {
    /// 用初始窗口构造。开流时双方约定初始信用 = `window`（即 `acked = 0`）。
    pub fn new(window: u64) -> Self {
        SendCredit {
            acked: 0,
            acked_low: 0,
            used: 0,
            window,
        }
    }

    /// 当前可用信用（还能发多少字节）。
    #[inline]
    pub fn available(&self) -> u64 {
        self.acked
            .saturating_add(self.window)
            .saturating_sub(self.used)
    }

    /// 收到 `Window` 帧：对端已消费到 `offset`（低 32 位）。
    ///
    /// # 幂等且抗丢包
    ///
    /// - 重复收到同一个偏移 → 差值 0 → 无变化
    /// - 中间帧丢了 → 下一个新偏移直接跳到位
    /// - 倒序的旧帧 → 差值 ≥ 2³¹ → 忽略
    ///
    /// 这三点是相对「增量语义」的核心优势：增量一丢就永久蒸发，
    /// 而绝对偏移**永远能追回来**。
    pub fn set_acked(&mut self, offset: u32) {
        let delta = offset.wrapping_sub(self.acked_low) as u64;
        // 差值 ≥ 2³¹ 视为旧包（或异常回退），忽略
        if delta < (1u64 << 31) {
            self.acked = self.acked.saturating_add(delta);
            self.acked_low = offset;
        }
    }

    /// ★ 信用恢复：强行把 `acked` 提到 `used`（认为已发出的数据全部被消费）。
    ///
    /// # 为什么需要这个（无 ARQ 阶段的临时兜底）
    ///
    /// `Data` 帧真丢了，接收方的 `consumed` 就永远少那一块，而发送方的
    /// `used` 已经包含它 —— 那份信用**永久不可回收**。累计丢失量超过
    /// 窗口大小后，发送方就彻底停死（真实丢包环境下几秒就会发生）。
    ///
    /// 根治手段是 ARQ（Phase 4.6，重传后对端自然能确认），
    /// 但那还没实现。在那之前，宁可把「对端缓冲可能被多塞几帧」
    /// 也不能让隧道永久停死。
    ///
    /// # 安全性
    ///
    /// 超额发送的后果是接收方 `inbound` 队列积压。那个队列是**有界**的
    /// （256 帧 ≈ 358 KB），满了会阻塞 `read_loop`，背压依然存在 ——
    /// 不会 OOM，只是内存占用暂时偏高。
    ///
    /// 返回被回收的信用量（0 表示本来就没欠）。
    pub fn recover(&mut self) -> u64 {
        let owed = self.used.saturating_sub(self.acked);
        if owed == 0 {
            return 0;
        }
        self.acked = self.used;
        // 同步 32 位镜像，否则后续 `set_acked` 的差值会算错
        self.acked_low = self.used as u32;
        owed
    }

    /// 尝试消费 `n` 字节的信用。
    ///
    /// 额度不足返回 `Err`，**调用方必须停止发送并等待 `Window` 帧**。
    /// 绝不能"少发一点凑合"——那会让字节流错位。
    #[inline]
    pub fn try_consume(&mut self, n: usize) -> Result<(), FlowError> {
        let avail = self.available();
        if (n as u64) > avail {
            return Err(FlowError::CreditExceeded {
                requested: n,
                available: avail,
            });
        }
        self.used += n as u64;
        Ok(())
    }

    /// 已经完全没信用了（被信用卡住）。
    #[inline]
    pub fn is_blocked(&self) -> bool {
        self.available() == 0
    }

    /// 已发布字节数（诊断用）。
    #[inline]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// 对端已消费字节数（诊断用）。
    #[inline]
    pub fn acked(&self) -> u64 {
        self.acked
    }
}

impl std::fmt::Debug for SendCredit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendCredit")
            .field("acked", &self.acked)
            .field("used", &self.used)
            .field("window", &self.window)
            .field("available", &self.available())
            .finish()
    }
}

// ============================================================================
// 接收侧：窗口与信用发放
// ============================================================================

/// 接收侧的窗口状态（跨任务共享、无锁）。
///
/// # 为什么用原子量而不是 `Mutex`
///
/// 两个任务同时访问：
/// - **读任务**：`on_received()`（每帧一次）+ `poll_grant()`（每 N 帧一次）
/// - **消费任务**：`on_consumed()`（每次成功写入后一次）
///
/// 全部是「读-改-写单个 `u64`」，用 `fetch_add` / `load` 即可，
/// 加锁只会平白增加争用（实测 `Mutex` 每次约 40 ns，而这几个操作各约 5 ns）。
///
/// # 为什么 `advertised` 也用原子量
///
/// 严格说它只在读任务里写，但需要被 `poll_grant` 自己读，
/// 用 `AtomicU64` 避免为「单线程独占」引入额外结构（如 `Cell`，
/// 而 `Cell` 不满足 `Sync`，无法跨任务共享）。
pub struct FlowCounters {
    /// 窗口大小（对端可以「超前」发送多少字节）。
    window: u64,
    /// 已接收的不重复字节数（读任务更新）。
    received: AtomicU64,
    /// 已交付给应用（成功写入下游）的字节数（消费任务更新）。
    consumed: AtomicU64,
    /// 已通告给对端的绝对上限（读任务更新）。
    advertised: AtomicU64,
    /// 累计补发的信用（用于诊断）。
    granted_total: AtomicU64,
}

impl FlowCounters {
    /// 用窗口大小构造。
    ///
    /// 初始 `advertised = 0`：它存的是「已通告的 **consumed 偏移**」，
    /// 而开流时双方约定「对端已有 `window` 字节信用」（隐式初始窗口，
    /// 不需要发帧）。所以初始通告偏移是 0，对应的上限就是 `0 + window`。
    pub fn new(window: u64) -> Self {
        FlowCounters {
            window,
            received: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            advertised: AtomicU64::new(0),
            granted_total: AtomicU64::new(0),
        }
    }

    /// 窗口大小。
    #[inline]
    pub fn window(&self) -> u64 {
        self.window
    }

    /// 记录接收了 `n` 字节的新数据。
    ///
    /// # 调用方必须保证「n 是新增的不重复字节」
    ///
    /// 去重是 ARQ 层的职责（它持有 `pkt_seq` 与重放窗口）。
    /// 若 ARQ 层误把重传的旧数据也算进来，接收方会以为缓冲快满了，
    /// 从而过早补发信用 → 对端发得更快 → 缓冲真的溢出。
    #[inline]
    pub fn on_received(&self, n: usize) {
        self.received.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// 记录应用消费了 `n` 字节（数据已成功写入下游 socket）。
    #[inline]
    pub fn on_consumed(&self, n: usize) {
        self.consumed.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// 检查是否需要通告信用；需要则返回**已消费的绝对偏移（低 32 位）**。
    ///
    /// # 补发时机（省 CPU 的关键）
    ///
    /// 只在**对端剩余信用不足窗口一半**时才通告 —— 否则每收一帧都要计算一次。
    /// 这与 TCP 的窗口更新策略一致：过早通告会产生大量无用小包。
    ///
    /// # 为什么通告的是 `consumed` 绝对值而不是增量
    ///
    /// 增量帧一丢，那份信用就**永久蒸发**（累计超过窗口即死锁）。
    /// 绝对值帧幂等、可自愈：只要有任何一帧到达，状态就被拉回正确值。
    /// 详见模块头部的对比表与实测数据。
    ///
    /// # 为什么目标上限是 `consumed + window`
    ///
    /// 这个公式保证「对端始终有 `window` 字节可用信用」：
    ///
    /// ```text
    /// 对端可使用量 = (consumed + window) - received
    ///              = window - (received - consumed)
    ///              = window - 缓冲中未消费的数据
    /// ```
    ///
    /// 只要缓冲未满，对端就还有空间 —— **这正是「窗口 ≥ BDP」要求的意义**。
    ///
    /// # 为什么基于 `consumed` 而不是 `received`
    ///
    /// 若按 `received` 补发，等价于「窗口无限」—— 接收方缓冲会无限制增长。
    /// 按 `consumed` 补发才能真正把「接收方消费能力」反馈给发送方。
    ///
    /// # 返回 `None` 的含义
    ///
    /// 「本次无需通告」，**不是**「永远不用通告」。
    /// 调用方应在两种时机调用：消费完成后（快速路径）、
    /// 以及周期定时器（抗丢包兜底，见 [`Self::current_offset`]）。
    pub fn poll_grant(&self) -> Option<u32> {
        let received = self.received.load(Ordering::Relaxed);
        let consumed = self.consumed.load(Ordering::Relaxed);
        let adv = self.advertised.load(Ordering::Relaxed);

        // 节流：对端剩余信用 > 窗口一半 → 不必通告
        // 注意 `adv` 存的是「已通告的 consumed 偏移」，上限要加回窗口
        let adv_limit = adv.saturating_add(self.window);
        if adv_limit.saturating_sub(received) * 2 > self.window {
            return None;
        }

        // `consumed` 没有前进 → 重复通告无意义（浪费带宽）
        if consumed <= adv {
            return None;
        }

        self.advertised.store(consumed, Ordering::Relaxed);
        self.granted_total
            .fetch_add(consumed - adv, Ordering::Relaxed);
        Some(consumed as u32)
    }

    /// 当前已消费偏移（低 32 位），供**周期定时重发**使用。
    ///
    /// # 为什么必须有定时重发
    ///
    /// [`Self::poll_grant`] 只在「收到数据后调用 `recv()`」时被触发。
    /// 一旦丢了 `Data` 帧导致对端阻塞，本端就收不到新数据 → `recv()`
    /// 不再被调用 → **永远没有补发机会**，形成死锁。
    ///
    /// 定时器每隔几十毫秒无条件重发一次当前偏移，能让丢失的信用自愈。
    /// 代价是每条流每周期一个 4 字节帧（256 流 × 20 Hz ≈ 20 KB/s），
    /// 可接受 —— 且只在有活跃流时才发。
    #[inline]
    pub fn current_offset(&self) -> u32 {
        self.consumed.load(Ordering::Relaxed) as u32
    }

    /// 已接收字节数（诊断用）。
    #[inline]
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// 已消费字节数（诊断用）。
    #[inline]
    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }

    /// 当前缓冲中未消费的字节数（诊断用）。
    #[inline]
    pub fn buffered(&self) -> u64 {
        self.received().saturating_sub(self.consumed())
    }

    /// 已通告的绝对上限（诊断用）。
    ///
    /// 注意它存的是「已通告的 `consumed` 偏移」，
    /// 实际授信上限 = `advertised() + window()`。
    #[inline]
    pub fn advertised(&self) -> u64 {
        self.advertised.load(Ordering::Relaxed)
    }

    /// 累计补发的信用量（诊断用）。
    #[inline]
    pub fn granted_total(&self) -> u64 {
        self.granted_total.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for FlowCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowCounters")
            .field("window", &self.window)
            .field("received", &self.received())
            .field("consumed", &self.consumed())
            .field("buffered", &self.buffered())
            .field("advertised", &self.advertised())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Window 帧编解码 ----

    #[test]
    fn 信用编码解码往返() {
        for v in [0u32, 1, 1024, 1 << 20, u32::MAX] {
            let mut buf = Vec::new();
            encode_window_credit(v, &mut buf);
            assert_eq!(buf.len(), WINDOW_PAYLOAD_LEN);
            assert_eq!(decode_window_credit(&buf).unwrap(), v);
        }
    }

    #[test]
    fn 信用编码是大端() {
        let mut buf = Vec::new();
        encode_window_credit(0x0102_0304, &mut buf);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04], "必须是网络字节序");
    }

    #[test]
    fn 长度错误的载荷被拒绝() {
        assert_eq!(
            decode_window_credit(&[]).unwrap_err(),
            FlowError::BadPayloadLen(0)
        );
        assert_eq!(
            decode_window_credit(&[0, 0, 1]).unwrap_err(),
            FlowError::BadPayloadLen(3)
        );
        assert_eq!(
            decode_window_credit(&[0, 0, 0, 0, 0]).unwrap_err(),
            FlowError::BadPayloadLen(5)
        );
    }

    // ---- 发送侧记账 ----

    #[test]
    fn 发送侧初始信用等于窗口() {
        let c = SendCredit::new(1000);
        assert_eq!(c.available(), 1000);
        assert!(!c.is_blocked());
    }

    #[test]
    fn 消费减少可用信用() {
        let mut c = SendCredit::new(1000);
        c.try_consume(300).unwrap();
        assert_eq!(c.available(), 700);
        c.try_consume(700).unwrap();
        assert_eq!(c.available(), 0);
        assert!(c.is_blocked());
    }

    #[test]
    fn 超额消费被拒绝() {
        let mut c = SendCredit::new(100);
        let e = c.try_consume(101).unwrap_err();
        assert_eq!(
            e,
            FlowError::CreditExceeded {
                requested: 101,
                available: 100
            }
        );
        // 失败后状态不变（不能"部分消费"）
        assert_eq!(c.available(), 100);
    }

    #[test]
    fn 收到授信后恢复可发送() {
        let mut c = SendCredit::new(100);
        c.try_consume(100).unwrap();
        assert!(c.is_blocked());

        // 对端已消费到 50 → 可用 = 50 + 100(窗口) - 100(已发) = 50
        c.set_acked(50);
        assert_eq!(c.available(), 50);
        assert!(!c.is_blocked());
        c.try_consume(50).unwrap();
        assert!(c.is_blocked());
    }

    // ---- 绝对偏移语义的核心性质（相对增量语义的最大优势）----

    #[test]
    fn 绝对偏移重复到达幂等() {
        let mut c = SendCredit::new(1000);
        c.try_consume(1000).unwrap();

        // 同一个偏移收 10 次，结果与收 1 次相同
        for _ in 0..10 {
            c.set_acked(500);
        }
        assert_eq!(c.acked(), 500);
        assert_eq!(c.available(), 500);
    }

    #[test]
    fn 绝对偏移丢帧后可自愈() {
        // 这是整个改造的目的：中间丢多少帧都没关系，
        // 只要有一个新帧到达就能对正
        let mut c = SendCredit::new(1000);
        c.try_consume(1000).unwrap();

        // 模拟丢了 1..=9 号帧，只收到 10 号（偏移 1000）
        c.set_acked(1000);
        assert_eq!(c.acked(), 1000, "丢 9 帧后应直接跳到正确值");
        assert_eq!(c.available(), 1000, "信用应完整恢复");
    }

    #[test]
    fn 乱序旧帧被忽略() {
        let mut c = SendCredit::new(1000);
        // 先收到新值 800
        c.set_acked(800);
        assert_eq!(c.acked(), 800);

        // 再收到延迟到达的旧值 300（差值 300-800 wrapping 是巨大的数 ≥ 2³¹）
        c.set_acked(300);
        assert_eq!(c.acked(), 800, "旧帧必须被忽略，不能回退信用");
    }

    #[test]
    fn 绝对偏移处理32位回绕() {
        // 传输超过 4 GB 时偏移会回绕。这是 QUIC `MAX_DATA` 的标准处理：
        // 用 `wrapping_sub` 算差值，差值 < 2³¹ 即视为前进。
        let mut c = SendCredit::new(1000);

        // 分步逼近回绕点（每步都 < 2³¹，与真实传输一致）
        c.set_acked(0x5000_0000);
        assert_eq!(c.acked(), 0x5000_0000u64);
        c.set_acked(0xA000_0000);
        assert_eq!(c.acked(), 0xA000_0000u64);
        c.set_acked(0xF000_0000);
        assert_eq!(c.acked(), 0xF000_0000u64);

        // 跨过 4 GB 回绕：0xF000_0000 → 0x2000_0000（前进 0x3000_0000）
        c.set_acked(0x2000_0000);
        assert_eq!(
            c.acked(),
            0xF000_0000u64 + 0x3000_0000,
            "回绕后应正确累计（约 4.5 GB），而不是回退"
        );
    }

    #[test]
    fn 过大跳跃被视为异常并忽略() {
        // 无法区分「前进 4 GB」与「回退」，按 QUIC 规则一律当旧包忽略。
        // 这在实际传输里不会发生（两次信用帧之间不可能前进 2 GB）。
        let mut c = SendCredit::new(1000);
        c.set_acked(0xFFFF_FF00);
        assert_eq!(c.acked(), 0, "从 0 跳到接近 4 GB 应被忽略，防止误判回退");
    }

    #[test]
    fn 信用恢复能回收丢失数据占用的额度() {
        // 无 ARQ 阶段的临时兜底：Data 帧真丢了，接收方 consumed 永远少那一块。
        // recover() 强行把 acked 提到 used，避免信用永久枯竭。
        let mut c = SendCredit::new(1000);
        c.try_consume(1000).unwrap();
        assert!(c.is_blocked());

        // 对端只确认了 600（剩下 400 的帧丢了）
        c.set_acked(600);
        assert_eq!(c.available(), 600);
        c.try_consume(600).unwrap();
        // 已发 1600，但对端只确认 600 → 欠 1000 字节的额度
        assert!(c.is_blocked());
        assert_eq!(c.used(), 1600);
        assert_eq!(c.acked(), 600);

        let recovered = c.recover();
        assert_eq!(recovered, 1000, "应回收 used-acked = 1600-600 字节的额度");
        assert_eq!(c.acked(), 1600, "recover 后 acked 追上 used");
        assert_eq!(c.available(), 1000, "完整窗口恢复");
        // 再调一次应为 0（已无欠账）
        assert_eq!(c.recover(), 0, "无欠账时应返回 0");
    }

    // ---- 接收侧窗口 ----

    #[test]
    fn 初始通告偏移为零() {
        // `advertised` 存的是「已通告的 consumed 偏移」，不是绝对上限。
        // 开流时双方约定「对端已有 window 字节信用」（隐式初始窗口），
        // 所以初始通告偏移是 0，授信上限 = 0 + window。
        let f = FlowCounters::new(1024);
        assert_eq!(f.advertised(), 0);
        assert_eq!(f.received(), 0);
        assert_eq!(f.consumed(), 0);
    }

    #[test]
    fn 少量接收不触发补发() {
        let f = FlowCounters::new(1024);
        // 收到 500（剩余 1024-500=524 > 512 = 窗口一半）→ 不补
        f.on_received(500);
        assert!(f.poll_grant().is_none(), "剩余信用充足时不应补发");
    }

    #[test]
    fn 接收过半后触发补发() {
        let f = FlowCounters::new(1024);
        f.on_received(600); // 剩余 424 < 512
        f.on_consumed(600);

        // 返回的是 consumed 的**绝对偏移**（不是增量）
        let offset = f.poll_grant().expect("应补发信用");
        assert_eq!(offset, 600);
        assert_eq!(f.advertised(), 600, "已通告偏移 = consumed");
        // 授信上限 = advertised + window = 1624
        assert_eq!(f.advertised() + f.window(), 1624);
        assert_eq!(f.granted_total(), 600);
    }

    #[test]
    fn 未消费时不补发以免缓冲无限增长() {
        let f = FlowCounters::new(1024);
        f.on_received(1024); // 全部收到但应用还没消费
                             // 剩余 0 < 512，会进入计算，但 consumed(0) 未前进
                             // → advertised 已等于 consumed → 无新偏移可通告
        assert!(
            f.poll_grant().is_none(),
            "应用未消费时绝不能补发，否则接收缓冲会无限增长"
        );
        assert_eq!(f.buffered(), 1024);
    }

    #[test]
    fn 消费后立即恢复信用() {
        let f = FlowCounters::new(1024);
        f.on_received(1024);
        assert!(f.poll_grant().is_none());

        f.on_consumed(1024); // 应用读完了
        let offset = f.poll_grant().expect("消费后应补发");
        assert_eq!(offset, 1024);
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn 连续消费持续补发() {
        let f = FlowCounters::new(1000);
        let mut total_granted = 0u64;

        // 模拟 10 轮「收 500 消费 500」
        for _ in 0..10 {
            f.on_received(500);
            f.on_consumed(500);
            if f.poll_grant().is_some() {
                total_granted += 500;
            }
        }

        assert_eq!(f.received(), 5000);
        assert_eq!(f.consumed(), 5000);
        assert_eq!(f.buffered(), 0);
        // 通告偏移必须跟上 consumed
        assert_eq!(
            f.advertised(),
            f.consumed(),
            "最后一次补发后已通告偏移应等于已消费量"
        );
        assert!(total_granted > 0);
    }

    #[test]
    fn 当前偏移就是已消费量() {
        // 供周期定时重发使用：定时器无条件取当前偏移发出，
        // 使丢失的信用能自愈。
        let f = FlowCounters::new(1024);
        assert_eq!(f.current_offset(), 0);
        f.on_received(700);
        f.on_consumed(700);
        assert_eq!(f.current_offset(), 700);
        f.on_consumed(300);
        assert_eq!(f.current_offset(), 1000);
    }

    #[test]
    fn 缓冲量计算正确() {
        let f = FlowCounters::new(1000);
        f.on_received(300);
        f.on_consumed(100);
        assert_eq!(f.buffered(), 200);
    }

    #[test]
    fn 未消费超过已接收不会下溢() {
        // 防御性场景：若 ARQ 层的消费记账早于接收记账（实现 bug），
        // 不能让 buffered() panic
        let f = FlowCounters::new(1000);
        f.on_consumed(100);
        assert_eq!(f.buffered(), 0, "should saturate at 0");
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // 专门验证常量关系，必须断言常量
    fn 窗口比例遵循hy2的2比5() {
        // Hysteria 2 官方推荐：「keep the ratio of stream receive window to
        // connection receive window at 2:5」。我们直接采用。
        assert_eq!(
            DEFAULT_CONN_WINDOW * 2,
            DEFAULT_STREAM_WINDOW * 5,
            "连接窗口:单流窗口应为 5:2（hy2 官方推荐比例）"
        );
        // 连接级必须严格大于流级，否则第二条流就会卡死
        assert!(DEFAULT_CONN_WINDOW > DEFAULT_STREAM_WINDOW);
        // 连接级至少容纳 2 条满载流（浏览器至少并发 6，但这里只做硬性下限检查）
        assert!(DEFAULT_CONN_WINDOW >= DEFAULT_STREAM_WINDOW * 2);
    }

    /// 完整的「信用耗尽 → 对端补发 → 恢复发送」流程。
    #[test]
    fn 端到端信用流转() {
        // 接收方窗口 1000
        let recv = FlowCounters::new(1000);
        // 发送方初始信用 = 1000（开流约定）
        let mut send = SendCredit::new(1000);

        // 发送方连发 1000 字节 → 信用耗尽
        assert!(send.try_consume(1000).is_ok());
        assert!(send.is_blocked());

        // 接收方收到并消费
        recv.on_received(1000);
        recv.on_consumed(1000);

        // 接收方补发（绝对偏移）
        let offset = recv.poll_grant().expect("应补发");
        // 发送方收到 Window 帧
        send.set_acked(offset);
        assert!(!send.is_blocked());
        assert_eq!(send.available(), 1000, "完整窗口恢复");
    }

    /// 丢包环境下的关键行为：即使补发帧丢了大半，隧道也能继续。
    ///
    /// 这是把增量语义改成绝对偏移的**直接原因**：实测
    /// `FLOWTCP_DROP_WINDOW=10` 时增量语义在 3.3 MB / 16 MB 处永久停滞，
    /// 而绝对偏移在同样丢包率下能跑完。
    ///
    /// 测试还覆盖了**兜底机制**：当信用真的耗尽且通告丢失时，
    /// 发送方可主动索取当前偏移（对应 `FlowCounters::current_offset`，
    /// 现实中由周期定时器驱动 —— 即 QUIC 的 PTO 探测思路）。
    #[test]
    fn 丢包环境下绝对偏移能自愈() {
        let recv = FlowCounters::new(1000);
        let mut send = SendCredit::new(1000);
        let mut lost = 0;
        let mut recovered_by_probe = 0;

        for round in 0..20 {
            let chunk = 500usize;

            // 信用不足 → 主动探测（模拟 PTO 定时器）
            if send.try_consume(chunk).is_err() {
                send.set_acked(recv.current_offset());
                recovered_by_probe += 1;
                send.try_consume(chunk)
                    .expect("探测后应有信用（窗口 1000 ≥ 单次 500）");
            }

            recv.on_received(chunk);
            recv.on_consumed(chunk);

            // 只有每 3 帧送达 1 帧（模拟 66% 的 Window 帧丢失）
            if let Some(offset) = recv.poll_grant() {
                if round % 3 == 0 {
                    send.set_acked(offset);
                } else {
                    lost += 1;
                }
            }
        }

        assert!(lost > 0, "测试应确实模拟了丢失，实际掉 {lost} 帧");
        assert!(
            recovered_by_probe > 0,
            "过大丢包率下应触发探测兜底，实际 {recovered_by_probe} 次"
        );
        assert_eq!(recv.consumed(), 20 * 500, "20 轮全部完成，未死锁");
        // ★ 关键性质：丢包误差**不累积**，始终只差「最后一次成功送达之后」的量。
        // 这正是不死锁的数学原因 —— 对比增量语义，那里每丢一帧就永久漏掉一块，
        // 累计超过窗口大小便彻底停摆。
        let drift = recv.consumed() - send.acked();
        assert!(
            drift <= 1000,
            "误差应局限于一次成功通告的范围（窗口大小）内，实际差 {drift}"
        );
    }
}
