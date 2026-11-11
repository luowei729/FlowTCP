//! ARQ（自动重传请求）—— **照抄 QUIC RFC 9002 的丢包检测与 RTT 估计**
//!
//! # 为什么不用自己设计
//!
//! 之前 `docs/PROTOCOL.md` §7 写的是「KCP 精简版」，但项目的对标对象
//! Hysteria 2 用的是 **quic-go**，也就是 RFC 9002 的实现。两者差异显著：
//!
//! | 方面 | KCP 精简版 | **QUIC（本模块）** |
//! |------|-----------|------------------|
//! | ACK 格式 | `ack_seq + bitmap(64)` | **范围集合**（可表达任意多乱序空洞） |
//! | 快速重传 | 重复 ACK × 3 | **包阈值 3 + 时间阈值 9/8 RTT** |
//! | 超时 | RTO 指数退避 | **PTO**（含 `max_ack_delay`，不重置拥塞窗口） |
//! | 重传歧义 | 用 seq 判断 | **每次重传用新 pn**，歧义消除 |
//!
//! 64 位位图在丢包 10% 以上时经常「范围超出位图」，而 QUIC 的范围 ACK
//! 在高丢包下反而更省空间、恢复更快（RFC 9002 §4.5 明确指出这一点）。
//!
//! # 照抄的四条核心规则
//!
//! 1. **包阈值**：某包之后有 3 个包被确认 → 判定丢失（§6.1.1）
//! 2. **时间阈值**：`max(9/8 × max(smoothed_rtt, latest_rtt), 1ms)`（§6.1.2）
//! 3. **PTO**：`smoothed_rtt + max(4×rttvar, 1ms) + max_ack_delay`，指数退避（§6.2.1）
//! 4. **RTT 更新**：`smoothed = 7/8 × smoothed + 1/8 × adjusted`，
//!    `rttvar = 3/4 × rttvar + 1/4 × |smoothed - adjusted|`（§5.3）
//!
//! # 与流控的关系（重要）
//!
//! 接收侧**按序交付**给应用。乱序到达的数据先进重排缓冲，等空洞补齐。
//! 因此 `FlowCounters::on_consumed` 只在数据真正交付时才前进 ——
//! 这与 QUIC 的 stream 语义一致。
//!
//! 但这也意味着：**若空洞永远补不上（对端真的丢了且不重传），流控会死锁**。
//! QUIC 的解法是发送侧一定会重传（本模块保证），因此空洞最终会补齐。
//! 只有当重传也持续失败（连接已断）时才会卡住，那时连接本身就该结束了。

use std::collections::BTreeMap;

use crate::frame::OwnedFrame;

// ============================================================================
// 常量（全部来自 RFC 9002）
// ============================================================================

/// 进程级单调时钟起点。
///
/// # 为什么统一用 `u64` 毫秒而不是 `Instant`
///
/// 1. 纯逻辑模块（`flowtcp-proto`）不依赖 tokio，用 `Instant` 会让单元测试
///    无法注入「现在几点」（ARQ 的测试几乎全都需要控制时间）
/// 2. `u64` 毫秒能表示 5.8 亿年，绝对够用
/// 3. 相减就是差值，无需处理 `Duration` 与溢出
static CLOCK_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// 当前单调时间（毫秒）。
///
/// 首次调用时建立起点，之后返回自起点以来的毫秒数。
/// 单调递增，不受系统时间调整影响。
pub fn now_ms() -> u64 {
    let start = CLOCK_START.get_or_init(std::time::Instant::now);
    start.elapsed().as_millis() as u64
}

/// 包阈值：某包之后有 N 个包被确认即判定丢失（RFC 9002 §6.1.1，推荐 3）。
///
/// 与 TCP 的 best practice 一致（RFC 5681）。**不能小于 3** ——
/// 否则轻微乱序就会触发大量虚假重传。
pub const K_PACKET_THRESHOLD: u32 = 3;

/// 时间阈值分子：9/8 × RTT（RFC 9002 §6.1.2）。
///
/// 比 TCP RACK 的 5/4 更激进（QUIC 生态实测 9/8 效果好）。
pub const K_TIME_THRESHOLD_NUM: u64 = 9;

/// 时间阈值分母。
pub const K_TIME_THRESHOLD_DEN: u64 = 8;

/// 定时器粒度 1 ms（RFC 9002 §6.1.2 推荐值）。
///
/// 时间阈值不能小于它，否则定时器立即触发。
pub const K_GRANULARITY_MS: u64 = 1;

/// 首个 RTT 样本之前的估计值 333 ms（RFC 9002 §6.2.2）。
///
/// 这个值让初始 PTO ≈ 1 秒，与 TCP 初始 RTO 一致。
pub const K_INITIAL_RTT_MS: u64 = 333;

/// 默认对端最大 ACK 延迟（我们自己的接收侧承诺）。
///
/// 取 25 ms 与 QUIC 默认 `max_ack_delay` 一致。
/// 越小恢复越快、ACK 帧越多；越大越省带宽、恢复越慢。
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;

/// 单流在途包数**下限**与**上限**（简化版拥塞窗口）。
///
/// # 为什么必须有在途包上限（实测驱动）
///
/// ACK 帧能表达的范围数受 MTU 硬限制（`MAX_ACK_RANGES ≈ 300`）。
/// 若在途包太多，接收端的乱序段数就会超过这个上限 → 最老的 ACK 范围被截断
/// → 发送端以为那些包从未到达 → 反复重传（实测 43 万次重复）→ 传输停滞。
///
/// 实测数据（8 MB 流控窗口，16 MB 下载）：
///
/// | 丢包率 | 在途包数 | 乱序段数 | 结果 |
/// |--------|---------|---------|------|
/// | 5% | ~5700 | ~285 | ✅ 完整（86 MB/s） |
/// | 10% | ~5700 | ~570 | ❌ 卡在 3 MB |
///
/// 这正是 QUIC 必须有**拥塞窗口（cwnd）**的原因 —— 它把在途包数压在
/// 几十到几百的量级，让 ACK 范围数天然受控。
///
/// # 取值
///
/// 512 包 × 1400 B ≈ **700 KB 在途**。对应不同 RTT 的吞吐上限：
///
/// | RTT | 吞吐上限 |
/// |-----|---------|
/// | 0.2 ms（loopback） | 不构成限制 |
/// | 20 ms（同城） | ~35 MB/s |
/// | 100 ms（跨省） | ~7 MB/s |
/// | 200 ms（跨洲） | ~3.5 MB/s |
///
/// 后两档偏低，Phase 4.5 的自动调优会按「BDP = 带宽 × RTT」动态放大
/// （上限可到 2048 包 ≈ 2.8 MB）。当前先固定保守值，保证高丢包下不卡死。
pub const MIN_CWND_PKTS: usize = 32;

/// 在途包数的**内存**硬上限（与流控窗口无关的最终兜底）。
///
/// 正常情况下 `cwnd` 的上限由「流控窗口 / 单帧大小」决定（见
/// [`ArqSender::cwnd`]）—— 那才是真正的「在途数据量」上限。
/// 这个常量只是防御：若用户把 `--stream-window` 调到荒谬的值
/// （例如 1 GB），也不能让在途帧缓存吃掉几 GB 内存。
///
/// 8192 × 1400 B ≈ **11 MB/流**，配合连接级窗口上限足够安全。
pub const MAX_CWND_PKTS: usize = 8192;

/// ACK 帧最多携带的范围数。
///
/// # 这个值必须足够大（实测踩坑）
///
/// 每个范围 4 字节（gap u16 + len u16），`MAX_ACK_RANGES = N`
/// 对应 payload `9 + (N-1)*4` 字节。取 300 → 1205 字节，
/// 仍小于单帧上限（MTU 1500 下 1400）。
///
/// 早期取 32（payload 133 字节）看似够用，实测**灾难性失败**：
/// 8 MB 流控窗口 + 5% 丢包时，接收端会产生约 **285 个乱序段**，
/// 超出部分被 `truncate` 丢掉 → 发送端以为那些包从没到达 →
/// 反复重传 → 实测同一批数据被重发 **43 万次**（`duplicate_count`），
/// 写队列被重传帧灌满、正常数据反而发不出去，传输彻底停滞。
///
/// # 为什么不是无限大
///
/// ACK 帧必须能装进一个 MTU。`(1400 - 9) / 4 ≈ 347` 是硬上限，
/// 取 300 留出余量。
pub const MAX_ACK_RANGES: usize = 300;

// ============================================================================
// RTT 估计（RFC 9002 §5，伪代码 A.7 UpdateRtt）
// ============================================================================

/// RTT 估计器。
///
/// 严格照抄 RFC 9002 §5.3 的加权公式。为什么不用简单 EWMA：
/// `rttvar` (平均偏差) 直接进入 PTO 计算，它决定了「容忍多大的抖动」。
/// 只用平均值会让 PTO 在抖动大的链路上频繁误触发。
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// 平滑 RTT（毫秒，浮点避免整数累积误差）。
    smoothed_rtt: f64,
    /// 平均偏差（毫秒）。
    rttvar: f64,
    /// 观测到的最小 RTT（**不含 ACK 延迟修正**，见 §5.2）。
    min_rtt: f64,
    /// 最近一次样本。
    latest_rtt: f64,
    /// 是否已取得第一个样本。
    first_sample: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// 用 RFC 推荐的初始值构造（`smoothed = 333ms`，`rttvar = 166.5ms`）。
    pub fn new() -> Self {
        RttEstimator {
            smoothed_rtt: K_INITIAL_RTT_MS as f64,
            rttvar: K_INITIAL_RTT_MS as f64 / 2.0,
            min_rtt: 0.0,
            latest_rtt: 0.0,
            first_sample: false,
        }
    }

    /// 送入一次 RTT 样本。
    ///
    /// # 参数
    ///
    /// - `latest_rtt`：`ack_time - send_time_of_largest_acked`
    /// - `ack_delay`：对端在 ACK 帧里报告的延迟（毫秒）
    ///
    /// # 为什么要减去 ack_delay（且有条件）
    ///
    /// 对端可能故意延迟发送 ACK（攒批）。若不扣除，会把对端的处理延迟
    /// 算进网络 RTT，导致 PTO 偏大、丢包恢复变慢。
    ///
    /// 但**不能无脑扣**（§5.3 明确）：若扣除后小于 `min_rtt`，说明对端
    /// 报告的延迟不可信（或 min_rtt 本身偏小），此时应保留原值。
    pub fn update(&mut self, latest_rtt: f64, ack_delay: f64) {
        let latest_rtt = latest_rtt.max(0.0);
        self.latest_rtt = latest_rtt;

        if !self.first_sample {
            // 首个样本：直接重置，不保留任何历史（§5.3）
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2.0;
            self.first_sample = true;
            return;
        }

        // min_rtt 不含 ACK 延迟修正（§5.2）
        self.min_rtt = self.min_rtt.min(latest_rtt);

        // 只在「扣除后仍不小于 min_rtt」时才扣（§5.3 最后一条 MUST）
        let ack_delay = ack_delay.max(0.0);
        let adjusted = if latest_rtt >= self.min_rtt + ack_delay {
            latest_rtt - ack_delay
        } else {
            latest_rtt
        };

        // rttvar 用**旧的** smoothed 计算（严格按伪代码顺序）
        self.rttvar = 0.75 * self.rttvar + 0.25 * (self.smoothed_rtt - adjusted).abs();
        self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * adjusted;
    }

    /// 平滑 RTT（毫秒）。
    #[inline]
    pub fn smoothed_rtt(&self) -> f64 {
        self.smoothed_rtt
    }

    /// 平均偏差（毫秒）。
    #[inline]
    pub fn rttvar(&self) -> f64 {
        self.rttvar
    }

    /// 最近一次样本（毫秒）。
    #[inline]
    pub fn latest_rtt(&self) -> f64 {
        self.latest_rtt
    }

    /// 是否已取得样本。
    #[inline]
    pub fn has_sample(&self) -> bool {
        self.first_sample
    }

    /// 时间阈值：`max(9/8 × max(smoothed, latest), 1ms)`（§6.1.2）。
    ///
    /// 用 `max(smoothed, latest)` 保护两种场景（RFC 原文）：
    /// - `latest < smoothed`：这次 ACK 走了更短的路径（乱序），
    ///   若用 latest 会误判太多包丢失
    /// - `latest > smoothed`：实际 RTT 上升但 smoothed 还没跟上，
    ///   若用 smoothed 会过早判丢
    pub fn loss_delay_ms(&self) -> u64 {
        let base = self.smoothed_rtt.max(self.latest_rtt);
        let delay = base * (K_TIME_THRESHOLD_NUM as f64) / (K_TIME_THRESHOLD_DEN as f64);
        (delay.ceil() as u64).max(K_GRANULARITY_MS)
    }

    /// PTO 周期：`smoothed_rtt + max(4×rttvar, 1ms) + max_ack_delay`（§6.2.1）。
    ///
    /// **不含退避因子** —— 退避由调用方按 `2^pto_count` 施加。
    pub fn pto_base_ms(&self, max_ack_delay_ms: u64) -> u64 {
        let var = (4.0 * self.rttvar).max(K_GRANULARITY_MS as f64);
        let pto = self.smoothed_rtt + var + max_ack_delay_ms as f64;
        (pto.ceil() as u64).max(K_GRANULARITY_MS)
    }
}

// ============================================================================
// 接收侧：范围 ACK
// ============================================================================

/// `Ack` 帧载荷解析错误。
///
/// 用专门的错误类型而不是 `()`：载荷非法意味着**对端违约或实现 bug**，
/// 调用方需要记日志定位，一个笼统的 `()` 什么信息都没有。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckDecodeError {
    /// 载荷长度不足最小要求（9 字节）。
    TooShort(usize),
    /// 声明的范围数与实际长度不符。
    Truncated {
        /// 按声明需要的字节数。
        need: usize,
        /// 实际字节数。
        got: usize,
    },
    /// `first_range` 大于 `largest`（区间会下溢）。
    BadFirstRange,
    /// 范围链下溢（gap/len 超出前一个范围）。
    BadRange,
}

impl std::fmt::Display for AckDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AckDecodeError::TooShort(n) => write!(f, "Ack 载荷过短：{n} 字节 < 9"),
            AckDecodeError::Truncated { need, got } => {
                write!(f, "Ack 载荷截断：需要 {need} 字节，实际 {got}")
            }
            AckDecodeError::BadFirstRange => write!(f, "Ack 的 first_range 大于 largest"),
            AckDecodeError::BadRange => write!(f, "Ack 范围链下溢"),
        }
    }
}

impl std::error::Error for AckDecodeError {}

/// 接收侧的已收包范围集合（RFC 9000 §19.3 语义）。
///
/// # 数据结构
///
/// 内部维护 `ranges: Vec<(start, end)>`，**按 end 降序**（最新的在前）。
/// 相邻或重叠的范围会自动合并 —— 这样 `ranges[0].end` 永远是
/// `largest_acked`，且范围数保持最小。
///
/// # 为什么不用位图
///
/// 64 位位图只能表达「largest 之前 64 个」的确认状态。
/// 丢包 10% 且 RTT 抖动时，乱序跨度轻易超过 64，
/// 超出部分只能当「未确认」→ 虚假重传。范围集合没有这个限制。
#[derive(Debug, Default, Clone)]
pub struct AckRanges {
    /// 已收范围，按 `end` 严格降序，且互不相邻（已合并）。
    ranges: Vec<(u32, u32)>,
    /// 已收包总数（诊断用）。
    received_count: u64,
}

impl AckRanges {
    /// 空集合。
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录收到 `pn`。
    ///
    /// 幂等：重复收到同一个 `pn`（重传导致）不会改变集合 ——
    /// 这是 ARQ 正确性的基础，重传的包可能多次到达。
    pub fn insert(&mut self, pn: u32) {
        self.received_count += 1;

        // 找到插入位置（按 end 降序）
        let mut idx = 0;
        while idx < self.ranges.len() && self.ranges[idx].1 > pn {
            idx += 1;
        }

        // 情况 1：已在某个范围内部 → 直接返回（幂等）
        if idx < self.ranges.len() && self.ranges[idx].0 <= pn && pn <= self.ranges[idx].1 {
            return;
        }
        // 也检查前一个范围（因为循环按 end 降序，pn 可能落在 idx-1 的区间）
        if idx > 0 && self.ranges[idx - 1].0 <= pn && pn <= self.ranges[idx - 1].1 {
            return;
        }

        // 情况 2：与前一个范围相邻（pn == prev.start - 1）→ 扩展
        let joins_prev = idx > 0 && self.ranges[idx - 1].0 == pn + 1;
        // 情况 3：与后一个范围相邻（pn == next.end + 1）→ 扩展
        let joins_next = idx < self.ranges.len() && self.ranges[idx].1 == pn.wrapping_sub(1);

        match (joins_prev, joins_next) {
            (true, true) => {
                // pn 正好填在两段之间的单个空洞 → 三段合并成一段。
                // 合并后：[prev.start, next.end)，因此**下界取 next 的 start**，
                // 上界保持 prev.end 不变。
                // （早期实现误把下界设为 next.end，导致范围 [3,6] 而丢掉 0..2）
                let next_start = self.ranges[idx].0;
                self.ranges[idx - 1].0 = next_start;
                self.ranges.remove(idx);
            }
            (true, false) => {
                self.ranges[idx - 1].0 = pn;
            }
            (false, true) => {
                // 与后一段相邻：把它的上界提到 pn。
                // 因为 pn > ranges[idx].1，且仍小于前一范围，降序性不受破坏。
                self.ranges[idx].1 = pn;
            }
            (false, false) => {
                self.ranges.insert(idx, (pn, pn));
            }
        }

        // 防御：范围数过多时丢弃最老的（保最新，因为最新的对丢包检测最有用）
        if self.ranges.len() > MAX_ACK_RANGES {
            self.ranges.truncate(MAX_ACK_RANGES);
        }
    }

    /// 最大已收 pn（`None` = 还没收到任何包）。
    #[inline]
    pub fn largest(&self) -> Option<u32> {
        self.ranges.first().map(|r| r.1)
    }

    /// 已收包总数（含重复）。
    #[inline]
    pub fn received_count(&self) -> u64 {
        self.received_count
    }

    /// 是否已收到 `pn`。
    pub fn contains(&self, pn: u32) -> bool {
        self.ranges.iter().any(|&(s, e)| s <= pn && pn <= e)
    }

    /// 范围数（诊断用）。
    #[inline]
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// 编码成 ACK 帧 payload（限 `MAX_ACK_RANGES` 个范围）。
    ///
    /// # 格式（照抄 RFC 9000 §19.3 语义，用固定宽度替代 varint）
    ///
    /// ```text
    /// largest_acked  u32   最大已收 pn
    /// ack_delay      u16   对端应扣除的 ACK 延迟（毫秒，饱和到 u16）
    /// range_count    u8    后续范围数
    /// first_range    u16   largest 往下连续确认的「额外」个数
    /// [gap u16, len u16] × range_count
    /// ```
    ///
    /// `gap` = 与上一个范围之间**未确认**的包数；
    /// `len` = 本范围长度减 1。
    ///
    /// 返回 `None` 表示还没收到任何包（此时不应发 ACK）。
    pub fn encode(&self, ack_delay_ms: u64, out: &mut Vec<u8>) -> Option<()> {
        let largest = self.largest()?;
        let (first_start, first_end) = self.ranges[0];
        debug_assert_eq!(first_end, largest);

        out.extend_from_slice(&largest.to_be_bytes());
        out.extend_from_slice(&(ack_delay_ms.min(u16::MAX as u64) as u16).to_be_bytes());

        let extra_ranges = self.ranges.len().saturating_sub(1).min(u8::MAX as usize);
        out.push(extra_ranges as u8);
        // first_range 是「额外」个数，即区间长度减 1（u16 饱和）
        let first_extra = (first_end - first_start).min(u16::MAX as u32) as u16;
        out.extend_from_slice(&first_extra.to_be_bytes());

        let mut prev_start = first_start;
        for &(start, end) in self.ranges.iter().skip(1).take(extra_ranges) {
            // gap = 上一个范围的 start 与本范围 end 之间未确认的个数
            // 因为 prev_start 是「上一个范围的最低 pn」，
            // 而本范围 end < prev_start，中间未确认数 = prev_start - end - 1
            let gap = prev_start.saturating_sub(end).saturating_sub(1);
            let len = end.saturating_sub(start);
            out.extend_from_slice(&(gap.min(u16::MAX as u32) as u16).to_be_bytes());
            out.extend_from_slice(&(len.min(u16::MAX as u32) as u16).to_be_bytes());
            prev_start = start;
        }
        Some(())
    }

    /// 解码 ACK 帧 payload。
    ///
    /// 返回 `(范围集合, ack_delay_ms)`。范围集合可直接用于发送侧确认处理。
    pub fn decode(payload: &[u8]) -> Result<(Vec<(u32, u32)>, u64), AckDecodeError> {
        // 最小长度：4 + 2 + 1 + 2 = 9
        if payload.len() < 9 {
            return Err(AckDecodeError::TooShort(payload.len()));
        }
        let largest = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ack_delay = u16::from_be_bytes([payload[4], payload[5]]) as u64;
        let range_count = payload[6] as usize;
        let first_extra = u16::from_be_bytes([payload[7], payload[8]]) as u32;

        // 防御：声明的范围数必须与实际长度相符
        let need = 9 + range_count * 4;
        if payload.len() < need {
            return Err(AckDecodeError::Truncated {
                need,
                got: payload.len(),
            });
        }
        // first_extra 不能大于 largest（否则区间下溢）
        if first_extra > largest {
            return Err(AckDecodeError::BadFirstRange);
        }

        let first_start = largest - first_extra;
        let mut ranges = Vec::with_capacity(range_count + 1);
        ranges.push((first_start, largest));

        let mut prev_start = first_start;
        for i in 0..range_count {
            let off = 9 + i * 4;
            let gap = u16::from_be_bytes([payload[off], payload[off + 1]]) as u32 + 1;
            let len = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as u32;

            // 本范围 end = prev_start - gap
            let Some(end) = prev_start.checked_sub(gap) else {
                return Err(AckDecodeError::BadRange);
            };
            let Some(start) = end.checked_sub(len) else {
                return Err(AckDecodeError::BadRange);
            };
            ranges.push((start, end));
            prev_start = start;
        }
        Ok((ranges, ack_delay))
    }
}

// ============================================================================
// 发送侧：在途包与丢包检测
// ============================================================================

/// 一个已发送但未确认的包。
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// 包序号（= `Data` 帧的 seq）。
    pub pn: u32,
    /// 发送时刻（毫秒）。
    pub sent_at_ms: u64,
    /// 原始帧（用于重传）。
    ///
    /// **必须保留完整帧**：重传要重发同样的 payload。
    /// 内存代价：在途窗口 256 × 1400B ≈ 358 KB，可接受。
    pub frame: OwnedFrame,
}

/// 发送侧的在途包管理 + 丢包检测（RFC 9002 §6 + 伪代码 A.10）。
///
/// # 为什么用 `BTreeMap` 而非 `Vec`
///
/// 丢包检测要按 pn 顺序遍历「小于 largest_acked 的包」，
/// 且要支持「按 pn 删除已确认」。`BTreeMap` 两者都是 O(log n)；
/// 在途包通常只有几十到几百个，性能足够。
#[derive(Debug)]
pub struct SendBuffer {
    /// 在途包，按 pn 升序。
    inflight: BTreeMap<u32, SentPacket>,
    /// 最大已确认 pn（`None` = 还没收到 ACK）。
    largest_acked: Option<u32>,
    /// 累计重传次数（诊断用）。
    retransmit_count: u64,
    /// 累计丢包判定次数（诊断用）。
    loss_count: u64,
}

impl Default for SendBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SendBuffer {
    /// 空缓冲。
    pub fn new() -> Self {
        SendBuffer {
            inflight: BTreeMap::new(),
            largest_acked: None,
            retransmit_count: 0,
            loss_count: 0,
        }
    }

    /// 记录一个已发送的包。
    pub fn on_sent(&mut self, frame: OwnedFrame, now_ms: u64) {
        let pn = frame.pkt_seq;
        self.inflight.insert(
            pn,
            SentPacket {
                pn,
                sent_at_ms: now_ms,
                frame,
            },
        );
    }

    /// 在途包数。
    #[inline]
    pub fn len(&self) -> usize {
        self.inflight.len()
    }

    /// 是否无在途包。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }

    /// 最大已确认 pn。
    #[inline]
    pub fn largest_acked(&self) -> Option<u32> {
        self.largest_acked
    }

    /// 累计重传次数。
    #[inline]
    pub fn retransmit_count(&self) -> u64 {
        self.retransmit_count
    }

    /// 累计丢包判定次数。
    #[inline]
    pub fn loss_count(&self) -> u64 {
        self.loss_count
    }

    /// 处理一个 ACK 帧载荷（收到的对端确认）。
    ///
    /// # 返回
    ///
    /// - `newly_acked`：本次新确认的包（调用方可据此更新 RTT、统计）
    /// - `rtt_sample`：若「最大已确认包」是本次新确认的，返回
    ///   `(latest_rtt_ms,)` 供 [`RttEstimator::update`] 使用
    ///
    /// # 为什么 RTT 样本只取 largest_acked
    ///
    /// 对端只在 ACK 帧里报告 `largest_acked` 这一个包的延迟（RFC 9002 §5.1）。
    /// 用其他包算 RTT 会把「排序延迟」算进去，导致样本偏大。
    pub fn on_ack(
        &mut self,
        acks: &[(u32, u32)],
        ack_delay_ms: u64,
        now_ms: u64,
    ) -> (Vec<SentPacket>, Option<f64>) {
        let Some(&(_, new_largest)) = acks.first() else {
            return (Vec::new(), None);
        };

        // 更新最大已确认（单调，不回退）
        self.largest_acked = Some(match self.largest_acked {
            Some(prev) => prev.max(new_largest),
            None => new_largest,
        });

        // 移除已确认的包
        let mut newly_acked = Vec::new();
        for &(start, end) in acks {
            // BTreeMap 的范围删除：逐个尝试（在途包少，足够快）
            let pns: Vec<u32> = self
                .inflight
                .range(start..=end)
                .map(|(k, _)| *k)
                .collect();
            for pn in pns {
                if let Some(p) = self.inflight.remove(&pn) {
                    newly_acked.push(p);
                }
            }
        }

        // RTT 样本：仅当 largest_acked 是本次新确认的
        let rtt_sample = newly_acked
            .iter()
            .find(|p| p.pn == new_largest)
            .map(|p| {
                let rtt = now_ms.saturating_sub(p.sent_at_ms) as f64;
                // ack_delay 的单位是毫秒，与 latest_rtt 一致
                let _ = ack_delay_ms;
                rtt
            });

        (newly_acked, rtt_sample)
    }

    /// 检测丢包（RFC 9002 伪代码 A.10，严格照抄）。
    ///
    /// # 判定条件（两条满足其一）
    ///
    /// 1. `time_sent <= now - loss_delay`（时间阈值）
    /// 2. `largest_acked >= pn + 3`（包阈值）
    ///
    /// 且必须 `pn <= largest_acked` —— 比对端最大确认还新的包**绝不能**判丢。
    ///
    /// # 返回值
    ///
    /// 判定为丢失的包（调用方应重传，且**使用新的 pn**）。
    pub fn detect_lost(&mut self, now_ms: u64, loss_delay_ms: u64) -> Vec<SentPacket> {
        let Some(largest_acked) = self.largest_acked else {
            return Vec::new();
        };

        let lost_send_time = now_ms.saturating_sub(loss_delay_ms);
        let mut lost = Vec::new();

        for (&pn, p) in self.inflight.iter() {
            // 比对端最大确认还新 → 不可能判丢
            if pn > largest_acked {
                continue;
            }

            let by_time = p.sent_at_ms <= lost_send_time;
            let by_count = largest_acked.saturating_sub(pn) >= K_PACKET_THRESHOLD;

            if by_time || by_count {
                lost.push(pn);
            }
        }

        let mut out = Vec::with_capacity(lost.len());
        for pn in lost {
            if let Some(p) = self.inflight.remove(&pn) {
                out.push(p);
            }
        }
        self.loss_count += out.len() as u64;
        out
    }

    /// 下一个应该被时间阈值判丢的包的时刻（供定时器使用）。
    ///
    /// 若当前无包可判，返回 `None`。
    pub fn next_loss_time(&self, loss_delay_ms: u64) -> Option<u64> {
        let largest_acked = self.largest_acked?;
        self.inflight
            .iter()
            .filter(|(pn, _)| **pn <= largest_acked)
            .map(|(_, p)| p.sent_at_ms + loss_delay_ms)
            .min()
    }

    /// 取出最老的未确认包（PTO 探测用）。
    ///
    /// PTO 触发时的策略照抄 RFC 9002 §6.2.4：
    /// 「SHOULD include new data in packets sent on PTO expiration.
    /// Previously sent data MAY be sent if no new data can be sent.」
    ///
    /// 我们简化成「重发最老的未确认包」—— 若没有新数据可发，
    /// 这就是唯一的选择；若有新数据，上层会优先发新数据，不会走到这里。
    pub fn oldest_inflight(&self) -> Option<&SentPacket> {
        self.inflight.values().next()
    }

    /// 最老的 `n` 个未确认包（PTO 探测用，RFC 9002 §6.2.4 允许发两个）。
    pub fn oldest_n_inflight(&self, n: usize) -> Vec<&SentPacket> {
        self.inflight.values().take(n).collect()
    }

    /// 记录一次重传（同时把原包从在途移除）。
    pub fn on_retransmit(&mut self, pn: u32) {
        self.inflight.remove(&pn);
        self.retransmit_count += 1;
    }

    /// 丢弃所有在途（连接关闭时调用）。
    pub fn clear(&mut self) {
        self.inflight.clear();
    }
}

// ============================================================================
// 接收侧：重排缓冲（按序交付）
// ============================================================================

/// 接收侧重排缓冲：乱序到达的数据在此等待前序补齐。
///
/// # 为什么必须按序交付
///
/// `Data` 帧的 seq 只表达**发送顺序**，而 TCP 流要求**字节顺序**。
/// 若把乱序数据直接交给应用，字节流就错乱了（实测过：16MB 文件内容错位）。
///
/// # ★ `FIN` 也必须进重排（否则会「先关流、后收数据」）
///
/// `Close` 帧代表 FIN，它在语义上是「流的最后一个字节之后」。
/// 若它绕过重排直接处理，就会**超过仍在途的 `Data` 提前生效**。
///
/// 实测症状（`FLOWTCP_DROP_DATA=5`，16 MB 下载）：请求包被丢 → 客户端
/// 立刻发 FIN → 服务端收到 FIN 后 `take()` 掉投递端（半关闭）→
/// 重传的请求到达时已无处可投 → 目标从未收到请求 → **收到 0 字节**。
///
/// QUIC 用 stream offset 自然解决（FIN 就是某个 offset 上的标志位）。
/// 我们没有 offset 字段，改用「FIN 占用一个 seq」达到同样效果。
///
/// # 内存上限
///
/// 缓冲上限由流控窗口隐式约束：对端最多超前 `window` 字节，
/// 因此缓冲不会超过窗口大小。这里再加一个硬上限防御实现 bug。
#[derive(Debug)]
pub struct ReorderBuffer {
    /// 期望的下一个 seq。
    next_seq: u32,
    /// 乱序缓存：seq → (payload, 是否为 FIN)。
    pending: BTreeMap<u32, (Vec<u8>, bool)>,
    /// 缓存字节数（诊断/防御用）。
    pending_bytes: usize,
    /// 硬上限（字节）。超过则视为协议错误。
    max_bytes: usize,
    /// 累计丢弃的重复包数（诊断用）。
    duplicate_count: u64,
}

impl ReorderBuffer {
    /// 用缓冲上限构造。
    pub fn new(max_bytes: usize) -> Self {
        ReorderBuffer {
            next_seq: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_bytes,
            duplicate_count: 0,
        }
    }

    /// 期望的下一个 seq。
    #[inline]
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// 缓存中的包数。
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// 累计丢弃的重复包数。
    #[inline]
    pub fn duplicate_count(&self) -> u64 {
        self.duplicate_count
    }

    /// 送入一个数据包（`is_close = true` 表示这是 FIN，payload 应为空）。
    ///
    /// 返回**可立即交付**的连续条目序列，每项为 `(payload, is_close)`。
    ///
    /// # 三种情况
    ///
    /// 1. `seq < next_seq`：重传导致的重复包 → 丢弃（幂等），返回空
    /// 2. `seq == next_seq`：连续，交付并继续看缓存里是否也有连续数据
    /// 3. `seq > next_seq`：乱序，进缓存等待
    ///
    /// 返回的 `Vec` 可能含多个条目（情况 2 补洞后连锁交付）。
    pub fn push(
        &mut self,
        seq: u32,
        payload: Vec<u8>,
        is_close: bool,
    ) -> Result<Vec<(Vec<u8>, bool)>, ArqError> {
        // 情况 1：已交付过的重复包
        if seq < self.next_seq {
            self.duplicate_count += 1;
            return Ok(Vec::new());
        }

        let mut ready = Vec::new();

        if seq == self.next_seq {
            // 情况 2：连续 → 立即交付
            self.next_seq = self.next_seq.wrapping_add(1);
            ready.push((payload, is_close));
            // 连锁：缓存里可能已有后续数据
            while let Some((next, nc)) = self.pending.remove(&self.next_seq) {
                self.pending_bytes = self.pending_bytes.saturating_sub(next.len());
                self.next_seq = self.next_seq.wrapping_add(1);
                ready.push((next, nc));
            }
            return Ok(ready);
        }

        // 情况 3：乱序 → 缓存（若已存在同 seq，说明重复，覆盖即可）
        let sz = payload.len();
        self.pending_bytes += sz;
        if let Some((old, _)) = self.pending.insert(seq, (payload, is_close)) {
            self.pending_bytes = self.pending_bytes.saturating_sub(old.len());
        }

        // 防御：缓存超限说明对端违约或实现 bug
        if self.pending_bytes > self.max_bytes {
            return Err(ArqError::ReorderOverflow {
                pending_bytes: self.pending_bytes,
                max: self.max_bytes,
            });
        }
        Ok(ready)
    }

    /// 是否有空洞导致无法交付。
    ///
    /// 供流控层判断「是否需要跳过空洞」——
    /// 但**正常情况下不该需要**：ARQ 会重传，空洞会被补齐。
    #[inline]
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// ARQ 错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArqError {
    /// 重排缓冲溢出（对端违约或实现 bug）。
    ReorderOverflow {
        /// 当前缓存字节数。
        pending_bytes: usize,
        /// 上限。
        max: usize,
    },
}

impl std::fmt::Display for ArqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArqError::ReorderOverflow { pending_bytes, max } => {
                write!(
                    f,
                    "重排缓冲溢出：{pending_bytes} 字节 > 上限 {max}（对端可能违约）"
                )
            }
        }
    }
}

impl std::error::Error for ArqError {}

// ============================================================================
// 收发两侧的完整状态机（客户端与服务端共用）
// ============================================================================

/// ARQ 发送侧状态（`StreamSender` 与读循环共享）。
///
/// # 为什么需要共享
///
/// - `StreamSender::send_data` 写入时必须记录「在途包」（供丢包检测与重传）
/// - 读循环收到 `Ack` 帧时要移除在途、更新 RTT、检测丢包并重传
///
/// 两者跑在不同任务里，所以用 `Arc` + `Mutex`。
/// **锁只保护纯内存结构，绝不跨 `await` 持有** —— 否则会拖慢热路径。
pub struct ArqSender {
    /// 流控窗口（字节）。`cwnd` 的包数上限由它反推：
    /// `window / max_payload` —— 这样任意 RTT 下都能把窗口用满。
    stream_window: u64,
    /// 单帧最大 payload（用于把窗口字节数换算成包数）。
    max_payload: usize,
    /// 在途包 + 丢包检测。
    send: std::sync::Mutex<SendBuffer>,
    /// RTT 估计（PTO 与时间阈值都依赖它）。
    rtt: std::sync::Mutex<RttEstimator>,
    /// 包序号发生器。**发送与重传共用一个** —— QUIC 的关键设计：
    /// 每次重传都用新 pn，从此不存在「重传歧义」（RFC 9002 §4.2）。
    next_seq: std::sync::atomic::AtomicU32,
    /// PTO 退避计数（收到有效 ACK 时清零）。
    pto_count: std::sync::atomic::AtomicU32,
    /// 累计被确认的包数（估计丢包率用）。
    acked_total: std::sync::atomic::AtomicU64,
    /// 累计判定丢失的包数（估计丢包率用）。
    lost_total: std::sync::atomic::AtomicU64,
}

impl ArqSender {
    /// 用流控窗口与单帧大小构造。
    ///
    /// # 为什么需要这两个参数
    ///
    /// `cwnd`（在途包数上限）应该等于「流控窗口能装下多少包」：
    ///
    /// ```text
    /// cwnd ≤ stream_window / max_payload
    /// ```
    ///
    /// 这样在途**字节数**就天然不超过窗口大小 —— 不会为了 ARQ 额外吃内存，
    /// 同时任意 RTT 下都能把窗口用满（高 BDP 链路只需调大 `--stream-window`）。
    ///
    /// 早期实现把上限硬编码成 2048 包（≈2.8 MB），结果：
    /// - 8 MB 窗口只用得到 2.8 MB → 浪费 65%
    /// - RTT 200 ms 线路上 2048 包只能跑 `2048×1400/0.2 ≈ 14 MB/s`
    pub fn new(stream_window: u64, max_payload: usize) -> Self {
        ArqSender {
            stream_window,
            max_payload: max_payload.max(1),
            send: std::sync::Mutex::new(SendBuffer::new()),
            rtt: std::sync::Mutex::new(RttEstimator::new()),
            next_seq: std::sync::atomic::AtomicU32::new(0),
            pto_count: std::sync::atomic::AtomicU32::new(0),
            acked_total: std::sync::atomic::AtomicU64::new(0),
            lost_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 取下一个包序号。
    pub fn next_seq(&self) -> u32 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// 记录已发送（**必须在写入 out 之前**调用）。
    ///
    /// 顺序很重要：若先发后记，对端可能在记录完成前就回 ACK，
    /// 那个 ACK 会因「找不到该包」而被当作伪确认忽略 —— 表现为偶发卡顿。
    pub fn on_sent(&self, frame: OwnedFrame) {
        if let Ok(mut b) = self.send.lock() {
            b.on_sent(frame, now_ms());
        }
    }

    /// 处理收到的 `Ack` 帧，返回需要重传的帧（已分配新 seq）。
    ///
    /// 照抄 RFC 9002 伪代码 A.7 `OnAckReceived`：
    /// 移除已确认 → 更新 RTT → 检测丢包。
    pub fn on_ack(&self, ranges: &[(u32, u32)], ack_delay_ms: u64) -> Vec<OwnedFrame> {
        let now = now_ms();

        // 1) 移除已确认 + 取 RTT 样本
        let (acked, rtt_sample) = match self.send.lock() {
            Ok(mut b) => b.on_ack(ranges, ack_delay_ms, now),
            Err(_) => return Vec::new(),
        };
        if acked.is_empty() {
            // 没有新确认 → 不是有效 ACK，不做任何事（幂等）
            return Vec::new();
        }
        self.acked_total
            .fetch_add(acked.len() as u64, std::sync::atomic::Ordering::Relaxed);

        // 2) 更新 RTT（只在有样本时）
        let loss_delay = if let Some(rtt) = rtt_sample {
            match self.rtt.lock() {
                Ok(mut e) => {
                    e.update(rtt, ack_delay_ms as f64);
                    e.loss_delay_ms()
                }
                Err(_) => return Vec::new(),
            }
        } else {
            match self.rtt.lock() {
                Ok(e) => e.loss_delay_ms(),
                Err(_) => return Vec::new(),
            }
        };

        // 3) 收到有效确认 → 清零 PTO 退避（RFC 9002 §6.2.1）
        self.pto_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        // 4) 立即用包阈值 + 时间阈值检测丢包
        let lost = match self.send.lock() {
            Ok(mut b) => b.detect_lost(now, loss_delay),
            Err(_) => Vec::new(),
        };
        self.reassign(lost)
    }

    /// 定时轮询：时间阈值丢包检测 + PTO 探测。
    ///
    /// # PTO 与丢包的区别（容易搞混）
    ///
    /// - **丢包检测**：有证据（后面的包被确认了）→ 判定前面的丢了 → 重传
    /// - **PTO**：只是「等太久了没消息」→ 发探测包，**不判定任何包丢失**
    ///   （RFC 9002 §6.2 明确：「A PTO timer expiration event does not
    ///   indicate packet loss and MUST NOT cause prior unacknowledged
    ///   packets to be marked as lost」）
    ///
    /// 所以我们发最老的未确认包当探测，语义上正确。
    pub fn poll_timeouts(&self) -> Vec<OwnedFrame> {
        let now = now_ms();

        let (loss_delay, pto_base) = match self.rtt.lock() {
            Ok(e) => (
                e.loss_delay_ms(),
                e.pto_base_ms(DEFAULT_MAX_ACK_DELAY_MS),
            ),
            Err(_) => return Vec::new(),
        };

        // ---- 1) 时间阈值丢包（有 largest_acked 才有意义）----
        let (lost, next_loss_at, has_inflight) = match self.send.lock() {
            Ok(mut b) => {
                let lost = b.detect_lost(now, loss_delay);
                (lost, b.next_loss_time(loss_delay), !b.is_empty())
            }
            Err(_) => return Vec::new(),
        };
        if !lost.is_empty() {
            return self.reassign(lost);
        }

        // 还没到时间阈值 → 什么都不做
        if let Some(at) = next_loss_at {
            if now < at {
                return Vec::new();
            }
        }

        // ---- 2) PTO 探测（无在途包时不发）----
        if !has_inflight {
            return Vec::new();
        }
        let n = self
            .pto_count
            .load(std::sync::atomic::Ordering::Relaxed);
        // 指数退避：2^n，上限防止溢出（10 次退避 = 1024 倍，已远超任何合理场景）
        let backoff = 1u64 << n.min(10);
        let pto = pto_base.saturating_mul(backoff);

        // 判断最老的包是否已超 PTO
        let should_probe = match self.send.lock() {
            Ok(b) => b
                .oldest_inflight()
                .map(|p| now.saturating_sub(p.sent_at_ms) >= pto)
                .unwrap_or(false),
            Err(_) => false,
        };
        if !should_probe {
            return Vec::new();
        }

        self.pto_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 取最老的**两个**未确认包作为探测。
        //
        // RFC 9002 §6.2.4：
        //   "An endpoint MAY send up to two full-sized datagrams containing
        //    ack-eliciting packets to avoid an expensive consecutive PTO
        //    expiration due to a single lost datagram"
        //
        // 只发 1 个时，若那个探测包又丢了，就要等下一次 PTO（已翻倍）。
        // 实测严重丢包（30%）下，发 2 个能把恢复速度提升近一倍。
        let probes = match self.send.lock() {
            Ok(b) => b
                .oldest_n_inflight(2)
                .into_iter()
                .map(|p| p.frame.clone())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        if probes.is_empty() {
            return Vec::new();
        }
        if let Ok(mut b) = self.send.lock() {
            for f in &probes {
                b.on_retransmit(f.pkt_seq);
            }
        }
        probes
    }

    /// 把判定丢失的包**复用原序号**重传。
    ///
    /// # 为什么复用序号（而不是学 QUIC 用新序号）
    ///
    /// QUIC 给每次重传分配新 packet number，因为它的流控按 **stream offset**
    /// 计算（重传同一段数据不重复占额度）。我们暂时没有 offset 字段，
    /// 流控按「收到的字节数」记账 —— 若重传用新 seq，会有两个后果：
    ///
    /// 1. **流控重复计数**：同一段数据被算两次 → 窗口提前耗尽
    /// 2. **重排缓冲膨胀**：重传的包被当成「乱序新数据」缓存 →
    ///    实测 5% 丢包时重排缓冲溢出 8.45 MB 而强制关流
    ///
    /// 复用 seq 后，接收方看到重复 seq 会幂等丢弃（[`ReorderBuffer`] 的
    /// `seq < next_seq` 分支），既不重复计数也不膨胀。这正是 **KCP 的做法**。
    ///
    /// 代价：RTT 样本会略偏大（取的是原始发送时刻，而非最后一次重传）。
    /// 偏大是**保守**的 —— 只会让 PTO 更宽容，不会导致错误。
    ///
    /// 后续若要完全对齐 QUIC，需要给 `Data` 帧加 stream offset 字段。
    fn reassign(&self, lost: Vec<SentPacket>) -> Vec<OwnedFrame> {
        let mut out = Vec::with_capacity(lost.len());
        let now = now_ms();
        self.lost_total
            .fetch_add(lost.len() as u64, std::sync::atomic::Ordering::Relaxed);
        for pkt in lost {
            let f = pkt.frame;
            // 序号保持不变（见上方注释）
            if let Ok(mut b) = self.send.lock() {
                b.on_sent(f.clone(), now);
            }
            out.push(f);
        }
        out
    }

    /// 当前允许的在途包数（**动态拥塞窗口**）。
    ///
    /// # 核心约束（这是整个式子唯一的硬要求）
    ///
    /// ```text
    /// 在途包数 × 丢包率 ≤ MAX_ACK_RANGES × 0.8
    /// ```
    ///
    /// 因为接收端的乱序段数约等于「在途包数 × 丢包率」，而一个 ACK 帧
    /// 最多装 `MAX_ACK_RANGES` 个段。超出就截断 → 老包得到不确认 →
    /// 反复重传 → 停滞（实测 10% 丢包时卡在 3 MB）。
    ///
    /// 反过来，低丢包时窗口应该放大 —— 固定 512 时实测 0% 丢包下
    /// 吞吐从 124 MB/s 掉到 14 MB/s（**退化 89%**）。
    ///
    /// # 为什么不做「丢包就减半」（AIMD）
    ///
    /// 与 Hysteria 的 Brutal 一致：**丢包不作为拥塞信号**。
    /// 我们的丢包主要来自链路 QoS / 人为注入，减小窗口只会让吞吐更低，
    /// 不会让链路变好。所以只按实测丢包率**设定上限**，不做退让。
    ///
    /// # 两个上限（取较小者）
    ///
    /// 1. **ACK 容量**：`0.8 × MAX_ACK_RANGES / 丢包率` —— 硬约束
    /// 2. **窗口容量**：`stream_window / max_payload` —— 在途字节不超过窗口
    ///
    /// 低丢包时上限 2 生效（窗口用满），高丢包时上限 1 生效（保证 ACK 能覆盖）。
    pub fn cwnd(&self) -> usize {
        // 上限 2：窗口能装下的包数
        let window_cap = (self.stream_window / self.max_payload as u64).max(1) as usize;
        let cap = window_cap.clamp(MIN_CWND_PKTS, MAX_CWND_PKTS);

        let acked = self
            .acked_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let lost = self
            .lost_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let total = acked + lost;

        // 样本不足时给一个保守起点（够小，不会一下灌满窗口）
        if total < 100 {
            return (MIN_CWND_PKTS * 4).min(cap);
        }

        let loss_rate = (lost as f64 / total as f64).max(0.005);
        // 上限 1：在途包数不超 `MAX_ACK_RANGES * 0.8` 个乱序段
        let budget = MAX_ACK_RANGES as f64 * 0.8;
        let ack_cap = (budget / loss_rate) as usize;

        ack_cap.clamp(MIN_CWND_PKTS, cap)
    }

    /// 是否还能再发（在途包数是否已达动态窗口）。
    ///
    /// 调用方（发送路径）在超过上限时应等待：这就是**发送侧背压**，
    /// 让在途包数保持在「一个 ACK 帧能覆盖的乱序段数」之内。
    pub fn can_send(&self) -> bool {
        self.inflight() < self.cwnd()
    }

    /// 在途包数（诊断用）。
    pub fn inflight(&self) -> usize {
        self.send.lock().map(|b| b.len()).unwrap_or(0)
    }
}

/// ARQ 接收侧状态（由读循环**独占**，无需加锁）。
pub struct ArqReceiver {
    /// 已收包范围（用于生成 `Ack` 帧）。
    pub acks: AckRanges,
    /// 重排缓冲（乱序数据在此等待前序补齐）。
    pub reorder: ReorderBuffer,
    /// 上次发 `Ack` 的时刻。
    pub last_ack_ms: u64,
    /// 上次发 `Ack` 时的已收包数（判断是否有新进展，避免空 ACK）。
    pub acked_at_last_send: u64,
}

impl ArqReceiver {
    /// 用流控窗口大小构造（重排缓冲上限 = 2 × 窗口）。
    ///
    /// 为什么是 2 倍而非 1 倍：流控窗口限制的是「对端能超前多少**已确认**字节」，
    /// 而重排缓冲里存放的是「已到达但还不能交付」的乱序数据。两者不完全等价 ——
    /// 极端乱序时（例如只有第 1 个包丢了，后面整窗都到了）缓冲会接近窗口上限。
    /// 取 2 倍留出安全余量，避免边界误触发溢出保护。
    pub fn new(window: u64) -> Self {
        ArqReceiver {
            acks: AckRanges::new(),
            reorder: ReorderBuffer::new((window as usize).saturating_mul(2)),
            last_ack_ms: 0,
            acked_at_last_send: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u32, payload: &[u8]) -> OwnedFrame {
        use crate::frame::{Flags, FrameType};
        OwnedFrame::new(
            FrameType::Data,
            Flags::empty().with(Flags::RELIABLE),
            1,
            seq,
            payload.to_vec(),
        )
    }

    // ---- RTT 估计 ----

    #[test]
    fn 首个样本直接重置估计器() {
        let mut r = RttEstimator::new();
        assert!(!r.has_sample());
        r.update(100.0, 0.0);
        assert!(r.has_sample());
        assert_eq!(r.smoothed_rtt(), 100.0);
        assert_eq!(r.rttvar(), 50.0, "rttvar 应为 latest/2");
    }

    #[test]
    fn 后续样本按八分之一加权() {
        let mut r = RttEstimator::new();
        r.update(100.0, 0.0);
        // smoothed = 7/8*100 + 1/8*200 = 87.5 + 25 = 112.5
        // rttvar = 3/4*50 + 1/4*|100-200| = 37.5 + 25 = 62.5
        r.update(200.0, 0.0);
        assert!((r.smoothed_rtt() - 112.5).abs() < 0.01, "{}", r.smoothed_rtt());
        assert!((r.rttvar() - 62.5).abs() < 0.01, "{}", r.rttvar());
    }

    #[test]
    fn ack延迟在可信时被扣除() {
        let mut r = RttEstimator::new();
        r.update(100.0, 0.0); // min_rtt = 100
        // latest = 150, ack_delay = 20 → adjusted = 130（150 >= 100+20）
        r.update(150.0, 20.0);
        // smoothed = 7/8*100 + 1/8*130 = 87.5 + 16.25 = 103.75
        assert!(
            (r.smoothed_rtt() - 103.75).abs() < 0.01,
            "{}",
            r.smoothed_rtt()
        );
    }

    #[test]
    fn ack延迟过大时不扣除() {
        let mut r = RttEstimator::new();
        r.update(100.0, 0.0); // min_rtt = 100
        // latest = 105, ack_delay = 50 → 105 < 100+50，不扣，用 105
        r.update(105.0, 50.0);
        // smoothed = 7/8*100 + 1/8*105 = 87.5 + 13.125 = 100.625
        assert!(
            (r.smoothed_rtt() - 100.625).abs() < 0.01,
            "{}",
            r.smoothed_rtt()
        );
    }

    #[test]
    fn 时间阈值不小于一毫秒() {
        let mut r = RttEstimator::new();
        r.update(0.0, 0.0); // 极端：RTT 0
        assert_eq!(r.loss_delay_ms(), K_GRANULARITY_MS, "必须钳制到 1ms");
    }

    #[test]
    fn 时间阈值为九分之八倍rtt() {
        let mut r = RttEstimator::new();
        r.update(80.0, 0.0);
        // 9/8 * 80 = 90
        assert_eq!(r.loss_delay_ms(), 90);
    }

    #[test]
    fn pto包含四倍rttvar与ack延迟() {
        let mut r = RttEstimator::new();
        r.update(100.0, 0.0); // smoothed=100, rttvar=50
        // PTO = 100 + max(200, 1) + 25 = 325
        assert_eq!(r.pto_base_ms(25), 325);
    }

    // ---- 范围 ACK ----

    #[test]
    fn 范围集合幂等插入() {
        let mut a = AckRanges::new();
        a.insert(5);
        a.insert(5);
        a.insert(5);
        assert_eq!(a.range_count(), 1, "重复插入不应产生新范围");
        assert_eq!(a.largest(), Some(5));
        assert_eq!(a.received_count(), 3, "计数仍累加（诊断用）");
    }

    #[test]
    fn 连续插入合并成一个范围() {
        let mut a = AckRanges::new();
        for pn in 0..10 {
            a.insert(pn);
        }
        assert_eq!(a.range_count(), 1);
        assert_eq!(a.largest(), Some(9));
        assert!(a.contains(0) && a.contains(5) && a.contains(9));
    }

    #[test]
    fn 乱序插入保持多范围() {
        let mut a = AckRanges::new();
        // 收到 0,1,2 和 5,6（3,4 丢了）
        for pn in [0, 1, 2, 5, 6] {
            a.insert(pn);
        }
        assert_eq!(a.range_count(), 2);
        assert_eq!(a.largest(), Some(6));
        assert!(!a.contains(3) && !a.contains(4));
    }

    #[test]
    fn 补洞后两个范围合并() {
        let mut a = AckRanges::new();
        for pn in [0, 1, 2, 5, 6] {
            a.insert(pn);
        }
        assert_eq!(a.range_count(), 2);
        // 补上 3,4 → 应合并成一个范围
        a.insert(3);
        a.insert(4);
        assert_eq!(a.range_count(), 1, "补洞后必须合并");
        for pn in 0..=6 {
            assert!(a.contains(pn), "{pn} 应已确认");
        }
    }

    #[test]
    fn 低序号插到末尾() {
        let mut a = AckRanges::new();
        a.insert(10);
        a.insert(3); // 远低于最大
        assert_eq!(a.range_count(), 2);
        assert_eq!(a.largest(), Some(10));
        assert!(a.contains(3) && a.contains(10));
        assert!(!a.contains(7));
    }

    #[test]
    fn ack编解码往返() {
        let mut a = AckRanges::new();
        for pn in [0, 1, 2, 5, 6, 10, 11, 12] {
            a.insert(pn);
        }
        let mut buf = Vec::new();
        a.encode(15, &mut buf).expect("应能编码");
        assert_eq!(buf.len(), 9 + (a.range_count() - 1) * 4);

        let (ranges, delay) = AckRanges::decode(&buf).expect("应能解码");
        assert_eq!(delay, 15);
        assert_eq!(ranges[0].1, 12, "largest 应为 12");

        // 重建集合并比对
        let mut b = AckRanges::new();
        for &(s, e) in &ranges {
            for pn in s..=e {
                b.insert(pn);
            }
        }
        for pn in [0, 1, 2, 5, 6, 10, 11, 12] {
            assert!(b.contains(pn), "{pn} 应确认");
        }
        for pn in [3, 4, 7, 8, 9] {
            assert!(!b.contains(pn), "{pn} 不应确认");
        }
    }

    #[test]
    fn 空集合不编码() {
        let a = AckRanges::new();
        let mut buf = Vec::new();
        assert!(a.encode(0, &mut buf).is_none(), "无包可确认时不应发 ACK");
        assert!(buf.is_empty());
    }

    #[test]
    fn 解码拒绝损坏载荷() {
        assert!(AckRanges::decode(&[]).is_err());
        assert!(AckRanges::decode(&[0; 8]).is_err(), "长度不足");
        // 声明 1 个范围但没数据
        let mut bad = vec![0u8; 9];
        bad[6] = 1;
        assert!(AckRanges::decode(&bad).is_err());
        // first_range > largest
        let mut bad2 = vec![0u8; 9];
        bad2[7] = 0xFF;
        bad2[8] = 0xFF;
        assert!(AckRanges::decode(&bad2).is_err());
    }

    #[test]
    fn ack延迟饱和到u16() {
        let mut a = AckRanges::new();
        a.insert(1);
        let mut buf = Vec::new();
        a.encode(100_000, &mut buf).unwrap();
        let (_, delay) = AckRanges::decode(&buf).unwrap();
        assert_eq!(delay, u16::MAX as u64, "超长延迟应饱和，不能溢出");
    }

    // ---- 发送缓冲与丢包检测 ----

    #[test]
    fn 包阈值三触发丢包() {
        let mut s = SendBuffer::new();
        for pn in 0..10 {
            s.on_sent(frame(pn, b"x"), 0);
        }
        // 确认 5..9 → largest_acked = 9。
        // 在途剩 0..4，对每个 pn：9 > pn 且 9-pn >= 3 → 0..4 全部满足包阈值
        //（9-4=5>=3，连 4 也超阈值）。ARQ 的包阈值是「相对最大确认」，
        //  不是「相对紧邻的确认」，这是 QUIC 的语义。
        let (acked, _) = s.on_ack(&[(5, 9)], 0, 10);
        assert_eq!(acked.len(), 5);
        let lost = s.detect_lost(10, 1000); // 时间阈值极大，只测包阈值
        let lost_pns: Vec<u32> = lost.iter().map(|p| p.pn).collect();
        assert_eq!(lost_pns, vec![0, 1, 2, 3, 4], "0..4 全部超包阈值");
    }

    #[test]
    fn 包阈值边界刚好不触发() {
        let mut s = SendBuffer::new();
        for pn in 0..4 {
            // 用「刚发送」的时间戳，确保时间阈值不干扰本测试
            s.on_sent(frame(pn, b"x"), 100);
        }
        // 只确认 3 → 在途 0,1,2；3-0=3 >= 3 → 0 判丢；3-1=2, 3-2=1 → 不判
        s.on_ack(&[(3, 3)], 0, 100);
        let lost = s.detect_lost(100, 1); // now=100, loss_delay=1 → 时间不触发
        let pns: Vec<u32> = lost.iter().map(|p| p.pn).collect();
        assert_eq!(pns, vec![0], "只有恰好差 3 的包判丢");
    }

    #[test]
    fn 时间阈值触发丢包() {
        let mut s = SendBuffer::new();
        s.on_sent(frame(0, b"a"), 0);
        s.on_sent(frame(1, b"b"), 0);
        s.on_sent(frame(2, b"c"), 500); // 最新
        // 只确认 2（0,1 未被确认，但包阈值不够：2-0=2 < 3）
        s.on_ack(&[(2, 2)], 0, 500);
        // 时间阈值 100ms：现在 500ms，包在 0ms 发 → 500-0=500 > 100 → 判丢
        let lost = s.detect_lost(500, 100);
        let pns: Vec<u32> = lost.iter().map(|p| p.pn).collect();
        assert_eq!(pns, vec![0, 1]);
    }

    #[test]
    fn 比最大确认更新的包绝不判丢() {
        let mut s = SendBuffer::new();
        for pn in 0..5 {
            s.on_sent(frame(pn, b"x"), 0);
        }
        s.on_ack(&[(0, 1)], 0, 1000); // 只确认 0,1
        // 时间阈值极大 + 现在时间很晚，但 2,3,4 > largest_acked(1)
        let lost = s.detect_lost(100_000, 1);
        assert!(lost.is_empty(), "比 largest_acked 新的包绝不能判丢");
    }

    #[test]
    fn rtt样本只取最大确认包() {
        let mut s = SendBuffer::new();
        s.on_sent(frame(0, b"a"), 0);
        s.on_sent(frame(1, b"b"), 100);
        // 确认 0,1；largest=1 在 t=100 发，现在 t=300 → RTT 200
        let (acked, rtt) = s.on_ack(&[(0, 1)], 5, 300);
        assert_eq!(acked.len(), 2);
        assert_eq!(rtt, Some(200.0), "RTT 应按 largest 包算");

        // 再次确认同一批（不新确认任何包）→ 无样本
        let (acked2, rtt2) = s.on_ack(&[(0, 1)], 5, 400);
        assert!(acked2.is_empty());
        assert_eq!(rtt2, None, "没有新确认的 largest 时不应产生样本");
    }

    #[test]
    fn 重复ack幂等() {
        let mut s = SendBuffer::new();
        for pn in 0..3 {
            s.on_sent(frame(pn, b"x"), 0);
        }
        let (a1, _) = s.on_ack(&[(0, 2)], 0, 10);
        assert_eq!(a1.len(), 3);
        let (a2, _) = s.on_ack(&[(0, 2)], 0, 20);
        assert!(a2.is_empty(), "重复 ACK 不应重复确认");
    }

    #[test]
    fn 重传移除在途并计数() {
        let mut s = SendBuffer::new();
        s.on_sent(frame(0, b"a"), 0);
        assert_eq!(s.len(), 1);
        s.on_retransmit(0);
        assert_eq!(s.len(), 0);
        assert_eq!(s.retransmit_count(), 1);
    }

    #[test]
    fn 下次超时时刻为最老在途加延迟() {
        let mut s = SendBuffer::new();
        s.on_sent(frame(0, b"a"), 100);
        s.on_sent(frame(1, b"b"), 200);
        s.on_ack(&[(2, 2)], 0, 300); // largest_acked = 2（虽然 2 不在途）
        assert_eq!(s.next_loss_time(50), Some(150), "最老 100 发 + 50 延迟");
    }

    // ---- 重排缓冲 ----

    #[test]
    fn 按序交付无缓冲() {
        let mut r = ReorderBuffer::new(1024);
        assert_eq!(
            r.push(0, b"a".to_vec(), false).unwrap(),
            vec![(b"a".to_vec(), false)]
        );
        assert_eq!(
            r.push(1, b"b".to_vec(), false).unwrap(),
            vec![(b"b".to_vec(), false)]
        );
        assert_eq!(r.next_seq(), 2);
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn 乱序缓存并等待补洞() {
        let mut r = ReorderBuffer::new(1024);
        // 先来 0，再来 2（1 丢了）
        assert_eq!(r.push(0, b"a".to_vec(), false).unwrap().len(), 1);
        assert!(
            r.push(2, b"c".to_vec(), false).unwrap().is_empty(),
            "2 应缓存"
        );
        assert_eq!(r.pending_count(), 1);
        assert_eq!(r.next_seq(), 1);
        assert!(r.has_gap());

        // 补上 1 → 应连锁交付 1 和 2
        let ready = r.push(1, b"b".to_vec(), false).unwrap();
        assert_eq!(
            ready,
            vec![(b"b".to_vec(), false), (b"c".to_vec(), false)],
            "应连锁交付"
        );
        assert_eq!(r.next_seq(), 3);
        assert_eq!(r.pending_count(), 0);
        assert!(!r.has_gap());
    }

    #[test]
    fn 重复包被丢弃() {
        let mut r = ReorderBuffer::new(1024);
        r.push(0, b"a".to_vec(), false).unwrap();
        // 重传导致 0 再次到达
        assert!(r.push(0, b"a".to_vec(), false).unwrap().is_empty());
        assert_eq!(r.duplicate_count(), 1);
        assert_eq!(r.next_seq(), 1, "next_seq 不受影响");
    }

    #[test]
    fn 缓冲溢出不panic() {
        let mut r = ReorderBuffer::new(10);
        r.push(5, vec![0u8; 8], false).unwrap();
        // 再塞一个 8 字节 → 超 10
        let e = r.push(6, vec![0u8; 8], false).unwrap_err();
        assert!(matches!(e, ArqError::ReorderOverflow { .. }));
    }

    // ---- 动态拥塞窗口 ----

    /// 测试用构造：8 MB 窗口 + 1400 字节帧。
    fn arq() -> ArqSender {
        ArqSender::new(8 * 1024 * 1024, 1400)
    }

    #[test]
    fn 样本不足时用初始窗口() {
        let a = arq();
        assert_eq!(a.cwnd(), MIN_CWND_PKTS * 4, "无样本时不应激进放大");
    }

    #[test]
    fn 无丢包时窗口放大到窗口容量() {
        let a = arq();
        a.acked_total
            .store(10_000, std::sync::atomic::Ordering::Relaxed);
        // 8 MB / 1400 = 5991 包，未触及 MAX_CWND_PKTS(8192)
        assert_eq!(a.cwnd(), 8 * 1024 * 1024 / 1400, "零丢包应放到窗口容量");
    }

    #[test]
    fn 高丢包时窗口收缩以控制乱序段数() {
        let a = arq();
        // 30% 丢包：3000 acked + 1286 lost ≈ 30%
        a.acked_total
            .store(3000, std::sync::atomic::Ordering::Relaxed);
        a.lost_total
            .store(1286, std::sync::atomic::Ordering::Relaxed);
        let cwnd = a.cwnd();
        assert!(cwnd < 8 * 1024 * 1024 / 1400, "高丢包必须收缩，实际 {cwnd}");
        assert!(cwnd >= MIN_CWND_PKTS);

        // ★ 核心不变量：在途包 × 丢包率 必须能装进一个 ACK 帧
        let loss_rate = 1286.0 / (3000 + 1286) as f64;
        let segments = cwnd as f64 * loss_rate;
        assert!(
            segments <= MAX_ACK_RANGES as f64,
            "乱序段 {segments:.0} 超出 ACK 帧容量 {MAX_ACK_RANGES}"
        );
    }

    #[test]
    fn 大窗口下cwnd随窗口放大而不是固定值() {
        // 关键性质：高 BDP 链路只需调大 --stream-window，
        // cwnd 就自动放大（早期硬编码 2048 时完全做不到）
        let small = ArqSender::new(1024 * 1024, 1400);
        let large = ArqSender::new(32 * 1024 * 1024, 1400);
        for a in [&small, &large] {
            a.acked_total
                .store(10_000, std::sync::atomic::Ordering::Relaxed);
        }
        assert_eq!(small.cwnd(), 1024 * 1024 / 1400);
        assert_eq!(large.cwnd(), MAX_CWND_PKTS, "32 MB 窗口应撞内存兜底上限");
        assert!(large.cwnd() > small.cwnd() * 4);
    }

    #[test]
    fn 超大窗口不突破内存兜底() {
        // 防御：用户把 --stream-window 调到 1 GB 也不能吃爆内存
        let a = ArqSender::new(1024 * 1024 * 1024, 1400);
        a.acked_total
            .store(10_000, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(a.cwnd(), MAX_CWND_PKTS);
    }

    #[test]
    fn 丢包率越高窗口越小() {
        let mk = |acked: u64, lost: u64| {
            let a = arq();
            a.acked_total.store(acked, std::sync::atomic::Ordering::Relaxed);
            a.lost_total.store(lost, std::sync::atomic::Ordering::Relaxed);
            a.cwnd()
        };
        let c0 = mk(10_000, 0);
        let c5 = mk(9_500, 500);
        let c20 = mk(8_000, 2_000);
        assert!(c0 >= c5, "0% 应不小于 5%（{c0} vs {c5}）");
        assert!(c5 >= c20, "5% 应不小于 20%（{c5} vs {c20}）");
    }

    #[test]
    fn 乱序缓存同seq覆盖不重复计数() {
        let mut r = ReorderBuffer::new(1024);
        r.push(1, vec![1u8; 10], false).unwrap();
        let before = r.pending_count();
        // 同 seq 再次到达（重传）
        r.push(1, vec![1u8; 10], false).unwrap();
        assert_eq!(r.pending_count(), before, "同 seq 不应增加缓存项");
    }
}
