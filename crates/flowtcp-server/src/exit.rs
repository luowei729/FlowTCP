//! 内层出口：把收到的帧变成真实网络连接
//!
//! # 职责
//!
//! 这是 FlowTCP 服务端的**数据面**。TLS 握手只解决"双方有共享密钥"，
//! 真正干活的是这里：
//!
//! ```text
//! 帧流入 ──→ OpenTcp ──→ TcpStream::connect(目标) ──→ 双向搬运
//!        ├─→ OpenUdp ──→ UdpSocket::bind ───────────→ 双向转发
//!        └─→ Data/Close ──→ 投递到对应流
//! ```
//!
//! # 为什么单一读循环 + 单一写循环
//!
//! 与服务端 TCP 连接只有**一条**字节流，读必须串行（否则字节流解析错乱）。
//! 写也必须串行（否则记录交错）。因此结构是：
//!
//! ```text
//!                 ┌─────────────────────────────┐
//!  读循环 ──→ 分发 │ streams: stream_id → 目标端 │ ←── 各目标端投递
//!                 └─────────────────────────────┘
//!                            │
//!                            ▼ 写队列（mpsc，单消费者）
//!                        写循环 ──→ 记录层加密 ──→ TCP
//! ```
//!
//! 每个流的目标端是独立 tokio 任务，可以自由并发读写自己的 socket。
//!
//! # 流生命周期
//!
//! | 事件 | 服务端动作 |
//! |------|-----------|
//! | 收到 `OpenTcp` | 校验策略 → 连接目标 → 注册 → 起搬运任务 |
//! | 连接失败 | 回 `Close(fin=false)`（即 RST 语义），客户端立刻关闭本地连接 |
//! | 收到 `Data` | 写入目标 socket（背压由目标 socket 的写缓冲自然产生） |
//! | 收到 `Close` | 关闭目标 socket，注销 |
//! | 目标关闭 | 回 `Close(fin=true)` + 注销 |

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flowtcp_proto::arq::{now_ms, AckRanges, ArqReceiver, ArqSender};
use flowtcp_proto::flow::{decode_window_credit, encode_window_credit, FlowCounters, SendCredit};
use flowtcp_proto::frame::{Address, Flags, FrameType, OwnedFrame, FRAME_HEADER_LEN};
use flowtcp_proto::record::{Keys, RecordDecoder, RecordEncoder};
use flowtcp_proto::{SlotTable, MAX_RECORD_PLAINTEXT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::policy::TargetPolicy;

/// 连接目标的超时。
///
/// 取 10 秒：与 `forward.rs` 的 `CONNECT_TIMEOUT` 保持一致。
/// 太长会让"目标黑洞"的连接长期占用流槽位，太短会误杀慢速链路。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 单流最大待写队列长度（帧数）。
///
/// 取 256：约 256 × 1400 ≈ 350KB 的单流缓冲上限。
/// 超过说明目标端消费不过来（或客户端在灌数据），此时应丢弃而非无限堆积 ——
/// 这正是 UDP 语义（宁可丢包也不阻塞其他流）。
/// 不可靠流（UDP）的待发队列长度。
///
/// UDP 用 `try_send` + 丢弃（丢包是 UDP 的正常语义），
/// 队列只是平滑突发，不需要大。
#[allow(dead_code)]
const MAX_STREAM_QUEUE: usize = 256;

/// 可靠流（TCP）的待写队列长度。
///
/// 与 [`MAX_STREAM_QUEUE`] 分开的理由：TCP 用 `send().await` 施加背压，
/// 队列只是「吸收突发」的缓冲，做大一些能显著减少读循环被阻塞的次数。
///
/// 取 2048 帧 × 1400 B ≈ 2.8 MB/流。配合 `max_streams = 256` 最坏 716 MB，
/// 看起来很大，但实际只有在「目标极慢 + 客户端猛灌」时才会吃满；
/// 生产部署可下调 `max_streams` 或后续由信用流控替代。
const MAX_RELIABLE_QUEUE: usize = 2048;

/// 出口错误。
#[derive(Debug, thiserror::Error)]
pub enum ExitError {
    /// 承载层 IO 失败。
    #[error("IO 失败: {0}")]
    Io(#[from] std::io::Error),
    /// 记录层错误（密钥不同步、被篡改等）。
    #[error("记录层错误: {0}")]
    Record(#[from] flowtcp_proto::RecordError),
    /// 帧编解码错误。
    #[error("帧错误: {0}")]
    Frame(#[from] flowtcp_proto::FrameError),
    /// 对端关闭。
    #[error("隧道已关闭")]
    Closed,
    /// 活跃流数超限。
    #[error("活跃流数超限（{0}）")]
    TooManyStreams(u16),
    /// 流控错误（对端违约或实现 bug）。
    #[error("流控错误: {0}")]
    Flow(String),
}

/// 出口配置。
#[derive(Debug, Clone)]
pub struct ExitConfig {
    /// 目标地址访问策略。
    pub policy: TargetPolicy,
    /// 单连接允许的最大并发流数。
    pub max_streams: u16,
    /// 单帧最大 payload（应与客户端一致）。
    pub max_payload: usize,
    /// 连接目标超时。
    pub connect_timeout: Duration,
    /// **单流接收窗口大小**（对齐 Hysteria 2 的 `initStreamReceiveWindow`）。
    ///
    /// 默认 [`flowtcp_proto::DEFAULT_STREAM_WINDOW`]（8 MB）。
    /// 客户端与服务端**必须一致**，否则开流时的隐式初始信用会错位。
    ///
    /// 调大适高 BDP 链路（如跨洲），调小可省内存（如路由器）。
    pub stream_window: u64,
}

impl Default for ExitConfig {
    fn default() -> Self {
        ExitConfig {
            // 默认拒绝内网：忘记配置时应安全而非暴露（secure by default）
            policy: TargetPolicy::DenyPrivate,
            max_streams: 256,
            max_payload: flowtcp_proto::max_payload_for_mtu(1500),
            connect_timeout: CONNECT_TIMEOUT,
            stream_window: flowtcp_proto::flow::DEFAULT_STREAM_WINDOW,
        }
    }
}

/// 出口统计。
#[derive(Debug, Default, Clone, Copy)]
pub struct ExitStats {
    /// 累计打开的流数。
    pub streams_opened: u64,
    /// 上行字节数（客户端 → 目标）。
    pub bytes_up: u64,
    /// 下行字节数（目标 → 客户端）。
    pub bytes_down: u64,
    /// 因策略拒绝的流数。
    pub denied: u64,
    /// 因连接失败而拒绝的流数。
    pub connect_failed: u64,
}

/// 一个流的目标端。
/// 服务端发送侧信用（跨任务共享）。
///
/// 与客户端的 `mux::SendFlow` 同构：`tcp_pump` 消费信用，
/// `read_loop` 收到 `Window` 帧时授信。
pub(crate) struct SendFlow {
    /// 信用记账。
    credit: std::sync::Mutex<SendCredit>,
    /// 信用到账通知。
    granted: tokio::sync::Notify,
}

impl SendFlow {
    fn new(initial: u64) -> Self {
        SendFlow {
            credit: std::sync::Mutex::new(SendCredit::new(initial)),
            granted: tokio::sync::Notify::new(),
        }
    }

    /// 申请 `n` 字节信用，不足则等待（按流背压）。
    ///
    /// `enable()` 必须在检查条件**之前**调用，否则会丢唤醒
    /// （`Notified` 首次 poll 才注册到等待队列）。详见 tokio `Notify` 文档。
    async fn acquire(&self, n: usize) -> Result<(), ExitError> {
        let n64 = n as u64;
        loop {
            let notified = self.granted.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let mut c = self.credit.lock().map_err(|_| ExitError::Closed)?;
                if c.available() >= n64 {
                    c.try_consume(n)
                        .map_err(|e| ExitError::Flow(e.to_string()))?;
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    /// 收到 `Window` 帧：对端已消费到 `offset`（**绝对偏移，不是增量**）。
    ///
    /// # 为什么是绝对偏移
    ///
    /// 增量语义下丢一个 `Window` 帧，那份信用就永久蒸发 —— 实测
    /// `FLOWTCP_DROP_WINDOW=10` 时传输在 3.3 MB / 16 MB 处永久停滞。
    /// 绝对偏移幂等可自愈：后续任何一个幸存的帧都能把状态拉回正确值。
    fn set_acked(&self, offset: u32) {
        if let Ok(mut c) = self.credit.lock() {
            c.set_acked(offset);
        }
        self.granted.notify_waiters();
    }
}

enum Target {
    /// TCP 流。
    Tcp {
        /// 把客户端数据投递给搬运任务。
        ///
        /// # 为什么是 `Option`（半关闭语义）
        ///
        /// 客户端发 `Close` 帧时只意味着「我不再发数据了」，
        /// 但**本端→客户端**方向的转仍可能要传很多数据（典型：HTTP 响应）。
        ///
        /// 所以收到 `Close` 不能直接删表，而是把这里 `take()` 成 `None`：
        /// - drop 掉发送端 → `tcp_pump` 的 `recv()` 返回 `None`
        ///   → 它 shutdown 目标写端，然后继续读目标直到目标也关闭；
        /// - **流本身留在表里**，`send_flow`/`recv_flow` 仍然可寻址
        ///   → 客户端后续补发的 `Window` 帧能正常授信。
        ///
        /// 曾经这里是个普通 `Sender`，`Close` 分支直接 `streams.remove(sid)`，
        /// 结果：`tcp_pump` 还在发数据，但 `Window` 帧因找不到流被全部丢弃
        /// → 发送侧信用永不恢复 → 下行传输**卡死在恰好 256 KB**。
        tx: Option<mpsc::Sender<Vec<u8>>>,
        /// 发送侧信用（本端 → 客户端，`tcp_pump` 消费）。
        send_flow: Arc<SendFlow>,
        /// 接收侧窗口（客户端 → 本端）。
        recv_flow: Arc<FlowCounters>,
        /// ARQ 发送侧（本端 → 客户端）。`tcp_pump` 用它记账，
        /// 读循环用它处理 `Ack` 帧与重传。
        arq_tx: Arc<ArqSender>,
        /// ARQ 接收侧（读循环独占）。
        arq_rx: ArqReceiver,
    },
    /// UDP 会话：直接持有 socket（可共享 send_to）。
    Udp {
        sock: Arc<UdpSocket>,
        default_target: Address,
    },
}

/// 出口主循环。
///
/// `stream` 是 TLS 握手后取回的**裸字节流**（见 [`flowtcp_tls::accept_raw`]）。
/// `tx_keys` 用于发往客户端，`rx_keys` 用于收客户端数据。
pub async fn run<S>(
    stream: S,
    tx_keys: Keys,
    rx_keys: Keys,
    config: ExitConfig,
) -> Result<ExitStats, ExitError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (r, w) = tokio::io::split(stream);

    // 写队列：所有流共享，单消费者保证记录不交错
    let (out_tx, out_rx) = mpsc::channel::<OwnedFrame>(1024);

    let writer_task = tokio::spawn(write_loop(w, RecordEncoder::new(tx_keys), out_rx));
    let stats = read_loop(r, RecordDecoder::new(rx_keys), out_tx, config).await?;

    // 读循环结束后写任务也应收尾（out_tx 已被 drop）
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_task).await;
    Ok(stats)
}

/// 写循环：帧 → 记录层加密 → 字节流。
///
/// 与客户端一样做批量合并：队列里有多个帧时打包进同一条记录，
/// 显著减少 syscall 与大流量下的 CPU 占用。
async fn write_loop<W>(mut w: W, mut enc: RecordEncoder, mut rx: mpsc::Receiver<OwnedFrame>)
where
    W: AsyncWrite + Unpin,
{
    let mut plain = Vec::with_capacity(MAX_RECORD_PLAINTEXT);
    let mut sealed = Vec::with_capacity(MAX_RECORD_PLAINTEXT + 64);

    // 故障注入（仅测试用，未设环境变量时零开销）。
    // 放在写循环而非 `tcp_pump`：这里能同时覆盖 Data 与 Window 两类帧，
    // 而 `tcp_pump` 只看得到 Data。详见 `flowtcp_proto::fault`。
    let fault = flowtcp_proto::fault::config();
    let fault_on = !fault.is_disabled();

    // ★ 批量合并时必须能「留回」一帧。
    //
    // 早期实现用 `while let Ok(next) = rx.try_recv() { if 超限 { break } ... }`：
    // `try_recv()` 已经把帧从队列里取出来了，`break` 之后这一帧就**永久丢失**。
    // 实测症状：16MB 文件只收到 15.4MB，内容错位（丢的不是尾部而是中间）。
    let mut carry: Option<OwnedFrame> = None;

    loop {
        // 优先取上一轮留下的帧，避免为它多等一次调度
        let first = match carry.take() {
            Some(f) => f,
            None => match rx.recv().await {
                Some(f) => f,
                None => break, // 所有发送端已 drop
            },
        };

        // 故障注入：被丢的帧等于「根本没发出去」，
        // 与 FakeTCP 上的丢包完全等价。
        if fault_on && fault.should_drop(first.frame_type) {
            continue;
        }

        plain.clear();
        // 编码失败必须终止（详见下方注释），绝不静默跳过
        if let Err(e) = first.encode(&mut plain) {
            tracing::error!(
                stream_id = first.stream_id,
                frame_type = ?first.frame_type,
                payload_len = first.payload.len(),
                error = %e,
                "帧编码失败（上层未按 max_payload 分片），终止写任务"
            );
            break;
        }

        // 批量塞入后续帧，直到接近记录上限。
        // 超限的那一帧放进 `carry`，**不丢弃**。
        while plain.len() + FRAME_HEADER_LEN <= MAX_RECORD_PLAINTEXT {
            match rx.try_recv() {
                Ok(next) => {
                    if plain.len() + next.encoded_len() > MAX_RECORD_PLAINTEXT {
                        carry = Some(next);
                        break;
                    }
                    // 故障注入（与首帧同样的处理）
                    if fault_on && fault.should_drop(next.frame_type) {
                        continue;
                    }
                    if let Err(e) = next.encode(&mut plain) {
                        tracing::error!(error = %e, "批量帧编码失败，终止写任务");
                        return;
                    }
                }
                Err(_) => break, // 队列已空
            }
        }

        sealed.clear();
        if enc.seal_into(&plain, &mut sealed).is_err() {
            break;
        }
        if w.write_all(&sealed).await.is_err() {
            break;
        }
        if w.flush().await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// 读循环：字节流 → 记录层解密 → 帧分发。
///
/// # ★ 原始字节必须缓冲（与客户端 `FrameReader` 同一个坑）
///
/// 一次 `read` 常常同时拿到好几条记录。若对读到的字节只调用一次
/// `RecordDecoder::open()` 并丢弃其余部分，第 2 条及之后的记录就永久丢失。
///
/// 实测表现：客户端 `OpenTcp` + `Data` 往往在同一个 TCP 段里到达，
/// `OpenTcp` 处理成功、`Data` 静默丢失 → "流打开了但数据传不过去"。
async fn read_loop<R>(
    mut r: R,
    mut dec: RecordDecoder,
    out: mpsc::Sender<OwnedFrame>,
    config: ExitConfig,
) -> Result<ExitStats, ExitError>
where
    R: AsyncRead + Unpin,
{
    // ★ 读循环**独占**流表（无锁）。实测查表 0.7 ns，
    //   而 `Arc<Mutex<HashMap>>` 是 53.5 ns —— 每帧都走这条路，差距显著。
    //
    // 各流的搬运任务跑在独立任务里，无法直接改表，
    // 因此它们的「收尾通知」走 `cleanup` 通道，由本循环统一处理。
    let mut streams: SlotTable<Target> = SlotTable::with_capacity_hint(config.max_streams);
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<u16>(256);
    let mut cleanup_open = true;

    let mut stats = ExitStats::default();

    // 下行字节由各流的搬运任务累加（它们跑在独立任务里，拿不到 &mut stats），
    // 因此用原子量共享，read_loop 结束时汇总。
    let bytes_down = Arc::new(std::sync::atomic::AtomicU64::new(0));

    /// 复用上限：明文堆积过多说明对端在灌不完整的帧（防御性上限）。
    const MAX_PENDING: usize = MAX_RECORD_PLAINTEXT * 8;

    // 未消费的原始字节（密文）与待切帧的明文 —— 与客户端完全对称的结构
    let mut raw: Vec<u8> = Vec::with_capacity(16384);
    let mut pending: Vec<u8> = Vec::with_capacity(MAX_RECORD_PLAINTEXT);
    let mut chunk = vec![0u8; 16384];
    // 周期信用重发的计数器（见步骤 3 的超时分支）
    let mut resend_count = 0u64;
    // ARQ 驱动的节流时间戳（见步骤 2.5）
    let mut last_arq_drive = 0u64;

    loop {
        // ---- 0) 处理搬运任务发来的「流已结束」通知 ----
        // 只在缓冲里没有待处理数据时做，避免打断数据流。
        while cleanup_open && raw.is_empty() && pending.is_empty() {
            match cleanup_rx.try_recv() {
                Ok(id) => {
                    streams.remove(id);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    cleanup_open = false;
                    break;
                }
            }
        }

        // ---- 1) 尽量把 raw 里的完整记录都解出来 ----
        loop {
            if raw.len() < flowtcp_proto::record::RECORD_HEADER_LEN {
                break;
            }
            let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
            if len < 24 {
                return Err(ExitError::Record(flowtcp_proto::RecordError::BadLength(
                    len,
                )));
            }
            let total = flowtcp_proto::record::RECORD_HEADER_LEN + len;
            if raw.len() < total {
                break;
            }
            let (_, plain, used) = dec.open(&raw[..total])?;
            raw.drain(..used);
            if pending.len() + plain.len() > MAX_PENDING {
                return Err(ExitError::Closed);
            }
            pending.extend_from_slice(&plain);
        }

        // ---- 2) 切帧并处理 ----
        loop {
            let (frame, used) = match OwnedFrame::decode(&pending) {
                Ok(v) => v,
                Err(flowtcp_proto::FrameError::Truncated) => break,
                Err(e) => return Err(ExitError::Frame(e)),
            };
            pending.drain(..used);
            handle_frame(
                frame,
                &mut streams,
                &out,
                &config,
                &mut stats,
                &bytes_down,
                &cleanup_tx,
            )
            .await?;
        }

        // ---- 2.5) 处理完一批帧后驱动 ARQ ----
        //
        // ★ 必须在这里也驱动：持续有数据时 `read` 永不超时，
        // 若只在超时分支驱动，`Ack` 将永远发不出去（见 `drive_arq` 注释）。
        //
        // 节流到 5ms：热路径上每帧都遍历所有流太浪费，
        // 而 5ms 相对 RTT 已经足够精细。
        {
            let now = now_ms();
            if now.saturating_sub(last_arq_drive) >= 5 {
                last_arq_drive = now;
                drive_arq(&mut streams, &out, false).await?;
            }
        }

        // ---- 3) 读更多原始字节 ----
        //
        // # 用 timeout 包住 read —— 周期信用重发（对应 QUIC 的 PTO 探测）
        //
        // `Window` 帧用绝对偏移（幂等、可自愈），但**帧本身仍可能丢**。
        // 若只在「消费时发一次」，那个帧丢了就再没人重发，发送侧信用停在旧值。
        // QUIC 的解法是把 `MAX_DATA` 放进重传队列等 ACK 重发；
        // 我们还没 ARQ（Phase 4.6），用周期无条件重发达到同样效果：
        // 4 字节/流/200ms，256 流满载也只有 5 KB/s。
        //
        // **`read` 是 cancel-safe 的**（tokio 文档明确保证：在 read 处被取消
        // 时没有数据被消费），所以超时打断后下一轮继续读同一位置是安全的。
        let read_result =
            tokio::time::timeout(std::time::Duration::from_millis(50), r.read(&mut chunk)).await;
        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                // 超时：没有新数据。每 4 个周期（200ms）强制重发信用帧
                resend_count = resend_count.wrapping_add(1);
                drive_arq(&mut streams, &out, resend_count % 4 == 0).await?;
                continue;
            }
        };
        if n == 0 {
            break; // 对端正常关闭
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    // 对端关闭：注销所有流（搬运任务会在 socket 关闭后自行退出）
    streams.clear();
    stats.bytes_down = bytes_down.load(std::sync::atomic::Ordering::Relaxed);
    Ok(stats)
}

/// 查询某条流是否要求可靠传输（`None` = 流不存在）。
///
/// TCP 流必须可靠（数据不能丢），UDP 流必须不可靠（丢了就丢，这是 UDP 语义）。
/// 与 Hysteria 2 一致：它的 TCP 走 QUIC stream、UDP 走 unreliable datagram。
fn stream_reliable(streams: &SlotTable<Target>, id: u16) -> Option<bool> {
    match streams.get(id) {
        Some(Target::Tcp { .. }) => Some(true),
        Some(Target::Udp { .. }) => Some(false),
        None => None,
    }
}

/// 处理单帧时需要用到的共享上下文。
///
/// 打包成一个结构体而不是逐个传参：`open_tcp`/`open_udp` 本来需要 8 个参数，
/// 极易传错顺序，且每加一个统计项就要改所有签名。
struct FrameCtx<'a> {
    /// 发帧入口（回客户端）。
    out: &'a mpsc::Sender<OwnedFrame>,
    /// 出口配置（策略、超时、上限）。
    config: &'a ExitConfig,
    /// 统计。
    stats: &'a mut ExitStats,
    /// 下行字节计数（各搬运任务共享）。
    bytes_down: Arc<std::sync::atomic::AtomicU64>,
    /// 流结束通知（搬运任务 → 读循环）。
    cleanup: mpsc::Sender<u16>,
}

/// 处理单个帧。
async fn handle_frame(
    mut frame: OwnedFrame,
    streams: &mut SlotTable<Target>,
    out: &mpsc::Sender<OwnedFrame>,
    config: &ExitConfig,
    stats: &mut ExitStats,
    bytes_down: &Arc<std::sync::atomic::AtomicU64>,
    cleanup: &mpsc::Sender<u16>,
) -> Result<(), ExitError> {
    // 打包成上下文，供 open_tcp / open_udp 使用（避免 8 参函数）
    let mut ctx = FrameCtx {
        out,
        config,
        stats,
        bytes_down: Arc::clone(bytes_down),
        cleanup: cleanup.clone(),
    };

    // ---- Window 帧：授信给本流的发送侧，不当作数据 ----
    if frame.frame_type == FrameType::Window {
        let sid = frame.stream_id;
        match decode_window_credit(&frame.payload) {
            Ok(offset) => {
                if let Some(Target::Tcp { send_flow, .. }) = streams.get(sid) {
                    // 绝对偏移：幂等，丢包/乱序/重复都安全
                    send_flow.set_acked(offset);
                    tracing::trace!(stream_id = sid, offset, "收到窗口更新");
                } else {
                    tracing::trace!(stream_id = sid, "收到未知/不可靠流的窗口更新，忽略");
                }
            }
            Err(e) => tracing::warn!(stream_id = sid, error = %e, "窗口帧载荷非法"),
        }
        return Ok(());
    }

    // ---- Ack 帧：ARQ 确认（照抄 RFC 9002 伪代码 A.7）----
    //
    // 处理顺序与客户端完全一致：移除已确认 → 更新 RTT → 检测丢包 → 重传。
    if frame.frame_type == FrameType::Ack {
        let sid = frame.stream_id;
        let Ok((ranges, ack_delay)) = AckRanges::decode(&frame.payload) else {
            tracing::warn!(stream_id = sid, "Ack 帧载荷非法，忽略");
            return Ok(());
        };
        let arq = match streams.get(sid) {
            Some(Target::Tcp { arq_tx, .. }) => Arc::clone(arq_tx),
            _ => {
                tracing::trace!(stream_id = sid, "收到未知/不可靠流的 Ack，忽略");
                return Ok(());
            }
        };
        let retransmit = arq.on_ack(&ranges, ack_delay);
        for mut f in retransmit {
            f.stream_id = sid;
            // 与 `drive_arq` 同理：不让写队列堵住读循环
            match out.try_send(f) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(_) => return Err(ExitError::Closed),
            }
        }
        return Ok(());
    }

    match frame.frame_type {
        FrameType::OpenTcp => {
            let target = match Address::decode(&frame.payload) {
                Ok((a, _)) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "OpenTcp 地址解析失败");
                    let _ = out.send(OwnedFrame::close(frame.stream_id, false)).await;
                    return Ok(());
                }
            };
            open_tcp(frame.stream_id, target, streams, &mut ctx).await;
        }

        FrameType::OpenUdp => {
            let target = match Address::decode(&frame.payload) {
                Ok((a, _)) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "OpenUdp 地址解析失败");
                    let _ = out.send(OwnedFrame::close(frame.stream_id, false)).await;
                    return Ok(());
                }
            };
            open_udp(frame.stream_id, target, streams, &mut ctx).await;
        }

        FrameType::Data => {
            let sid = frame.stream_id;

            // ---- 可靠性一致性校验 ----
            //
            // 可靠性是**流级属性**（由 OpenTcp/OpenUdp 唯一决定），
            // Data 帧上的 `RELIABLE` 只是冗余标记。
            //
            // 为什么必须校验：若实现有 bug 导致某帧漏标（或错标），
            // TCP 流会静默丢一段数据 —— 上层表现为「文件下载损坏」，
            // 几乎无法复现定位。这里宁可断开也不要静默损坏。
            if let Some(expected) = stream_reliable(streams, sid) {
                let actual = frame.flags.has(Flags::RELIABLE);
                if actual != expected {
                    tracing::error!(
                        stream_id = sid,
                        expected,
                        actual,
                        "Data 帧的 RELIABLE 标志与流类型不一致，协议错误"
                    );
                    return Err(ExitError::Closed);
                }
            }

            // 取出目标端（需要 clone 才能释放锁后 await）
            // ---- ARQ：记录确认范围 + 重排（**必须先于投递**）----
            //
            // 可靠流要求**按序交付**：`pkt_seq` 是发送顺序，而 TCP 流要求
            // 字节顺序。乱序直接写目标 socket 会让字节流错乱。
            //
            // 这一段必须用 `get_mut`（重排缓冲可变），且**不能跨 await** ——
            // 所以先算出 `ready` 列表，再去投递。
            let mut arq_tx: Option<Arc<ArqSender>> = None;
            let mut ready: Option<Vec<(Vec<u8>, bool)>> = None;
            if let Some(Target::Tcp {
                arq_rx,
                arq_tx: tx_arq,
                ..
            }) = streams.get_mut(sid)
            {
                arq_tx = Some(Arc::clone(tx_arq));
                arq_rx.acks.insert(frame.pkt_seq);
                let payload = std::mem::take(&mut frame.payload);
                match arq_rx.reorder.push(frame.pkt_seq, payload, false) {
                    Ok(list) => ready = Some(list),
                    Err(e) => {
                        tracing::warn!(stream_id = sid, error = %e, "重排缓冲溢出，关闭流");
                        let _ = out.send(OwnedFrame::close(sid, false)).await;
                        streams.remove(sid);
                        return Ok(());
                    }
                }
            }

            enum Action {
                Tcp {
                    tx: Option<mpsc::Sender<Vec<u8>>>,
                    recv_flow: Arc<FlowCounters>,
                },
                Udp(Arc<UdpSocket>, Option<Address>),
                None,
            }
            // 无锁查表（0.7 ns）
            let action = match streams.get(sid) {
                Some(Target::Tcp {
                    tx,
                    send_flow: _,
                    recv_flow,
                    arq_tx: _,
                    arq_rx: _,
                }) => Action::Tcp {
                    // 半关闭后 `tx` 为 `None`：流还在（供授信寻址），
                    // 但客户端已经不会再发数据，这时收到 Data 只能丢弃。
                    tx: tx.clone(),
                    recv_flow: Arc::clone(recv_flow),
                },
                Some(Target::Udp {
                    sock,
                    default_target,
                }) => {
                    // HAS_ADDR 时 payload 前置了目标，否则用默认目标
                    if frame.flags.has(Flags::HAS_ADDR) {
                        Action::Udp(Arc::clone(sock), None) // None = 从 payload 解析
                    } else {
                        Action::Udp(Arc::clone(sock), Some(default_target.clone()))
                    }
                }
                None => Action::None,
            };

            match action {
                Action::Tcp { tx, recv_flow } => {
                    // 客户端已半关闭（或已注销）：本方向不再接收数据。
                    // 仍然要记账 —— 这些字节实际到达了本端，若不记
                    // `received` 不前进，后续 `poll_grant` 会算错补发量。
                    //
                    // 注意：此时的长度来自重排缓冲（`frame.payload` 已被 take）。
                    let ready_list = ready.take().unwrap_or_default();
                    let total_len: u64 = ready_list.iter().map(|(d, _)| d.len() as u64).sum();
                    recv_flow.on_received(total_len as usize);
                    let Some(tx) = tx else {
                        // 客户端已半关闭：本方向不再接收新数据。
                        // 直接结束本帧处理（后续分支与本帧无关）。
                        tracing::trace!(stream_id = sid, "客户端已半关闭，丢弃入站数据");
                        return Ok(());
                    };

                    //
                    // 曾经这里用的是 `try_send` + 「队列满则丢弃」，理由是
                    // 「阻塞会让一个慢目标拖垮整条隧道」。这个理由对 **UDP** 成立，
                    // 对 **TCP** 是灾难性的 —— TCP 是可靠字节流，丢一个字节
                    // 就等于数据损坏。
                    //
                    // 实测症状：上传 64MB 只到达 29MB（丢掉 38MB，约 57%），
                    // 且客户端毫不知情（`sendall` 全部成功返回）。
                    // 队列只有 256 帧 ≈ 358KB，而 read 循环解密远快于
                    // tcp_pump 逐帧写目标 socket，队列必然溢出。
                    //
                    // 正确做法：
                    // - **可靠流**（TCP）：`send().await` 施加背压。
                    //   代价是慢目标会短暂阻塞读循环（HOL），但这比静默丢数据好得多。
                    //   Phase 4 的信用流控会把它变成「按流窗口限速」，彻底消除 HOL。
                    // - **不可靠流**（UDP）：`try_send` 丢弃是正确的 UDP 语义。
                    // 可靠流可能一次交付多个（补洞后连锁交付）
                    //
                    // ★ FIN 也会从这条路径「连锁交付」出来：它先到达时被缓存，
                    // 随后的数据包补齐了空洞 → 一次 push 就把它带出来了。
                    // 早期这里直接 `continue` 跳过空 payload，结果 FIN 被吞掉、
                    // 流永不半关闭 → 目标 socket 永不收到 EOF →
                    // 实测「上行 256 KB 以后卡死」。
                    let mut saw_fin = false;
                    for (data, is_close) in ready_list {
                        if is_close {
                            saw_fin = true;
                            continue;
                        }
                        let len = data.len() as u64;
                        if tx.send(data).await.is_err() {
                            // 接收端已 drop（流已关闭）→ 正常，静默跳过
                            break;
                        }
                        stats.bytes_up += len;
                    }
                    // 连锁交付里带出了 FIN → 现在执行半关闭
                    if saw_fin {
                        if let Some(Target::Tcp { tx: slot, .. }) = streams.get_mut(sid) {
                            *slot = None;
                            tracing::trace!(stream_id = sid, "连锁交付带出 FIN，半关闭写端");
                        }
                    }
                    // ARQ 发送侧需要定期被驱动（发 Ack / 丢包检测 / PTO），
                    // 由读循环的定时分支统一处理，这里不用做什么。
                    let _ = &arq_tx;
                }
                Action::Udp(sock, default) => {
                    let (dest, data) = match parse_udp_payload(&frame, default) {
                        Some(v) => v,
                        None => return Ok(()),
                    };
                    if let Some(addr) = resolve_addr(&dest).await {
                        // 策略二次校验：UDP 同样要防内网扫描与 DNS rebinding
                        if let Err(reason) = config.policy.check_resolved(addr) {
                            tracing::trace!(%addr, %reason, "UDP 目标被策略拒绝");
                            return Ok(());
                        }
                        if sock.send_to(data, addr).await.is_ok() {
                            stats.bytes_up += data.len() as u64;
                        }
                    }
                }
                Action::None => {
                    tracing::trace!(stream_id = sid, "未知流的 Data 帧，丢弃");
                }
            }
        }

        FrameType::Close => {
            let sid = frame.stream_id;
            // # 半关闭语义（这是本次修复的正确性关键）
            //
            // 客户端发 `Close` 只代表**它不再发数据**，不代表它不再收数据。
            // 典型场景：`GET /bigfile` 发完请求就半关闭，然后长时间收响应。
            //
            // 因此：
            // - **TCP**：只 `take()` 掉数据投递端（让 `tcp_pump` 收到 EOF
            //   并 shutdown 目标写端），**保留表项**，这样后续 `Window`
            //   信用帧仍能找到 `send_flow` 授信；流由 `tcp_pump` 结束时
            //   的 `cleanup` 真正注销。
            // - **UDP**：无半关闭概念，直接注销。
            // ★ 可靠流的 FIN 必须**按序**处理（见 `flowtcp_proto::arq` 的说明）。
            //
            // 客户端把 FIN 也编进了 ARQ 序号，所以这里要先把它送进重排缓冲，
            // 只有当它前面的所有 `Data` 都到齐后，才真正执行半关闭。
            //
            // 反例（实测）：请求包被丢 + FIN 直接生效 → 服务端提前半关闭
            // → 重传的请求无处可投 → 下载拿到 0 字节。
            let mut arq_ready: Option<Vec<(Vec<u8>, bool)>> = None;
            if let Some(Target::Tcp { arq_rx, .. }) = streams.get_mut(sid) {
                arq_rx.acks.insert(frame.pkt_seq);
                match arq_rx.reorder.push(frame.pkt_seq, Vec::new(), true) {
                    Ok(list) => arq_ready = Some(list),
                    Err(e) => {
                        tracing::warn!(stream_id = sid, error = %e, "重排缓冲溢出，关闭流");
                        let _ = out.send(OwnedFrame::close(sid, false)).await;
                        streams.remove(sid);
                        return Ok(());
                    }
                }
            }

            // 先把按序就绪的数据投递（FIN 之前的 Data 可能刚好凑齐）
            let mut fin_now = false;
            let had_arq = arq_ready.is_some();
            if let Some(list) = arq_ready {
                for (payload, is_close) in list {
                    if is_close {
                        fin_now = true;
                        continue;
                    }
                    if let Some(Target::Tcp { tx: Some(tx), .. }) = streams.get(sid) {
                        let tx = tx.clone();
                        let len = payload.len() as u64;
                        if tx.send(payload).await.is_ok() {
                            stats.bytes_up += len;
                        }
                    }
                }
            }

            // FIN 尚未轮到 → 什么都不做，等它前面的包补齐
            if had_arq && !fin_now {
                tracing::trace!(stream_id = sid, "FIN 未到序，等待前序数据");
                return Ok(());
            }

            match streams.get_mut(sid) {
                Some(Target::Tcp { tx, .. }) => {
                    // drop 掉投递端 → tcp_pump 的 recv() 返回 None → 半关闭
                    *tx = None;
                    tracing::trace!(stream_id = sid, "客户端半关闭写端（保留流供授信）");
                }
                Some(Target::Udp { .. }) => {
                    streams.remove(sid);
                    tracing::trace!(stream_id = sid, "UDP 会话已关闭");
                }
                None => {
                    tracing::trace!(stream_id = sid, fin = frame.is_fin(), "关闭未知流");
                }
            }
            let _ = frame.is_fin();
        }

        FrameType::Ping => {
            // 心跳：原样回 Pong（payload 长度随机，回显保持一致即可）
            let pong = OwnedFrame::new(
                FrameType::Pong,
                Flags::empty(),
                frame.stream_id,
                0,
                frame.payload.clone(),
            );
            let _ = out.send(pong).await;
        }

        // Pong / Ack / Fec / Window / Error 由客户端发起时忽略
        _ => {}
    }
    Ok(())
}

/// 解析 UDP Data 帧的 payload。
fn parse_udp_payload(frame: &OwnedFrame, default: Option<Address>) -> Option<(Address, &[u8])> {
    match default {
        Some(d) => Some((d, &frame.payload)),
        None => match Address::decode(&frame.payload) {
            Ok((addr, used)) => Some((addr, &frame.payload[used..])),
            Err(e) => {
                tracing::trace!(error = %e, "UDP 地址解析失败");
                None
            }
        },
    }
}

/// 把 [`Address`] 解析成 socket 地址（域名走系统解析器）。
async fn resolve_addr(addr: &Address) -> Option<SocketAddr> {
    match addr {
        Address::V4(v4) => Some(SocketAddr::V4(*v4)),
        Address::V6(v6) => Some(SocketAddr::V6(*v6)),
        Address::Domain(host, port) => {
            // 用 tokio 的异步解析，避免阻塞运行时线程
            match tokio::net::lookup_host((host.as_str(), *port)).await {
                Ok(mut it) => it.next(),
                Err(e) => {
                    tracing::debug!(host, port, error = %e, "域名解析失败");
                    None
                }
            }
        }
    }
}

/// 打开一条 TCP 流并起搬运任务。
async fn open_tcp(
    stream_id: u16,
    target: Address,
    streams: &mut SlotTable<Target>,
    ctx: &mut FrameCtx<'_>,
) {
    let (out, config, stats) = (ctx.out.clone(), ctx.config, &mut *ctx.stats);
    let (bytes_down, cleanup) = (Arc::clone(&ctx.bytes_down), ctx.cleanup.clone());
    stats.streams_opened += 1;

    // ---- 1) 策略校验（域名只能在此刻校验解析结果）----
    if let Err(reason) = config.policy.check(&target) {
        tracing::debug!(%stream_id, target = %target, %reason, "目标被策略拒绝");
        stats.denied += 1;
        let _ = out.send(OwnedFrame::close(stream_id, false)).await;
        return;
    }

    // ---- 2) 流数上限 ----
    if streams.len() >= config.max_streams as usize {
        tracing::debug!(%stream_id, "流数超限，拒绝");
        let _ = out.send(OwnedFrame::close(stream_id, false)).await;
        return;
    }

    // ---- 3) 连接目标 ----
    let sock_addr = match resolve_addr(&target).await {
        Some(a) => a,
        None => {
            stats.connect_failed += 1;
            let _ = out.send(OwnedFrame::close(stream_id, false)).await;
            return;
        }
    };

    // 域名解析后必须再校验一次真实 IP：防 DNS rebinding
    if let Err(reason) = config.policy.check_resolved(sock_addr) {
        tracing::debug!(%stream_id, %sock_addr, %reason, "解析后地址被策略拒绝");
        stats.denied += 1;
        let _ = out.send(OwnedFrame::close(stream_id, false)).await;
        return;
    }

    let conn = tokio::time::timeout(config.connect_timeout, TcpStream::connect(sock_addr)).await;
    let conn = match conn {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::debug!(%stream_id, %sock_addr, error = %e, "连接目标失败");
            stats.connect_failed += 1;
            let _ = out.send(OwnedFrame::close(stream_id, false)).await;
            return;
        }
        Err(_) => {
            tracing::debug!(%stream_id, %sock_addr, "连接目标超时");
            stats.connect_failed += 1;
            let _ = out.send(OwnedFrame::close(stream_id, false)).await;
            return;
        }
    };
    // 代理流量多为小包交互，关掉 Nagle 直接降低 RTT
    let _ = conn.set_nodelay(true);

    // ---- 4) 注册流 ----
    // TCP 是可靠流：大缓冲 + 背压（见 Data 分支的注释）
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(MAX_RELIABLE_QUEUE);

    // 两侧流控状态：发送侧（本端→客户端）、接收侧（客户端→本端）
    // 窗口大小由配置决定（默认 8 MB，对齐 hy2 的 initStreamReceiveWindow）
    let send_flow = Arc::new(SendFlow::new(config.stream_window));
    let recv_flow = Arc::new(FlowCounters::new(config.stream_window));

    // ARQ 状态：TCP 流可靠（有 ACK + 重传），与 Hysteria 2 一致。
    // cwnd 的包数上限由流控窗口反推（见 `ArqSender::cwnd`）。
    let arq_tx = Arc::new(ArqSender::new(config.stream_window, config.max_payload));
    let arq_rx = ArqReceiver::new(config.stream_window);

    streams.insert(
        stream_id,
        Target::Tcp {
            tx: Some(data_tx),
            send_flow: Arc::clone(&send_flow),
            recv_flow: Arc::clone(&recv_flow),
            arq_tx: Arc::clone(&arq_tx),
            arq_rx,
        },
    );

    // ---- 5) 起搬运任务：目标 → 客户端 ----
    // `config` 是借用，不能跨 spawn 边界，先取出需要的拷贝值
    let max_payload = config.max_payload;
    let out_clone = out.clone();
    // 收尾发 FIN 需要 ARQ 状态，但 `arq_tx` 会被 move 进 `tcp_pump`
    let arq_tx_for_fin = Arc::clone(&arq_tx);
    tokio::spawn(async move {
        tcp_pump(
            stream_id,
            conn,
            data_rx,
            out_clone.clone(),
            Arc::clone(&bytes_down),
            max_payload,
            send_flow,
            recv_flow,
            arq_tx,
        )
        .await;
        // 目标关闭或出错：回 FIN 并通知读循环注销本流。
        //
        // ★ FIN 必须占用一个 ARQ 序号（与客户端对称）。
        // 若用 seq=0，客户端重排缓冲会把它当作「已交付过的重复包」丢掉
        // （此时 next_seq 早已是几千），导致客户端永远等不到关闭信号 ——
        // 实测表现为「数据几乎收完但卡满 60 秒超时」。
        let mut fin_frame = OwnedFrame::close(stream_id, true);
        fin_frame.pkt_seq = arq_tx_for_fin.next_seq();
        arq_tx_for_fin.on_sent(fin_frame.clone());
        let _ = out_clone.send(fin_frame).await;
        // FIN 也可能被丢：等它被确认后再注销（超时保护 5 秒）
        wait_arq_drain(
            &arq_tx_for_fin,
            &out_clone,
            stream_id,
            Duration::from_secs(5),
        )
        .await;
        // 通道可能已关闭（隧道断了），此时无需再通知
        let _ = cleanup.send(stream_id).await;
    });

    tracing::debug!(%stream_id, target = %target, %sock_addr, "TCP 流已打开");
}

/// 驱动所有流的 ARQ 周期任务：发 `Ack`、时间阈值丢包、PTO 探测。
///
/// # ★ 为什么不能只在 `read` 超时时调用
///
/// 早期实现把这段逻辑放在 `timeout(50ms, r.read())` 的**超时分支**里。
/// 结果是：**只要对端持续灌数据，`read` 就永远不会超时 → 这段代码永不执行
/// → `Ack` 一发不出**。
///
/// 后果是灾难性的：发送侧收不到 `Ack` → `largest_acked` 恒为 `None`
/// → **包阈值丢包检测永不触发**（它依赖 `largest_acked`）→ 只能靠 PTO，
/// 而 PTO 初始就是 `333 + 4×166 + 25 ≈ 1 秒`，且指数退避。
///
/// 实测症状：5% 丢包上传 16 MB **完全卡死**（40 秒无进展），
/// 而 0% 丢包时 124 MB/s 正常 —— 差别只在有没有 ACK。
///
/// 所以：**每处理完一批帧就驱动一次**（带节流），而不是等超时。
async fn drive_arq(
    streams: &mut SlotTable<Target>,
    out: &mpsc::Sender<OwnedFrame>,
    force_window: bool,
) -> Result<(), ExitError> {
    let now = now_ms();
    let mut pending: Vec<OwnedFrame> = Vec::new();

    for (sid, target) in streams.iter_mut() {
        let Target::Tcp {
            recv_flow,
            arq_tx,
            arq_rx,
            ..
        } = target
        else {
            continue; // UDP 流无流控、无 ARQ
        };

        // ---- 1) 周期信用帧（流控抗丢包兜底）----
        let offset = recv_flow.current_offset();
        if force_window || offset != recv_flow.advertised() as u32 {
            let mut payload = Vec::with_capacity(4);
            encode_window_credit(offset, &mut payload);
            pending.push(OwnedFrame::new(
                FrameType::Window,
                Flags::empty(),
                sid,
                0,
                payload,
            ));
        }

        // ---- 2) 待发的 Ack ----
        //
        // 纯上传场景（对端只发不收）下本端没有数据要发，
        // 若不主动发 Ack，对端只能靠 PTO 重传 —— 那是秒级延迟。
        // 发 Ack 的两个触发条件（**必须保留强制周期**）
        //
        // 1. 有新收到的包 + 距上次 ≥ 25ms（低延迟）
        // 2. **距上次 ≥ 100ms，无条件重发**（抗 ACK 丢失 + 维持对端丢包检测）
        //
        // # 为什么条件 2 不可省（实测踩坑）
        //
        // 早期只写条件 1（`has_news && due`）。数据灌完后不再有新包 →
        // `has_news` 恒为 false → **Ack 彻底停发**。发送方于是永远不知道
        // 最后那几个空洞是否已到达，只能靠 PTO（秒级 + 指数退避）逐个数，
        // 表现为「256 KB 以后完全卡死」。
        let received = arq_rx.acks.received_count();
        let has_news = received > arq_rx.acked_at_last_send;
        let elapsed = now.saturating_sub(arq_rx.last_ack_ms);
        let should_send = (has_news && elapsed >= 25) || elapsed >= 100;
        if should_send && arq_rx.acks.largest().is_some() {
            let delay = now.saturating_sub(arq_rx.last_ack_ms);
            let mut payload = Vec::with_capacity(16);
            if arq_rx.acks.encode(delay, &mut payload).is_some() {
                pending.push(OwnedFrame::new(
                    FrameType::Ack,
                    Flags::empty(),
                    sid,
                    0,
                    payload,
                ));
                arq_rx.last_ack_ms = now;
                arq_rx.acked_at_last_send = received;
            }
        }

        // ---- 3) 时间阈值丢包 + PTO 探测 ----
        for mut f in arq_tx.poll_timeouts() {
            f.stream_id = sid;
            pending.push(f);
        }
    }

    // ★ 全部用 `try_send`：读循环不能被写队列堵住，否则无法处理对端 `Ack`
    // → 包阈值丢包检测失效 → 丢包时只能靠秒级 PTO（实测会卡死）。
    // 这些帧（Window / Ack / PTO 重传）都可重发，丢弃完全安全。
    for f in pending {
        match out.try_send(f) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(_) => return Err(ExitError::Closed),
        }
    }
    Ok(())
}

/// 等待某条流的在途包全部被确认（QUIC 的「收尾/draining」过程）。
///
/// # 为什么必须有这个
///
/// 目标 socket 读到 EOF 时，**最后一批帧可能还在途**（其中有被丢的）。
/// 若此时立即发 `Close` 关流，接收方要么收不到那些帧、要么收到 `Close` 后
/// 直接结束 —— 重传就再也没机会发生。
///
/// 实测证据（`FLOWTCP_DROP_DATA=5`，16 MB 下载）：
/// 不加等待时只能收到 **9 MB**（丢 46%），因为剩下的包还没来得及重传就关流了。
///
/// # 与 QUIC 的对应关系
///
/// QUIC 在 `CONNECTION_CLOSE` 之前要求所有在途数据被确认或判定丢失；
/// 它在 stream 层用 `FIN` 位置等待 `MAX_STREAM_DATA` 对齐。
/// 我们用「等 inflight 清零」达到同样效果。
///
/// # 超时保护
///
/// 对端可能已经消失（进程崩溃/网络断）。等不到就放弃，否则会永久挂住。
async fn wait_arq_drain(
    arq: &ArqSender,
    out: &mpsc::Sender<OwnedFrame>,
    stream_id: u16,
    max_wait: Duration,
) {
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut quiet_rounds = 0u32;

    loop {
        if arq.inflight() == 0 {
            // 连续两轮为 0 才算真清空（避免竞态：刚发出还没登记）
            quiet_rounds += 1;
            if quiet_rounds >= 2 {
                return;
            }
        } else {
            quiet_rounds = 0;
        }

        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                stream_id,
                inflight = arq.inflight(),
                "收尾等待超时，仍有未确认包（对端可能已断开）"
            );
            return;
        }

        // 驱动 PTO 重传（poll_timeouts 内部会按退避决定是否真的重传）
        for mut f in arq.poll_timeouts() {
            f.stream_id = stream_id;
            if out.send(f).await.is_err() {
                return; // 隧道已断
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// TCP 流的搬运任务：把目标端读到的数据发回客户端，把客户端数据写入目标。
///
/// 参数多是因为两个方向的状态都要显式传入 —— 不搞全局/结构体，
/// 让调用点一眼能看出每个方向的流控归属（少一个都是 bug）。
#[allow(clippy::too_many_arguments)]
async fn tcp_pump(
    stream_id: u16,
    mut conn: TcpStream,
    mut from_client: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<OwnedFrame>,
    bytes_down: Arc<std::sync::atomic::AtomicU64>,
    // 单帧 payload 上限。**读到的数据必须按此分片**，否则超过
    // `MAX_FRAME_PAYLOAD` 的帧会被 `encode` 拒绝 ——
    // 而一旦上层用 `let _ =` 吞掉错误，数据就会被静默丢弃。
    max_payload: usize,
    // 发送侧信用：每帧发出前必须申请，不足则等待客户端补发（按流背压）。
    send_flow: Arc<SendFlow>,
    // 接收侧窗口：客户端数据成功写入目标后必须上报 `on_consumed`，
    // 否则信用永不恢复 → 流控死锁。
    recv_flow: Arc<FlowCounters>,
    // ARQ 发送侧：每个发出的包都要登记在途（供丢包检测与重传）。
    arq_tx: Arc<ArqSender>,
) {
    let (mut tr, mut tw) = conn.split();
    // 读缓冲可以比 max_payload 大（减少 syscall），但发送前必须分片
    let mut buf = vec![0u8; 32 * 1024];
    // 客户端已关闭写端后，必须禁用该 select 分支 ——
    // 否则 recv() 会持续立即返回 None，形成 100% CPU 的忙循环。
    let mut client_closed = false;

    loop {
        tokio::select! {
            // ---- 客户端 → 目标 ----
            data = from_client.recv(), if !client_closed => {
                match data {
                    Some(d) => {
                        let len = d.len();
                        if tw.write_all(&d).await.is_err() {
                            tracing::trace!(%stream_id, "写目标失败");
                            return;
                        }
                        // ★ 数据已成功交给目标 → 释放接收侧信用
                        recv_flow.on_consumed(len);

                        // ★ 补发 `Window` 信用帧 —— **必须紧跟 `on_consumed`**。
                        //
                        // 窗口上限 = `consumed + window`，所以只有消费之后
                        // 才能算出正确的补发量。放在这里（而不是读取路径）
                        // 是为了让背压真正作用在「目标写不进去」这件事上：
                        // 目标慢 → 消费慢 → 补发少 → 客户端发送被限速，
                        // 而不会在内存里堆起无限队列。
                        //
                        // 反例（曾经踩过的坑）：把补发放在收帧处 → 消费永远
                        // 滞后于接收 → 补发量恒为 0 → 客户端发完初始窗口就卡死。
                        if let Some(delta) = recv_flow.poll_grant() {
                            let mut payload = Vec::with_capacity(4);
                            encode_window_credit(delta, &mut payload);
                            let wf = OwnedFrame::new(
                                FrameType::Window,
                                Flags::empty(),
                                stream_id,
                                0,
                                payload,
                            );
                            // 写队列满则 await：良性背压，不会丢信用
                            if out.send(wf).await.is_err() {
                                return; // 隧道已断
                            }
                        }
                    }
                    None => {
                        // 客户端关闭了流：半关闭目标写端，让目标自行结束，
                        // 然后继续读目标剩余数据直到它关闭（真正的半关闭语义）
                        let _ = tw.shutdown().await;
                        client_closed = true;
                    }
                }
            }

            // ---- 目标 → 客户端 ----
            read = tr.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        // 目标正常关闭：**先等所有在途包被确认**再返回。
                        // 否则丢失的尾包再无重传机会（实测会丢近一半数据）。
                        drop(buf); // 释放读缓冲，减轻收尾期间的内存压力
                        wait_arq_drain(
                            &arq_tx,
                            &out,
                            stream_id,
                            Duration::from_secs(10),
                        )
                        .await;
                        return;
                    }
                    Ok(n) => {
                        // ★ 按 max_payload 分片：一次 read 可能拿到 32KB，
                        //   而单帧上限只有 16KB（FakeTCP 承载下更小，约 1400B）。
                        //   不分片会让 encode 失败 → 数据丢失。
                        let len = n as u64;
                        for chunk in buf[..n].chunks(max_payload) {
                            // ★ 先申请信用再发。不足则 await 等 `Window` 帧 ——
                            // 这是**按流**背压：只有这条流被卡住，其他流照常。
                            if send_flow.acquire(chunk.len()).await.is_err() {
                                return; // 隧道已断
                            }

                            // 在途包数上限（简化版拥塞窗口，与客户端对称）。
                            //
                            // 为什么信用之外还要限包数：信用按**字节**控制，
                            // 而 ACK 帧的表达力按**包数**受限 —— 8 MB 窗口是
                            // 5700 个包，10% 丢包就有 570 个乱序段，超出单个
                            // ACK 帧能装下的范围数（≈300）→ 老包永远得不到
                            // 确认 → 反复重传 → 停滞。
                            //
                            // 详见 `flowtcp_proto::arq::MAX_INFLIGHT_PKTS`。
                            let mut spins = 0u32;
                            while !arq_tx.can_send() {
                                tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                                spins += 1;
                                if spins > 25_000 {
                                    return; // 对端可能已消失
                                }
                            }
                            // 序号从 ARQ 取（重传也从同一计数器取，保证唯一）
                            let seq = arq_tx.next_seq();
                            let f = OwnedFrame::new(
                                FrameType::Data,
                                // TCP 流：必须可靠（丢了要 ARQ 重传）
                                Flags::empty().with(Flags::RELIABLE),
                                stream_id,
                                seq,
                                chunk.to_vec(),
                            );
                            // 先登记在途再发（顺序不可颠倒）
                            arq_tx.on_sent(f.clone());
                            if out.send(f).await.is_err() {
                                return; // 隧道已断
                            }
                        }
                        bytes_down.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::trace!(%stream_id, error = %e, "读目标失败");
                        return;
                    }
                }
            }
        }
    }
}

/// 打开一个 UDP 会话。
async fn open_udp(
    stream_id: u16,
    default_target: Address,
    streams: &mut SlotTable<Target>,
    ctx: &mut FrameCtx<'_>,
) {
    let (out, config, stats) = (ctx.out.clone(), ctx.config, &mut *ctx.stats);
    let (bytes_down, cleanup) = (Arc::clone(&ctx.bytes_down), ctx.cleanup.clone());
    stats.streams_opened += 1;

    // UDP 会话不预先解析默认目标（它可能只是占位地址），
    // 每个包发往哪个地址由 HAS_ADDR 决定或复用默认目标。

    if streams.len() >= config.max_streams as usize {
        tracing::debug!(%stream_id, "UDP 流数超限，拒绝");
        let _ = out.send(OwnedFrame::close(stream_id, false)).await;
        return;
    }

    // 绑一个本地 UDP 端口。绑 0.0.0.0 而非默认目标的地址族，
    // 是为了让同一会话能同时发往 v4 与 v6（域名解析结果可能两者都有）。
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::debug!(%stream_id, error = %e, "绑定 UDP 失败");
            stats.connect_failed += 1;
            let _ = out.send(OwnedFrame::close(stream_id, false)).await;
            return;
        }
    };

    streams.insert(
        stream_id,
        Target::Udp {
            sock: Arc::clone(&sock),
            default_target: default_target.clone(),
        },
    );

    // 起收包任务：UDP 回包 → Data(HAS_ADDR) 帧
    // 这里直接 move `out`（不再需要它），省一次 Clone
    let policy = config.policy;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::trace!(%stream_id, error = %e, "UDP 收包失败");
                    break;
                }
            };

            // 回包源地址也要过策略：防止被诱导去访问内网并回传数据
            if policy.check_resolved(from).is_err() {
                continue;
            }

            // 组 payload：目标地址 + 数据
            let addr = match from {
                SocketAddr::V4(v4) => Address::V4(v4),
                SocketAddr::V6(v6) => Address::V6(v6),
            };
            let mut payload = Vec::with_capacity(n + 20);
            if addr.encode(&mut payload).is_err() {
                continue;
            }
            payload.extend_from_slice(&buf[..n]);

            let f = OwnedFrame::new(
                FrameType::Data,
                Flags::empty().with(Flags::HAS_ADDR),
                stream_id,
                0,
                payload,
            );
            let len = n as u64;
            if out.send(f).await.is_err() {
                break;
            }
            bytes_down.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        }
        // 通知读循环注销本 UDP 会话
        let _ = cleanup.send(stream_id).await;
    });

    tracing::debug!(%stream_id, target = %default_target, "UDP 会话已打开");
}
