//! 流复用：一条隧道承载多条本地连接
//!
//! # 结构
//!
//! ```text
//! 本地连接 A ──┐
//! 本地连接 B ──┼─→ stream_id 1/2/3 ─→ [写任务] ─→ FrameWriter ─→ 隧道
//! 本地连接 C ──┘                        ↑
//!                                   mpsc 队列
//! 本地连接 A ←─┐
//! 本地连接 B ←─┼─← stream_id 分发 ←─ [读任务] ←─ FrameReader ←─ 隧道
//! 本地连接 C ←─┘
//! ```
//!
//! # 为什么写侧必须单任务
//!
//! 一条记录里可以打包多个帧（见 [`crate::tunnel`]），但**不能交错写入**：
//! 两个任务同时 `write_all` 会让字节流交错，对端解出乱码。
//! 因此所有发帧请求都排队到一个 mpsc，由唯一写任务串行写入 —— 顺带获得
//! 批量合并的机会（一次 syscall 写多条记录）。
//!
//! 读侧天然单任务（一个读循环），按 `stream_id` 分发到各流自己的队列。
//!
//! # ★ 为什么读循环**独占**流表（性能关键，实测 53.5 → 0.7 ns）
//!
//! 早期实现用 `Arc<Mutex<HashMap<u16, Sender>>>` 作为注册表，
//! 每收到一帧都要「抢锁 + 哈希 + 查找 + clone」。
//! 实测（`cargo run --release -p flowtcp-client --example bench_registry`）：
//!
//! | 实现 | 单次查找 |
//! |------|---------|
//! | `Arc<Mutex<HashMap>>` | **53.5 ns** |
//! | `Arc<Mutex<Vec<Option>>>` | 42.7 ns |
//! | **读循环独占 `Vec`（无锁）** | **0.7 ns** |
//!
//! 省下的 52.8 ns 相当于 64B 包加密成本（235 ns）的 **22%**。
//! 按 256 流 × 1000 包/秒 计，每秒省 13.5 ms CPU。
//!
//! 做法：读循环独占槽位表；**注册/注销改走控制通道**（`Ctl`），
//! `Register` 带 `oneshot` 应答，保证调用方拿到权威的「是否成功」。
//! 只有 `open`/`close` 走通道（每连接一次），热路径完全无锁。

use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use flowtcp_proto::arq::{now_ms, AckRanges, ArqReceiver, ArqSender};
use flowtcp_proto::flow::{
    decode_window_credit, encode_window_credit, FlowCounters, SendCredit, DEFAULT_STREAM_WINDOW,
};
use flowtcp_proto::frame::{Address, Flags, FrameType, OwnedFrame};
use flowtcp_proto::SlotTable;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::tunnel::{Tunnel, TunnelError};

/// 复用层错误。
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// 活跃流数已达上限。
    #[error("活跃流数已达上限 {0}")]
    TooManyStreams(u16),
    /// stream_id 空间耗尽（理论上需要 65535 条并发流才会发生）。
    #[error("stream_id 空间耗尽")]
    IdExhausted,
    /// 隧道已关闭。
    #[error("隧道已关闭")]
    TunnelClosed,
    /// 隧道 IO 错误。
    #[error("隧道错误: {0}")]
    Tunnel(#[from] TunnelError),
    /// 流控错误（对端违约或实现 bug）。
    #[error("流控错误: {0}")]
    Flow(String),
}

/// 发送侧信用（跨任务共享）。
///
/// # 谁在读、谁在写
///
/// - **写（消费信用）**：`StreamSender::send_data`（pump 的上行分支）
/// - **写（授信）**：`read_loop` 收到 `Window` 帧时
///
/// 因此必须跨任务共享。用 `std::sync::Mutex`（锁内只有几次整数运算、绝不 await）
/// + `tokio::sync::Notify`（唤醒阻塞的发送方）。
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

    /// 申请 `n` 字节信用，不足则**等待**（这就是背压）。
    ///
    /// # 为什么必须 `enable()` 再检查（防丢唤醒）
    ///
    /// `Notify::notified()` 返回的 future 只有在**首次被 poll** 时才注册到
    /// 等待队列。若先检查条件、再 `await`，在这两步之间到达的通知会丢失，
    /// 导致发送方永久挂起（经典 lost-wakeup）。
    ///
    /// `Notified::enable()` 让 future 立即注册，从而消除这个窗口。
    /// 这是 tokio 官方推荐的模式（见 `Notify` 文档的「正确用法」示例）。
    async fn acquire(&self, n: usize) -> Result<(), MuxError> {
        let n64 = n as u64;
        loop {
            // 先注册通知，再检查条件
            let notified = self.granted.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let mut c = self.credit.lock().map_err(|_| MuxError::TunnelClosed)?;
                if c.available() >= n64 {
                    c.try_consume(n)
                        .map_err(|e| MuxError::Flow(e.to_string()))?;
                    return Ok(());
                }
            }

            // 信用不足：等对端发 Window 帧
            notified.await;
        }
    }

    /// 收到 `Window` 帧：对端已消费到 `offset`（**绝对偏移，不是增量**）。
    ///
    /// # 为什么是绝对偏移
    ///
    /// 增量语义下丢一个 `Window` 帧，那份信用就永久蒸发 —— 实测
    /// `FLOWTCP_DROP_WINDOW=10` 时下行传输在 3.3 MB / 16 MB 处永久停滞。
    /// 绝对偏移幂等可自愈：后续任何一个幸存的帧都能把状态拉回正确值。
    fn set_acked(&self, offset: u32) {
        if let Ok(mut c) = self.credit.lock() {
            c.set_acked(offset);
        }
        // 用 notify_waiters 而非 notify_one：虽然每条流只有一个发送者，
        // 但 notify_waiters 语义更明确（all 已注册的等待者都检查一遍条件）。
        self.granted.notify_waiters();
    }

    /// 当前可用信用（诊断用）。
    fn available(&self) -> u64 {
        self.credit.lock().map(|c| c.available()).unwrap_or(0)
    }
}

/// 流表中的一条流。
///
/// 把「投递队列」与「两侧流控状态」放在一起：`read_loop` 独占这张表，
/// 一次查找就能拿到处理各类帧所需的全部信息（无锁、~0.7 ns）。
struct StreamEntry {
    /// 入站数据队列（投递给 `StreamReceiver`）。
    inbound: mpsc::Sender<OwnedFrame>,
    /// 发送侧信用。`None` = 该流不启用信用流控（UDP 流）。
    send_flow: Option<Arc<SendFlow>>,
    /// 接收侧窗口。`None` = 该流不启用信用流控（UDP 流）。
    ///
    /// 读循环**只**做 `on_received` 记账，**不**在这里补发信用 ——
    /// 原因见 `StreamReceiver::recv` 的注释（补发必须紧跟消费）。
    recv_flow: Option<Arc<FlowCounters>>,
    /// ARQ 发送侧状态。`None` = 不可靠流（UDP），不做重传。
    ///
    /// 交给读循环是为了让 `Ack` 帧能就地处理（移除在途、检测丢包、重传）。
    arq_tx: Option<Arc<ArqSender>>,
    /// ARQ 接收侧状态（读循环独占）。
    arq_rx: Option<ArqReceiver>,
}

/// 注册结果。
///
/// 用枚举而非 `bool`：调用方需要区分「流数超限」（应报 `TooManyStreams`）
/// 与「ID 回绕碰撞」（应换 ID 重试）—— 两者的处理完全不同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegOutcome {
    /// 注册成功。
    Ok,
    /// 活跃流数已达上限。
    TooMany,
    /// 该 ID 已被占用（`stream_id` 回绕后撞上未释放的槽位）。
    IdTaken,
}

/// 控制命令：由 `Mux` 发给读循环，避免热路径抢锁。
enum Ctl {
    /// 注册一条流。读循环是流数的权威仲裁者，结果经 `reply` 返回。
    Register {
        /// 流 ID。
        id: u16,
        /// 该流的完整条目（入站队列 + 两侧流控状态）。
        entry: StreamEntry,
        /// 注册结果。
        reply: oneshot::Sender<RegOutcome>,
    },
    /// 注销一条流（`StreamSender`/`StreamReceiver` 全部 drop 时发出）。
    Unregister {
        /// 流 ID。
        id: u16,
    },
}

/// 注销守卫：`StreamSender`/`StreamReceiver` 全部 drop 时自动通知读循环移除槽位。
///
/// # 为什么用 `try_send` 而不是 `send`
///
/// `Drop` 是同步上下文，不能 `await`。控制通道深度 1024，
/// 即使批量关流也几乎不会满；万一满了，读循环还有兜底：
/// 给该流 `send` 帧时会因接收端已 drop 而失败，此时自动清理槽位。
struct Guard {
    ctl: mpsc::Sender<Ctl>,
    id: u16,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.ctl.try_send(Ctl::Unregister { id: self.id });
    }
}

/// 流复用器。
///
/// 持有两个后台任务的句柄与共享状态。`Mux` 本身被 drop **不会**立即停止
/// 任务（任务持有自己的拷贝）；要主动停止请 drop 所有 `StreamSender`，
/// 或直接 drop 底层连接。
pub struct Mux {
    /// 发帧入口（克隆给各流）。
    out: mpsc::Sender<OwnedFrame>,
    /// 控制通道（注册/注销）—— 读循环独占槽位表的代价。
    ctl: mpsc::Sender<Ctl>,
    /// 活跃流数（由读循环维护，供外部统计读取）。
    active: Arc<AtomicUsize>,
    /// 下一个候选 stream_id。
    next_id: Arc<AtomicU16>,
    /// 单流最大并发数。
    max_streams: u16,
    /// 单帧最大 payload。
    max_payload: usize,
    /// 单流接收窗口大小（客户端与服务端必须一致）。
    stream_window: u64,
    /// 已开流总数（累计，用于统计）。
    total_opened: Arc<AtomicU64>,
}

impl Mux {
    /// 在已建立的隧道上启动复用层。
    ///
    /// `max_payload` 决定单帧切分粒度：
    /// - 真 TCP 承载（Phase 3）可用 16374
    /// - FakeTCP 承载（Phase 4）必须 ≤ [`flowtcp_proto::max_payload_for_mtu`]
    ///
    /// 传 0 表示用 1400（与 MTU 1500 的最终形态一致，便于测试即生产）。
    pub fn spawn<S>(tunnel: Tunnel<S>, max_streams: u16, max_payload: usize) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 默认窗口（对齐 Hysteria 2 的 initStreamReceiveWindow = 8 MB）
        Self::spawn_with_window(tunnel, max_streams, max_payload, DEFAULT_STREAM_WINDOW)
    }

    /// 同 [`Self::spawn`]，但可指定**单流窗口**。
    ///
    /// # 为什么窗口必须可配
    ///
    /// 窗口大小是「带宽 × RTT」的直接函数：
    ///
    /// | 场景 | 建议值 |
    /// |------|--------|
    /// | 局域网 / 同城（RTT < 10ms） | 1~2 MB 足够 |
    /// | 家用宽带跨省（RTT 50ms） | 8 MB（默认） |
    /// | 跨洲 / 高 BDP（RTT 200ms+） | 16~32 MB |
    /// | 路由器 / 小内存设备 | 1~4 MB（省内存） |
    ///
    /// 对齐 Hysteria 2 的 `quic.initStreamReceiveWindow`：它也是可配的，
    /// 且官方 Performance 文档给出的调优值是 25.6 MB。
    ///
    /// **客户端与服务端必须一致**，否则开流的隐式初始信用会错位。
    pub fn spawn_with_window<S>(
        tunnel: Tunnel<S>,
        max_streams: u16,
        max_payload: usize,
        stream_window: u64,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<OwnedFrame>(1024);
        // 控制通道：深度足够覆盖「瞬间批量开流/关流」的突发
        let (ctl_tx, ctl_rx) = mpsc::channel::<Ctl>(1024);
        let active = Arc::new(AtomicUsize::new(0));

        // ---- 写任务：串行写 + 批量合并 ----
        let writer = tunnel.writer;
        tokio::spawn(async move { write_loop(writer, rx).await });

        // ---- 读任务：解帧 + 按 stream_id 分发（独占槽位表，无锁）----
        //
        // ★ 读任务**不再持有**出站队列。
        //
        // 以前它需要 out 来发 `Window` 信用帧，那是流控的**错误位置**
        // （补发必须紧跟消费，见 `StreamReceiver::recv`）。
        // 删掉这个持有关系还额外解决了一类风险：
        //
        // ```text
        // read_loop 持有 out(Sender)
        //   → 写任务的 rx 收不到 None，永不退出
        //   → 底层连接不 shutdown → read_loop 等不到 EOF
        // ```
        //
        // 现在读循环与写任务的存活完全解耦。
        let reader = tunnel.reader;
        let active_for_read = Arc::clone(&active);
        // read_loop 需要 out 来做周期信用重发（PTO 兜底）。
        // 注意：它仍会通过 `ctl.recv() == None` 退出（Mux drop 时），
        // 退出后释放 out → 写任务收 None → shutdown，无循环依赖。
        let out_for_resend = tx.clone();
        tokio::spawn(async move {
            read_loop(reader, out_for_resend, ctl_rx, active_for_read, max_streams).await
        });

        Mux {
            out: tx,
            ctl: ctl_tx,
            active,
            next_id: Arc::new(AtomicU16::new(1)),
            max_streams,
            max_payload: if max_payload == 0 { 1400 } else { max_payload },
            // 0 视为「用默认值」，避免误传 0 导致窗口为 0（流一开就卡死）
            stream_window: if stream_window == 0 {
                DEFAULT_STREAM_WINDOW
            } else {
                stream_window
            },
            total_opened: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 单帧最大 payload。
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// 当前活跃流数。
    pub fn active_streams(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// 累计开流数。
    pub fn total_opened(&self) -> u64 {
        self.total_opened.load(Ordering::Relaxed)
    }

    /// 打开一条 TCP 流。
    pub async fn open_tcp(&self, target: Address) -> Result<StreamHandle, MuxError> {
        let mut payload = Vec::new();
        target
            .encode(&mut payload)
            .map_err(|e| MuxError::Tunnel(TunnelError::Frame(e)))?;
        self.open_stream(FrameType::OpenTcp, payload).await
    }

    /// 打开一个 UDP 会话。
    ///
    /// `default_target` 是后续 `Data` 帧的默认目标；若要发往其他目标，
    /// 帧上带 `HAS_ADDR` 标志并在 payload 前置地址。
    pub async fn open_udp(&self, default_target: Address) -> Result<StreamHandle, MuxError> {
        let mut payload = Vec::new();
        default_target
            .encode(&mut payload)
            .map_err(|e| MuxError::Tunnel(TunnelError::Frame(e)))?;
        self.open_stream(FrameType::OpenUdp, payload).await
    }

    /// 打开一条流（内部通用）。
    async fn open_stream(
        &self,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<StreamHandle, MuxError> {
        // 可靠性由开流帧类型唯一决定 —— 这是权威来源
        let reliable = matches!(frame_type, FrameType::OpenTcp);

        // ---- 流控状态（仅可靠流启用）----
        //
        // 为什么 UDP 流不启用信用流控：
        // - UDP 允许丢包（丢是语义的一部分），不需要背压
        // - 若给 UDP 加信用，丢包时 `consumed` 不前进 → 信用永不恢复 →
        //   比"丢包"严重得多（会直接死锁）
        // 所以 UDP 只靠下游 `try_send` 丢弃即可。
        //
        // 连接级窗口（stream_id = 0）留到 Phase 4.5 与自动调优一起实现；
        // 当前只做流级，先在有内核窗口兜底的真 TCP 上验证正确性。
        let (send_flow, recv_flow) = if reliable {
            (
                Some(Arc::new(SendFlow::new(self.stream_window))),
                Some(Arc::new(FlowCounters::new(self.stream_window))),
            )
        } else {
            (None, None)
        };

        // ARQ 状态在下方重试循环内创建：ID 回绕碰撞时会重试，
        // 每次重试必须是全新状态（否则会带着上一轮的 in-flight 记录）。

        // ---- 1) 分配 stream_id + 注册（读循环是流数的权威仲裁者）----
        //
        // ID 单调递增（回绕时重试）。**不复用已关闭的 ID**：
        // FakeTCP 下帧可能乱序，复用会让「旧流的迟包」被投递给新流。
        let (id, inbound_rx, arq_tx) = {
            let mut attempt = 0u32;
            loop {
                // 跳过 0（保留值）
                let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
                if cand == 0 {
                    continue;
                }

                // ---- ARQ 状态（仅可靠流启用）----
                //
                // 与 Hysteria 2 完全一致：
                // - TCP → 可靠（走 QUIC stream，有 ACK + 重传）
                // - UDP → 不可靠（走 RFC 9221 unreliable datagram，禁止重传）
                //
                // 给 UDP 加重传会让丢包变延迟（重传要等 RTT），
                // 而 UDP 的价值就是「宁可丢也不要等」。
                // cwnd 的包数上限由流控窗口反推，所以要把窗口传进去
                let arq_tx = if reliable {
                    Some(Arc::new(ArqSender::new(
                        self.stream_window,
                        self.max_payload,
                    )))
                } else {
                    None
                };
                let arq_rx = if reliable {
                    Some(ArqReceiver::new(self.stream_window))
                } else {
                    None
                };

                let (itx, irx) = mpsc::channel::<OwnedFrame>(256);
                let (rtx, rrx) = oneshot::channel();
                if self
                    .ctl
                    .send(Ctl::Register {
                        id: cand,
                        entry: StreamEntry {
                            inbound: itx,
                            send_flow: send_flow.clone(),
                            recv_flow: recv_flow.clone(),
                            arq_tx: arq_tx.clone(),
                            arq_rx,
                        },
                        reply: rtx,
                    })
                    .await
                    .is_err()
                {
                    return Err(MuxError::TunnelClosed);
                }

                match rrx.await {
                    // 注册成功
                    Ok(RegOutcome::Ok) => break (cand, irx, arq_tx),
                    // 流数超限：直接报错，换 ID 也没用
                    Ok(RegOutcome::TooMany) => {
                        return Err(MuxError::TooManyStreams(self.max_streams));
                    }
                    // ID 回绕碰撞：换一个 ID 重试（槽位可能马上被释放）
                    Ok(RegOutcome::IdTaken) => {
                        attempt += 1;
                        if attempt > 8 {
                            return Err(MuxError::IdExhausted);
                        }
                        continue;
                    }
                    // 读循环已退出
                    Err(_) => return Err(MuxError::TunnelClosed),
                }
            }
        };

        self.total_opened.fetch_add(1, Ordering::Relaxed);

        // ---- 2) 发 OpenTcp / OpenUdp 帧 ----
        // 若隧道已关闭，回滚注册并报错（否则本地连接会一直等一个永不到来的响应）
        let open_frame = OwnedFrame::new(frame_type, Flags::empty(), id, 0, payload);
        if self.out.send(open_frame).await.is_err() {
            self.unregister(id);
            return Err(MuxError::TunnelClosed);
        }

        let guard = Arc::new(Guard {
            ctl: self.ctl.clone(),
            id,
        });

        let (sender, receiver) = StreamHandle::pair(
            id,
            self.out.clone(),
            inbound_rx,
            guard,
            self.max_payload,
            reliable,
            send_flow,
            recv_flow,
            arq_tx,
        );
        Ok(StreamHandle { sender, receiver })
    }

    /// 尽力注销一条流（不阻塞、不失败）。
    ///
    /// 用 `try_send` 而非 `send`：注销可能发生在 `Drop` 里（同步上下文），
    /// 不能 await。若队列满则放弃 —— 读循环还有「发送失败即自动清理」的兜底。
    fn unregister(&self, id: u16) {
        let _ = self.ctl.try_send(Ctl::Unregister { id });
    }
}

/// 写任务：串行写入 + 尽量合并小帧。
async fn write_loop<W>(
    mut writer: crate::tunnel::FrameWriter<W>,
    mut rx: mpsc::Receiver<OwnedFrame>,
) where
    W: AsyncWrite + Unpin,
{
    // 故障注入（仅测试用，未设环境变量时 `fault` 为 `None`，
    // 热路径只多一次 `Option` 判空）。详见 `flowtcp_proto::fault`。
    let fault = flowtcp_proto::fault::config();
    let fault_on = !fault.is_disabled();

    while let Some(first) = rx.recv().await {
        // 故障注入：被丢的帧等价于「在 FakeTCP 上丢失」
        if !(fault_on && fault.should_drop(first.frame_type)) {
            if let Err(e) = writer.push(&first).await {
                tracing::debug!(error = %e, "写任务失败，隧道终止");
                break;
            }
        }
        // 批量合并：把队列里已有的帧一次塞进同一条记录，显著减少 syscall。
        // 用 try_recv 而非 await，避免为凑批而引入延迟（低延迟优先于吞吐）。
        while let Ok(next) = rx.try_recv() {
            if fault_on && fault.should_drop(next.frame_type) {
                continue;
            }
            if let Err(e) = writer.push(&next).await {
                tracing::debug!(error = %e, "写任务失败，隧道终止");
                return;
            }
        }
        if let Err(e) = writer.flush_record().await {
            tracing::debug!(error = %e, "写任务 flush 失败，隧道终止");
            break;
        }
    }

    // ★ 必须 shutdown 底层写半。
    //
    // 所有 `Mux` 与 `StreamSender` 都被 drop 后，这里才退出循环。
    // 若不 shutdown，服务端的读循环收不到 EOF，会一直挂在这条连接上 ——
    // 表现为"客户端已退出但服务端连接数不下降"，且对端要等很久才超时。
    let frames = writer.frames_sent();
    let mut inner = writer.into_inner();
    let _ = inner.shutdown().await;
    tracing::debug!(frames, "写任务退出");
}

/// 读任务：解帧并按 `stream_id` 分发。
///
/// # ★ 这是全链路最热的循环
///
/// 每一帧都要走一次「查表 + 投递」。因此这里**独家持有** [`SlotTable`]，
/// 不做任何加锁 —— 实测查表 0.7 ns，而 `Arc<Mutex<HashMap>>` 是 53.5 ns。
///
/// 注册/注销通过 `ctl` 通道送达。注册带 `oneshot` 应答，
/// 保证 `open_stream` 拿到权威结论（成功 / ID 冲突 / 隧道已关）。
///
/// # 取消安全性
///
/// `select!` 的 cancel safety 依赖 `FrameReader::recv` 是取消安全的：
/// 它在 `inner.read().await` 处被取消时 tokio 保证**没有数据被消费**，
/// 且已解出的明文仍留在 `self.pending` 里，下一轮继续用。
async fn read_loop<R>(
    mut reader: crate::tunnel::FrameReader<R>,
    // 出站队列：**仅用于周期信用重发**（见下方 `resend_tick` 分支）。
    // 数据帧的 `Window` 补发在 `StreamReceiver::recv` 里（消费点），
    // 这里只做「丢包兜底」，两者职责不同。
    out: mpsc::Sender<OwnedFrame>,
    mut ctl: mpsc::Receiver<Ctl>,
    active: Arc<AtomicUsize>,
    max_streams: u16,
) where
    R: AsyncRead + Unpin,
{
    let mut slots: SlotTable<StreamEntry> = SlotTable::with_capacity_hint(max_streams);

    // ---- 周期信用重发（对应 QUIC 的 PTO 探测）----
    //
    // # 为什么必须有这个
    //
    // `Window` 帧用绝对偏移（幂等、可自愈），但**帧本身仍可能丢**。
    // 如果只靠「消费时发一次」，那个帧丢了就再也不会重发 ——
    // 发送侧信用停在旧值，直到有新数据消费才会更新。
    //
    // QUIC 的解法是把 `MAX_DATA` 放进重传队列，等不到 ACK 就重发。
    // 我们还没 ARQ（Phase 4.6），用**周期无条件重发**达到同样效果：
    // 4 字节/流/200ms，256 流满载也只有 5 KB/s，完全可接受。
    //
    // # 为什么 50ms 周期、200ms 强制重发
    //
    // - 50ms：有变化时快速同步（低延迟优先）
    // - 200ms：与常见 RTT 同量级，保证「丢一帧最多耽误 200ms」
    //
    // 没有变化的周期不发（省带宽），只有每 4 个周期强制发一次。
    // 20ms：既是信用帧的兜底重发周期，也是 ARQ 的发 Ack / 丢包检测周期。
    //
    // 为什么从 50ms 收到 20ms：ARQ 的 `max_ack_delay` 是 25ms，
    // 周期必须小于它才不会成为瓶颈。客户端用 `select!` 结构，
    // 无论是否有数据到达 tick 都会被公平轮询（不像服务端那样依赖 read 超时）。
    let mut resend_tick = tokio::time::interval(std::time::Duration::from_millis(20));
    resend_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tick_count = 0u64;
    // 控制通道是否需要继续监听。
    //
    // 通道关闭时会直接 `break`（见下方注释），因此这个标志在当前实现里
    // 恒为 true。保留它是为了让 `select!` 的分支能被显式禁用 ——
    // 将来若改成"关闭后继续收尾"，这里就是开关。
    let ctl_open = true;

    loop {
        tokio::select! {
            // ---- 周期信用重发（QUIC PTO 的简化版）----
            //
            // 遍历所有启用流控的流，把「已消费偏移」再发一遍。
            // 有变化时立即发（低延迟），无变化时每 4 个周期（200ms）强制发一次
            // （抗丢包）。详见循环外 `resend_tick` 的注释。
            _ = resend_tick.tick() => {
                tick_count = tick_count.wrapping_add(1);
                let force = tick_count % 10 == 0;
                let now = now_ms();

                // ---- ARQ 定时任务（每 50ms）----
                //
                // 两件事，都必须靠定时器（无法由事件驱动）：
                // 1. **发 Ack**：对端可能在等我们的确认，但我们没有新数据要发
                //    （纯下载场景），若不主动发，对端只能靠 PTO 重传
                // 2. **时间阈值丢包 + PTO**：包丢了但没有后续包被确认时，
                //    包阈值永远不触发，只能靠时间
                //
                // 遍历期间可能要 `out.send()`（await），所以先收集再发。
                let mut arq_out: Vec<OwnedFrame> = Vec::new();
                for (sid, entry) in slots.iter_mut() {
                    let Some(arq_tx) = entry.arq_tx.clone() else {
                        continue;
                    };

                    // --- 1) 待发的 Ack ---
                    if let Some(rx) = entry.arq_rx.as_mut() {
                        let received = rx.acks.received_count();
                        // 有新的确认范围才发（避免空 ACK 占用带宽）
                        let has_news = received > rx.acked_at_last_send;
                        let due = now.saturating_sub(rx.last_ack_ms) >= 25;
                        if has_news && due && rx.acks.largest().is_some() {
                            let delay = now.saturating_sub(rx.last_ack_ms);
                            let mut payload = Vec::with_capacity(16);
                            if rx.acks.encode(delay, &mut payload).is_some() {
                                arq_out.push(OwnedFrame::new(
                                    FrameType::Ack,
                                    Flags::empty(),
                                    sid,
                                    0,
                                    payload,
                                ));
                                rx.last_ack_ms = now;
                                rx.acked_at_last_send = received;
                            }
                        }
                    }

                    // --- 2) 时间阈值丢包 + PTO 探测 ---
                    for mut f in arq_tx.poll_timeouts() {
                        f.stream_id = sid;
                        arq_out.push(f);
                    }
                }
                // 同上：全部用 `try_send`，避免读循环被写队列反压。
                // Ack / Window / PTO 重传都是可重发的，丢弃安全。
                for f in arq_out {
                    match out.try_send(f) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                        Err(_) => return,
                    }
                }

                for (sid, entry) in slots.iter() {
                    let Some(fc) = entry.recv_flow.as_ref() else {
                        continue;
                    };
                    let offset = fc.current_offset();
                    // 未变化的周期跳过（省带宽）；`force` 时无条件重发
                    if !force && offset == fc.advertised() as u32 {
                        continue;
                    }
                    let mut payload = Vec::with_capacity(4);
                    encode_window_credit(offset, &mut payload);
                    let wf =
                        OwnedFrame::new(FrameType::Window, Flags::empty(), sid, 0, payload);
                    // ★ 用 `try_send` 而非 `send().await`：**读循环绝不能被写队列堵住**。
                    //
                    // 若这里阻塞，读循环就无法处理对端发来的 `Ack` → 发送侧
                    // `largest_acked` 不更新 → 包阈值丢包检测永不触发 →
                    // 只能靠 PTO（秒级 + 指数退避）→ 大量丢包时永远补不完。
                    //
                    // 信用帧本身就是幂等的（绝对偏移），丢了下一轮（20ms）
                    // 或 200ms 的强制重发会补上，所以丢弃完全安全。
                    match out.try_send(wf) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // 写队列拥塞：跳过本轮，下轮自然会重发
                        }
                        Err(_) => break, // 通道关闭 = 隧道已断
                    }
                }
            }

            // ---- 控制命令：注册 / 注销（低频，每连接一次）----
            cmd = ctl.recv(), if ctl_open => {
                match cmd {
                    Some(Ctl::Register { id, entry, reply }) => {
                        // 流数上限的权威判断在这里（读循环独占表）
                        let outcome = if slots.len() >= max_streams as usize {
                            RegOutcome::TooMany
                        } else if slots.insert(id, entry) {
                            active.store(slots.len(), Ordering::Relaxed);
                            RegOutcome::Ok
                        } else {
                            RegOutcome::IdTaken
                        };
                        // 调用方若已放弃等待（超时/取消），reply 失败可忽略
                        let _ = reply.send(outcome);
                    }
                    Some(Ctl::Unregister { id }) => {
                        if slots.remove(id).is_some() {
                            active.store(slots.len(), Ordering::Relaxed);
                        }
                    }
                    // ★ Mux 已 drop → **立即退出**，不能"继续等在途数据"。
                    //
                    // 这里曾经写的是 `ctl_open = false`（禁用分支但继续循环），
                    // 会造成**循环依赖死锁**：
                    //
                    // ```text
                    // read_loop 持有 out(Sender)
                    //   → write_loop 的 rx 收不到 None，永不退出
                    //   → 底层连接不 shutdown
                    //   → read_loop 的 reader.recv() 等不到 EOF
                    //   → read_loop 永不退出，out 永不释放
                    // ```
                    //
                    // 实测症状：所有 e2e 测试报「服务端应结束: Elapsed」。
                    //
                    // Mux 被 drop 意味着**用户已放弃这条隧道**，
                    // 此时在途数据没有意义，立即退出是正确语义。
                    None => break,
                }
            }

            // ---- 数据帧：热路径，无锁查表 ----
            frame = reader.recv() => {
                let mut frame = match frame {
                    Ok(f) => f,
                    Err(TunnelError::Closed) => {
                        tracing::debug!("隧道被对端关闭");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "读任务失败，隧道终止");
                        break;
                    }
                };

                let sid = frame.stream_id;

                // ---- Ack 帧：ARQ 确认，不上投递 ----
                //
                // 与 `Window` 一样是**控制帧**，必须在这里拦截，
                // 否则上层会看到不该看到的帧。
                //
                // 照抄 RFC 9002 伪代码 A.7 `OnAckReceived`：
                // 移除已确认 → 更新 RTT → 检测丢包 → 重传。
                if frame.frame_type == FrameType::Ack {
                    let Ok((ranges, ack_delay)) = AckRanges::decode(&frame.payload) else {
                        tracing::warn!(stream_id = sid, "Ack 帧载荷非法，忽略");
                        continue;
                    };
                    let Some(arq) = slots.get(sid).and_then(|e| e.arq_tx.as_ref()).cloned()
                    else {
                        // 未知流或不可靠流：Ack 无意义，忽略
                        tracing::trace!(stream_id = sid, "收到未知/不可靠流的 Ack，忽略");
                        continue;
                    };
                    // 先 clone 出结构再释放借用（下面要 await）
                    let retransmit = arq.on_ack(&ranges, ack_delay);
                    for mut f in retransmit {
                        f.stream_id = sid;
                        // 重传走同一个写队列，与数据帧一起被批量合并
                        if out.send(f).await.is_err() {
                            tracing::debug!("写队列已关闭，重传失败");
                            break;
                        }
                    }
                    continue;
                }

                // ---- Window 帧：授信给本流的发送侧，不投递给应用 ----
                //
                // 必须在投递前拦截：`Window` 是流控元信息，不属于数据流，
                // 若投递给 `StreamReceiver` 会让上层看到不该看到的帧。
                if frame.frame_type == FrameType::Window {
                    match decode_window_credit(&frame.payload) {
                        Ok(offset) => {
                            if let Some(flow) = slots.get(sid).and_then(|e| e.send_flow.as_ref()) {
                                // 绝对偏移：幂等，丢包/乱序/重复都安全
                                flow.set_acked(offset);
                                tracing::trace!(stream_id = sid, offset, "收到窗口更新");
                            } else {
                                tracing::trace!(stream_id = sid, "收到未知流的窗口更新，忽略");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(stream_id = sid, error = %e, "窗口帧载荷非法");
                        }
                    }
                    continue;
                }

                // 用 `get_mut`：ARQ 的重排缓冲需要可变访问。
                // 读循环是流表的唯一持有者，所以这里没有借用冲突。
                let Some(entry) = slots.get_mut(sid) else {
                    // 未知 stream_id：本地已关闭但服务端还有残留包，直接丢弃。
                    // 这在 TCP 语义下完全正常（RST 后对端仍可能发来在途数据）。
                    tracing::trace!(stream_id = sid, "丢弃未知流的帧");
                    continue;
                };

                // ---- ARQ 发送侧状态（`Ack` 帧需要它来授信/检测丢包）----
                let arq_tx = entry.arq_tx.clone();
                let inbound = entry.inbound.clone();

                // ---- 接收侧记账（**只记账，绝不在这里补发信用**）----
                //
                // 教训：这里曾经在记账后立刻 `poll_grant()` 补发信用，
                // 结果**必然死锁**，实测卡在恰好 `DEFAULT_STREAM_WINDOW`：
                //
                // ```text
                // 本循环是单任务，`inbound.send()` 有空位时不 yield
                //   → 一口气把整个窗口全塞进队列（这期间 consumed 恒为 0）
                //   → 每次 poll_grant 都算得 target = 0 + window = advertised
                //      → 一律返回 None，一个字节都没补发
                //   → 对端发完初始窗口后阻塞等信用，不再有新数据到达
                //   → 本循环也没机会再调 poll_grant → 双向永久阻塞
                // ```
                //
                // 正确做法：`poll_grant` 必须紧跟 `on_consumed`，
                // 而 `on_consumed` 只发生在**应用取走数据**时。
                // 所以补发逻辑放在 `StreamReceiver::recv()` 里（见该处注释）。
                //
                // 注意 `on_received` 在这里（收到即记账，含乱序），
                // 而 `on_consumed` 在 `StreamReceiver::recv`（按序交付后才算消费）。
                // 两者的差 = 缓冲中未交付的字节，正是流控要限制的量。
                if frame.frame_type == FrameType::Data {
                    if let Some(fc) = entry.recv_flow.as_ref() {
                        fc.on_received(frame.payload.len());
                    }
                }

                // ---- Close 帧：可靠流必须进重排（FIN 有序化）----
                //
                // 见 `StreamSender::close` 的注释：FIN 是「最后一个字节之后」，
                // 必须排在所有在途 `Data` 之后。绕过重排会导致提前关流。
                // FIN 是否走 ARQ 序号空间？
                //
                // 只有「seq >= 已交付进度」的才是真正的有序 FIN。
                // `seq < next_seq` 的 FIN 有二种来源：
                //   - 测试桩 / 简易对端，直接用 `OwnedFrame::close()`（seq=0）
                //   - 异常重置帧（不走 ARQ）
                // 这类 FIN 必须按普通 Close 立即处理，否则会被重排当作
                // 「重复包」丢弃 → 流永不关闭 → 上层死等（实测 e2e 全部超时）。
                let use_ordered_fin = frame.frame_type == FrameType::Close
                    && frame.is_fin()
                    && arq_tx.is_some()
                    && entry
                        .arq_rx
                        .as_ref()
                        .is_some_and(|rx| frame.pkt_seq >= rx.reorder.next_seq());
                if use_ordered_fin {
                    let ready = if let Some(rx) = entry.arq_rx.as_mut() {
                        rx.acks.insert(frame.pkt_seq);
                        match rx.reorder.push(frame.pkt_seq, Vec::new(), true) {
                            Ok(list) => list,
                            Err(e) => {
                                tracing::warn!(stream_id = sid, error = %e, "重排缓冲溢出，关闭流");
                                let _ = inbound.send(OwnedFrame::close(sid, false)).await;
                                slots.remove(sid);
                                active.store(slots.len(), Ordering::Relaxed);
                                continue;
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    let mut gone = false;
                    for (payload, is_close) in ready {
                        let f = if is_close {
                            OwnedFrame::close(sid, true)
                        } else {
                            OwnedFrame::new(FrameType::Data, frame.flags, sid, frame.pkt_seq, payload)
                        };
                        if inbound.send(f).await.is_err() {
                            gone = true;
                            break;
                        }
                    }
                    if gone && slots.remove(sid).is_some() {
                        active.store(slots.len(), Ordering::Relaxed);
                    }
                    continue;
                }

                // ---- 其他非 Data 帧：原样投递（异常 Close / Ping / Error 等）----
                //
                // ★ 绝不能在下面「重建帧」的路径里被改写类型 ——
                // 曾经把 `Close` 也重建成 `Data`，导致对端永远收不到关闭信号，
                // `pump` 的下行分支死等，整条流卡住（实测 e2e 全部超时）。
                if frame.frame_type != FrameType::Data {
                    if inbound.send(frame).await.is_err() && slots.remove(sid).is_some() {
                        active.store(slots.len(), Ordering::Relaxed);
                    }
                    continue;
                }

                // ---- Data 帧：ARQ 重排（仅可靠流）----
                //
                // 可靠流必须**按序交付**：`pkt_seq` 是发送顺序，而 TCP 流要求
                // 字节顺序。乱序直接交付会让字节流错乱（实测过 16MB 内容错位）。
                //
                // 不可靠流（UDP）不做重排：数据报的顺序由上层协议自己负责
                // （这正是 UDP 语义），而且重排会让延迟变大。
                let ready: Vec<(Vec<u8>, bool)> = if arq_tx.is_some() {
                    if let Some(rx) = entry.arq_rx.as_mut() {
                        rx.acks.insert(frame.pkt_seq);
                        match rx.reorder.push(
                            frame.pkt_seq,
                            std::mem::take(&mut frame.payload),
                            false,
                        ) {
                            Ok(list) => list,
                            Err(e) => {
                                // 重排缓冲溢出 = 对端违约或实现 bug。
                                // 断开比继续更安全（继续会让内存无限增长）。
                                tracing::warn!(stream_id = sid, error = %e, "重排缓冲溢出，关闭流");
                                let _ = inbound.send(OwnedFrame::close(sid, false)).await;
                                slots.remove(sid);
                                active.store(slots.len(), Ordering::Relaxed);
                                continue;
                            }
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    // 不可靠流：原样交付（顺序由上层协议自己负责）
                    vec![(std::mem::take(&mut frame.payload), false)]
                };

                // ---- 投递给应用 ----
                // 可靠流可能一次交付多个（补洞后连锁交付）；
                // 队列满则阻塞 —— 这是**有意**的背压。
                let mut receiver_gone = false;
                for (payload, is_close) in ready {
                    let f = if is_close {
                        OwnedFrame::close(sid, true)
                    } else {
                        OwnedFrame::new(FrameType::Data, frame.flags, sid, frame.pkt_seq, payload)
                    };
                    if inbound.send(f).await.is_err() {
                        receiver_gone = true;
                        break;
                    }
                }
                // 该流的接收端可能已 drop（本地连接关闭）→ 顺手清理槽位，
                // 这是 `Guard::drop` 的 try_send 失败时的兜底。
                if receiver_gone && slots.remove(sid).is_some() {
                    active.store(slots.len(), Ordering::Relaxed);
                }
            }
        }
    }

    // 清除所有槽位 → 各 StreamReceiver 的 recv() 返回 None → 上层关闭本地连接
    slots.clear();
    active.store(0, Ordering::Relaxed);
    tracing::debug!(frames = reader.frames_received(), "读任务退出");
}

/// 一条已打开的流的「句柄」：可直接拆成收发两端。
pub struct StreamHandle {
    /// 发送端。
    pub sender: StreamSender,
    /// 接收端。
    pub receiver: StreamReceiver,
}

impl StreamHandle {
    #[allow(clippy::too_many_arguments)]
    fn pair(
        id: u16,
        out: mpsc::Sender<OwnedFrame>,
        inbound: mpsc::Receiver<OwnedFrame>,
        guard: Arc<Guard>,
        max_payload: usize,
        reliable: bool,
        send_flow: Option<Arc<SendFlow>>,
        recv_flow: Option<Arc<FlowCounters>>,
        arq: Option<Arc<ArqSender>>,
    ) -> (StreamSender, StreamReceiver) {
        (
            StreamSender {
                id,
                // 发送端需要写队列来发数据帧
                out: out.clone(),
                guard: Arc::clone(&guard),
                max_payload,
                seq: 0,
                reliable,
                send_flow,
                arq,
            },
            StreamReceiver {
                id,
                inbound,
                guard,
                recv_flow,
                // 接收端也需要写队列：消费数据后要补发 `Window` 信用帧。
                // 早期没给这个字段，导致补发无处可发 → 流控死锁。
                out,
            },
        )
    }

    /// 流 ID。
    pub fn id(&self) -> u16 {
        self.sender.id
    }

    /// 拆成 (发送端, 接收端)，便于分别交给两个任务。
    pub fn split(self) -> (StreamSender, StreamReceiver) {
        (self.sender, self.receiver)
    }
}

/// 流发送端。
pub struct StreamSender {
    /// 流 ID。
    pub id: u16,
    out: mpsc::Sender<OwnedFrame>,
    /// 注销守卫：本端 drop 时若接收端也已 drop，则从注册表移除。
    /// 字段本身不读取，但持有它才能保证 Drop 时机正确。
    #[allow(dead_code)]
    guard: Arc<Guard>,
    max_payload: usize,
    /// 流内包序号（Phase 4 的 ARQ 会用到；Phase 3 仅递增用于诊断）。
    seq: u32,
    /// 发送侧信用。`None` = 不启用流控（UDP 流）。
    send_flow: Option<Arc<SendFlow>>,
    /// **该流是否可靠**（是否需要 ARQ 重传）。
    ///
    /// # 这是流级属性，不是帧级属性（关键设计）
    ///
    /// 由开流帧类型唯一决定：
    /// - `OpenTcp` → `true`（TCP 是可靠字节流，丢了必须重传）
    /// - `OpenUdp` → `false`（UDP 是数据报，丢了就丢 —— 这正是 UDP 语义）
    ///
    /// 与 Hysteria 2 的做法一致：它的 TCP 走 QUIC stream（可靠，有 ACK + 重传），
    /// UDP 走 QUIC unreliable datagram（RFC 9221，无重传；
    /// 官方文档明确「任一分片丢失则整个包丢弃」）。
    ///
    /// # 为什么不逐帧决定
    ///
    /// 若可靠性由每个 Data 帧自己声明，只要有**一帧**漏标 `RELIABLE`，
    /// 该 TCP 流就会静默丢一段数据 —— 对上层表现为「下载文件损坏」，
    /// 且几乎不可能复现定位。因此以流状态为权威，
    /// 帧上的 `RELIABLE` 只是冗余校验（见 [`crate::mux`] 模块文档）。
    reliable: bool,
    /// ARQ 发送侧状态。`None` = 不可靠流（UDP），不做重传。
    arq: Option<Arc<ArqSender>>,
}

impl StreamSender {
    /// 单帧最大 payload。
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// 发送数据（自动按 `max_payload` 分片）。
    ///
    /// # 为什么要分片
    ///
    /// 一次 `read()` 可能拿到 64KB（内核缓冲），但单帧上限受记录层
    /// （16384）与 MTU（1400）共同约束。在发送侧统一分片，服务端就永远
    /// 只需处理"合乎规格"的帧，不必到处做防御性判断。
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), MuxError> {
        // 可靠性由流的类型决定（TCP=可靠，UDP=不可靠），在此统一打标。
        let flags = if self.reliable {
            Flags::empty().with(Flags::RELIABLE)
        } else {
            Flags::empty()
        };

        for chunk in data.chunks(self.max_payload) {
            // ★ 先申请信用再发（可靠流）。
            //
            // 顺序不能颠倒：先发再记账会让对端短暂收到超限数据 ——
            // 若接收方缓冲已满，这些数据要么被丢弃（TCP 语义被破坏），
            // 要么撑爆内存。
            //
            // `acquire` 在信用不足时会 `await` 等待 `Window` 帧，
            // 这就是**按流背压**：只有这条流被卡住，其他流照常跑
            // （不像全隧道背压会连带卡住所有流）。
            if let Some(flow) = &self.send_flow {
                flow.acquire(chunk.len()).await?;
            }

            // 在途包数上限（简化版拥塞窗口）。
            //
            // 为什么在信用之外还要限包数：信用按**字节**控制，而 ACK 帧的
            // 表达力按**包数**受限。8 MB 窗口 = 5700 个包，10% 丢包就有
            // 570 个乱序段，超出单个 ACK 帧能装下的范围数（≈300）→
            // 老包永远得不到确认 → 反复重传 → 停滞。
            //
            // 详见 `flowtcp_proto::arq::MAX_INFLIGHT_PKTS` 的实测表格。
            if let Some(a) = &self.arq {
                let mut spins = 0u32;
                while !a.can_send() {
                    // 让出执行权，等读循环处理 ACK（它会移除在途包）
                    tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                    spins += 1;
                    // 防御：极端情况下（对端消失）不要无限等
                    if spins > 25_000 {
                        return Err(MuxError::TunnelClosed);
                    }
                }
            }

            // 序号来源：可靠流用 ARQ 的共享计数器（重传也从这里取，
            // 保证全局唯一）；不可靠流用本地计数器。
            let seq = match &self.arq {
                Some(a) => a.next_seq(),
                None => {
                    let s = self.seq;
                    self.seq = self.seq.wrapping_add(1);
                    s
                }
            };
            let f = OwnedFrame::new(FrameType::Data, flags, self.id, seq, chunk.to_vec());
            // ★ 先登记在途再发出（顺序不可颠倒，见 `ArqTx::on_sent` 的注释）
            if let Some(a) = &self.arq {
                a.on_sent(f.clone());
            }
            self.out.send(f).await.map_err(|_| MuxError::TunnelClosed)?;
        }
        Ok(())
    }

    /// 在途未确认包数（仅可靠流有意义；诊断用）。
    #[allow(dead_code)]
    pub fn inflight_packets(&self) -> Option<usize> {
        self.arq.as_ref().map(|a| a.inflight())
    }

    /// 该流是否需要 ARQ 重传。
    pub fn is_reliable(&self) -> bool {
        self.reliable
    }

    /// 当前可用发送信用（仅可靠流有意义；UDP 流返回 `None`）。
    pub fn available_credit(&self) -> Option<u64> {
        self.send_flow.as_ref().map(|f| f.available())
    }

    /// 发送带目标地址的数据（UDP 会话切换目标时用）。
    pub async fn send_datagram(&mut self, target: &Address, data: &[u8]) -> Result<(), MuxError> {
        let mut payload = Vec::with_capacity(data.len() + 20);
        target
            .encode(&mut payload)
            .map_err(|e| MuxError::Tunnel(TunnelError::Frame(e)))?;
        payload.extend_from_slice(data);

        // UDP 数据报：**永不带 RELIABLE**（丢了就丢，这才是 UDP 语义）。
        // HAS_ADDR 表示 payload 前置了目标地址（切换目标时需要）。
        let f = OwnedFrame::new(
            FrameType::Data,
            Flags::empty().with(Flags::HAS_ADDR),
            self.id,
            self.seq,
            payload,
        );
        self.seq = self.seq.wrapping_add(1);
        self.out.send(f).await.map_err(|_| MuxError::TunnelClosed)
    }

    /// 关闭流。
    ///
    /// `fin = true` 表示正常关闭；`false` 表示重置。
    ///
    /// # 可靠流的 FIN 必须占用一个 ARQ 序号
    ///
    /// FIN 在语义上是「流的最后一个字节之后」，**必须排在所有 `Data` 之后**。
    /// 若它用固定 seq（如 0）绕过重排，就会超过仍在途的数据提前生效 ——
    /// 实测（`FLOWTCP_DROP_DATA=5`）请求包被丢 + FIN 先到 → 服务端提前半关闭
    /// → 重传的请求无处可投 → 下载拿到 **0 字节**。
    ///
    /// 所以可靠流的 FIN 走 `next_seq()`，接收方按序处理它。
    /// 不可靠流（UDP）无重排概念，seq 保持 0。
    pub async fn close(&self, fin: bool) -> Result<(), MuxError> {
        let seq = match &self.arq {
            Some(a) => a.next_seq(),
            None => 0,
        };
        let mut f = OwnedFrame::close(self.id, fin);
        f.pkt_seq = seq;
        // FIN 也要登记在途：否则它丢了就再也不会重发
        if let Some(a) = &self.arq {
            a.on_sent(f.clone());
        }
        self.out.send(f).await.map_err(|_| MuxError::TunnelClosed)
    }

    /// 流 ID（避免 `pub id` 与 trait 冲突时的备用访问器）。
    pub fn stream_id(&self) -> u16 {
        self.id
    }
}

/// 流接收端。
pub struct StreamReceiver {
    /// 流 ID。
    pub id: u16,
    inbound: mpsc::Receiver<OwnedFrame>,
    #[allow(dead_code)]
    guard: Arc<Guard>,
    /// 接收侧窗口。`None` = 不启用流控（UDP 流）。
    ///
    /// **消费方必须在数据成功写入下游后调用 `on_consumed`**，
    /// 否则信用永不恢复 → 发送方永久阻塞（流控死锁）。
    /// 这就是「信用按已交付而非已接收计算」的落地点。
    recv_flow: Option<Arc<FlowCounters>>,
    /// 隧道写队列：消费数据后在这里补发 `Window` 信用帧。
    ///
    /// 为什么接收端也要持有写队列？因为**补发信用的唯一正确时机是消费之后**
    /// （见 [`Self::recv`] 的详细解释）。读循环不能代劳 ——
    /// 它跑在消费之前，那时 `consumed` 还没前进。
    out: mpsc::Sender<OwnedFrame>,
}

impl StreamReceiver {
    /// 收下一帧。
    ///
    /// 返回 `None` 表示隧道或该流已关闭。
    ///
    /// # ★ 这里是整个信用流控的**唯一正确补发点**
    ///
    /// 取出数据的同时做两件事：
    /// 1. `on_consumed(n)` —— 告诉窗口「这段已被应用吃掉」
    /// 2. `poll_grant()` —— 按新的 `consumed` 算出该补多少信用并发 `Window` 帧
    ///
    /// ## 为什么必须在这里，而不是在读循环
    ///
    /// 窗口的目标上限是 `consumed + window`。**`consumed` 只在消费时前进**，
    /// 而读循环跑在消费**之前**。
    ///
    /// 曾经的写法是读循环收到 Data 就 `poll_grant`，实测**必然死锁**：
    /// 读循环是单任务，塞队列时不 yield，一口气塞满 256 KB 而应用一个字节
    /// 都没取走 → 每次 `poll_grant` 都算得 `target = 0 + window = advertised`
    /// → 一个字节都不补发 → 对端发完初始窗口就永久阻塞。
    /// 现象是「传了几百 KB 后彻底卡住」，且没有任何错误日志。
    ///
    /// 搬到消费点后，`consumed` 一定是最新的，时机天然正确。
    /// 顺带解决了「调用方忘了上报」的误用风险 —— 上报与补发都在 `recv()` 内完成，
    /// 只要数据被取走就一定会补发。
    ///
    /// 缓冲上限由 `inbound` 队列深度保证（256 帧 ≈ 358 KB），
    /// 所以「取走即算消费」不会让内存失控。
    pub async fn recv(&mut self) -> Option<OwnedFrame> {
        let f = self.inbound.recv().await?;

        // 只有 Data 帧占流控额度（Window/Close/Ping 等控制帧不计）
        if f.frame_type != FrameType::Data {
            return Some(f);
        }

        // 1) 记账：这段数据已被应用取走
        self.on_consumed(f.payload.len());

        // 2) 按需补发信用。`poll_grant` 自带「消耗过半才补」的节流，
        //    所以这里逐帧调用不会产生大量小帧 —— 大多数调用直接返回 None。
        if let Some(delta) = self.recv_flow.as_ref().and_then(|fc| fc.poll_grant()) {
            let mut payload = Vec::with_capacity(4);
            encode_window_credit(delta, &mut payload);
            let wf = OwnedFrame::new(FrameType::Window, Flags::empty(), self.id, 0, payload);
            // 用 `try_send`：这是消费侧路径，若在这里 await 写队列，
            // 应用取数据的节奏就被写队列的拥塞绑住了。
            // 丢了无所谓 —— 读循环的周期重发（20ms / 200ms）会补上。
            let _ = self.out.try_send(wf);
        }

        Some(f)
    }

    /// 流 ID。
    pub fn stream_id(&self) -> u16 {
        self.id
    }

    /// 手动上报已消费的字节数。
    ///
    /// 通常**不需要**调用 —— [`Self::recv`] 已自动上报并补发信用。
    /// 只有在你需要「先把数据暂存、稍后才确认消费」的高级场景才用得到
    /// （例如自己做批处理，想让窗口更保守）。
    ///
    /// 注意：手调本方法**不会**触发信用补发（补发在 `recv` 内），
    /// 所以单独调用它意义有限。
    #[inline]
    pub fn on_consumed(&self, n: usize) {
        if let Some(fc) = self.recv_flow.as_ref() {
            fc.on_consumed(n);
        }
    }

    /// 接收侧窗口统计（诊断用）。
    pub fn flow(&self) -> Option<&Arc<FlowCounters>> {
        self.recv_flow.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tunnel_pair;
    use flowtcp_proto::frame::Address;
    use std::time::Duration;

    /// ★ TCP 流的 Data 帧必须带 `RELIABLE`，UDP 流必须不带。
    ///
    /// 这是「TCP 可靠 / UDP 不可靠」在线格式上的落地点。
    /// 与 Hysteria 2 的划分一致：
    /// - TCP → QUIC bidirectional stream（可靠，有 ACK + 重传）
    /// - UDP → QUIC unreliable datagram（RFC 9221，无重传）
    #[tokio::test]
    async fn tcp流带reliable标志而udp流不带() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 8, 1400);

        // ---- TCP 流 ----
        let mut tcp = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();
        assert!(tcp.sender.is_reliable(), "TCP 流必须标记为可靠");
        assert_eq!(
            server.reader.recv().await.unwrap().frame_type,
            FrameType::OpenTcp
        );
        tcp.sender.send_data(b"x").await.unwrap();
        let f = server.reader.recv().await.unwrap();
        assert!(
            f.flags.has(Flags::RELIABLE),
            "TCP 流的 Data 帧必须带 RELIABLE（否则 FakeTCP 下丢了不重传 → TCP 语义被破坏）"
        );

        // ---- UDP 流 ----
        let mut udp = mux
            .open_udp(Address::Domain("dns.example".into(), 53))
            .await
            .unwrap();
        assert!(!udp.sender.is_reliable(), "UDP 流必须标记为不可靠");
        assert_eq!(
            server.reader.recv().await.unwrap().frame_type,
            FrameType::OpenUdp
        );
        udp.sender.send_data(b"y").await.unwrap();
        let f = server.reader.recv().await.unwrap();
        assert!(
            !f.flags.has(Flags::RELIABLE),
            "UDP 流的 Data 帧绝不能带 RELIABLE —— 否则会为重传引入额外延迟，违背 UDP 语义"
        );
    }

    /// UDP 的 `send_datagram`（带目标地址）同样不能带 `RELIABLE`。
    #[tokio::test]
    async fn udp数据报不带reliable() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 8, 1400);
        let h = mux
            .open_udp(Address::Domain("a.example".into(), 53))
            .await
            .unwrap();
        let (mut tx, _rx) = h.split();
        server.reader.recv().await.unwrap(); // OpenUdp

        tx.send_datagram(&Address::V4("8.8.8.8:53".parse().unwrap()), b"q")
            .await
            .unwrap();
        let f = server.reader.recv().await.unwrap();
        assert!(f.flags.has(Flags::HAS_ADDR), "应带目标地址");
        assert!(!f.flags.has(Flags::RELIABLE), "UDP 数据报不得带 RELIABLE");
    }

    /// 开流后服务端应收到 `OpenTcp` 帧，且地址与请求一致。
    #[tokio::test]
    async fn 开流后能收到open帧() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 16, 1400);

        let target = Address::V4("127.0.0.1:80".parse().unwrap());
        let handle = mux.open_tcp(target.clone()).await.unwrap();
        let id = handle.id();

        let f = server.reader.recv().await.unwrap();
        assert_eq!(f.frame_type, FrameType::OpenTcp);
        assert_eq!(f.stream_id, id);
        let (addr, _) = Address::decode(&f.payload).unwrap();
        assert_eq!(addr, target);
    }

    #[tokio::test]
    async fn 数据双向互通() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 16, 100);

        let handle = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();
        let (mut tx, mut rx) = handle.split();

        // 服务端先读掉 OpenTcp
        let open = server.reader.recv().await.unwrap();
        assert_eq!(open.frame_type, FrameType::OpenTcp);
        let sid = open.stream_id;

        // 客户端发 250 字节 → 按 max_payload=100 应切成 3 帧
        tx.send_data(&[0xAB; 250]).await.unwrap();
        let mut got = Vec::new();
        while got.len() < 250 {
            let f = server.reader.recv().await.unwrap();
            assert_eq!(f.frame_type, FrameType::Data);
            assert_eq!(f.stream_id, sid);
            got.extend_from_slice(&f.payload);
        }
        assert_eq!(got, vec![0xAB; 250]);

        // 服务端回发 → 客户端 StreamReceiver 应收到
        server
            .writer
            .send(&OwnedFrame::data(sid, b"pong".to_vec()))
            .await
            .unwrap();
        let f = rx.recv().await.expect("应收到帧");
        assert_eq!(f.payload, b"pong");
    }

    #[tokio::test]
    async fn 关闭流后注册表清理() {
        let (client, _server) = tunnel_pair();
        let mux = Mux::spawn(client, 16, 1400);
        let handle = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();
        // 注册是同步完成的（open_stream 会 await RegOutcome）
        assert_eq!(mux.active_streams(), 1);

        drop(handle);

        // 注销是**异步**的：`Guard::drop` 只能 `try_send`（Drop 不能 await），
        // 由读循环收到 `Ctl::Unregister` 后才真正移除槽位。
        // 因此 `active_streams()` 是最终一致（only for stats）；
        // 权威的流数上限判定在读循环内同步完成，不受影响。
        let mut waited = 0;
        while mux.active_streams() != 0 && waited < 100 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            waited += 1;
        }
        assert_eq!(mux.active_streams(), 0, "注销应在 500 ms 内生效");
    }

    #[tokio::test]
    async fn 超过流上限被拒绝() {
        let (client, _server) = tunnel_pair();
        let mux = Mux::spawn(client, 2, 1400);

        let _a = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();
        let _b = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await
            .unwrap();

        let e = mux
            .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
            .await;
        assert!(matches!(e, Err(MuxError::TooManyStreams(2))));
    }

    #[tokio::test]
    async fn stream_id不重复() {
        let (client, _server) = tunnel_pair();
        let mux = Mux::spawn(client, 64, 1400);

        let mut ids = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..32 {
            let h = mux
                .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
                .await
                .unwrap();
            ids.push(h.id());
            handles.push(h);
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "stream_id 必须唯一");
        assert!(!ids.contains(&0), "0 是保留 id");
    }

    #[tokio::test]
    async fn udp帧带目标地址() {
        let (client, mut server) = tunnel_pair();
        let mux = Mux::spawn(client, 8, 1400);

        let h = mux
            .open_udp(Address::Domain("dns.example".into(), 53))
            .await
            .unwrap();
        let (mut tx, _rx) = h.split();

        let open = server.reader.recv().await.unwrap();
        assert_eq!(open.frame_type, FrameType::OpenUdp);
        let (addr, _) = Address::decode(&open.payload).unwrap();
        assert_eq!(addr, Address::Domain("dns.example".into(), 53));

        // 切目标：带 HAS_ADDR
        tx.send_datagram(&Address::V4("8.8.8.8:53".parse().unwrap()), b"q")
            .await
            .unwrap();
        let f = server.reader.recv().await.unwrap();
        assert_eq!(f.frame_type, FrameType::Data);
        assert!(f.flags.has(Flags::HAS_ADDR));
        let (addr, used) = Address::decode(&f.payload).unwrap();
        assert_eq!(addr, Address::V4("8.8.8.8:53".parse().unwrap()));
        assert_eq!(&f.payload[used..], b"q");
    }
}
