# FlowTCP 变更日志

所有变更记录使用北京时间（UTC+8）。新记录追加在最上方。

---

- [2026-11-11 01:56 北京时间] ★★★ Phase 4.6 ARQ 完成：照抄 QUIC RFC 9002，0~30% 丢包全部逐字节完整
  - **背景**：按用户要求「优先用 hy1/hy2 的成熟方法」。hy2 的 ARQ 就是 **quic-go**，
    因此直接照抄 RFC 9002（丢包检测与 RTT 估计）与 RFC 9000 §19.3（范围 ACK）
  - **新增 `flowtcp-proto/src/arq.rs`（33 单测）**
    - `RttEstimator`：`smoothed = 7/8·smoothed + 1/8·adjusted`，
      `rttvar = 3/4·rttvar + 1/4·|smoothed-adjusted|`，含 ACK 延迟扣除（§5.3）
    - `AckRanges`：**范围 ACK**（替代原设计的 64 位位图），最多 300 个段
    - `SendBuffer`：包阈值 3 + 时间阈值 9/8·RTT（§6.1）
    - `ReorderBuffer`：按序交付 + FIN 有序化
    - `ArqSender`/`ArqReceiver`：两侧共用的完整状态机
  - **PTO 照抄 §6.2.1**：`smoothed + max(4·rttvar, 1ms) + max_ack_delay`，指数退避
  - **动态拥塞窗口（Brutal 式）**：`cwnd = clamp(0.8·MAX_ACK_RANGES / 丢包率, 32, 2048)`
    - **丢包不减窗口**（与 Brutal 一致：丢包不是拥塞信号）
    - 核心不变量：`在途包 × 丢包率 ≤ ACK 帧容量`，否则老包永远得不到确认

  - **实测：16 MB 传输，应用层帧注入丢包（真 TCP 承载）**

    | 丢包率 | 下行 | 完整性 | 上行 | 完整性 |
    |--------|------|--------|------|--------|
    | 0% | 69.6 MB/s | ✅ 逐字节一致 | 14.2 MB/s | ✅ |
    | 5% | 16.4 MB/s | ✅ 逐字节一致 | — | — |
    | 10% | 28.1 MB/s | ✅ 逐字节一致 | 14.5 MB/s | ✅ |
    | 20% | 14.0 MB/s | ✅ 逐字节一致 | 13.8 MB/s | ✅ |
    | 30% | 7.2 MB/s | ✅ 逐字节一致 | 12.4 MB/s | ✅ |

    **对比 ARQ 之前（5% 丢包）**：下行 60 s 超时只收 **2.4 MB**，上行卡死

  - **过程中修复的 6 个致命 bug（全部实测暴露）**
    1. **重传用新 seq → 流控重复计数 + 重排缓冲溢出 8.45 MB 强制关流**
       → 改为**复用原 seq**（KCP 做法），重复包幂等丢弃
    2. **`Close` 不占 ARQ 序号 → FIN 超过在途数据提前生效** → 收到 **0 字节**
       → 两侧 FIN 都占用 `next_seq()`
    3. **FIN 走 `Data` 分支「连锁交付」时被 `continue` 跳过** → 流永不关闭
       → 检测到 `is_close` 时执行半关闭
    4. **持续有数据时 `read` 永不超时 → 定时分支不执行 → ACK 一发不出**
       → 抽出 `drive_arq()`，每处理完一批帧就驱动（节流 5ms）
    5. **`has_news` 条件让 ACK 在数据灌完后停发** → 最后空洞永不确认
       → 加「100ms 无条件重发」
    6. **`MAX_ACK_RANGES = 32` 截断最老范围** → 发送端反复重传同一批，
       实测 `duplicate_count` 达 **43 万次** → 提到 300（MTU 上限）
  - **读循环绝不能被写队列堵住**：所有控制帧（Window/Ack/PTO 重传）改用
    `try_send`。原先用 `send().await` 时，数据洪流会堵住读循环 →
    无法处理对端 ACK → 包阈值丢包检测失效 → 只能靠秒级 PTO
  - **收尾 drain**（QUIC 的 draining）：目标 EOF 后先等 inflight 清零再关流，
    否则丢失的尾包再无重传机会（实测丢 46%）
  - 测试：**375 全绿**（ARQ 新增 33 个），clippy 零警告

- [2026-11-11 00:08 北京时间] ★★★ 丢包环境实测 + 按 hy2/QUIC 对齐改造（吞吐 500 倍提升）
  - **背景**：用户要求「模拟丢包环境测试」并「优先用 hy1/hy2 的成熟方法，不要造轮子」。
    为此新建应用层故障注入（`tc netem` 只能模拟链路丢包，真 TCP 承载下会被内核重传
    掩盖，测不出流控真实行为），**结果一测就暴露出致命缺陷**
  - **新增 `flowtcp-proto/src/fault.rs`**：应用层丢帧注入（5 单测）
    - `FLOWTCP_DROP_DATA=<0..100>` / `FLOWTCP_DROP_WINDOW=<0..100>` 环境变量
    - 线程本地 xorshift32（无 `rand` 依赖），热路径退化为两次 `f64` 比较
    - **只丢 Data/Window**，控制帧永不丢（否则无法区分「开流失败」与「流控死锁」）
    - 接入两侧 `write_loop`，等价模拟 FakeTCP 承载的真实丢包

  - **Bug 1（致命）：`Window` 帧是增量语义，丢一个就永久蒸发**
    - 实测：`FLOWTCP_DROP_WINDOW=10` 时下行 45 秒超时只收 **3.3 MB / 16 MB**
    - 根因：增量 `delta` 丢失后那份信用永远消失，累计超过窗口（当时 256 KB）即死锁
    - 修复：改成 **QUIC `MAX_DATA` 式的绝对偏移**（`consumed` 的低 32 位）
      - 幂等：重复收到同一偏移无副作用
      - 抗丢包：中间丢多少帧，只要有一个新帧到达就完全对正
      - 抗乱序：差值 ≥ 2³¹ 视为旧包忽略（与 QUIC 一致）
      - 4 GB 回绕：`wrapping_sub` 差值处理，已验证
    - `SendCredit` 重构为 `acked` / `acked_low` / `used` / `window`
  - **Bug 2：`Window` 帧丢了没人重发**
    - 即便用绝对偏移，若只在「消费时发一次」，那一帧丢了就再无机会
    - 修复：两侧读循环加 **50 ms 周期重发**（有变化立即发，每 4 个周期即 200 ms
      无条件重发一次）—— 即 QUIC **PTO 探测**的简化版
    - 成本：4 字节/流/200 ms，256 流满载也只有 5 KB/s

  - **按 hy2 对齐窗口参数（不再自己拍数字）**
    - 读取 `Brutal` 源码（`brutal.go`）确认其核心公式：
      `cwnd = bps × SmoothedRTT × 2 / ackRate`，`OnCongestionEvent` 是空实现
      （丢包**不降速**），`InSlowStart`/`InRecovery` 均返回 `false`（无状态机）
    - hy2 官方 QUIC 默认窗口：流 **8 MB** / 连接 **20 MB**（严格 2:5 比例），
      Performance 文档另有调优值 25.6 MB / 64 MB（仍 2:5）
    - **改动**：`DEFAULT_STREAM_WINDOW` 256 KB → **8 MB**（放大 32 倍），
      `DEFAULT_CONN_WINDOW` 4 MB → **20 MB**，并加测试强制校验 2:5 比例
    - 新增 `--stream-window <SIZE>` CLI 参数（支持 `512K` / `8M` / `16M`），
      对齐 hy2 的 `initStreamReceiveWindow`；客户端服务端必须一致

  - **实测：丢包环境行为（16 MB，真 TCP 承载）**

    | 场景 | 改造前 | 改造后 | 完整性 |
    |------|--------|--------|--------|
    | Window 丢 10% | 45 s 超时，收 **3.3/16 MB** | **0.128 s，131.5 MB/s** | ✅ 完整 |
    | Window 丢 30% | 死锁 | **0.119 s，141.6 MB/s** | ✅ 完整 |
    | Data 丢 5% | 60 s 超时，收 **2.4/16 MB** | **0.113 s，141.2 MB/s** | 缺 5.06% |
    | Data 丢 5% + Window 丢 10% | 死锁 | 0.116 s，137.2 MB/s | 缺 5.03% |

    **吞吐提升约 500 倍**（3.3 MB/45s ≈ 0.07 MB/s → 131.5 MB/s）
    - `Data` 丢 5% 时恰好丢 5.06% 数据 —— 无额外损失，**这正是 ARQ（Phase 4.6）
      要解决的唯一剩余问题**
    - `tc netem` 链路丢包（1%/5%/10%）实测：1% → 53.8/35.1 MB/s，5% → 9.0/4.3，
      10% → 2.4/1.6 MB/s，数据全部完整（内核 TCP 重传兜底）

  - **RTT 环境验证（`tc netem delay 50ms`，RTT≈100 ms）**
    - 上行：1.5 MB/s（256 KB 窗口）→ **3.2 MB/s**（8 MB 窗口），**2.1 倍**
    - 同期**原生 TCP 基线只有 1.0~15.9 MB/s 且方差极大**（两轮差 16 倍）——
      说明瓶颈是内核 socket 缓冲与 netem 本身，**我们的流控已不再是瓶颈**
    - hy2 Performance 文档第一条建议即 `sysctl net.core.rmem_max=16777216`，已验证

  - 测试：**342 全绿**（+12 新增：fault 5 个、绝对偏移语义 6 个、字节解析 2 个，
    另含 --stream-window 端到端），clippy 零警告

- [2026-11-10 23:35 北京时间] ★★★ Phase 4 信用流控全链路打通 + 修复两个致命死锁
  - **结果**：`proxy_e2e` 10/10 通过（耗时 30.06s → 11.45s），全量 `cargo test --workspace`
    **329 个测试全绿**，`cargo clippy --workspace --all-targets` **零警告**
  - **实测吞吐（release，真 TCP 承载，loopback，64MB 逐字节比对）**

    | 场景 | 本轮 | 流控前基线 | 变化 |
    |------|------|-----------|------|
    | 下行 64MB | **169.9 MB/s** | 143 MB/s | **+19%** |
    | 上行 64MB | **189.5 MB/s** | 154 MB/s | **+23%** |
    | 双向并发 | 123.7 / 126.1 MB/s | 98.8 / 137 MB/s | 合计 +6% |

    完整性与一致性全部 ✅（`cmp` 逐字节一致 / 接收端字节数精确等于 67108864）

  - **Bug 1（死锁）：`poll_grant` 挂错了位置 —— 挂在「接收」而非「消费」**
    - 窗口目标上限是 `consumed + window`，而 `consumed` 只在**应用取走数据**时前进
    - 读循环是单任务，`inbound.send()` 有空位时不 yield → 一口气把 256 KB 塞满队列，
      这期间 `consumed` 恒为 0 → 每次 `poll_grant` 都算得 `target == advertised`
      → **一个字节都没补发** → 对端发完初始窗口就永久阻塞
    - 症状极隐蔽：**恰好卡在 262144 字节（= `DEFAULT_STREAM_WINDOW`）**，
      30 秒超时，无任何错误日志
    - 修复：补发逻辑从 `read_loop` 搬到 `StreamReceiver::recv()`（客户端）与
      `tcp_pump` 中 `on_consumed` 之后（服务端）。**补发必须紧跟消费**，
      这样 `consumed` 一定是最新值
    - 附带收益：`recv()` 内建上报+补发，调用方不可能漏，误用风险归零
  - **Bug 2（死锁）：服务端 `Close` 帧直接删表，导致后续 `Window` 帧无处授信**
    - 客户端发 `Close` 只代表「我不再发数据」，不代表不再收数据
      （典型：`GET /bigfile` 发完请求就半关闭，然后长时间收响应）
    - 原实现 `streams.remove(sid)` 把 `Target` 整个删掉 → `tcp_pump` 虽持有
      `send_flow` 的 clone 继续发数据，但**读循环再也找不到这条流**
      → 客户端补发的 `Window` 帧全被当成「未知流的窗口更新」丢弃
      → 服务端发满 256 KB 后永久阻塞
    - 修复：`Target::Tcp.tx` 改为 `Option<Sender>`，`Close` 时 `take()` 成 `None`
      （drop → `tcp_pump` 收到 EOF 走半关闭），**保留表项供授信寻址**；
      流由 `tcp_pump` 结束时的 `cleanup` 真正注销
  - **顺带清理：`read_loop` 不再持有出站队列**
    - 补发搬走后它不需要 `out` 了。删掉这个持有关系还额外消除了一类风险：
      `read_loop` 持 `Sender` → 写任务收不到 `None` → 不 shutdown → 读循环等不到 EOF
  - 测试：`flow.rs` 新增 19 个（Window 帧 codec / `SendCredit` / `FlowCounters` /
    端到端信用流转 / 窗口关系约束）

- [2026-11-10 23:10 北京时间] ★★★ 修复 3 个静默丢数据 bug（大数据量完整性 100% 达成）+ 实测吞吐
  - **背景**：上一轮吞吐测试出现「16MB 只收到 32KB / 15.4MB」的异常，深挖后发现
    **3 个静默丢数据缺陷**，全部不产生任何错误日志，只能靠字节比对发现
  - **Bug 1：服务端 `write_loop` 用 `let _ = encode()` 吞掉错误**
    - `tcp_pump` 读缓冲 32KB 直接当单帧 payload，而 `MAX_FRAME_PAYLOAD` 是 16KB
    - `if len <= MAX { let _ = encode() }` 条件不成立就跳过编码 → `plain` 为空 → `continue`
    - **该帧被静默丢弃**。症状：下载 16MB 只到 32KB
    - 修复：`encode` 失败必须记 error 并终止写任务；`tcp_pump` 按 `max_payload` 分片
  - **Bug 2：`write_loop` 批量合并时 `try_recv()` 后 `break` 丢帧**
    - `try_recv()` 已把帧取出队列，`break` 后该帧**永久丢失**
    - 症状：16MB 只到 15.4MB，且内容错位（丢的是中间而非尾部）
    - 修复：引入 `carry: Option<OwnedFrame>` 把超限帧「留回」下一轮
  - **Bug 3：★★ 服务端对 TCP 流用 `try_send` 队列满即丢弃**
    - 原注释理由「阻塞会让一个慢目标拖垮整条隧道」对 **UDP** 成立，
      对 **TCP 是灾难性的** —— 可靠字节流丢一个字节就是数据损坏
    - 队列仅 256 帧 ≈ 358KB，read 循环解密远快于 `tcp_pump` 逐帧写目标 socket
    - 症状：上传 64MB 只到达 29MB（**丢 57%**），而客户端 `sendall` 全部成功
    - 修复：TCP 用 `send().await` 施加背压 + 队列提升到 2048 帧（`MAX_RELIABLE_QUEUE`）；
      UDP 保持 `try_send` 丢弃（正确的 UDP 语义）
  - **Bug 4：`pump` 用 `select!` 任一侧结束就取消另一侧**
    - 浏览器半关闭写端（HTTP/1.0 `Connection: close`）后，响应被掐断
    - 修复：用 `tokio::pin!` + 半关闭语义 —— 上行结束只发 FIN 并**继续收下行**
  - **实测吞吐（release 构建，本机 loopback，真 TCP 承载）**：
    | 场景 | 结果 |
    |------|------|
    | 下行 64MB | **143 MB/s（约 1.15 Gbps）**，字节完全一致 |
    | 上行 64MB | **154 MB/s**，字节完全一致 |
    | 双向并发 | 上行 98.8 MB/s + 下行 137 MB/s |
    | 服务端告警 | 0 条 |
  - **新增 2 个回归测试**（总数 308 → **310**）：
    - `下行大流量字节完全一致`（2MB，含首个不一致偏移定位）
    - `上行大流量字节完全一致`（2MB）
    - 两者都**逐字节比对**，不只比长度 —— 这是唯一能抓住此类 bug 的方式

- [2026-11-10 22:47 北京时间] ★★★ 修正可靠性语义：TCP 必须 ARQ、UDP 禁止 ARQ（核实 hy2 官方协议）
  - **背景**：用户指出「hy2 等协议 TCP 是有重传机制的，一般是游戏（UDP）没有重传机制」，
    要求核实。**核实结论：用户判断完全正确。**
  - **hy2 官方协议规范原文确认**（`v2.hysteria.network/docs/developers/Protocol/`）：
    - **TCP** → `QUIC bidirectional stream`（可靠，有 ACK + 重传）
    - **UDP** → `QUIC unreliable datagram`（RFC 9221，无重传）
    - 分片规则直接印证：「If one or more fragments of a packet are lost,
      **the entire packet MUST be discarded**」（丢片即整包丢弃，不重传）
  - **发现并修复代码缺陷**：`StreamSender::send_data` 用 `Flags::empty()`，
    TCP 流与 UDP 流的 `Data` 帧**在帧层面完全无法区分** ——
    Phase 4 接 ARQ 后接收方无法判断该对哪些帧请求重传
  - **修复设计（可靠性是流级属性，不是帧级属性）**：
    - `StreamSender` 新增 `reliable: bool`，由**开流帧类型唯一决定**
      （`OpenTcp` → 可靠；`OpenUdp` → 不可靠），并提供 `is_reliable()` 访问器
    - `send_data` 按 `reliable` 统一打 `Flags::RELIABLE` 标志
    - `send_datagram`（UDP 专用）明确注释「永不带 RELIABLE」
    - **服务端新增一致性校验** `exit::stream_reliable()`：
      `Data` 帧的 `RELIABLE` 与流类型不一致时**立即断开**并记 error 日志
      —— 宁可报错也不要静默丢数据（静默丢数据表现为「下载文件损坏」，几乎无法复现）
  - **新增 2 个回归测试**（总数 306 → **308**）：
    `tcp流带reliable标志而udp流不带`、`udp数据报不带reliable`
  - **`docs/FLOW_CONTROL.md` 新增 §5.2.1 / §5.2.2**：
    - 引用 hy2 官方原文，把「TCP 有重传 / UDP 无重传」的区分写死
    - FlowTCP 的对应设计表（开流帧 → ARQ 策略）
    - 解释「为什么不能统一都可靠」（队头阻塞、延迟放大、流量放大）
    - 强调「可靠性是流级属性」及服务端一致性校验的必要性

- [2026-11-10 22:22 北京时间] ★★ 加密路径 CPU 优化（实测小包 -48%）+ 流控方案调研
  - **背景**：用户明确指出「流控实现不好会导致隧道带宽低、CPU 占用高」，并要求
    「加密算法选用 CPU 原生占用低的方式」。先量化再优化。
  - **新增 `crates/flowtcp-proto/examples/bench_record.rs`**：记录层性能基准
    - 量化了 4 种包大小 × 2 种 AEAD 的加解密耗时
    - 量化了 `Aes128Gcm::new_from_slice`（**124 ns**）与 `Aes128::new_from_slice`（**75 ns**）的代价
  - **★ 关键发现**：每次 `seal`/`open` 都在重建密码学实例，
    合计 **199 ns/包** —— 占 64B 小包（DNS/游戏/VoIP）总耗时的 **44%**
  - **优化 `record.rs`：缓存密码学实例**
    - `Keys` 新增 `cipher: Arc<CachedCipher>`，构造时一次性建立
      `Aes128Gcm` 与 `Aes128`（seq_mask 用）实例
    - `seq_mask` / `encrypt_in_place` / `decrypt_in_place` 改用缓存实例，不再做密钥调度
    - `Keys::clone` 变成 O(1) 引用计数（不再深拷贝 round key 表）
    - 删除已冗余的 `key` / `sn_key` 字段（密钥由实例持有）
  - **实测收益**：
    | 包大小 | 优化前 | 优化后 | 提升 |
    |--------|--------|--------|------|
    | 64B | 452 ns | **235 ns** | **-48%** |
    | 512B | 915 ns | **684 ns** | -25% |
    | 1400B | 1773 ns | **1542 ns** | -13% |
    | 16KB | 16021 ns | 15988 ns | -0.2% |
  - **新增 `AeadAlgo::{hw_accel, preferred, preference_list}`**
    - 运行时 `is_x86_feature_detected!("aes")` 检测 AES-NI，自动选最优算法
    - 有 AES-NI → `Aes128Gcm`；无 → `ChaCha20Poly1305`
    - 实测本机 AES-128-GCM 比 ChaCha20-Poly1305 **小包快 8.0 倍**（235 vs 1881 ns），
      但无 AES-NI 的 ARM 上会反过来 —— 所以必须运行时选，不能写死
  - **新增 5 个回归测试**（总数 292 → **297**）：
    硬件加速检测真实性、首选算法跟随硬件、偏好列表首位一致、
    两种算法线格式长度相同（保证可无缝协商切换）、`Keys::clone` 是引用计数
  - **新增 `docs/FLOW_CONTROL.md`**：QUIC / quinn / TUIC / Hysteria(hy1/hy2) 流控调研
    - QUIC 两级信用制、BDP 铁律（窗口 < BDP 则流控成为吞吐瓶颈）、
      流控帧必须搭便车、丢包导致流控死锁的机理
    - quinn 的参数取舍（`receive_window`/`stream_receive_window`/`send_window`/`send_fairness`/GSO）
    - TUIC 的启示：**UDP 不该走可靠流**（用 QUIC Datagram 而非 STREAM）
    - Hysteria 的 Brutal CC 为何**不适用于我们**（FakeTCP 外层是 TCP，QoS 看不到 UDP）
    - FlowTCP Phase 4 的完整设计方案：`Window` 帧用 32 位增量（省 CPU）、
      三级丢包跳过（超时/FEC/ARQ）、`Vec<Option<Target>>` 替换 `Arc<Mutex<HashMap>>`
    - CPU 优化清单（已完成 + 待做，含预期收益）

- [2026-11-10 21:55 北京时间] ★★★ Phase 3 完成：SOCKS5 / HTTP / HTTPS 三种入口 + 服务端出口数据面
  - **新增 `crates/flowtcp-client`（35 个单元测试）**：完整的客户端侧实现
    - `transport.rs`：承载层抽象 `Transport` trait + `TcpTransport`（Phase 4 接 FakeTCP 时上层零改动）
    - `tunnel.rs`：`Tunnel::handshake_on()` 自研 TLS 1.3 握手 + 记录层 + `FrameWriter`/`FrameReader`
    - `mux.rs`：流复用（stream_id 分配、单写任务串行化、按 id 分发、Drop 自动注销）
    - `entry/socks5.rs`：CONNECT + **UDP ASSOCIATE**（含 SOCKS5 UDP 头解析与目标切换）
    - `entry/http.rs`：CONNECT 隧道 + 绝对 URI 改写为 origin-form
    - `entry/https.rs`：HTTP 代理套本地 TLS，**默认自签证书、可指定文件**
    - `entry/mod.rs`：`pump()` 本地流 ↔ FlowTCP 流双向搬运
    - `config.rs`：`ClientConfig` / `EntryAddrs` / `HttpsCert`
  - **新增 `flowtcp-tls::Takeable` + `accept_raw()`**：
    解决 `tokio_boring::SslStream` 没有 `into_inner()` 的问题 ——
    握手后用 `get_mut().take()` 取回裸字节流，才能切到自研记录层
  - **新增 `flowtcp-proto::OwnedFrame`**：拥有 payload 的帧，可跨越 `await`
  - **新增 `flowtcp-server::{exit, policy, server}`**
    - `exit.rs`：数据面（OpenTcp→TcpStream、OpenUdp→UdpSocket、Data/Close 分发、
      单写任务、目标→客户端回传、流生命周期管理）
    - `policy.rs`：**目标地址策略**（默认 `DenyPrivate`，防 SSRF / 内网扫描 / 云元数据）
      含 IPv4 私网/CGNAT/保留段、IPv6 ULA/链路本地、**IPv4-mapped 绕过防护**、DNS rebinding 二次校验
    - `server.rs`：进程级主循环（并发 accept、统计、优雅退出）
  - **`session.rs::serve_ours` 改为 `accept_raw` + `exit::run`**：真正的数据面接通
  - **CLI 新增 `server` / `client` 子命令**（`args.rs` 手写解析，支持 `--k v` / `--k=v` / 开关）
  - **修复 3 个架构级 bug（详见 DEVTIPS §14）**：
    1. ★ **一次 `read` 读到多条记录时后续记录被丢弃** ——
       客户端与服务端 read 路径都忽略了 `RecordDecoder::open()` 返回的 `used`，
       表现为「流打开了但数据一条也传不过去」，且只在特定 TCP 分片时序下出现
    2. `pump` 用 `tokio::join!` 导致对端关闭后仍挂在本地 `read` 上（连接与任务泄漏），改 `select!`
    3. `tcp_pump` 在客户端半关闭后 `select!` 分支忙循环（100% CPU），加 `if !client_closed` 守卫
  - **新增 e2e 测试 14 个**（总数 223 → 265+）：
    - `tests/proxy_e2e.rs` 8 个：SOCKS5 TCP / SOCKS5 UDP（含切目标）/ HTTP CONNECT /
      HTTP 绝对 URI 改写 / HTTPS 自签证书 / 8 流并发 / 策略拒绝 / 域名目标
    - `steal_e2e.rs` 改为**真实数据面往返**（TcpEcho 目标 + 真客户端 API + 字节统计断言）
  - **`HTTPS 入口默认自签证书，也可 `--cert`/`--key` 指定**（用户明确要求）

- [2026-11-10 20:47 北京时间] ★★★ 方案 G 完成：自研 TLS 1.3 客户端，ClientHello 票据认证打通
  - **背景**：DEVTIPS §11/§12 证明了标准 BoringSSL 无法做 ClientHello 层认证
    （转录包含 ClientHello 全部字节，字节流改写 session_id 必然导致 `BAD_DECRYPT`），
    SSL_SESSION 路径也已源码级排除。唯一出路是自己实现 TLS 1.3 客户端。
  - **新增 `crates/flowtcp-tls/src/tls13_client.rs`**：完整 TLS 1.3 客户端
    - 握手全流程：CH → SH → EE → Cert → CV → server Finished → client Finished
    - `RecordLayer`：`nonce = iv XOR (0x00000000 || seq_be)`、AAD=5 字节记录头
    - `Tls13Stream<S>`：握手后应用数据流（`write_all` / `read_one`）
    - 只支持 TLS_AES_128_GCM_SHA256（0x1301）+ x25519，其余明确报错
    - 明确不支持：HelloRetryRequest、PSK/会话恢复、0-RTT、客户端证书、证书链校验
  - **新增 `ClientHelloParams::authed()`**（`chbuilder.rs`）：解决「票据依赖
    client_random」的顺序问题 —— 先定 random → 算 ticket → 再拼 ClientHello
  - **`handshake()` 签名改为 `(stream, sni, &AuthKey)`**：内部自动算票据
  - **修复 4 个关键 bug（全部实测定位，详见 DEVTIPS §13）**：
    1. 中间盒兼容模式的**明文 ChangeCipherSpec 记录**未跳过 → 被当密文解密报「记录太短」
    2. 服务端 Finished **未加入转录** → 服务端报 `DIGEST_CHECK_FAILED`
    3. CertificateVerify 验签时**重复裁剪**转录 → 验签失败
    4. `exporter_master_secret` 误经 `KeySchedule::early()` → **多套一层 HKDF-Extract**，
       双端 exporter 完全不同（新增 `KeySchedule::from_secret()` 修正）
  - **修复 exporter 派生**：从一层改为 RFC 8446 §7.5 的**两层**
    `HKDF-Expand-Label(Derive-Secret(E, label, ""), "exporter", Hash(context))`
  - **验证方式**：用 BoringSSL `SSL_CTX_set_keylog_callback` 导出服务端全部
    traffic secret，逐字节与客户端比对 —— client/server hs secret、app secret、
    `EXPORTER_SECRET` **全部一致**
  - **新增测试 30 个**（总数 193 → 223）：
    - `tls13_client` 单元测试 14 个
    - `key_schedule` exporter 固定向量回归测试 2 个
    - `tests/tls13_e2e.rs` 5 个（含 **exporter 与 BoringSSL 完全一致**）
    - `steal_e2e.rs` 核心测试从 `#[ignore]` 转为通过
  - **`steal_e2e.rs` 场景 2 转为通过**：完整链路验证
    客户端算票据 → 服务端 `judge()` 认证 → 临时证书签发 → 双端握手 →
    临时证书公钥验证 → 发内层 OpenTcp 帧 → 服务端返回 `Proxied`
  - **clippy 零警告、`cargo test --workspace` 全绿（223 通过）**

- [2026-11-10 17:12 北京时间] ★ 架构定稿 + 项目文档重建
  - **确定协议定位**：TCP/UDP/DNS/ICMP 代理流量 → 封装为「外观为 TLS 1.3 的伪 TCP 数据报」
  - **否决方案**（附原因，避免重复讨论）：
    - QUIC-over-TCP：Nginx 无法按路径反代传输层字节；内层 TLS 强制双层加密
    - h2 直连（naiveproxy 式）：需独占 443，无法挂路径
    - WSS + yamux：本质是真 TCP，有 HOL 与拥塞控制，丧失 UDP 低延迟
    - GOST `relay+tls`：smux 单窗口，HOL 无法根治；`probeResist` 对 relay 无效
    - udp2raw / kcptun / UDPspeeder：承载在 UDP 或 FakeTCP 上，**无法套 TLS**（无有序可靠流）
  - **确定承载层**：FakeTCP（raw socket 伪造 TCP 头，无重传/无流控/无拥塞控制），复用 `phantun` 的 `fake-tcp` crate
  - **确定加密层**：单次标准 TLS 1.3 握手（rustls）→ 用 `export_keying_material` 派生密钥 → 自定义记录层（显式序号，借 DTLS 1.3 序号加密）
  - **确定分流策略**：握手后首帧明文判定（`PRI `/`GET `→nginx，`FTAUTH`→代理，其他→nginx 400），ClientHello 零私有字段
  - **确定内置 nginx**：源码静态编译（`--without-http_ssl_module`），仅 Linux amd64/arm64，明文 HTTP 反代
  - **确定 ACME**：DNS-01 优先 + HTTP-01 备选；明确排除 TLS-ALPN-01（与 FakeTCP 端口冲突）
  - **确定模板站**：内置文档站主题（模仿 VitePress），内容参数化防批量指纹
  - **文档**：新建 `docs/PROTOCOL.md`（协议规范 v0.1 草案）；重写 `PROJECT_PLAN.md`、`DEVTIPS.md`、`CHANGELOG.md`、`DEPLOY_CREDENTIALS.md`
  - **工程**：新建 `.gitignore`（此前缺失，导致 `DEPLOY_CREDENTIALS.md` 有被提交到 Git 的风险）
  - **待办**：ClientHello 指纹实现方案（自研 / uTLS 等价 / fork rustls）尚未定

- [2026-11-10 17:48 北京时间] ★ 协议核心实现 + 工程链路打通
  - **新增 `crates/flowtcp-proto`（纯逻辑，无 IO）**
    - `frame.rs`：内层帧编解码（10 字节固定头）、SOCKS5 对齐的地址编码、MTU 预算计算
    - `record.rs`：记录层 AEAD（AES-128-GCM / ChaCha20-Poly1305）、显式序号 + XOR 掩码、
      1024 位重放滑动窗口、TLS 1.3 记录伪装
    - `keyderive.rs`：TLS exporter → 6 段方向性密钥（HKDF-Expand，含会话上下文隔离）
  - **新增 `crates/flowtcp-cli`**：`selftest`（5 项协议自检）/ `info` / `help`
  - **测试**：46 个单元测试全部通过，覆盖乱序、丢包、重放、篡改、方向隔离、MTU 边界
  - **工程链路**
    - `Dockerfile`：多阶段（chef / builder / dist / ci）+ cargo-chef 依赖缓存
    - `.dockerignore`、`.github/workflows/ci.yml`（fmt → clippy → test → 多架构编译）
    - `README.md`：项目介绍、架构图、快速开始、选型取舍、路线图
  - **修复的关键设计错误（重要）**
    - 初版将**掩码后的序号**放入 AAD，形成「AAD 依赖密文 → 密文依赖 AAD」循环依赖，
      被迫加密两遍且长度计算错误（45 vs 29）。改为 AAD 使用**未掩码序号**
      （符合 RFC 9147 §4.2.3 原文），加密恢复单遍，性能与正确性同时改善
    - `FrameIter::consumed()` 在遇到半包时错误推进了 pos，导致无法识别尾部残留。已修正为不推进
  - **环境验证（Stage 0 部分完成）**
    - 国内客户端 `47.102.196.219` → 国外服务器 `141.144.231.134`：
      ICMP 可达（RTT 194ms，丢包 25%）；TCP 80/443 返回 `Connection refused`
      （数据包到达服务器但无监听）→ **TCP 通路正常，方案前提成立**
    - 待补免密：`141.144.231.134`、`10.0.100.1`（passwall）
  - **已知限制**：arm64 在 x86 上经 QEMU 模拟编译 ≥5 分钟，本地不适用，交由 GitHub Actions

- [2026-11-10 18:18 北京时间] ★★ FakeTCP 承载层 + 真实 TCP 互通验证通过
  - **环境就绪**：三台机器免密打通
    - `141.144.231.134` 国外服务端（Debian 5.10，TUN 可用，`ip_forward=1`，内存仅 183MB 可用）
    - `47.102.196.219` 国内客户端（Ubuntu 6.8，`rp_filter=2` 需改，1GB 可用）
    - `10.0.100.1` OpenWRT/ImmortalWrt 25.12（ash shell，PassWall 已装）
  - **★ 决定性验证：真实 TCP ↔ 用户态 FakeTCP 握手成功**
    - 用真实内核 TCP 栈（`bash /dev/tcp`）连入用户态 fake-tcp 监听端口
    - 结果：三次握手完成 + 双向数据收发正确（`ECHO:hello-real-tcp`）
    - **结论：抗主动探测与「伪装网站 fallback」技术路径成立**
  - **★ 发现并修复 fake-tcp 的关键限制（必须 patch）**
    - 上游只接受 `seq == 0` 的 SYN（因 phantun 客户端 ISN 固定从 0 开始）
    - 真实 TCP 栈 ISN 按 RFC 6528 随机 → 必然被回 RST → 伪装 fallback 完全不可用
    - 已 patch（`vendor/fake-tcp/src/lib.rs` 的 `[FlowTCP PATCH #1]`）：放开 ISN 限制
  - **新增 `crates/flowtcp-faketcp`**
    - `netcfg.rs`：**运行时自动配置 TUN + iptables**（幂等、可清理、失败回滚）
      - 自动探测公网 IP（`ip route get 8.8.8.8`）
      - 三条规则：`nat PREROUTING` / `nat OUTPUT` / `nat POSTROUTING`(SNAT)
      - 自动关闭 `rp_filter`
      - **端口完全可配置**，不强制 443
    - `transport.rs`：`FakeTcpListener` / `FakeTcpStream` 封装，数据报语义，超 MTU 显式报错
  - **实测踩过的 4 个 iptables 坑（已写入 DEVTIPS §7.3）**
    1. `raw -j NOTRACK` 会让 DNAT 完全失效（conntrack 被绕过）
    2. 本机流量走 `OUTPUT` 链，只配 `PREROUTING` 导致本机测试 RST
    3. `rp_filter=2` 导致握手成功但数据收不到
    4. `-A` 追加在有 Docker 时可能永不命中，必须 `-I` 插链首
  - **依赖工程化**
    - 新增 `vendor/fake-tcp`（path 依赖，含 patch），workspace `exclude = ["vendor"]`
    - `rand` 统一升至 0.9（fake-tcp 的 `SmallRng::from_os_rng` 需要）
    - Dockerfile 与 CI 增加 `COPY vendor`（path 依赖必须进构建上下文）
  - **质量**：52 个测试通过（46 proto + 6 faketcp），clippy 零警告，容器内门禁通过

- [2026-11-10 18:44 北京时间] ★★★ Phase 2 完成：TLS 握手层 + Chrome 指纹实测通过
  - **新增 `crates/flowtcp-tls`**
    - `fingerprint.rs`：Chrome 级指纹（cipher / curves / sigalgs / GREASE / permute / OCSP / SCT）
    - `split.rs`：首帧分流判定（`FTAUTH` vs HTTP/1.x vs HTTP/2 vs 未知）
    - `handshake.rs`：客户端/服务端握手 + exporter 密钥导出 + 服务端读首帧分流
  - **★ 外部检测验证 Chrome 指纹成功（关键成果）**
    - 用 `tls.peet.ws` 第三方检测，JA4 = `t13d1513h2_8daaf6152771_...`
    - **`8daaf6152771` 是 Chrome 桌面版公认的 JA4 cipher+extension 哈希**
    - 对照实验：Plain 配置得到 `5b57614c22b0`，证明配置真实生效
  - **★ 发现并修正一个反直觉的关键错误**
    - 初版设 `set_min_proto_version(TLS1_3)` → JA4 变成 `55b375c5d22e`（完全不匹配 Chrome）
    - 原因：真 Chrome 的 ClientHello 是 **TLS 1.2 兼容格式**，会携带 `ec_point_formats`、
      `extended_master_secret`、`renegotiation_info` 等 1.2 时代扩展；
      设 min=1.3 后 BoringSSL 认为无需兼容，直接省略这些扩展 → 扩展数从 13 掉到 7
    - 修正：**客户端不设 min 版本**，由服务端强制 `min = TLS1.3`
    - 另需显式开启 `enable_ocsp_stapling()` + `enable_signed_cert_timestamps()`
      （Chrome 2018 起强制 SCT）
  - **新增 CLI `fingerprint` 子命令**
    - `flowtcp fingerprint`：连接检测服务，输出 JA3/JA4 并判定是否像 Chrome
    - `flowtcp fingerprint --plain`：对照实验，验证配置是否真的生效
  - **`crates/flowtcp-cli` 改为 `#[tokio::main]`**（fingerprint 需要异步 IO）
  - **质量**：82 个测试通过（46 proto + 6 faketcp + 25 tls + 5 cli），clippy 零警告

- [2026-11-10 18:49 北京时间] ★★★ 重大决策：不做内置 nginx，改用「偷网站」（REALITY 式）+ AnyTLS 式 padding
  - **决策变更**：否决 Phase 5 的「内置静态编译 nginx + ACME」方案
    - 新方案：认证失败时把 **TCP 字节流原样透传**给真实网站（如 `www.microsoft.com:443`）
    - 收益：**不需要自己的域名、不需要证书、不需要 ACME、不需要 nginx**
    - 原理：探测者看到的是真实网站完整无误的 TLS 会话（真证书/真链/真 OCSP），
      我们从未参与 TLS，因此不可能露破绽——比「自己扮演网站」强得多
  - **两个项目的真实定位（澄清）**
    - **REALITY**：偷网站 ✅。用 `ClientHello.session_id` 做认证载体，失败则透传
    - **AnyTLS**：**不偷网站** ❌，必须自己的证书。核心贡献是 `paddingScheme`
    - 结论：两者互补，最终方案 = REALITY 式偷网站 + AnyTLS 式 padding
  - **新增 `flowtcp-proto/src/steal.rs`（偷网站核心）**
    - 自写 ClientHello 解析器（不依赖 TLS 库）：提取 `session_id` / `SNI` / `key_share` / `random`
    - 认证票据：`session_id[32] = AEAD(key, nonce=0, aad=client_random, plaintext=ver‖ts‖short_id‖pad)`
    - 密钥来源复用 ClientHello **本来就有的** X25519 `key_share`：
      `shared = X25519(reality_priv, client_key_share_pub)`，**无需额外字段**
    - 裁决：SNI 允许列表 + X25519 存在 + 解密成功 + 时间窗 ±30s + short_id 匹配
    - 任一失败 → `Verdict::Forward`，带具体原因（仅记日志，绝不回给客户端）
  - **新增 `flowtcp-proto/src/padding.rs`（AnyTLS 式流量整形）**
    - 完整支持 AnyTLS `paddingScheme` 语法：`stop=N`、`a-b` 范围、`c` 检查符号
    - **支持无序号续行**（AnyTLS 官方默认方案就有这种写法）
    - 确定性抖动（同输入同输出，便于回测与回放）
    - 默认只整形前 8 个包：握手阶段才是特征最明显处，数据阶段整形会严重损害吞吐
  - **质量**：115 个测试通过（79 proto + 6 faketcp + 25 tls + 5 cli），clippy 零警告

- [2026-11-10 19:12 北京时间] ★★ 临时证书机制 + 服务端双模式
  - **核实并澄清 AnyTLS 的真实做法**
    - `anytls-go` 参考实现**也是自签**：`util.GenerateKeyPair(time.Now, "")` + 客户端 `InsecureSkipVerify: true`
    - 官方注释明确：「仅示例使用，生产不建议」
    - 生产部署（sing-box / mihomo）**必须配真实 CA 证书**，靠标准 PKI 抗 MITM
  - **确认偷网站方案必须自签**
    - 认证失败时是透明中转，不需要私钥
    - 认证通过后必须自己完成握手，而**没有真网站私钥** → 只能现场生成
  - **★ 自签的安全保证：ECDH 派生 Ed25519 签证书**
    - `shared = X25519(我方临时私钥, 对方公钥)` → `seed = HKDF(shared, salt=client_random, info="flowtcp steal v1 cert")`
    - 服务端 `SigningKey(seed)` 签自签证书；客户端 `VerifyingKey(seed)` 验公钥匹配
    - 中间人无 REALITY 私钥 → 算不出 seed → 无法伪造能通过验签的证书
    - 跨会话复用旧证书也会失败（每连接 `client_random` 不同）
  - **新增 `flowtcp-proto::KeyPurpose`（密钥用途隔离）**
    - 票据密钥与证书种子用**不同 HKDF info 标签**
    - 若相同，拿到证书签名密钥就能反推票据密钥 → 可伪造任意 session_id 绕过认证
    - 新增 `derive_cert_seed()` / `is_seed_usable()`
    - X25519 共享密钥全零（低阶点攻击）时显式拒绝，不降级
  - **新增 `flowtcp-tls::tempcert`**
    - `issue_temp_cert()`：用种子派生 Ed25519 → 手工拼 PKCS#8 DER（16 字节固定前缀）→ rcgen 签自签证书
    - `verify_temp_cert()`：验公钥匹配 + 有效期（ASN.1 UTCTime/GeneralizedTime 解析）
    - 证书签名不单独验：由 TLS 的 `CertificateVerify` 完成更强证明（已在模块文档说明原因）
    - 真网站证书（RSA/ECDSA）返回 `Untrusted` 而非错误（对应「爬虫模式」场景）
  - **新增 `flowtcp-tls::ServerMode`（双模式并存）**
    - `Steal`：偷网站，零域名零证书，失败透传到真实网站
    - `OwnCert`：AnyTLS 生产方式，自有证书 + 本地 HTTP fallback
  - **测试覆盖关键安全性质**
    - `双方派生同一种子` / `服务端证书通过客户端验签`
    - `中间人证书被拒绝` / `真网站证书被判不可信` / `不同会话证书不通用`
    - `退化种子被拒绝` / `证书调试不泄露私钥`
  - **质量**：128 个测试通过（88 proto + 6 faketcp + 29 tls + 5 cli），clippy 零警告

- [2026-11-10 19:46 北京时间] ★★★ 服务端落地 + 发现架构级限制（ClientHello 认证 vs 标准 TLS）
  - **新增 `crates/flowtcp-server`（服务端核心）**
    - `forward.rs`：TCP 字节流透传（含已读字节重放、PROXY protocol v1/v2）
    - `session.rs`：单连接裁决与分流（读 ClientHello → 7 步校验 → 分流处置）
    - 集成测试 5 个场景，其中 4 个通过（透传路径**完全可用**）
  - **新增 `flowtcp-tls` 模块**
    - `prebuf.rs`：预置缓冲流（把判定阶段读走的 ClientHello 还给 BoringSSL）
    - `inject.rs`：ClientHello 票据注入 + ServerHello 回显还原（双向改写）
    - `mode.rs`：服务端双模式（`Steal` 偷网站 / `OwnCert` 自有证书）
    - `tempcert.rs` 改为 **ECDSA P-256**（Ed25519 在 Mozilla 预设下握手失败）
  - **★ 与 AnyTLS 源码核实的重要事实**
    - `anytls-go` 参考实现**也是自签证书** + 客户端 `InsecureSkipVerify`
    - 官方注释明确「仅示例使用，生产不建议」
    - 生产部署（sing-box/mihomo）必须配真实 CA 证书
  - **★★★ 发现架构级限制（已写入 DEVTIPS §11）**
    - **TLS 1.3 握手转录包含 ClientHello 全部字节**（RFC 8446 §4.4.1）
    - 客户端字节流层改写 `session_id` 后，BoringSSL 内部转录仍是原值
      → 双方转录不同 → 握手密钥不同 → `BAD_DECRYPT`
    - 实测失败链路：ECDH 不可行 → 对称方案通过 → 单向改写 `DECODE_ERROR`
      → 双向改写 `BAD_DECRYPT` → 换证书算法仍失败
    - REALITY 能这么做是因为它 **fork 了 Go 的 crypto/tls**，客户端是 uTLS
    - `boring` crate 未暴露 `SSL_CTX_set_client_hello_cb`，也无法在握手前设 `session_id`
    - 该测试已标记 `#[ignore]` 并写明原因
  - **三条可选路径（待决策，见 PROJECT_PLAN 决策 #30）**
    - A. 改 AnyTLS 式握手后认证（工作量小，但抗探测能力大降）
    - B. **在 boring-sys 中暴露 `client_hello_cb`（推荐）** —— 保住 REALITY 级能力
    - C. 客户端自研 ClientHello 构造（放弃已实现的 JA4 匹配成果）
  - **质量**：167 个测试通过（94 proto + 6 faketcp + 52 tls + 6 server + 5 cli + 4 e2e），clippy 零警告

- [2026-11-10 20:21 北京时间] ★★★ 方案 G 启动：自研 ClientHello 构造器（指纹已验证匹配 Chrome）
  - **背景**：`SSL_SESSION` 方案（路径 E）已实测排除，源码级证据见 DEVTIPS §12
  - **新增 `flowtcp-tls/src/chbuilder.rs`（ClientHello 构造器）**
    - 完整复刻 Chrome 的 ClientHello 结构：legacy_version / random / session_id / cipher / 扩展
    - **17 个扩展**：GREASE, SNI, EMS, renegotiation_info, supported_groups, sigalgs,
      SCT, key_share, psk_modes, supported_versions, ec_point_formats, session_ticket,
      ALPN, status_request, compress_certificate, ALPS, padding
    - **GREASE 五处插入**：cipher[0] / 扩展 / groups[0] / versions[0] / key_share[0]
    - **padding 扩展**填充至 512 字节，避免固定长度成为指纹
    - `session_id` 可自由填入票据（自研的核心价值）
  - **新增 `flowtcp-tls/src/ja4.rs`（JA4 指纹计算）**
    - 用于**客观验证** ClientHello 是否像 Chrome，无需完整握手
    - ★ 实测校准出一个反直觉的事实：`tls.peet.ws` 报的 B 段
      `8daaf6152771` = `sha256(排序后 cipher 4hex 列表)[0..12]`，**不含扩展**
    - 同时提供 `cipher_ext` 联合哈希（FoxIO 规范变体）供诊断
    - 用 BoringSSL 生成的 ClientHello 作为"黄金样本"校验实现正确性
  - **★★ 关键成果：自研构造器指纹与 BoringSSL（即 Chrome）完全一致**
    ```
    自研构造器：t13d1617h2_8daaf6152771_ef763107f677
    BoringSSL ：t13d1615h2_8daaf6152771_ef763107f677
                            ↑ B 段 = Chrome 标准值，C 段也一致
    ```
    - 差异仅在 A 段的扩展数量（17 vs 15），因为我们补了 Chrome 有而 BoringSSL 未发的扩展
    - **这证明「自研 ClientHello + 自由设置 session_id」在指纹上不可区分**
  - **修正的 bug**
    - cipher 列表最初只写了 6 个 TLS1.2 cipher，Chrome 实际是 12 个 → 补齐后 B 段匹配
    - 测试中偏移计算错误（cipher 长度字段在 76 而非 77）
    - ALPN 断言格式错误（应为 `list_len(2) + proto_len(1) + proto`）
  - **质量**：186 个测试通过（94 proto + 6 faketcp + 71 tls + 6 server + 5 cli + 4 e2e），clippy 零警告
