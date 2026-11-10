# 流控与 CPU 开销：协议调研与 FlowTCP 方案

> 创建: 2026-11-10 22:30 (北京时间)
> 状态: **调研完成，方案待实施（Phase 4）**
> 关联: `PROJECT_PLAN.md` Phase 4 / `DEVTIPS.md`

本文档回答两个问题：

1. **QUIC / quinn / TUIC / Hysteria(hy1/hy2) 是怎么做流控的？**
2. **FlowTCP 应该怎么做，才能既跑满带宽又不烧 CPU？**

文中的性能数字均来自本项目在真实机器上的实测（`cargo run --release -p flowtcp-proto --example bench_record`），
不是网上抄的 benchmark。

---

## 一、先看清我们的场景与它们的差异

这是最关键的一节。**照抄 QUIC 的方案会做错**，因为承载层不同。

| 维度 | QUIC / TUIC / Hysteria | FlowTCP |
|------|------------------------|---------|
| 承载 | **UDP**（内核数据报） | **FakeTCP**（raw socket 伪造 TCP 头） |
| 丢包处理 | 自己实现 ARQ + 拥塞控制 | 同为自研，但**没有内核 TCP 的重传** |
| 乱序 | 常态（UDP） | 常态（无重排） |
| 流控目的 | 防内存溢出 + 配合拥塞控制 | **仅防内存溢出**（无拥塞窗口概念） |
| 拥塞信号 | 丢包 / ECN / RTT | **不适用**：QoS 环境人为丢包，按丢包降速是自杀 |
| 中间盒 | 可能限速 UDP | 看到的是 TCP，**不会被 QoS** |

### 1.1 为什么我们不能用「丢包当拥塞信号」

Hysteria 的 Brutal 拥塞控制就是为解决这个问题而生的，它的核心洞察是：

> 在 QoS 限速的环境里，丢包**不代表拥塞**，而是运营商在限速。
> 此时按 TCP 的方式指数降速，会让带宽永久卡在低水平。

FlowTCP 的解法更彻底：**外层是 TCP，QoS 根本看不到 UDP**。
所以我们不需要「对抗丢包降速」，只需要：

1. **不把自己压垮**（发送速率 ≤ 接收方处理能力）
2. **不因流控限制吞吐**（窗口 ≥ BDP）
3. **CPU 开销恒定**（不能每包做复杂计算）

结论：**FlowTCP 的「流控」= 纯信用制内存保护，不含拥塞控制**。
拥塞控制在 FakeTCP 场景下由「多倍发包 + FEC」替代（Phase 4 后续）。

---

## 二、QUIC 的流控（RFC 9000 §4）

### 2.1 两级信用制

```
连接级：MAX_DATA         → 所有流的总字节上限
流级：  MAX_STREAM_DATA  → 单条流的字节上限
```

- **绝对偏移**：`MAX_STREAM_DATA` 携带的是「最大绝对字节偏移」，不是增量
- 发送方 MUST NOT 超过任一限制，否则接收方以 `FLOW_CONTROL_ERROR` 断连
- 接收方只允许**增大**限制，减小无效
- 并发流数由 `MAX_STREAMS` 单独控制（累计计数，非并发计数）

### 2.2 自动调优（§4.2 的原文要点）

> A receiver can use an **autotuning mechanism** to tune the frequency and amount
> of advertised additional credit based on a round-trip time estimate and the rate
> at which the receiving application consumes data, similar to common TCP
> implementations.

即：**窗口 = f(RTT, 消费速率)**，而不是固定值。

### 2.3 性能铁律（§4.3 Flow Control Performance）

原文（这段话是本文档最重要的引用）：

> **If an endpoint cannot ensure that its peer always has available flow control
> credit that is greater than the peer's bandwidth-delay product on this
> connection, its receive throughput will be limited by flow control.**

翻译：**可用信用必须 ≥ BDP，否则流控就成了吞吐瓶颈。**

BDP = 带宽 × RTT。举例：
- 100 Mbps × 200 ms = 2.5 MB
- 1 Gbps × 200 ms = 25 MB

这就是为什么「窗口给小了带宽上不去」——它不是 bug，是数学。

第二个铁律：

> Packet loss can cause gaps in the receive buffer, preventing the application
> from consuming data and freeing up receive buffer space.

**丢包造成空洞 → 应用无法消费 → 缓冲不释放 → 信用不增长 → 死锁。**
这是流控设计里最隐蔽的坑，必须靠「乱序缓冲 + 超时跳过」解决。

第三个（省 CPU 的关键）：

> As an optimization, an endpoint could send frames related to flow control
> **only when there are other frames to send**, ensuring that flow control does
> not cause extra packets to be sent.

**流控帧必须搭便车，不能单独发包。**

---

## 三、quinn 的实现参数（Rust 生态最佳实践）

quinn 把 QUIC 的抽象落成了具体参数，其注释里的取舍理由很值得抄：

| 参数 | 作用 | 关键说明（来自 quinn 文档） |
|------|------|---------------------------|
| `receive_window` | 连接级接收窗口 | **应 ≥ 期望延迟 × 最大吞吐**；越大越能容纳「一条流阻塞时另一条流跑满」 |
| `stream_receive_window` | 流级接收窗口 | 设得比 `receive_window` 小，**防止单流独占接收缓冲** |
| `send_window` | 应用已写未确认的字节上限 | **控制内存**；「希望支撑大量连接的端点应设得足够低，避免每条连接都吃满窗口」 |
| `max_concurrent_bidi_streams` | 并发流上限 | 「最坏内存 = 并发流数 × 流接收窗口」 |
| `send_fairness` | 同优先级流是否轮转 | **关闭可减少分片与协议开销**（大量小流的负载） |
| `enable_segmentation_offload` | GSO | **「批量发送相同 header 的包时大幅降低 CPU」** |
| `packet_threshold` | 乱序容忍包数 | 不应小于 3（RFC 5681） |
| `initial_rtt` / `time_threshold` | 时间维度乱序容忍 | 按 RTT 的倍数 |

### 3.1 从 quinn 学到的三条

1. **两级窗口是有原因的**：流级小、连接级大 → 单流不能挤占全局
2. **`send_window` 是内存保护而非吞吐控制**：它限制的是「应用写了但还没被确认」的量
3. **GSO 是最有效的 CPU 优化**：一次系统调用发多个包。我们在 FakeTCP 上对应的是
   「一次 `write` 多个数据报」

---

## 四、TUIC 的做法

TUIC 是 **QUIC 上加一层代理协议**，所以：

- **流控完全继承 QUIC** —— 它自己不做流控
- 真正的创新在别处：

| 特性 | 说明 |
|------|------|
| **0-RTT** | 复用会话票据，首包即可带数据。省 1 RTT |
| **UDP over QUIC Datagram** | 不用 STREAM 承载 UDP，而用不可靠数据报扩展（RFC 9221）。**避免为 UDP 引入 ARQ 开销** |
| **原生多路复用** | 无 TCP-over-TCP 的队头阻塞 |
| **BBR 拥塞控制** | 用带宽/延迟估计而非丢包 |

### 4.1 对我们的启示

**「UDP 不该走可靠流」** 这条非常重要。
我们当前的 `OpenUdp` 走的是 `Data` 帧 + 可靠性（虽然 Phase 3 没 ARQ，但语义上是可靠流）。
Phase 4 应该明确：**UDP 流的帧禁止 ARQ 重传**，丢了就丢 —— 这才是 UDP 语义。

---

## 五、Hysteria 1/2 的做法

### 5.1 hy1（Hysteria 1）

- 基于 **QUIC** 的自定义协议
- 核心创新：**Brutal 拥塞控制**

**Brutal 的原理**（这是它真正的价值）：

```
每个端点维护一个"固定发送速率"配置值
每隔一段时间交换「我实际收到了多少」（ack 里带接收速率）
发送方按 min(自身配置速率, 对端报告的接收速率) 发送
```

关键设计：
- **不用丢包作为拥塞信号**（QoS 环境下丢包 ≠ 拥塞）
- 用**显式速率反馈**代替隐式信号
- 结果：在人为丢包 30% 的链路上仍能跑满

### 5.2 hy2（Hysteria 2）

- 协议重写，但仍是 QUIC + Brutal
- 主要变化是**伪装形态**：从「无特征的自定义 UDP」改为 **HTTP/3 形态**
  （这也是我们项目的思路 —— 只是我们选了 TLS 1.3 over FakeTCP）

### 5.2.1 ★ TCP 有重传、UDP 没有 —— 这个区分必须写清楚

被反复问到的一个点，这里用官方协议原文确认。

**Hysteria 2 官方协议规范**（`v2.hysteria.network/docs/developers/Protocol/`）：

| 流量类型 | 承载通道 | 可靠性 |
|---------|---------|--------|
| **TCP** | `QUIC bidirectional stream` | **可靠 · 有 ACK + 重传** |
| **UDP**（游戏/DNS/QUIC） | `QUIC unreliable datagram`（RFC 9221） | **不可靠 · 无重传** |

原文：

> **TCP**: For each TCP connection, the client MUST create a new
> **QUIC bidirectional stream** and send the following TCPRequest message
>
> **UDP**: UDP packets MUST be encapsulated in the following UDPMessage format
> and sent over **QUIC's unreliable datagram** (for both client-to-server and
> server-to-client)

最直接的证据是它的分片规则：

> Due to the limit imposed by QUIC's **unreliable** datagram channel...
> If one or more fragments of a packet are lost, **the entire packet MUST be
> discarded.**

「分片丢了就整个丢弃，不请求重传」—— 这就是 UDP 语义。

**所以：游戏/实时流量不重传是对的，这不是"简化"，而是 UDP 的定义。**

### 5.2.2 FlowTCP 的对应设计

| 流量 | 开流帧 | ARQ 重传 | 理由 |
|------|--------|---------|------|
| TCP | `OpenTcp` (0x01) | **必须** | TCP 是可靠字节流；FakeTCP 承载层不做重传，因此必须由我们补上 |
| UDP | `OpenUdp` (0x02) | **禁止** | UDP 是数据报；重传只会增加延迟、破坏实时性 |

#### 可靠性是**流级属性**，不是帧级属性

这是最容易做错的地方。可靠性由**开流帧类型唯一决定**，并在两处体现：

1. **权威来源**：`OpenTcp` 创建的流 → 可靠；`OpenUdp` → 不可靠
2. **冗余标记**：`Data` 帧的 `flags.RELIABLE` 位必须与流类型一致

第 2 点的作用不是"让每帧自己决定"，而是**校验**。若实现有 bug 导致某帧漏标，
TCP 流会静默丢一段数据 —— 上层表现为「下载的文件损坏」，几乎无法复现。
因此服务端收到 `RELIABLE` 与流类型不一致的 `Data` 帧时**立即断开连接**
（`crates/flowtcp-server/src/exit.rs::stream_reliable`），宁可报错也不要静默损坏。

#### 为什么不能"统一都可靠"

有人会想：既然可靠更安全，为什么不让 UDP 也走可靠传输？

- **队头阻塞**：重传必须等，一个丢包会让该 UDP 会话的所有后续包卡住
- **延迟放大**：游戏/语音对延迟敏感，宁可丢一帧也不要等 200 ms 的重传
- **流量放大**：实时流量的丢包往往是拥塞或瞬时抖动，重传会加剧

Hysteria 用 QUIC Datagram、TUIC 用 `UDP over QUIC Datagram`，
本质都是同一个结论：**UDP 流量绝不能走可靠通道。**

### 5.3 Brutal 的真实实现（源码级，2026-11-10 补齐）

之前我只写了「Brutal 用固定速率 + 显式速率反馈」这种教科书式描述。
这次直接读了 `core/internal/congestion/brutal/brutal.go`（193 行），
**它的核心只有一个公式，没有任何状态机**：

```go
const (
    pktInfoSlotCount           = 5    // 5 秒滑动窗口采样
    minSampleCount             = 50   // 样本不足不更新
    minAckRate                 = 0.8  // 补偿上限钳制
    congestionWindowMultiplier = 2    // 2×BDP 铁律
)

// ★ 全部逻辑就在这三行
func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
    rtt := b.rttStats.SmoothedRTT()
    if rtt <= 0 {
        return 10240                        // 还没测到 RTT 时的兜底
    }
    cwnd := congestion.ByteCount(
        float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
    if cwnd < b.maxDatagramSize {
        cwnd = b.maxDatagramSize
    }
    return cwnd
}

// ★ 丢包完全不影响速率 —— 这是 Brutal 最大的特征
func (b *BrutalSender) OnCongestionEvent(...) {
    // Stub
}

// ★ 没有慢启动、没有恢复阶段
func (b *BrutalSender) InSlowStart() bool { return false }
func (b *BrutalSender) InRecovery() bool  { return false }
```

`ackRate` 的更新（每收到一批 ACK/丢包事件）：

```go
rate := float64(ackCount) / float64(ackCount + lossCount)
if rate < minAckRate {
    b.ackRate = minAckRate      // 钳制：丢包再狠，补偿也不会超过 1.25 倍
} else {
    b.ackRate = rate
}
```

#### 公式拆解（这是最值得学的一点）

| 因子 | 含义 |
|------|------|
| `bps × RTT` | BDP（带宽时延积）—— 「管道里能装多少」 |
| `× 2` | 2×BDP 铁律（窗口必须 ≥ 2×BDP 才不成为瓶颈） |
| `÷ ackRate` | **丢包补偿**：丢包 20% 时 ackRate=0.8，窗口放大 1.25 倍 |
| `min(.., 0.8)` | 丢包超过 20% 后不再继续放大（防雪崩） |

**关键洞察**：Brutal 不是「不顾丢包狂发」，而是
**「按实测丢包率反向放大窗口，把丢掉的量补回来」**。
丢 20% 的包，就把窗口放大 25% —— 这样实际到达对端的量恰好等于配置速率。

#### 对 FlowTCP 的启示（三条，可直接用）

1. **窗口不能是固定值，应由实测 RTT 决定**
   我们原先用固定的 `DEFAULT_STREAM_WINDOW`。正确做法是
   `窗口 = max(固定下限, 2 × 实测 BDP)`。这样 RTT 从 10 ms 变 200 ms 时
   窗口自动放大 20 倍，而不是死守一个数字。

2. **丢包环境下窗口要放大而不是缩小**
   这是 Brutal 与所有经典拥塞控制（Reno/CUBIC）的根本分歧。
   我们的场景（FakeTCP + 被 QoS）与 hy2 完全一致，因此
   **应当采用同样的「按 ackRate 反向补偿」思路**，而不是丢包就退让。

3. **不需要慢启动/拥塞避免状态机**
   Brutal 明确 `InSlowStart() = false`、`InRecovery() = false`。
   状态机是为「探测链路容量」服务的；当我们已知目标速率时，
   状态机只会带来 RTT 抖动和收敛延迟。

#### 但我们不能照抄的部分

Brutal 需要用户**准确填写带宽**（`bandwidth.up/down`）。填高了会
「slow, unstable connection and wasted data」（官方原话）。

FlowTCP 的用户不会填这个数 —— 所以：

- **短期（现在）**：用 hy2 的固定窗口默认值（见下节），
  并暴露 CLI 参数让高级用户手调（等价于 hy2 的 `initStreamReceiveWindow`）
- **中期（Phase 4.6）**：实现 BBR 式的带宽估计（hy2 也支持
  `congestion.type: bbr`，它不需要配置带宽），得到 `bps` 后再套用
  Brutal 的 `cwnd = bps × RTT × 2 / ackRate` 公式

### 5.3.1 ★ hy2 的流控窗口默认值（官方两组数字）

hy2 有**两套**推荐值，都是 2:5 比例，用途不同：

| 来源 | 流级 | 连接级 | 比例 | 用途 |
|------|------|--------|------|------|
| Full Server Config 默认 | 8 MB | 20 MB | 2:5 | 保守默认 |
| Performance 调优 | 25.6 MB (26843545) | 64 MB (67108864) | ≈2:5 | 跑满高 BDP 链路 |

官方原话（Performance 文档）：

> We **strongly recommend** that you maintain a stream-to-connection
> receive window ratio **close to 2/5**. This prevents one or two blocked
> streams from hogging the entire connection.

> We do not recommend changing these values unless you fully understand
> what you are doing.

#### FlowTCP 的取值决定

采用**保守默认 8 MB / 20 MB**，理由：

1. 我们的服务端可用内存仅 **183 MB**（见部署记录），64 MB/连接太激进
2. 8 MB 在 RTT 100 ms 链路上可跑 `8MB/0.1s ≈ 80 MB/s`，远超家用宽带
3. 需要更高性能时可调（对齐 hy2 的可配置性）

**对照我们早期的 256 KB**：只有 hy2 默认值的 **1/32**，
在 RTT 100 ms 下实测仅 1.5 MB/s —— 这正是本轮发现的硬瓶颈。

#### 内存上限的算法（为什么连接级上限是必需的）

```
单连接最坏内存 = min(流数 × 流窗口, 连接窗口)
              = min(256 × 8MB, 20MB) = 20MB
```

没有连接级上限时，256 条流 × 8 MB = **2 GB** —— 路由器直接 OOM。

### 5.3.2 hy2 的其它性能调优（可直接抄）

官方 Performance 文档列出的瓶颈排查顺序，我们应当照做：

```bash
# 1) 系统 UDP 缓冲区（我们用 FakeTCP，但同样适用 socket buffer）
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# 2) 进程优先级（低功耗设备上减少延迟抖动）
chrt -r 20 $(pidof flowtcp)
```

第 2 条尤其重要：**「On devices with limited CPU resources, high load can
cause latency jitter」** —— 我们的 OpenWRT 目标平台正是这类设备。

### 5.4 为什么我们不需要 Brutal 的「固定速率发送」

（原 §5.3 的内容，保留但修正结论）

Brutal 解决的是「UDP 被 QoS 丢包」的问题。
**FlowTCP 的 FakeTCP 外层让 QoS 根本看不到 UDP**，所以不需要
「无视丢包狂发」来对抗 QoS 限速。

但 **Brutal 的另一半洞察（窗口按 RTT/丢包动态计算）我们必须学**，
因为 FakeTCP 承载下的丢包仍会发生（真实链路丢包、MTU 分片丢失）。

所以最终路线是：

| 机制 | 来源 | 我们的做法 |
|------|------|-----------|
| 流控窗口大小 | hy2 QUIC 默认值 | 8 MB / 20 MB（2:5） |
| 窗口随 RTT 自动调整 | Brutal 公式 | Phase 4.5，`max(下限, 2×BDP)` |
| 丢包反向补偿 | Brutal `ackRate` | Phase 4.6，随 ARQ 一起做 |
| ARQ 重传 | QUIC（hy2 继承） | Phase 4.6，仅 TCP 流 |
| FEC | quinn / hy1 | Phase 4.7 |

---

## 六、FlowTCP Phase 4 设计方案

### 6.1 设计目标（按优先级）

| # | 目标 | 硬指标 |
|---|------|--------|
| 1 | **不能成为吞吐瓶颈** | 单流可用信用 ≥ 2×BDP |
| 2 | **CPU 开销恒定** | 每包额外 < 100 ns |
| 3 | **内存可控** | 单连接 < 32 MB |
| 4 | **丢包不导致流控死锁** | 乱序缓冲 + 超时跳过 |
| 5 | **UDP 语义不被破坏** | UDP 流禁止 ARQ |

### 6.2 帧设计（复用已有的 `Window = 0x09`）

现有帧头：`type(1) | flags(1) | stream_id(2) | pkt_seq(4) | len(2)` = 10 字节

**`Window` 帧载荷**：

```
stream_id(2) | credit_delta(4)
```

- `stream_id = 0` 表示连接级（省一字节标志位）
- `credit_delta` 是**增量**而非绝对偏移

#### 为什么用增量而不是 QUIC 的绝对偏移

| 方案 | 每包开销 | 接收方状态 |
|------|---------|-----------|
| 绝对偏移（QUIC） | 4~8 字节（变长整数） | 需维护「累计已发字节」u64 |
| **增量（本方案）** | 固定 4 字节 | **无需累计计数** |

省掉累计计数的价值：**每帧少一次 u64 加法 + 一次比较**，且状态更少。

风险：增量可能丢失（帧丢失）→ 信用永久少一块。
解决：**定期发一次「绝对校准」**（每 N 帧或每 RTT 一次），用 `flags.LAST` 标志区分。

### 6.3 窗口参数（按 BDP 铁律计算）

```
默认值（可配置）：
  stream_window   = 256 KB    ← 单流上限
  conn_window     = 4 MB      ← 全部流合计
  initial_credit  = 64 KB     ← 开流时的初始信用

自动调优（每 RTT 评估一次）：
  若 消费速率 × RTT > 当前窗口 × 0.5 → 窗口 × 2（上限 8 MB）
  若 消费速率 × RTT < 当前窗口 × 0.125 → 窗口 × 0.75（下限 64 KB）
```

为什么 `stream_window` 远小于 `conn_window`：
**防止单条大流（如下载）挤占所有缓冲，让小流（DNS、SSH）饿死。**

### 6.4 信用更新策略（省 CPU 的关键）

**绝不单独发 `Window` 帧**。三个搭便车时机：

1. 写任务 `flush_record()` 时，若队列里有待发信用，附在同一条记录里
2. 每收到 N 条记录（N=8）后检查一次（避免逐包检查的分支预测开销）
3. 信用消耗超过窗口 50% 时立即补（保证不会突然阻塞）

伪代码：

```rust
// 在读循环里（每解出一条记录后）
if frames_since_window_check >= 8 || credit_low {
    frames_since_window_check = 0;
    if let Some(delta) = flow.consumed_since_last_advertise() {
        out.send(OwnedFrame::window(stream_id, delta)).await;
    }
}
```

### 6.5 丢包不导致死锁（最隐蔽的坑）

**问题**：接收方按 `pkt_seq` 排序交付，若 `seq=5` 丢了，`seq=6..` 都卡在缓冲里，
应用读不到 → 不释放信用 → 发送方停摆 → 死锁。

**解法（三级）**：

1. **超时跳过**：某流最老的空洞超过 200 ms（可配）就跳过，记一次 `gap_loss`
2. **FEC 优先**：空洞在同一个 FEC 组内时，先用冗余包恢复（不发重传请求）
3. **ARQ 兜底**：仍缺失则发 `Ack` 帧带 bitmap 请求重传

**关键不变量**：无论数据是否补齐，**信用必须按「已接收字节」而非「已交付字节」计算**。
这是 QUIC §4.5 `Final Size` 的简化版 —— 我们不需要精确的 final size，
只需要保证「缓冲不会无限增长」。

### 6.6 CPU 优化清单

#### ✅ 已完成（本次）

| 优化 | 收益（实测） |
|------|-------------|
| **缓存密码学实例**（`Arc<CachedCipher>`） | 64B 包 **-48%**（452→235 ns）、1400B **-13%** |
| **AEAD 算法按 CPU 自动选择** | 无 AES-NI 的设备避免 5~10 倍退化 |
| `Keys::clone` 改为 Arc 引用计数 | 每连接省 2 次 AES key expansion |

实测对比（本机，AES-NI 可用）：

| 包大小 | 优化前 | 优化后 | AES vs ChaCha |
|--------|--------|--------|---------------|
| 64B | 452 ns | **235 ns** | 235 vs 1881 ns（**8.0×**） |
| 512B | 915 ns | **684 ns** | 684 vs 2281 ns（3.3×） |
| 1400B | 1773 ns | **1542 ns** | 1542 vs 3354 ns（2.2×） |
| 16 KB | 16021 ns | 15988 ns | 15988 vs 19072 ns（1.2×） |

**结论：有 AES-NI 时 AES-128-GCM 完胜**，小包优势最明显（8 倍）。
这正是「必须按 CPU 选算法」的实证 —— 若无脑选 ChaCha20，DNS 查询的 CPU 会高 8 倍。

#### ⬜ 待做（Phase 4）

| 优化 | 预期收益 | 说明 |
|------|---------|------|
| **去掉 `Arc<Mutex<HashMap<u16, Target>>>`** | 高并发下大幅降锁竞争 | 改用 `Vec<Option<Target>>` 按 stream_id 直接索引（u16 → 65536 槽，约 512 KB，可接受） |
| **批量 seal** | 减少函数调用与内存分配 | 一次 `seal_into` 多条记录，复用同一个明文/密文缓冲 |
| **接收缓冲环形复用** | 避免每包 `Vec::new` | 当前 `decrypt_in_place` 里 `ciphertext.to_vec()` 每包一次分配 |
| **FakeTCP GSO 类比** | 一次 write 多个数据报 | 需要 `flowtcp-faketcp` 支持批量发送 |
| **每流状态紧凑化** | 减少缓存未命中 | 把热字段（窗口、seq）放同一 cache line |

##### 为什么 `Arc<Mutex<HashMap>>` 是重大瓶颈

当前 `mux.rs` 与 `exit.rs` 的读循环里：

```rust
// 每收到一帧都要抢锁
let tx = registry.lock().ok().and_then(|m| m.get(&frame.stream_id).cloned());
```

- `HashMap` 查找 + `Mutex` 加解锁 ≈ 30~60 ns
- 256 条并发流、每条 1000 包/秒 → 每秒 25.6 万次抢锁
- **单核情况下这与加密开销同量级**

改成 `Vec<Option<...>>` 后变成「一次数组索引 + 无锁（读循环独占）」，
降到 2~5 ns。

### 6.6.1 实测吞吐（2026-11-10 23:35，release 构建，**流控已接入**）

#### 阶段一：流控接入前（2026-11-10 23:10，修复 4 个静默丢数据 bug 后）

| 场景 | 吞吐 | 完整性 |
|------|------|--------|
| 下行 64 MB | 143 MB/s（≈1.15 Gbps） | ✅ 逐字节一致 |
| 上行 64 MB | 154 MB/s | ✅ 逐字节一致 |
| 双向并发（32MB↑ + 64MB↓） | 98.8 / 137 MB/s | ✅ |

#### 阶段二：流控全链路接入后（本轮）

| 场景 | 吞吐 | 相对阶段一 | 完整性 |
|------|------|-----------|--------|
| 下行 64 MB | **169.9 MB/s（≈1.36 Gbps）** | **+19%** | ✅ 逐字节一致 |
| 上行 64 MB | **189.5 MB/s（≈1.52 Gbps）** | **+23%** | ✅ 精确 67108864 B |
| 双向并发（64MB↑ + 64MB↓） | 123.7 / 126.1 MB/s | 合计 +6% | ✅ |

**流控接入不但没掉速，反而更快了。** 原因：

1. `read_loop` 不再持有出站队列，热路径少了一次 `send().await` 与一个 `Arc` 持有
2. `poll_grant` 自带「消耗过半才补」的节流 —— 2 MB 传输只产生约 8 个 `Window` 帧，
   摊到每帧成本可忽略
3. 背压更早生效（在「目标写不进去」处而非「队列满」处），内存峰值更低

测试环境：本机 loopback + **真 TCP 承载** + release 构建 + 64 MB 确定性数据。

> **注意这些数字不能代表 FakeTCP 承载的性能。**
> Phase 4.8 接入 FakeTCP 后：MTU 1400（载荷更小）、无内核重传（需 ARQ）、
> 乱序到达（需重排）—— 三者都会显著降低吞吐，必须重测。

#### 阶段一为什么「没有流控也能跑满」？

因为用的是 `send().await` **背压**：

```
read 循环解密 → tx.send(frame).await ──队列满则阻塞──→ tcp_pump 写目标 socket
```

由于 TCP 内核 socket 本身有接收窗口，目标端的消费速度天然限制了整条链路 ——
**内核 TCP 在替我们做流控**。

#### 那 Phase 4 为什么还需要自己实现流控？

因为 **FakeTCP 没有内核 TCP 的窗口**。一旦承载层换成 FakeTCP：

- 没有接收窗口 → 发送方无法感知接收方容量
- 无重传 → 只能靠 `send().await` 阻塞读循环 → **整条隧道 HOL**
- 一个慢目标会卡住所有流（这正是我们要避免的）

因此流控的真正价值不是「跑得更快」，而是**在无内核流控的承载上，
用窗口代替阻塞，消除跨流 HOL**。这也是为什么 §6.3 强调
「流控帧必须搭便车」—— 不能为流控额外发包，否则吞吐反而下降。

### 6.6.2 ★★★ 补发信用的唯一正确位置（本轮踩死过的坑，必读）

实现时最容易犯的错误是**把 `poll_grant()` 挂在「收到数据」的路径上**。
这样写**必然死锁**，而且症状极具欺骗性：卡在**恰好等于窗口大小**的字节数上，
30 秒超时，零错误日志。

完整分析见 `DEVTIPS.md` §18。核心结论：

| 路径 | 该做什么 |
|------|---------|
| **接收**（`on_received(n)`） | **只记账，绝不补发** |
| **消费**（`on_consumed(n)`） | 记账 + **立即** `poll_grant()` + 发 `Window` 帧 |

原因是窗口上限为 `consumed + window`：

- 接收路径上 `consumed` 还是 0 → `target == advertised` → 补发量恒为 0
- 消费路径上 `consumed` 刚刚前进 → 补发必然生效

配套的两个设计决定：

1. **客户端把上报+补发内建进 `StreamReceiver::recv()`**
   早期让调用方自己调 `on_consumed`，只要一处忘了就是同款死锁。
   内建后从 API 层面消灭误用，代价仅为「取走即算消费」的轻微乐观
   （缓冲上限由 `inbound` 队列深度 256 帧 ≈ 358 KB 兜底）。
2. **`Window` 帧的接收必须能在半关闭后继续工作**
   TCP 是双向独立关闭的。客户端发 `Close` 只代表「我不再发数据」，
   绝不代表「我不再收数据」。所以服务端的 `Target::Tcp` 用
   `tx: Option<Sender>`，收到 `Close` 时只 `take()` 掉投递端，
   **流本身保留在表里**，否则后续 `Window` 帧会因「未知流」被全部丢弃，
   发送侧信用永不恢复。

### 6.6.3 ★★★ 丢包环境实测（2026-11-11 00:08，应用层帧注入）

`tc netem` 只能模拟**链路**丢包 —— 真 TCP 承载下会被内核重传掩盖，
**测不出流控的真实缺陷**。为此新增 `flowtcp_proto::fault`，
在应用层按概率丢弃出站帧（等价模拟 FakeTCP 承载）：

```bash
FLOWTCP_DROP_DATA=5      # 丢 5% Data 帧
FLOWTCP_DROP_WINDOW=10   # 丢 10% Window 帧
```

#### 改造前后对比（16 MB，真 TCP 承载）

| 场景 | 改造前（增量语义） | 改造后（QUIC 式绝对偏移 + PTO） |
|------|-------------------|------------------------------|
| Window 丢 10% | 45 s 超时，收 **3.3/16 MB** | **0.128 s，131.5 MB/s**，完整 |
| Window 丢 30% | 死锁 | **0.119 s，141.6 MB/s**，完整 |
| Data 丢 5% | 60 s 超时，收 **2.4/16 MB** | **0.113 s，141.2 MB/s**，缺 5.06% |
| Data 5% + Window 10% | 死锁 | 0.116 s，137.2 MB/s，缺 5.03% |

**吞吐提升约 500 倍**（0.07 MB/s → 131.5 MB/s）。

#### 两个关键读法

1. **`Window` 丢 30% 完全不掉速** —— 绝对偏移（幂等、可自愈）+
   50 ms 周期重发（PTO 简化版）完全吸收了信用帧丢失。
2. **`Data` 丢 5% 恰好丢 5.06%** —— 无额外损失、无卡死。
   这剩余的 5% 就是 **ARQ（Phase 4.6）唯一需要解决的问题**。

#### 为什么必须是绝对偏移（QUIC `MAX_DATA` 的做法）

| 性质 | 增量语义 | 绝对偏移 |
|------|---------|---------|
| 幂等 | ❌ 重复收会多算 | ✅ 同一值收 N 次等价收 1 次 |
| 抗丢包 | ❌ 丢一帧永久蒸发 | ✅ 下一帧到达即对正 |
| 抗乱序 | ❌ 旧帧会重复累加 | ✅ 差值 ≥ 2³¹ 自动忽略 |
| 抗回绕 | 不适用 | ✅ `wrapping_sub` 处理 4 GB 回绕 |

**数学原因**：绝对偏移的误差只差「最后一次成功送达之后」的量，**永不累积**；
增量语义每丢一帧就永久漏掉一块，累计超过窗口即死锁。

#### `tc netem` 链路丢包（另一层测试）

| 丢包率 | 下行 | 上行 | 完整性 |
|--------|------|------|--------|
| 1% | 53.8 MB/s | 35.1 MB/s | ✅ |
| 5% | 9.0 MB/s | 4.3 MB/s | ✅ |
| 10% | 2.4 MB/s | 1.6 MB/s | ✅ |

内核 TCP 重传兜底，数据全部完整 —— 但**这层测不出流控缺陷**，
两层测试缺一不可。

#### RTT 环境（`netem delay 50ms`，RTT≈100 ms）

| 窗口 | 上行 |
|------|------|
| 256 KB（改造前） | 1.5 MB/s |
| **8 MB（现在）** | **3.2 MB/s（2.1 倍）** |

同一环境下**原生 TCP 基线仅 1.0~15.9 MB/s（两轮差 16 倍）** ——
说明 3.2 MB/s 已落在原生波动范围内，**流控不再是瓶颈**，
瓶颈是内核 socket 缓冲（`net.ipv4.tcp_rmem` 默认 128 KB）。

### 6.7 与 ARQ 的关系

流控与 ARQ 是**两个正交的机制**，不要混在一起：

| 机制 | 管什么 | 何时生效 |
|------|--------|---------|
| **流控** | 发送方能不能发（接收方是否有空间） | 始终 |
| **ARQ** | 发出去的数据要不要重传 | 检测到丢失 |

**顺序**：先流控（拿信用）→ 再 ARQ（发/重传）。重传**也消耗信用**。

### 6.8 实施顺序（避免一次改太多）

| 步骤 | 内容 | 状态 |
|------|------|------|
| **4.1** | `Window` 帧编解码 + 单元测试 | ✅ 完成（19 单测） |
| **4.2** | 发送侧信用记账（`SendCredit` + `SendFlow`） | ✅ 完成 |
| **4.3** | 接收侧信用发放（`FlowCounters`，搭便车） | ✅ 完成 |
| **4.3.1** | ★ 补发位置修正（接收 → 消费）+ 半关闭不注销 | ✅ 完成（见 §6.6.2） |
| **4.3.2** | `SlotTable` 替换 `HashMap`（无锁流表） | ✅ 完成（53.5 → 0.7 ns） |
| **4.5** | 自动调优（消费速率 × RTT） | ⬜ 待做 |
| **4.6** | ARQ（`Ack` 帧 + 重传队列 + 超时跳过空洞） | ⬜ 待做 |
| **4.7** | FEC | ⬜ 待做 |
| **4.8** | 接 FakeTCP | ⬜ 待做 |

**4.6 的前置条件（必读）**：ARQ 的重传队列若只等 `Ack`，一旦 `Ack` 丢失，
`consumed` 不前进 → 与 §6.6.2 完全同款的死锁。**必须配「超时跳过空洞」**
（默认 200 ms）：超时即视为该段已消费，继续推进窗口。
宁可让流控记账偏保守，也不能让隧道停死。

---

## 七、结论

### 7.1 对本项目最重要的 5 条

1. **窗口必须 ≥ 2×BDP**，否则流控就是吞吐瓶颈（这是数学，不是调优）
2. **流控帧必须搭便车**，绝不单独发包（QUIC §4.3 明确建议）
3. **信用按「已接收」而非「已交付」计算**，否则丢包会流控死锁
4. **UDP 流禁止 ARQ**（TUIC 用 QUIC Datagram 的启示）—— 丢了就丢
5. **AEAD 算法必须按 CPU 选**：实测本机 AES 比 ChaCha20 小包快 8 倍，
   但在无 AES-NI 的 ARM 上会反过来

### 7.2 不要照抄的部分

| QUIC/Hysteria 的做法 | 为什么 FlowTCP 不适用 |
|---------------------|----------------------|
| 丢包 → 拥塞窗口减半 | FakeTCP 外层是 TCP，QoS 看不到，丢包只来自真实拥塞 |
| Brutal 固定速率 + 速率反馈 | 我们不需要「对抗 QoS 丢包」，因为 QoS 不作用在 TCP 上 |
| 64 位绝对偏移 | 32 位增量更省 CPU，4 GB 窗口对本场景足够 |
| 连接迁移（PATH_CHALLENGE） | 我们只有一条固定路径 |

### 7.3 一句话总结

> **QUIC 的流控是「为配合拥塞控制而设计」的，FlowTCP 只需要「纯内存保护」。**
> **所以我们应该做得比 QUIC 简单，但窗口数学必须遵守同一套 BDP 约束。**

---

## 八、参考资料

- RFC 9000 §4 Flow Control（本文档所有「原文」引用的来源）
- RFC 9002 QUIC Loss Detection and Congestion Control
- RFC 9221 QUIC Datagram（TUIC 用它承载 UDP）
- quinn `TransportConfig` 文档（各参数的取舍理由）
- Hysteria 1/2 Brutal 拥塞控制设计（固定速率 + 显式接收速率反馈）
- 本项目实测：`crates/flowtcp-proto/examples/bench_record.rs`
