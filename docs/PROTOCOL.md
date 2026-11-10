# FlowTCP 协议规范 v0.1（草案）

> 最后更新: 2026-11-10 17:12 (北京时间)
> 状态: 架构确定，待实现验证
> 本文档是代码实现的唯一真相源，实现与本文档不一致时以本文档为准（或先改文档再改代码）。

---

## 0. 一句话定义

FlowTCP 是一套 **把 TCP/UDP/DNS/ICMP 代理流量封装成「外观为 TLS 1.3 的伪 TCP 数据报」** 的传输协议。
外层 DPI 看到的是 `TCP:443 + 标准 TLS 1.3 握手 + 加密应用数据`，内层保留 UDP 的**乱序、无重传、可丢包**语义。

---

## 1. 设计红线（不可违反）

| # | 红线 | 原因 |
|---|------|------|
| 1 | **不得使用真实 TCP 三次握手** | 真 TCP 会引入内核拥塞控制与 HOL 阻塞，丧失 UDP 低延迟特性 |
| 2 | **握手必须是标准 TLS 1.3** | 抗主动探测；ClientHello 不得含任何私有字段 |
| 3 | **数据记录必须是显式序号** | 隐式序号（标准 TLS）丢包即全链失效，见 RFC 9147 §3 |
| 4 | **只有一层 AEAD** | 双层 TLS 会带来双倍 CPU 与 TLS-in-TLS 特征 |
| 5 | **分流判定只能在「握手后首帧明文」** | ClientHello 阶段的任何差异都会被指纹识别 |
| 6 | **不可靠模式必须可关闭重传** | 游戏/语音场景下重传 = 延迟抖动 |

---

## 2. 协议分层

```
┌──────────────────────────────────────────────┐
│ L5 应用适配：SOCKS5(CONNECT/UDP ASSOCIATE)、   │
│             HTTP CONNECT、DNS:53、ICMP        │
├──────────────────────────────────────────────┤
│ L4 复用层：stream_id 多路复用 + 可选 ARQ + FEC │
├──────────────────────────────────────────────┤
│ L3 记录层：AEAD 加密 + 显式序号 + TLS 记录伪装 │
├──────────────────────────────────────────────┤
│ L2 握手层：标准 TLS 1.3（rustls）+ 首帧分流    │
├──────────────────────────────────────────────┤
│ L1 承载层：FakeTCP（raw socket，协议号=6）     │
└──────────────────────────────────────────────┘
```

---

## 3. L1：FakeTCP 承载层

### 3.1 行为要求

| 项 | 规范 |
|----|------|
| 报文 | 自行构造 IPv4/IPv6 + TCP 头，IP 协议号 = 6 |
| 握手 | 模拟 SYN / SYN-ACK / ACK，ISN 随机（CSPRNG） |
| seq/ack | 数据发送时 seq 递增（按 payload 长度），ack 回填最近收到的 seq |
| 选项 | 首个 SYN 必须带 MSS(1460)、SACK_Permitted、Timestamps、WScale(7) |
| DF 位 | 必须置 1，禁止中途分片 |
| 重传 | **无**。丢包由上层 ARQ 或 FEC 处理 |
| 流控 | **无** |
| 拥塞控制 | **无** |
| 乱序 | **允许并透传** |

### 3.2 内核冲突处理

```bash
# 必须屏蔽内核对该端口的 TCP 处理，否则内核回 RST
# 方案：DNAT 到 TUN，或直接 DROP 内核可见的 RST
nft add rule inet filter input tcp dport 443 counter drop   # 仅当 FakeTCP 自行处理时
```

- 推荐用 **TUN 接口**（同 phantun）：`PREROUTING` DNAT 到 TUN 地址，用户态读写 TUN。
- 权限：`cap_net_admin` + `cap_net_raw`（无需完整 root）。

### 3.3 MTU 预算

| 层 | 开销 |
|----|------|
| IPv4 头 | 20 |
| TCP 头 | 20 |
| TLS 记录头 | 5 |
| masked_seq | 8 |
| AEAD tag | 16 |
| 内层帧头 | 8 |
| **合计** | **77** |

链路 MTU 1500 → **内层单帧 payload 上限 = 1400**（留 23 字节安全余量）。
Path MTU < 1400 时应降级到 1280（IPv6 最小 MTU）。

---

## 4. L2：握手与分流

### 4.1 握手流程

```
客户端                                         服务端
  │── SYN（ISN=随机） ────────────────────────→│
  │←──────────────────────── SYN-ACK ─────────│
  │── ACK ────────────────────────────────────→│
  │── ClientHello（标准 Chrome 指纹）─────────→│
  │←── ServerHello + EncryptedExtensions ─────│
  │←── Certificate（真证书，LE 签发）─────────│
  │←── CertificateVerify + Finished ──────────│
  │── Finished ───────────────────────────────→│
  │── [首帧 app_data 加密] ───────────────────→│
  │←── 分流结果 ──────────────────────────────│
```

**ClientHello 硬性要求**（必须逐项对齐真实 Chrome）：

| 字段 | 值 |
|------|-----|
| legacy_version | 0x0303 |
| TLS 版本 | supported_versions = [0x0304, 0x0303] |
| ALPN | `h2`, `http/1.1` |
| SNI | 真实域名，与证书一致 |
| cipher_suites | 完整 Chrome 顺序（含 GREASE） |
| extensions | 完整 Chrome 集合（含 GREASE、key_share、signature_algorithms 等） |
| session_id | 32 字节随机 |
| **禁止** | 任何自定义 extension、非标 length、异常 padding |

> 客户端指纹库可参考 `utls` / `boring` 的 Chrome 预设，但实现时需用 rustls 的 `ClientHello` 构造能力或自研。
> **待定项**：是否引入 uTLS 同类能力。见 §12 开放问题。

### 4.2 分流判定（唯一判定点）

服务端解密握手后**第一个** `application_data` 记录的明文，按首字节匹配：

| 前缀 | 判定 | 动作 |
|------|------|------|
| `PRI ` | HTTP/2 preface | 转 nginx:8443（明文 h1.1 反代） |
| `GET ` / `POST` / `HEAD` / `PUT ` / `DELE` / `OPTI` / `PATC` / `CONN` | HTTP/1.1 请求 | 转 nginx:8443 |
| `FTAUTH` | FlowTCP 客户端 | 进入认证 → 切换记录层 |
| 其他 | 未知 | 转 nginx（由其返回 400/404，保持真实） |

**关键**：判定前必须**完整接收该记录**。若该记录丢失，靠 ARQ 重传（握手/认证阶段强制启用可靠模式）。

### 4.3 密钥导出

TLS 1.3 握手完成后，双方调用 TLS exporter（RFC 8446 §7.5）：

```
master = TLS-Exporter("EXPORTER-FlowTCP-v1", context, 32)
  context = ClientHello.random (32B) || ServerHello.random (32B)

c2s_key = HKDF-Expand(master, "flowtcp c2s key", 32)
s2c_key = HKDF-Expand(master, "flowtcp s2c key", 32)
c2s_sn  = HKDF-Expand(master, "flowtcp c2s sn",  16)
s2c_sn  = HKDF-Expand(master, "flowtcp s2c sn",  16)
c2s_iv  = HKDF-Expand(master, "flowtcp c2s iv",  12)
s2c_iv  = HKDF-Expand(master, "flowtcp s2c iv",  12)
```

- AEAD：`AES-128-GCM`（有 AES-NI 时）或 `ChaCha20-Poly1305`（ARM 无 AES 加速时）
- 单层 AEAD，**不再叠加任何第二层加密**

### 4.4 认证帧（首帧明文内容）

`FTAUTH` 之后的标准 TLS 加密内容：

```
+--------+--------+--------+--------+--------+---------+
|"FTAUTH"| ver(1) | ulen(1)| user(ulen)                 |
+--------+--------+--------+--------+--------+---------+
| ts(8, unix 秒)  | nonce(8)                        |
+--------+--------+--------+--------+--------+---------+
| hmac_sha256(32)                                 |
+-------------------------------------------------+
```

- `ver`：协议版本，v0.1 = 0x01
- `hmac = HMAC-SHA256(secret, "FTAUTH" || ver || user || ts || nonce)`
- 校验窗口：`|now - ts| <= 60s`
- nonce 去重：服务端维护 60s 内已用 nonce 集合（LRU）
- 失败：**延迟 1~3s 随机后静默关闭**（不给探测者区分信号）

---

## 5. L3：记录层格式

### 5.1 线上格式（与真 TLS 逐字节同构）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
|     0x17      |  0x03 |  0x03 |         length (16)          |
+---------------+---------------+-------------------------------+
|                    masked_seq (64)                            |
+---------------------------------------------------------------+
|                    ciphertext (length - 8)                    |
+---------------------------------------------------------------+
```

- `0x17 0x03 0x03` = TLS 1.3 application_data（与真 TLS 完全一致）
- `length` = `8 + len(ciphertext)`，`ciphertext = plaintext + 16B tag`
- `letter` 上限 2^14（16384），超长必须分帧

### 5.2 序号加密（借 DTLS 1.3 §4.2.3）

```
发送端：
  mask   = AES-ECB(sn_key, ciphertext[0..16])[0..8]
  masked = seq XOR mask

接收端：
  mask   = AES-ECB(sn_key, ciphertext[0..16])[0..8]   # 只依赖密文，无鸡蛋问题
  seq    = masked_seq XOR mask
  nonce  = iv XOR (0x00000000 || seq_be_u64)          # 12 字节
```

- `seq` 从 0 开始，单调递增，**永不重用**
- 要求 `len(ciphertext) >= 16`（tag 已保证）
- 序号空间耗尽前必须重新握手（2^62 上限，实际不可达）

### 5.3 AAD

```
AAD = record_header(5B) || masked_seq(8B) = 13 字节
```

> 使用 masked 值作为 AAD，确保收发双方线上字节一致。

### 5.4 重放与乱序窗口

- 接收端维护 **1024 位**滑动窗口
- `seq <= right_edge - 1024` → 直接丢弃
- 窗口内已标记 → 丢弃（重放）
- 解密失败 → 丢弃，计入 AEAD 失败计数（超过 2^20 次则断连）

---

## 6. L4：内层帧格式

记录层明文是**一个或多个内层帧**的串联：

```
+--------+--------+---------------+---------------+
| type(1)| flags(1)| stream_id(2)                 |
+--------+--------+---------------+---------------+
| pkt_seq(4)                     | payload_len(2)|
+--------+--------+---------------+---------------+
| payload (payload_len)                          |
+-------------------------------------------------+
```

固定头 **9 字节**。

### 6.1 帧类型

| type | 名称 | 说明 |
|------|------|------|
| 0x01 | `OPEN_TCP` | 打开 TCP 流；payload = 目标地址 |
| 0x02 | `OPEN_UDP` | 打开 UDP 会话；payload = 目标地址 |
| 0x03 | `DATA` | 数据 |
| 0x04 | `CLOSE` | 关闭流；flags 区分正常/异常 |
| 0x05 | `ACK` | ARQ 确认；payload = 位图 |
| 0x06 | `PING` | 心跳；payload 长度随机 8~32 |
| 0x07 | `PONG` | 心跳响应 |
| 0x08 | `FEC` | 冗余包；payload = 校验数据 |
| 0x09 | `WINDOW` | 流控更新（可选，默认关闭） |
| 0x0A | `ERROR` | 错误通知；payload = code(2) + msg |

### 6.2 flags

| bit | 含义 |
|-----|------|
| 0x01 | `RELIABLE`：要求对端 ACK 并重传 |
| 0x02 | `LAST`：FEC 组的最后一个数据包 |
| 0x04 | `FIN`：流结束（配合 CLOSE） |
| 0x08 | `CORK`：允许合并发送（小包聚合） |

### 6.3 地址编码（OPEN 帧 payload）

```
+--------+------------------------+
| atyp(1)| addr(var) | port(2)    |
+--------+------------------------+
atyp: 0x01=IPv4(4B)  0x03=域名(1B len + n)  0x04=IPv6(16B)
```

与 SOCKS5 地址格式一致，便于零拷贝映射。

### 6.4 stream_id 分配

| 范围 | 用途 |
|------|------|
| 0 | 控制流（AUTH 之后承载 PING/ERROR） |
| 1..0x7FFF | 客户端发起 |
| 0x8000..0xFFFE | 服务端发起（反向代理场景预留） |
| 0xFFFF | 保留 |

- 客户端分配单调递增，回绕时跳过已用值
- 流关闭后 `stream_id` 进入 `TIME_WAIT` 时长（60s）后才可复用

---

## 7. ARQ（照抄 QUIC RFC 9002）

> **本节已按 hy2 的实现路线重写。** hy2 的 ARQ 就是 quic-go，因此这里直接采用
> RFC 9002（丢包检测与 RTT 估计）与 RFC 9000 §19.3（范围 ACK）的机制与参数。
> 原「KCP 精简版」方案（64 位位图 + RTO 指数退避）已废弃，理由见 §7.6。

### 7.1 启用条件

| 阶段 | 强制/可选 |
|------|----------|
| TLS 握手 | **强制**（标准 TLS 要求有序可靠） |
| AUTH | **强制** |
| `OpenTcp` 流 | **强制**（TCP 是可靠字节流） |
| `OpenUdp` 流 | **禁止**（UDP 语义 = 丢了就丢） |

与 Hysteria 2 完全一致：它的 TCP 走 QUIC stream（有 ACK + 重传），
UDP 走 RFC 9221 unreliable datagram（官方原文：「任一分片丢失则整个包丢弃」）。

### 7.2 参数（全部来自 RFC 9002）

| 常量 | 值 | 出处 |
|------|-----|------|
| `kPacketThreshold` | 3 | §6.1.1 |
| `kTimeThreshold` | 9/8 | §6.1.2 |
| `kGranularity` | 1 ms | §6.1.2 |
| `kInitialRtt` | 333 ms | §6.2.2 |
| `MAX_ACK_DELAY` | 25 ms | QUIC 默认 |
| `MAX_ACK_RANGES` | 300 | 受 MTU 约束（见 §7.6） |
| `MIN_CWND_PKTS` / `MAX_CWND_PKTS` | 32 / 2048 | 见 §7.5 |

### 7.3 `Ack` 帧格式（范围 ACK）

替代原设计的 `ack_seq(4) + bitmap(8)`。用固定宽度编码（不用 QUIC varint，
便于快速解析），语义与 RFC 9000 §19.3 一致：

```text
largest_acked  u32   已收到的最大 pn
ack_delay      u16   对端应扣除的 ACK 延迟（毫秒，饱和）
range_count    u8    后续范围数
first_range    u16   largest 往下连续确认的「额外」个数
[gap u16, len u16] × range_count
```

- `gap` = 与上一个范围之间**未确认**的包数
- `len` = 本范围长度减 1
- 范围按 `end` 严格降序，相邻/重叠自动合并

**为什么位图不行**（RFC 9002 §4.5）：64 位位图只能表达 largest 之前 64 个包的
状态；丢包 10% 时乱序跨度轻易超过 64，超出部分只能当「未确认」→ 虚假重传。
范围 ACK 没有这个限制。

### 7.4 丢包检测（RFC 9002 §6.1）

一个包被判定丢失，需满足 `pn <= largest_acked`，且**二者其一**：

1. **包阈值**：`largest_acked - pn >= 3`
2. **时间阈值**：`sent_at <= now - max(9/8 × max(smoothed_rtt, latest_rtt), 1ms)`

**比对端最大确认还新的包绝不判丢** —— 这是硬约束。

### 7.5 PTO 与拥塞窗口

**PTO**（§6.2.1）：

```text
PTO = smoothed_rtt + max(4·rttvar, kGranularity) + max_ack_delay
退避：× 2^pto_count（收到有效 ACK 时清零）
```

**PTO 到期不判定任何包丢失**（§6.2 原文：「A PTO timer expiration event does
not indicate packet loss and MUST NOT cause prior unacknowledged packets to be
marked as lost」），只发一个探测包（取最老的未确认包）。

**动态拥塞窗口**（照抄 Brutal 的思路，丢包**不**减窗口）：

```text
cwnd = clamp(0.8 × MAX_ACK_RANGES / 丢包率, 32, 2048)
```

核心不变量：

```text
在途包数 × 丢包率  ≤  一个 Ack 帧能装下的范围数
```

因为接收端的乱序段数约等于「在途包数 × 丢包率」。超出就会截断 →
老包得不到确认 → 反复重传 → 停滞（实测 10% 丢包时卡在 3 MB）。

**为什么不做 AIMD**：与 Hysteria 的 Brutal 一致 —— 丢包主要来自链路 QoS，
减小窗口只会让吞吐更低，不会让链路变好。只按实测丢包率**设定上限**。

### 7.6 ★ 三个必须知道的实现约束（实测暴露）

#### 7.6.1 FIN 必须占用 ARQ 序号

`Close(fin=true)` 在语义上是「流的最后一个字节之后」，**必须排在所有
`Data` 之后**。若用固定 seq（如 0）绕过重排，它会超过仍在途的数据提前生效 ——
实测（5% 丢包）请求包被丢 + FIN 先到 → 服务端提前半关闭 → 重传的请求
无处可投 → 下载拿到 **0 字节**。

QUIC 用 stream offset 天然解决；我们没有 offset，所以让 FIN 占一个 `next_seq()`。

#### 7.6.2 重传复用原 seq（不学 QUIC 用新 pn）

QUIC 给每次重传分配新 packet number，因为它按 **stream offset** 算流控
（重传同一段不重复占额度）。我们按「收到的字节」记账，若重传用新 seq：

1. 流控重复计数 → 窗口提前耗尽
2. 重排缓冲把重传当「乱序新数据」缓存 → 实测涨到 8.45 MB 触发溢出保护

**复用 seq 后**接收方幂等丢弃重复包，两个问题都消失（这是 KCP 的做法）。
代价：RTT 样本偏大（保守，只会让 PTO 更宽容）。

#### 7.6.3 读循环绝不能被写队列堵住

`Ack` / `Window` / PTO 重传都从读循环发出。若用 `send().await`：

```text
数据洪流 → 写队列满 → 读循环阻塞
  → 无法处理对端 Ack → largest_acked 不更新
  → 包阈值检测失效 → 只能靠秒级 PTO → 停滞
```

**必须用 `try_send`，满了就丢**（这些帧都幂等可重发：`Window` 是绝对偏移、
`Ack` 每 100 ms 必发、PTO 下轮再试）。

### 7.7 收尾（draining）

目标 EOF 后，**先等 `inflight` 清零再关注解流**，否则丢失的尾包再无重传机会
（实测不加等待时 5% 丢包只收到 9 MB / 16 MB）。

### 7.8 实测（16 MB，应用层帧注入，真 TCP 承载）

| 丢包率 | 下行 | 完整性 | 上行 |
|--------|------|--------|------|
| 0% | 69.6 MB/s | ✅ 逐字节一致 | 14.2 MB/s |
| 10% | 28.1 MB/s | ✅ 逐字节一致 | 14.5 MB/s |
| 20% | 14.0 MB/s | ✅ 逐字节一致 | 13.8 MB/s |
| 30% | 7.2 MB/s | ✅ 逐字节一致 | 12.4 MB/s |

对比 ARQ 之前（5% 丢包）：下行 60 秒超时只收 **2.4 MB**，上行**完全卡死**。

## 8. FEC（抗丢包）

### 8.1 XOR 模式（轻量，默认）

```
每 K 个同 stream 的 DATA 帧生成 1 个 FEC 帧：
parity = payload_1 XOR payload_2 XOR ... XOR payload_K
```

- 补齐：短包尾部补 0 到本组最大长度
- FEC 帧 payload：`group_id(4) + count(1) + max_len(2) + parity(max_len)`
- 丢 1 个包可无损恢复；丢 2 个则需 ARQ

### 8.2 Reed-Solomon 模式（强，可选）

- crate：`reed-solomon-erasure`
- 参数：`data_shards` / `parity_shards` 可配（默认 10/3 ≈ 30% 冗余）
- 适用：高丢包链路（> 15%），代价是带宽上升与 CPU 增加

### 8.3 推荐配置

| 场景 | 模式 | 参数 |
|------|------|------|
| 游戏 / 语音 | 不可靠 + XOR | K=5, 20% 冗余 |
| 网页 / SSH | ARQ | 关闭 FEC |
| 视频 / 大文件 | 不可靠 + XOR | K=20, 5% 冗余 |
| 高丢包链路 | 不可靠 + RS | 10/3 |

---

## 9. 拥塞控制与应用层限速

```toml
[transport.cc]
mode = "brutal"    # none | brutal | bbr
up_mbps = 100
down_mbps = 200
```

| 模式 | 说明 | 适用 |
|------|------|------|
| `none` | 不限速，全速发送 | 局域网 / 可信链路 |
| `brutal` | 固定速率令牌桶，无视丢包 | 已知带宽、追求稳定延迟 |
| `bbr` | 基于 RTT/带宽估计 | 带宽未知、链路多变 |

- **限速唯一执行点**在应用层令牌桶；底层 FakeTCP 不做任何限速
- `brutal` 模式下丢包由 FEC 补偿，严禁开启 ARQ 重传（会双重放大）

---

## 10. 应用协议映射

### 10.1 TCP CONNECT

```
客户端                                   服务端
SOCKS5 CONNECT
  → stream_id=N, OPEN_TCP(目标地址)
  → 服务端 connect() 成功 → 无响应（隐式成功）
  → 双向 DATA 帧（flags 可带 RELIABLE）
失败：ERROR 帧（code=0x0001 连接拒绝 / 0x0002 DNS 失败）
```

### 10.2 UDP ASSOCIATE

```
客户端                                   服务端
SOCKS5 UDP ASSOCIATE
  → OPEN_UDP(首个目标地址) → stream_id=N
  → 每个 UDP 数据报封装为一个 DATA 帧（flags 不含 RELIABLE，默认）
  → 服务端用真实 UDP socket 发往目标
  → 目标返回 → 服务端封装 DATA 帧回传
会话回收：stream 空闲 120s → 服务端发 CLOSE
```

- **单个 stream 承载多个目标地址**：UDP ASSOCIATE 允许同一客户端向不同目标发包，因此每个 DATA 帧的 payload 需带目标地址前缀（当目标变化时）
- 优化：`OPEN_UDP` 指定默认目标，同目标的数据帧省略地址前缀（用 flags bit 0x10 标记 `HAS_ADDR`）

### 10.3 DNS

- 客户端监听 `127.0.0.1:53`（UDP + TCP）
- 若为独立 listener 模式：直接复用 UDP 流，目标为上游 DNS
- 若为透明重定向（TUN/iptables）：同 UDP 流程
- 防泄漏：客户端必须拦截所有 `:53` 出站并强制走隧道

### 10.4 ICMP

- 客户端：内置 `flowping <host>` 子命令，不截获系统 `ping`
- 服务端：Linux `SOCK_DGRAM + IPPROTO_ICMP`（需 `net.ipv4.ping_group_range` 放开，**免 root**）
- 帧类型：复用 `OPEN_UDP` + 特殊 atyp（`0x05 = ICMP-echo`）
- payload：`icmp_id(2) + icmp_seq(2) + ttl_req(1) + data`
- **不支持**：traceroute（TTL 语义无法还原）

---

## 11. 心跳与流量伪装

| 项 | 规范 |
|----|------|
| 心跳间隔 | 25~35s 随机（**必须有抖动**，固定间隔可被长期观察识别） |
| 心跳载荷 | 8~32 字节随机填充 |
| 空闲填充 | 可配置：每 T 秒发送 0~64 字节随机 padding 帧（模拟 HTTP keepalive 噪声） |
| 首包延迟 | 认证通过后，服务端可延迟 0~50ms 再返回首个数据，模拟真实 RTT 分布 |
| 关闭行为 | 客户端断开时发标准 TLS `close_notify`，**不要直接 RST** |

---

## 12. 开放问题（待实现验证）

| # | 问题 | 待定方案 |
|---|------|---------|
| 1 | ClientHello 指纹如何做到真实 Chrome 级 | A. 自研 ClientHello 构造；B. 引入 uTLS 等价能力；C. fork rustls |
| 2 | rustls 是否支持读取 exporter | 已确认支持 `export_keying_material` |
| 3 | 探测流量反代 nginx 时，h2 → h1.1 降级的兼容性 | 需实测 Chrome h2 行为 |
| 4 | FakeTCP 在 Windows/Android 的实现路径 | WinDivert / root，见 PROJECT_PLAN §风险 |
| 5 | 多路径/多连接负载均衡策略 | Phase 2 设计 |
| 6 | ICMP 是否需要 root | 用 `ping_group_range` 免 root，待测 |

---

## 13. 版本与兼容

| 字段 | 值 |
|------|-----|
| 协议版本 | `0x01`（v0.1） |
| exporter label | `EXPORTER-FlowTCP-v1` |
| 兼容策略 | 主版本不同 → 认证失败 → 静默关闭 |

---

*本规范随开发迭代更新。修改协议必须同步更新本文件并记录到 CHANGELOG.md。*
