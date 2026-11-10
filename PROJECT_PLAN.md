# FlowTCP 项目开发方案

> 版本: v0.13（★ Phase 4.6 ARQ 完成：照抄 QUIC RFC 9002，0~30% 丢包全部逐字节完整）
> 创建日期: 2026-11-10 17:12 (北京时间)
> 最后更新: 2026-11-11 01:56 (北京时间)
> 状态: **Phase 3 完工 + Phase 4 前置优化完成**，进入 Phase 4（信用流控 → ARQ → FEC → FakeTCP）

---

## 一、项目定位

FlowTCP 是一套**独立、跨平台、高性能的代理传输协议**。核心目标：在 UDP 被 QoS 限速/丢包/限制的网络环境中，用**外观像 TCP+TLS 1.3 的伪 TCP 数据报**承载 TCP/UDP/DNS/ICMP 代理流量，同时**保留 UDP 的乱序、无重传、低延迟语义**。

### 1.1 一句话技术路线

```
SOCKS5/HTTP/DNS/ICMP 入口
  → 内层帧（stream 复用 + 可选 ARQ + FEC）
  → 单层 AEAD（密钥来自 TLS 1.3 exporter）
  → 自定义记录层（显式序号，伪装成 TLS application_data）
  → FakeTCP（raw socket 伪造 TCP 头，无拥塞控制）
  → 公网 DPI 看到：TCP:443 + 标准 TLS 1.3
  → 服务端解封装 → 真实 UDP/TCP socket
```

### 1.2 六条不可违反的红线

| # | 红线 | 后果 |
|---|------|------|
| 1 | 不得使用真实 TCP 三次握手 | 否则引入拥塞控制 + HOL，UDP 低延迟全失 |
| 2 | 握手必须是 100% 标准 TLS 1.3 | ClientHello 加私有字段 = 被指纹识别 |
| 3 | 数据记录必须显式序号 | 隐式序号丢包即全链失效（RFC 9147 §3） |
| 4 | 只允许一层 AEAD | 双层 TLS = 双倍 CPU + TLS-in-TLS 特征 |
| 5 | 分流判定只能在「握手后首帧明文」 | 其他判定点都会留下可比对差异 |
| 6 | 不可靠模式必须能彻底关闭重传 | 游戏/语音场景下重传 = 延迟抖动 |

---

## 二、四层架构

```
┌──────────────────────────────────────────────────────────┐
│ L5 应用适配层（客户端本地）                                │
│  SOCKS5 CONNECT / UDP ASSOCIATE │ HTTP CONNECT            │
│  DNS :53 listener │ flowping（ICMP）                       │
├──────────────────────────────────────────────────────────┤
│ L4 复用层                                                  │
│  stream_id 多路复用 │ 可选 ARQ（KCP 精简版）│ FEC │ 限速   │
├──────────────────────────────────────────────────────────┤
│ L3 记录层                                                  │
│  AES-128-GCM / ChaCha20-Poly1305 │ 显式序号 + 序号加密      │
│  伪装成 TLS 1.3 application_data（0x17 03 03）             │
├──────────────────────────────────────────────────────────┤
│ L2 握手层                                                  │
│  标准 TLS 1.3（BoringSSL）│ ClientHello 认证 │ 失败则透传    │
├──────────────────────────────────────────────────────────┤
│ L1 承载层                                                  │
│  FakeTCP（raw socket + TUN）│ 无重传/无流控/无拥塞控制      │
└──────────────────────────────────────────────────────────┘
```

### 2.1 服务端额外组件

| 组件 | 职责 | 关键约束 |
|------|------|---------|
| **透传转发器** | 认证失败时把 TCP 字节流转发给真实网站 | 双向 copy，零解析，不参与 TLS |
| **临时证书签发** | 认证通过后自行完成 TLS 握手 | 现场生成临时密钥对 + 自签证书 |
| **出口模块** | 真实 TCP/UDP/DNS 连接 | 预留上游代理链（SOCKS5/HTTP）扩展点 |

---

## 三、已确认的架构决策

| # | 决策点 | 结论 |
|---|--------|------|
| 1 | 承载层 | FakeTCP（raw socket），复用 `phantun` 的 `fake-tcp` crate |
| 2 | 加密 | 单次 TLS 1.3 握手 + `export_keying_material` 派生，单层 AEAD |
| 3 | 记录层 | `0x17 03 03 │ len │ masked_seq(8) │ ciphertext+tag` |
| 4 | 序号 | 显式 + XOR 掩码（借 DTLS 1.3 §4.2.3），容忍乱序 |
| 5 | 分流 | **ClientHello.session_id 认证**：失败 → 透传真网站；成功 → 走代理 |
| 6 | 可靠性 | 握手/AUTH 强制 ARQ；数据段可选（不可靠+KCP+自适应） |
| 7 | 抗丢包 | XOR FEC（默认）/ Reed-Solomon（高丢包） |
| 8 | 拥塞控制 | `none` / `brutal`（固定速率）/ `bbr`，应用层令牌桶为唯一限速点 |
| 9 | 输入协议 | SOCKS5 TCP/UDP、HTTP CONNECT、DNS、ICMP（flowping） |
| 10 | 服务端伪装 | **偷网站**：透传到真实网站，零证书零 nginx（见 #22） |
| 11 | 证书 | **不需要**（偷网站方案）。认证通过后用现场生成的临时证书 |
| 12 | 客户端平台 | Linux / Windows / Android（有 root 走 FakeTCP，无 root 降级 WSS） |
| 13 | 服务端平台 | 仅 Linux（amd64 + arm64） |
| 14 | 技术栈 | Rust + Tokio + rustls + quinn-proto 之外的自研记录层 |
| 15 | ClientHello 指纹 | **不自研**。用成熟的 BoringSSL（`boring`/`tokio-boring`）—— 已实测支持 `set_grease_enabled`、`set_permute_extensions`、`set_cipher_list`、`set_curves_list`、`set_sigalgs_list` 及 `export_keying_material` |
| 16 | fake-tcp 使用方式 | 项目内 **vendor + patch**（`[FlowTCP PATCH #1]` 接受任意 ISN），因上游只接受 `seq==0` 的 SYN |
| 17 | 网络配置 | **运行时自动完成**（`flowtcp-faketcp::netcfg`）：TUN 创建 + `rp_filter` + 3 条 iptables 规则，幂等且可回滚 |
| 18 | 监听端口 | **完全可配置**，不强制 443（`NetConfig::port`） |
| 19 | TLS-in-TLS 缓解 | 参考 AnyTLS 的 `paddingScheme`：按包序号施加长度填充/分包策略，破坏「内层 TLS 记录尺寸可预测」的特征 |
| 20 | ★ ClientHello 版本策略 | **客户端不设 `min_proto_version`**（默认 1.2~1.3），由服务端强制 TLS1.3。设 min=1.3 会让 BoringSSL 省略 TLS1.2 时代扩展，JA4 偏离 Chrome（实测 `55b375c5d22e` vs 正确值 `8daaf6152771`） |
| 21 | 必备扩展开关 | `set_grease_enabled` + `set_permute_extensions` + `enable_ocsp_stapling` + `enable_signed_cert_timestamps`，缺任一都会偏离 Chrome |
| 22 | ★★ **服务端伪装方式** | **不做内置 nginx、不做 ACME、不要自己的证书**。改用 REALITY 式「偷网站」：认证失败时把 TCP 字节流**原样透传**给真实网站 |
| 23 | 认证载体 | `ClientHello.session_id`（32 字节，TLS 1.3 的兼容性字段，内容不受约束）；密钥复用 ClientHello 已有的 X25519 `key_share`，**不引入任何额外字段** |
| 24 | 流量整形 | AnyTLS 式 `paddingScheme`：按写入序号施加分片/填充，只整形前 8 个包（握手阶段才是特征源） |
| 25 | 偷网站目标选择 | 国外站、TLS 1.3 + h2、证书链完整、**IP 与服务器相近**、不要有域名跳转 |
| 26 | ★ 临时证书 | 偷网站模式必须自签（没有真网站私钥）。安全性靠 **ECDH 派生 Ed25519** 签证书：`seed = HKDF(X25519(双方), salt=client_random)`，客户端验公钥匹配 |
| 27 | 密钥用途隔离 | 票据密钥与证书种子用不同 HKDF info 标签，防止「拿到证书密钥反推票据密钥」 |
| 28 | 服务端双模式 | `Steal`（偷网站，零证书）/ `OwnCert`（AnyTLS 生产方式，自有证书），共享同一套票据认证 |
| 29 | 证书签名验证 | 不单独验自签证书签名，由 TLS 的 `CertificateVerify` 完成（更强证明） |
| 30 | ★★★ **ClientHello 认证的实现路径** | **待决策**。已实测：字节流层改写 `session_id` 因 TLS 1.3 转录包含 ClientHello 全部字节而必然失败（`BAD_DECRYPT`）。三选一：<br/>**A** 改 AnyTLS 式握手后认证（1~2 天，抗探测大降）<br/>**B** 在 `boring-sys` 暴露 `SSL_CTX_set_client_hello_cb`（3~5 天，**推荐**，保住 REALITY 级能力）<br/>**C** 客户端自研 ClientHello（2 周+，放弃 JA4 成果） |
| 31 | 对称票据方案 | 因 `boring` 不暴露 `key_share` 临时私钥，ECDH 方案不可行。改用 `HMAC-SHA256(secret, label‖client_random‖window)` 派生票据与证书种子，安全性等价，且客户端只需预共享密钥 |

### 3.1.1 方案 G：自研 TLS 1.3 客户端（2026-11-10 20:47 定案并完成）

| # | 决策 | 理由 |
|---|------|------|
| 32 | **自研 TLS 1.3 客户端**（不用 BoringSSL 做客户端） | 标准库的握手转录由库内部维护，无法包含我们改写的 `session_id`（DEVTIPS §11）。自研后转录由我们逐字节控制，票据可自由填入 |
| 33 | 客户端**只支持** `TLS_AES_128_GCM_SHA256` + `x25519` | Chrome 首选就是它；范围小 = 代码少 = 审计容易。其余算法明确报 `Unsupported` 而非静默降级 |
| 34 | 服务端**继续用 BoringSSL** | 服务端是"看起来像真网站"的一方，用真库天然无指纹问题；且它是被动响应，转录由我们读到的字节决定，不存在不一致 |
| 35 | 客户端 **不校验证书链**，只验证 `CertificateVerify` 签名 + 临时证书公钥 | 临时证书是自签的，链校验无意义。真正保证身份的是「`cert_seed` 派生的公钥」+「exporter 一致性」 |
| 36 | exporter 派生用 `KeySchedule::from_secret()`，**不复用** `early()` | `early()` 内含 `HKDF-Extract`，exporter_master_secret 已是最终 secret，再套一层会全错（DEVTIPS §13.4） |
| 37 | 应用数据用自研 `Tls13Stream<S>`，不用 `SslStream` | 客户端没有 BoringSSL 会话对象。`Tls13Stream` 在**记录层**与 BoringSSL 对齐即可互通 |

**明确不支持（有意为之，非遗漏）：**

- HelloRetryRequest —— 我们只发 x25519，不会触发
- PSK / 会话恢复 / 0-RTT —— 每条连接都做完整握手（票据认证已足够快）
- 客户端证书 —— 服务端不要求
- AES-256-GCM / ChaCha20 / secp384r1 —— Chrome 首选 AES-128-GCM + x25519

**验证方式（可复现）：**

```rust
// 测试文件：crates/flowtcp-tls/tests/tls13_e2e.rs
// 用 BoringSSL keylog 导出服务端全部 secret，与客户端逐字节比对
unsafe extern "C" {
    fn SSL_CTX_set_keylog_callback(ctx: *mut c_void, cb: Option<extern "C" fn(...)>);
}
```

实测结果：`CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET`、`CLIENT/SERVER_TRAFFIC_SECRET_0`、
`EXPORTER_SECRET` **全部一致**，`SSL_export_keying_material` 输出也一致。

### 3.1.2 Phase 3 数据面决策（2026-11-10 21:55 定案并完成）

| # | 决策 | 理由 |
|---|------|------|
| 38 | 新增独立的 `flowtcp-client` crate | 客户端要支持 Windows/Android（Phase 6），不能塞进 `flowtcp-server`；`flowtcp-cli` 只做参数解析与进程管理 |
| 39 | `Transport` trait 抽象承载层 | Phase 3 用真 TCP 打通数据面，Phase 4 换 FakeTCP 时上层零改动。先把「帧边界/半包/流生命周期/UDP 地址切换」在可靠链路上测清 |
| 40 | 握手后**取回裸字节流**（`Takeable` + `accept_raw`） | `tokio_boring::SslStream` 没有 `into_inner()`。不取回就无法切到自研记录层，只能继续用 TLS 记录层（隐式序号，丢包即失步），项目核心价值归零 |
| 41 | 客户端**不读首帧**做分流 | 方案 G（`session_id` 票据）已把分流决策提前到读 ClientHello 时。认证通过后客户端立刻切记录层，若还用 `accept()` 读首帧会白等 10 秒超时 |
| 42 | 目标策略默认 `DenyPrivate` | 密码泄漏 + 无策略 = 内网沦陷（SSRF）。默认值决定"忘记配置"时的行为，必须 secure by default |
| 43 | 域名目标的**连接后二次校验** | 防 DNS rebinding（域名先解析到公网、再解析到内网）。这是唯一可靠的防护点 |
| 44 | HTTPS 入口**默认自签证书**，可 `--cert/--key` 指定 | 本地 TLS 不经过公网，证书公信力无意义；零配置可用的价值远大于"少一个浏览器警告" |
| 45 | 新增 `OwnedFrame`（payload 为 `Vec<u8>`） | `Frame<'a>` 的借用无法跨越 `await`。数据面必然要「读出记录 → 切帧 → await 写目标」，必须所有权版本 |
| 46 | 写侧**单任务 + mpsc 队列** | 两个任务同时 `write_all` 会让记录交错、对端解出乱码。单消费者顺带获得批量合并（减少 syscall） |
| 47 | 流写队列满时**丢弃**而非阻塞 | 阻塞会让一个慢目标拖垮整条隧道上的所有流。UDP 语义就是"宁可丢包" |
| 48 | HTTP 入口**只改写首个请求**的绝对 URI | 完整 HTTP 解析器要处理 chunked/100-continue/WebSocket 升级/h2 前言，每条都是潜在请求走私漏洞，而 99% 流量走 CONNECT |

### 3.1.3 Phase 4 流控与 CPU 决策（2026-11-10 22:22 调研定案）

> 完整调研与实测数据见 [`docs/FLOW_CONTROL.md`](docs/FLOW_CONTROL.md)。

| # | 决策 | 理由 |
|---|------|------|
| 49 | **流控只管内存保护，不做拥塞控制** | FakeTCP 外层是 TCP，QoS 看不到 UDP，丢包只来自真实拥塞。照抄 QUIC 的「丢包减半窗口」会在 QoS 环境自杀 |
| 50 | **不实现 Hysteria 的 Brutal CC** | Brutal 解决的是「UDP 被 QoS 丢包」，而我们的 FakeTCP 已让 QoS 失效。同样的目标用更简单的方法达到 |
| 51 | `Window` 帧用 **32 位增量**而非 QUIC 的 64 位绝对偏移 | 省掉接收侧的「累计已发字节」u64 状态与每帧一次加法/比较。4 GB 窗口对本场景足够 |
| 52 | **信用帧必须搭便车**，绝不单独发包 | QUIC §4.3 明确建议；我们复用已有的批量合并逻辑（`write_loop` 已实现） |
| 53 | **窗口 ≥ 2×BDP** | RFC 9000 §4.3 铁律：可用信用 < BDP 时，流控就是吞吐瓶颈。这是数学不是调优 |
| 54 | `stream_window`(256KB) 远小于 `conn_window`(4MB) | 防止单条大流挤占全部缓冲，让小流（DNS/SSH）饿死 |
| 55 | **信用按「已接收」而非「已交付」计算** | 否则丢包造成空洞 → 应用不消费 → 缓冲不释放 → 流控死锁（QUIC §4.3 明确警告） |
| 56 | ★ **TCP 流必须 ARQ 重传，UDP 流禁止 ARQ** | 已核实 hy2 官方协议：TCP 走 `QUIC bidirectional stream`（可靠有重传），UDP 走 `QUIC unreliable datagram`（RFC 9221，无重传）。**可靠性是流级属性（由开流帧类型唯一决定），不是帧级属性** —— 逐帧决定会让某一帧漏标时静默丢数据 |
| 56.1 | `Data` 帧的 `RELIABLE` 标志只作**冗余校验** | 与流类型不一致时服务端立即断开并记 error。目的是让实现 bug 立即暴露 —— 静默丢数据表现为「下载文件损坏」，几乎无法复现 |
| 56.2 | 不允许「统一都可靠」 | 队头阻塞（一个丢包卡住整个会话）、延迟放大（游戏宁可丢帧不等 200ms）、流量放大（重传加剧拥塞） |
| 57 | **AEAD 算法运行时按 CPUID 选择** | 实测本机 AES 比 ChaCha20 小包快 **8 倍**，但无 AES-NI 的 ARM 上会反过来。写死任何一个都会在部分设备上高 5~10 倍 CPU |
| 58 | **缓存密码学实例**（`Arc<CachedCipher>`） | 实测每包重建 key schedule 占 64B 包加密耗时的 **44%**；缓存后小包 -48% |
| 59 | **`Vec<Option<Target>>` 替换 `Arc<Mutex<HashMap>>`**（Phase 4.4） | 读循环每帧抢锁+查表 30~60 ns，与加密开销同量级；数组索引只需 2~5 ns |

**Phase 4 实施顺序（每步可独立验证）：**

| 步骤 | 内容 | 风险 |
|------|------|------|
| 4.1 | `Window` 帧编解码 | 无（纯编解码） |
| 4.2 | 发送侧信用记账 | 低 |
| 4.3 | 接收侧信用发放（搭便车） | 低 |
| **4.4** | **`Vec<Option<Target>>` 替换 HashMap（纯 CPU 优化）** | **无协议风险，优先做** |
| 4.5 | 窗口自动调优 | 中 |
| 4.6 | ARQ（`Ack` + 重传队列）**仅对 TCP 流生效** | 高 |
| 4.7 | FEC | 中 |
| 4.8 | 接 FakeTCP 承载 | 高 |

### 3.1.4 数据完整性决策（2026-11-10 23:10，实测驱动）

> 详见 [`DEVTIPS.md`](../DEVTIPS.md) §17。这些决策全部由真实 bug 驱动，
> 不是理论推导。

| # | 决策 | 理由 |
|---|------|------|
| 60 | ★ **可靠流（TCP）永远不丢数据，只允许背压或断开** | 队列满时 `try_send` 丢弃会让 64MB 上传只到 29MB（丢 57%），而客户端完全无感知。TCP 丢一个字节就是数据损坏 |
| 61 | **不可靠流（UDP）允许 `try_send` 丢弃** | 丢包是 UDP 的正常语义；背压反而会放大延迟、破坏实时性 |
| 62 | **`encode` 失败必须终止而不是跳过** | `let _ = encode()` + 条件判断导致超限帧被静默跳过（16MB 只到 32KB，丢 99.8%） |
| 63 | **批量合并超限时必须 `carry` 留回，不能 `break` 丢弃** | `try_recv()` 已把帧取出队列，`break` 后永久丢失；症状是内容错位（丢中间帧） |
| 64 | **`pump` 必须实现半关闭语义** | `select!` 任一侧结束就取消对侧会掐断响应（浏览器半关闭写端是常态） |
| 65 | **大流量测试必须逐字节比对** | 4 个 bug 中有 3 个只改变内容不改变"成功"状态，只比长度或状态码全部漏掉 |

**验收基线（真 TCP 承载，release 构建）：**

| 场景 | 目标 |
|------|------|
| 下行 64MB | ≥ 100 MB/s 且逐字节一致 |
| 上行 64MB | ≥ 100 MB/s 且逐字节一致 |
| 服务端丢包告警 | 0 条 |

### 3.1.5 信用流控接入决策（2026-11-10 23:35，实测驱动）

> 详见 [`DEVTIPS.md`](../DEVTIPS.md) §18 与 [`docs/FLOW_CONTROL.md`](FLOW_CONTROL.md) §6.6.2。
> 两条决策全部由**死锁**驱动 —— 都是从「功能完全正确、就是不通」里挖出来的。

| # | 决策 | 理由 |
|---|------|------|
| 66 | ★ **`poll_grant()` 必须紧随 `on_consumed()`，严禁放在接收路径上** | 窗口上限是 `consumed + window`，接收路径上 `consumed` 还是 0 → 补发量恒为 0 → 对端发完初始窗口就死锁。症状是卡在**恰好 256 KB**、30s 超时、零日志 |
| 67 | ★ **`StreamReceiver::recv()` 内建「上报 + 补发」**，不暴露给调用方 | 早期让调用方自己调 `on_consumed`，只要一处忘了就是同款死锁。内建后从 API 层面消灭误用；缓冲上限由队列深度（256 帧 ≈ 358 KB）兜底 |
| 68 | ★ **`Close` 帧是半关闭，绝不允许直接注销流** | TCP 双向独立关闭。`GET /bigfile` 发完请求就半关闭，然后长时间收响应。删表会让后续 `Window` 帧因「未知流」被丢弃 → 发送侧信用永不恢复 → 卡死在 256 KB |
| 69 | **`Target::Tcp.tx` 用 `Option<Sender>`**，`Close` 时 `take()` 成 `None` | drop 掉投递端 → `tcp_pump` 收到 EOF 走半关闭；**表项保留**供 `Window` 帧授信寻址；真正注销由 `tcp_pump` 结束时的 `cleanup` 完成 |
| 70 | **`read_loop` 不持有出站队列** | 补发搬走后它不再需要。删掉这个持有关系还消除了「读循环持 `Sender` → 写任务收不到 `None` → 不 shutdown → 读循环等不到 EOF」的循环依赖死锁 |
| 71 | **半关闭状态下收到的 Data 仍要 `on_received` 记账** | 这些字节物理上到达了本端，不记会让后续 `poll_grant` 算错补发量，窗口记账永久偏移 |

**验收基线（真 TCP 承载，release 构建，流控已接入）：**

| 场景 | 目标 | 实测 |
|------|------|------|
| 下行 64MB | ≥ 100 MB/s 且逐字节一致 | ✅ **169.9 MB/s**（+19%） |
| 上行 64MB | ≥ 100 MB/s 且逐字节一致 | ✅ **189.5 MB/s**（+23%） |
| 双向并发 64+64MB | 数据完整 | ✅ 123.7 / 126.1 MB/s |
| 测试总数 | 无回归 | ✅ **329 全绿**，clippy 零警告 |

### 3.1.6 丢包环境决策（2026-11-11 00:08，应用层故障注入实测驱动）

> 详见 [`DEVTIPS.md`](../DEVTIPS.md) §19 与 [`docs/FLOW_CONTROL.md`](FLOW_CONTROL.md) §6.6.3。
> 全部决策来自实测 —— 应用层丢帧注入一测，就发现流控**在丢包下完全不可用**。

| # | 决策 | 理由 |
|---|------|------|
| 72 | ★ **`Window` 帧必须用绝对偏移（QUIC `MAX_DATA` 语义），禁止增量** | 增量丢一帧那份信用永久蒸发 —— 实测 `FLOWTCP_DROP_WINDOW=10` 时 45s 超时只收 3.3/16 MB。绝对偏移幂等、抗丢包、抗乱序、抗 4GB 回绕，改造后同场景 **0.128s 完整收完，131.5 MB/s**（约 500 倍） |
| 73 | ★ **信用帧必须周期重发（QUIC PTO 的简化版）** | 绝对偏移只解决「丢了能对正」，前提是**得有一帧到达**。若只在消费时发一次，那帧丢了再无机会。50ms 周期 + 每 200ms 强制重发，成本 4B/流/200ms |
| 74 | **`poll_grant` 返回 `consumed` 的绝对偏移，不再是 `delta`** | 语义统一：接收方只需报告「我已消费到哪」，发送方自行算可用量 |
| 75 | ★ **`DEFAULT_STREAM_WINDOW` 256 KB → 8 MB，`DEFAULT_CONN_WINDOW` 4 MB → 20 MB** | 直接采用 hy2 官方 QUIC 默认值（严格 2:5 比例）。256 KB 在 RTT 100ms 下上限仅 2.5 MB/s（实测 1.5），比 hy2 小 32 倍 |
| 76 | **窗口必须可配（`--stream-window`，支持 `512K`/`8M`/`16M`）** | 对齐 hy2 的 `initStreamReceiveWindow`。窗口是「带宽 × RTT」的函数，没有普适值 |
| 77 | **必须提供应用层故障注入（`FLOWTCP_DROP_*`）** | `tc netem` 的链路丢包在真 TCP 承载下会被内核重传掩盖，**测不出流控缺陷**。两层测试缺一不可 |
| 78 | ★ **优化前必须先测同环境的原生基线** | RTT 100ms 下我们 3.2 MB/s 看似很差，但原生 TCP 基线只有 1.0~15.9 MB/s（两轮差 16 倍）—— 瓶颈是内核缓冲而非流控。不测基线会在错误的地方改代码 |
| 79 | **只丢 Data/Window，控制帧永不丢** | 控制帧丢失会让流建立不起来，无法区分「开流失败」与「流控死锁」 |
| 80 | **`fault` 模块用 `OnceLock` + 线程本地 xorshift32** | 热路径不读环境变量、不引 `rand` 依赖；每线程独立种子避免序列相同 |

**火力基准（16 MB，真 TCP 承载）：**

| 场景 | 目标 | 实测 |
|------|------|------|
| Window 丢 30% | 不掉速、数据完整 | ✅ 141.6 MB/s，完整 |
| Data 丢 5% | 不死锁，只丢 5% | ✅ 缺 5.06%，无额外损失 |
| RTT 100ms 上行 | 优于 256 KB 窗口 | ✅ 1.5 → 3.2 MB/s（2.1 倍） |

**关于 hy2/Brutal 的可借鉴与不可借鉴**（详见 FLOW_CONTROL §5.3）：

| 机制 | 结论 |
|------|------|
| QUIC `MAX_DATA` 绝对偏移 | ✅ **已照抄** |
| QUIC 窗口默认值 8MB/20MB（2:5） | ✅ **已照抄** |
| PTO 超时探测 | ✅ 已用简化版（周期重发） |
| Brutal `cwnd = bps × RTT × 2 / ackRate` | ⬜ Phase 4.6，需先有带宽估计（BBR） |
| Brutal「丢包不降速」 | ⬜ 同上 |
| Brutal 需要用户填带宽 | ❌ 我们的用户不会填，走 BBR 路线 |

### 3.1.7 ARQ 决策（2026-11-11 01:56，照抄 QUIC 后实测驱动）

> 详见 [`DEVTIPS.md`](../DEVTIPS.md) §20 与 [`docs/PROTOCOL.md`](PROTOCOL.md) §7。
> 按「优先用 hy1/hy2 的成熟方法」的要求，hy2 的 ARQ 就是 quic-go，
> 因此全部机制与参数直接取自 RFC 9002 / RFC 9000。
> 6 条决策都是由「集成后连爆 6 个 bug」逼出来的。

| # | 决策 | 理由 |
|---|------|------|
| 81 | ★ **丢包检测：包阈值 3 + 时间阈值 9/8·RTT**（RFC 9002 §6.1） | 原 KCP 方案的「重复 ACK × 3」在范围 ACK 下不适用。这两个阈值是 QUIC 生态的共识值 |
| 82 | ★ **范围 ACK 替代 64 位位图**（RFC 9000 §19.3） | 位图只能表达 largest 前 64 个包；丢包 10% 时乱序跨度轻松超 64 → 虚假重传。RFC 9002 §4.5 明确指出范围 ACK 在高丢包下恢复更快 |
| 83 | **`MAX_ACK_RANGES = 300`**（不是 32） | 32 时实测 `duplicate_count` 达 **43 万**：8 MB 窗口 5% 丢包产生约 285 个乱序段，截断后发送端反复重传同一批。300 是 MTU 硬上限（`(1400-9)/4 ≈ 347`）留余量 |
| 84 | ★ **重传复用原 seq**（不学 QUIC 用新 pn） | 我们流控按「收到字节」记账（无 stream offset）。用新 seq 会导致流控重复计数 + 重排缓冲涨到 8.45 MB 触发溢出。复用 seq 让接收方幂等丢弃，两个问题都消失（KCP 做法） |
| 85 | ★ **FIN 占用 ARQ 序号**（`Close` 用 `next_seq()`） | FIN 是「最后一个字节之后」，必须排在所有 Data 之后。用固定 seq=0 会超过在途数据提前生效，实测导致**收到 0 字节** |
| 86 | ★ **动态 cwnd = `0.8·MAX_ACK_RANGES / 丢包率`，丢包不减窗口** | 核心不变量「在途包 × 丢包率 ≤ ACK 容量」。固定 512 时 0% 丢包吞吐退化 89%（14 vs 124 MB/s）；动态后恢复 69.6 MB/s 且 30% 丢包仍完整。丢包不作为拥塞信号（与 Brutal 一致） |
| 87 | ★ **控制帧一律 `try_send`，读循环绝不阻塞** | 用 `send().await` 时数据洪流堵住读循环 → 无法处理对端 Ack → 包阈值检测失效 → 只能靠秒级 PTO → 停滞 |
| 88 | **ARQ 驱动放在「每批帧」而非「read 超时」** | 持续有数据时 `read` 永不超时 → ACK 一发不出 → `largest_acked` 恒 None → 包阈值检测永不触发 |
| 89 | **ACK 除「有新包」外，每 100ms 无条件重发** | 只靠 `has_news` 时，数据灌完后 ACK 停发 → 最后的空洞永不确认 |
| 90 | **收尾 drain：目标 EOF 后等 inflight 清零再关流** | 否则丢失的尾包再无重传机会（实测不加等待只收到 9/16 MB） |

**实测基线（16 MB，应用层帧注入，真 TCP 承载）：**

| 丢包率 | 下行 | 完整性 | 上行 |
|--------|------|--------|------|
| 0% | 69.6 MB/s | ✅ 逐字节一致 | 14.2 MB/s |
| 10% | 28.1 MB/s | ✅ 逐字节一致 | 14.5 MB/s |
| 20% | 14.0 MB/s | ✅ 逐字节一致 | 13.8 MB/s |
| 30% | 7.2 MB/s | ✅ 逐字节一致 | 12.4 MB/s |

对比 ARQ 之前（5% 丢包）：下行 60 秒超时只收 2.4 MB，上行完全卡死。

### 3.1 已被否决的方案（避免重复讨论）

| 方案 | 否决原因 |
|------|---------|
| QUIC over TCP（quinn-proto） | Nginx 无法按路径反代传输层字节；需关 CC/pacing/PTO；双层 TLS |
| h2 直连（naiveproxy 式） | 需独占 443，无法挂路径；本质真 TCP |
| WSS + yamux | 本质真 TCP，有 HOL 与拥塞控制，丧失 UDP 特性 |
| GOST `relay+tls` | smux 单窗口 → HOL 无法根治；`probeResist` 对 relay 无效 |
| udp2raw | FakeTCP 无有序流，**无法套 TLS**；单目标；需 iptables + root |
| kcptun / UDPspeeder | 承载在 UDP 上，套 TLS 不可行；UDP 本身被 QoS |
| 真 TLS over FakeTCP | TLS 隐式序号遇丢包全链失败（RFC 9147 §3） |
| DTLS 1.3 直接使用 | 密文头格式与 TLS 不同，DPI 可区分 |

---

## 四、工程结构

### 4.1 代码目录（已落地部分）

```text
FlowTCP/
├── Cargo.toml                      # workspace 根
├── Dockerfile                      # 多阶段：chef / builder / dist / ci
├── .github/workflows/ci.yml        # fmt → clippy → test → 多架构编译
├── crates/
│   ├── flowtcp-proto/              # ✅ 协议核心（纯逻辑，无 IO）
│   │   ├── src/frame.rs            #   内层帧编解码 + 地址编码 + MTU 预算
│   │   ├── src/record.rs           #   记录层 AEAD + 序号掩码 + 重放窗口
│   │   ├── src/keyderive.rs        #   TLS exporter → 方向性密钥
│   │   └── src/lib.rs              #   常量与再导出
│   ├── flowtcp-cli/                # ✅ 统一 CLI（selftest / info）
│   ├── flowtcp-faketcp/            # ✅ FakeTCP 承载 + 运行时网络自动配置
│   │   ├── src/netcfg.rs           #   TUN + iptables 幂等配置（端口可配）
│   │   └── src/transport.rs        #   数据报语义收发封装
│   ├── flowtcp-tls/                # ✅ TLS 1.3 握手 + Chrome 指纹 + 分流
│   │   ├── src/fingerprint.rs      #   Chrome 指纹（JA4 实测匹配 8daaf6152771）
│   │   ├── src/split.rs            #   首帧分流判定
│   │   └── src/handshake.rs        #   握手 + exporter 密钥导出
│   ├── flowtcp-client/             # ⬜ SOCKS5 / DNS / ICMP 入口
│   └── flowtcp-server/             # ⬜ 出口 + 透传转发器 + 临时证书
├── vendor/fake-tcp/                # ✅ 被 patch 的第三方伪 TCP 栈（见 PATCH #1）
├── templates/docs/                 # ⬜ 内置伪装站点（VitePress 风格）
├── deploy/                         # ⬜ systemd / install.sh
├── docs/PROTOCOL.md                # ✅ 协议规范（唯一真相源）
└── README.md                       # ✅ 项目介绍与快速开始
```

### 4.2 已实现模块摘要

| 模块 | 行数 | 关键能力 |
|------|------|---------|
| `frame.rs` | ~700 | 10 字节帧头、9 种帧类型、SOCKS5 对齐地址、`max_payload_for_mtu()` |
| `record.rs` | ~800 | AES-128-GCM / ChaCha20-Poly1305、序号掩码、1024 位重放窗口、单遍加密 |
| `keyderive.rs` | ~400 | TLS exporter → 6 段密钥、方向隔离、脱敏 Debug |
| `flowtcp-cli` | ~350 | 无依赖子命令解析、5 项协议自检 |
| 测试 | 46 个 | 乱序 / 丢包 / 重放 / 篡改 / 方向隔离 / MTU 边界 |


### 4.2 运行时目录

```
/var/lib/flowtcp/
├── www/                        # 模板站（内嵌资源释放）
├── certs/{domain.crt,domain.key,acme/}
└── state/{cert-renewal.json, traffic.db}
```

---

## 五、开发阶段规划

| Phase | 目标 | 验收标准 |
|-------|------|---------|
| **Stage 0** | 环境验证（零开发） | ✅ **已完成**：TCP:80/443 返回 `Connection refused`（包到达），ICMP 25% 丢包 |
| **Phase 1** | FakeTCP 打通 | ✅ **已完成**：真实内核 TCP 与用户态 FakeTCP 握手 + 双向传输实测通过 |
| **Phase 2** | TLS 握手 + 分流 | ✅ **已完成**：JA4 `8daaf6152771` 与 Chrome 一致；4 类首帧分流正确 |
| **Phase 2.5** | 偷网站认证核心 | ✅ **已完成**：透传 4 场景 e2e 通过（真浏览器视角无破绽） |
| **Phase 2.6** | ★ 自研 TLS 1.3 客户端（方案 G） | ✅ **已完成**：与 BoringSSL 握手成功；`EXPORTER_SECRET` 等全部 secret **逐字节一致**；票据认证全链路 e2e 通过 |
| **Phase 3** | ★ 三入口 + 出口数据面 | ✅ **已完成**：SOCKS5（TCP+UDP）/ HTTP（CONNECT+绝对 URI）/ HTTPS（默认自签）全部实测 HTTP 200；8 流并发、策略拒绝、域名解析 e2e 全绿 |
| **Phase 4** | 信用流控 + ARQ + FEC | 🔶 **进行中**：4.1~4.6 已完成<br>（375 测试全绿；**0~30% 丢包全部逐字节完整**）<br>⬜ 4.5 窗口自动调优（按 BDP 放大 cwnd）· 4.7 FEC · 4.8 接 FakeTCP |
| **Phase 5** | 透传转发 + 临时证书 | 浏览器访问拿到真实网站的响应；认证客户端走代理 |
| **Phase 6** | 多平台客户端 | Windows（WinDivert）、Android（root）、无 root WSS 降级 |
| **Phase 7** | 产品化 | 多用户、流量统计、订阅管理、GUI |

---

## 六、平台支持矩阵

| 平台 | FakeTCP | 权限 | 备注 |
|------|---------|------|------|
| Linux（服务端） | ✅ | `cap_net_admin`+`cap_net_raw` | 主目标，必选 |
| Linux（客户端） | ✅ | 同上 | 主目标 |
| Windows | ⚠️ | 管理员 + WinDivert | 杀软可能告警 |
| Android（root） | ✅ | root | |
| Android（无 root） | ❌ | — | **降级 WSS 承载**（牺牲 UDP 特性） |
| macOS / iOS | ❌ | — | 系统限制，暂不支持 |

---

## 七、主要风险

| # | 风险 | 影响 | 缓解 |
|---|------|------|------|
| 1 | 目标网络 TCP:443 也被 QoS | 方案整体失效 | Stage 0 先验证；备选 ICMP 隧道 / 端口跳跃 |
| 2 | ClientHello 指纹做不到 Chrome 级 | 被主动探测识别 | Phase 2 专项攻关（自研 / uTLS 等价 / fork rustls） |
| 3 | FakeTCP 在 Windows/Android 稳定性 | 跨平台受阻 | 优先 Linux 验证，Windows 用 WinDivert，Android 无 root 降级 |
| 4 | 偷的网站本身被墙/限速 | 透传体验差 | 选 IP 相近、国内可达的目标；支持运行时切换 |
| 5 | 双层密钥派生实现错误 | 安全漏洞 | 严格按 RFC 8446 §7.5，加测试向量 |
| 6 | 服务端私钥泄露 | 他人可冒用身份 | 私钥权限 0600；`StealConfig` 实现脱敏 Debug |
| 7 | 伪装站被批量指纹识别 | 抗探测失效 | 内容参数化 + 资源哈希命名 + 多主题 |

---

## 八、文档索引

| 文档 | 内容 |
|------|------|
| `docs/PROTOCOL.md` | **协议规范 v0.1**（帧格式、握手、记录层、ARQ、FEC） |
| `docs/FLOW_CONTROL.md` | **流控与 CPU 开销**：QUIC/quinn/TUIC/Hysteria 调研 + Phase 4 设计方案 |
| `DEVTIPS.md` | 开发踩坑与铁律（§16 可靠性语义 / §17 静默丢数据） |
| `CHANGELOG.md` | 变更日志 |
| `DEPLOY_CREDENTIALS.md` | 部署凭证（不入 Git） |

---

*本文档随项目开发持续更新，最新版本始终在 Git 仓库中。*

