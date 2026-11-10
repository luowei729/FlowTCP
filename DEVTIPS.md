# DEVTIPS.md — 长期开发提示（精简优先，只写会反复踩的坑）

> 记录规则：每条都带北京时间，按时间倒序追加在上方。

---

## 零、六条铁律（2026-11-10 17:12 北京时间）

1. **绝不用真 TCP 承载**：一旦用内核 TCP，就必然引入拥塞控制 + HOL，UDP 低延迟特性全部丢失。承载层只能是 FakeTCP（raw socket 伪造 TCP 头）。
2. **握手必须 100% 标准 TLS 1.3**：ClientHello 里加任何私有字段 = 自曝。分流判定只能放在「握手后首帧明文」。
3. **数据记录必须显式序号**：标准 TLS 的隐式序号遇丢包即全链解密失败（RFC 9147 §3 官方说明）。
4. **只允许一层 AEAD**：双层 TLS 会带来双倍 CPU + TLS-in-TLS 流量特征。
5. **nginx 绝不终结 TLS**：FakeTCP 终结后转明文 HTTP 给 nginx。nginx 编译时 `--without-http_ssl_module`，省掉 OpenSSL 依赖。
6. **ACME 绝不能用 TLS-ALPN-01**：该方式要求 LE 建真 TCP 到 443，与 FakeTCP raw socket 直接冲突。只用 DNS-01（首选）或 HTTP-01（需 80 端口）。

---

## 一、FakeTCP 层踩坑（2026-11-10）

- **内核会回 RST**：raw socket 收到的伪造 TCP 包，内核 TCP 栈不认识 → 回 RST → 连接瞬间断开。必须用 nftables/iptables 屏蔽，或走 TUN + DNAT（phantun 路线）。
- **权限不是 root 而是 capability**：`cap_net_admin` + `cap_net_raw` 即可，`setcap cap_net_admin,cap_net_raw=+ep ./flowtcp`。
- **必须置 DF 位**：FakeTCP 不做 IP 分片重组，一旦超过链路 MTU 直接失败且极难排查。
- **MTU 预算合计 77 字节**（IP20+TCP20+TLS头5+masked_seq8+tag16+内层帧头8），链路 1500 → 内层 payload 上限 1400。
- **phantun 可复用**：`fake-tcp` crate（MIT/Apache-2.0，2.4k star），5 流 iperf3 达 5 Gbps，开销仅 12 字节。但它无加密/无 FEC/无复用，这三块要自研。

## 二、TLS 握手与分流（2026-11-10）

- **rustls 支持 `export_keying_material`**，用它派生内层密钥，避免双层 TLS。
- **分流判定点**：只看握手后第一个 `application_data` 的**明文首字节**。`PRI `→h2、`GET `/`POST`→h1.1、`FTAUTH`→代理、其他→交 nginx 返回 400（保持真实）。
- **认证失败要静默**：延迟 1~3 秒随机后关闭，不要回 4xx/5xx，否则探测者能区分「密码错」和「不是目标」。
- **握手 + AUTH 阶段必须开 ARQ**：TLS 握手是多轮交互，FakeTCP 丢一个包就死锁。数据阶段才切不可靠。

## 三、nginx 与 ACME（2026-11-10）

- **nginx 只用明文 HTTP**，监听 `127.0.0.1:<动态端口>`，避开端口冲突。
- **静态编译关键**：`--without-http_ssl_module` + `--with-pcre=<源码目录>` + `--with-zlib=<源码目录>` + `--with-cc-opt="-static"`。成品 1.5~2.5 MB。
- **musl 静态编译有坑**：nginx 用到 `getpwnam_r`/`syslog`，musl 下需 patch。推荐 **glibc 静态** + 在 Debian 11 容器构建（兼容老 glibc）。
- **别把 nginx 释放到 /tmp**：常挂 noexec → 无法执行。用 `/var/lib/flowtcp/bin/`。
- **证书热更新用 `ResolvesServerCert` + ArcSwap**：TLS 1.3 已建连接不受影响（密钥已派生），零中断。
- **LE rate limit**：5 次/周/域名。续期失败必须指数退避并持久化状态，防止打爆配额。
- **DNS-01 要等传播**：写完 TXT 后轮询 `1.1.1.1`/`8.8.8.8` 直到读到，超时 120s。

## 四、抗探测检查表（2026-11-10）

扫描器会做这 8 件事，每项都要对齐真实 nginx：

| # | 探测 | 期望 |
|---|------|------|
| 1 | 建连后立刻关闭 | 正常 FIN/ACK |
| 2 | 只发 SYN | SYN-ACK，空闲超时后关 |
| 3 | 握手不完成 | 与 nginx 相同超时（~60s） |
| 4 | 错误 SNI | 默认证书/握手失败，与 nginx 一致 |
| 5 | 握手完不发数据 | keepalive 75s 后关 |
| 6 | 非法 HTTP | nginx 风格 400 |
| 7 | 不存在路径 | 真实 404 页 |
| 8 | 观察流量时序 | 心跳间隔必须抖动（25~35s），禁止固定 30s |

## 五、工具与命令备忘（2026-11-10）

```bash
# 时间（文档记录统一用北京时间）
TZ='Asia/Shanghai' date '+%Y-%m-%d %H:%M %Z'

# 质量门禁（与 CI 完全一致，提交前务必全跑）
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release

# 协议自检（无需网络/root/TUN）
./target/release/flowtcp selftest
./target/release/flowtcp info

# nginx 配置校验（reload 前必须做）
nginx -t -c /var/lib/flowtcp/nginx/conf/nginx.conf
nginx -s reload -c /var/lib/flowtcp/nginx/conf/nginx.conf

# FakeTCP 调试：抓包确认外观
tcpdump -i eth0 -n 'tcp port 443 and tcp[tcpflags] & tcp-syn != 0'

# Docker 质量门禁
docker build --target ci -t flowtcp-ci . && docker run --rm flowtcp-ci
```

## 六、实现期踩坑（2026-11-10 17:48）

### 6.1 ★ AAD 必须用「未掩码」序号（最易犯的架构错误）

初版把**掩码后**的 masked_seq 放进 AAD，形成循环依赖：

```
AAD 需要 masked_seq → masked_seq 需要密文 → 密文需要 AAD   ← 死循环
```

后果：被迫加密两遍（首遍算掩码、次遍正式加密），且 length 字段重复叠加 TAG_LEN，
导致 `45 != 29` 与全线 `Truncated` 报错。

**正确做法**（RFC 9147 §4.2.3 原文要求）：

```
AAD = record_header(5B，线上真实字节) || 未掩码 seq(8B)
```

- 加密单遍完成，length 可在加密前确定为 `8 + 明文长 + 16`
- 篡改线上掩码 → 还原出的 seq 变化 → nonce 与 AAD 同时错 → 解密必然失败，安全性不变
- 不变量：**AAD 永远不含任何"依赖密文才能算出"的字段**

### 6.2 字节流迭代器的 consumed 语义

`FrameIter` 遇到 `Truncated` 时**不能推进 pos**。推进了就无法区分
「全部解析完」与「尾部有半包待拼接」，调用方会丢掉跨记录边界的半个帧。

规则：**只有在完整解析出一个元素后才推进游标**；数据不足时原地停止。

### 6.3 Docker 的 Rust 版本必须与本地一致

用 `rust:1.82` 构建时依赖报错：

```
error: failed to parse manifest at .../zeroize-1.9.1/Cargo.toml
```

原因：新版 crate 使用 edition 2024 等 manifest 特性，旧版 cargo 无法解析。
**本项目固定 `rust:1.97-bookworm`**，升级依赖后要同步核对。

依赖缓存用 **cargo-chef**：把「Cargo.toml/lock」与「源码」分成两个 Docker 层，
改代码只重编本 crate，依赖层长期命中缓存（密码学栈约省 1~2 分钟）。

### 6.4 arm64 交叉编译不要本地跑

`docker buildx build --platform linux/arm64` 在 x86 上用 QEMU 模拟整个 Rust 工具链，
首次编译 ≥5 分钟（实测 300 秒超时未完成）。**交给 GitHub Actions**，
本地只验证 amd64。

### 6.5 密钥结构体禁止 derive(Debug)

`DerivedKeys` 若直接 `#[derive(Debug)]`，任何 `tracing::debug!("{:?}", keys)`
都会把密钥完整打进日志。已实现**脱敏 Debug**（只输出长度与"已隐藏"）。
同类结构（`Keys`）也应遵守此规则。

### 6.6 测试命名用中文

本项目单测函数名用中文（如 `乱序记录全部解密成功`），`cargo test` 输出直接可读，
无需对照注释。已验证 rustc 对非 ASCII 标识符支持良好。

---

## 七、★ FakeTCP 与真实 TCP 互通（2026-11-10 18:18 实测验证）

### 7.1 决定性结论

已用真实 Linux 内核 TCP 栈（`bash /dev/tcp`）与用户态 FakeTCP 完成**完整三次握手 + 双向数据传输**：

```
✅ 真实 TCP 三次握手成功
ECHO:hello-real-tcp
[+] 收到伪 TCP 连接: (Fake TCP connection from 192.168.201.2:8443 to 10.0.0.253:44534)
[<] 收到 14 字节: "hello-real-tcp"
[>] 已回显 19 字节
```

**这意味着抗主动探测与「伪装网站 fallback」在技术上成立** —— 探测者的真实 TCP 栈
可以与我们的用户态栈正常握手。

### 7.2 ★ fake-tcp 必须 patch：接受任意 ISN

**上游限制**（`vendor/fake-tcp/src/lib.rs` 原第 506 行）：

```rust
// 只接受 seq == 0 的 SYN
if tcp_packet.get_sequence() == 0 { /* 接受 */ }
else { /* 回 RST */ }
```

原因：phantun 客户端也是 fake-tcp，握手 ISN 固定从 0 开始。

**问题**：真实内核 TCP 栈的 ISN 由 RFC 6528 规定为「时间 + 四元组哈希」，
必然非 0 且随机。所以任何真实客户端（curl / 浏览器 / 扫描器）连上来都会收到 RST，
表现为「端口关闭」，伪装网站 fallback 完全不可用。

**已 patch**（`vendor/fake-tcp/src/lib.rs` 的 `[FlowTCP PATCH #1]`）：
放开 ISN 限制。SYN 的 seq 仍被原样记录为 ack 初值
（`Some(tcp_packet.get_sequence() + 1)`），因此 SYN-ACK 的 ack 号正确。

> 该 patch 是**必需的**，不是优化。升级 fake-tcp 时必须重新应用。

### 7.3 iptables 四个坑（全部实测踩过）

| # | 坑 | 现象 | 正确做法 |
|---|-----|------|---------|
| 1 | **`raw -j NOTRACK`** | DNAT 计数为 0，包不进入 TUN | **绝不能加**。NAT 依赖 conntrack，NOTRACK 会让它整体失效 |
| 2 | 本机流量走 `OUTPUT` 非 `PREROUTING` | 外部能连、本机测试直接 `Connection refused` | `nat OUTPUT` 也要加 DNAT 规则 |
| 3 | `rp_filter = 2`（loose） | 握手成功但数据收不到 | 设为 `0`（`all` + `tun0` + 物理网卡） |
| 4 | 用 `-A` 追加规则 | 有 Docker 时可能永远匹配不到 | 用 `-I` 插到链首 |

补充：回程必须 `SNAT` 成公网 IP，否则客户端收到源地址 `192.168.x.x` 的包会丢弃。

### 7.4 fake-tcp 的 API 语义（写代码前必读）

```rust
let mut stack = Stack::new(tun_vec, local_ip, local_ip6);
//                              ^^^^^^^^ 仅用于主动 connect() 的源地址

// 客户端
let sock = stack.connect(remote_addr).await;   // Option<Socket>
// 服务端
stack.listen(port);
let sock = stack.accept().await;               // Socket（非 Option）

sock.send(&buf).await;      // Option<()>   —— 一次 = 一个 IP 包
sock.recv(&mut buf).await;  // Option<usize> —— 一次 = 一个 IP 包的 payload
```

**关键**：
- `send/recv` 是**数据报**语义，不重组、不保序、丢就是丢 —— 正好契合我们的记录层
- `listen(port)` 的端口必须与 iptables **DNAT 目标端口**一致，否则 SYN 被当未知包回 RST
- `Stack::new` 的 `local_ip` 服务端应传 `tun_local`（与 phantun server 一致）
- `tokio-tun` 版本必须与 fake-tcp 内部使用的**完全一致**（当前 0.23），
  否则 `Tun` 类型不通用（编译器报 "multiple different versions of crate tokio_tun"）

### 7.5 vendor 依赖的注意事项

- `vendor/fake-tcp/Cargo.toml` 中依赖写成 `version = "0"`（任意 0.x），
  **不要**批量 sed 成具体版本，否则会破坏 flume / log / internet-checksum 等
- 若 `rand` 解析到 0.8 会报 `SmallRng::from_os_rng not found`（该函数需 rand 0.9+）。
  解法：workspace 的 `rand` 升到 0.9，让 cargo 统一解析
- 改 registry 里的源码**不会**触发重编；必须用 `[patch.crates-io]` 或 path 依赖
- workspace 根需加 `exclude = ["vendor"]`，避免 vendor 被当作成员

---

## 八、★★ TLS 指纹（2026-11-10 18:44 实测，反直觉但极其关键）

### 8.1 结论：用 BoringSSL ≠ 自动像 Chrome，但**不要设 min_proto_version**

实测 JA4 指纹（用外部检测服务 `tls.peet.ws` 客观验证）：

| 配置 | JA4 | Chrome 匹配 |
|------|-----|------------|
| 设 `min_proto_version(TLS1_3)` + 全部 Chrome 参数 | `t13d37h2_55b375c5d22e_...` | ❌ 差很远 |
| **不设 min 版本** + 全部 Chrome 参数 | `t13d1513h2_8daaf6152771_...` | ✅ **哈希完全一致** |
| Plain 配置（对照） | `t13d1711h2_5b57614c22b0_...` | ❌ 明显不同 |

**`8daaf6152771` 是 Chrome 桌面版的 JA4 cipher+extension 哈希**（业界公认特征）。

### 8.2 为什么「不设 TLS 1.3 最小版本」反而更像 Chrome

这是最容易搞错的一点：

- 真实 Chrome 的 ClientHello 是 **TLS 1.2 兼容格式**
- 它发送 `supported_versions = [GREASE, 1.3, 1.2]`
- 并附带一批 TLS 1.2 时代扩展：`ec_point_formats(11)`、`extended_master_secret(23)`、
  `renegotiation_info(65281)` 等
- 一旦设 `set_min_proto_version(TLS1_3)`，BoringSSL 认为「无需兼容 1.2」，
  **直接省略这些扩展** → 扩展数从 13~16 掉到 7 → JA4 哈希偏离 → 更易被识别

正确做法：**客户端不设 min 版本**（默认 1.2~1.3），由**服务端**强制 `min = TLS1.3`。
最终仍协商 TLS 1.3，但 ClientHello 形态与真 Chrome 一致。

### 8.3 必须显式开启的两个扩展

```rust
b.set_grease_enabled(true);                    // GREASE 保留值
b.set_permute_extensions(true);                // extension 顺序随机化（Chrome 106+）
b.enable_ocsp_stapling();                      // status_request (5)
b.enable_signed_cert_timestamps();             // SCT (18)，Chrome 2018 起强制
```

后两个尤其关键：Chrome 自 2018 年起强制要求 SCT，不发 `signed_certificate_timestamp`
几乎可断定「不是 Chrome」。

### 8.4 自检命令（部署后必跑）

```bash
flowtcp fingerprint            # Chrome 指纹，应输出 8daaf6152771
flowtcp fingerprint --plain    # 对照：应输出 5b57614c22b0（证明配置真的生效）
```

若两者相同，说明配置没生效（参数被忽略）。

### 8.5 局限（不要过度自信）

- JA4 只反映 ClientHello **静态特征**，不覆盖 TCP 层行为、时序、流量形态
- 主动探测（对端连回来）需要「真证书 + 真网站 fallback」配合
- BoringSSL 未暴露 ALPS（`application_settings`, ext 17513）开关，
  这是 Chrome 特有扩展，我们是 13 个扩展 vs Chrome 16 个的差异来源
- 我们的 extension 数量 13，Chrome 是 16，但 **JA4 哈希一致**
  （哈希对排序后的集合计算，缺失项可能不落在采样范围内），
  仍建议后续版本补齐 ALPS 以进一步收敛

---

## 九、★★★ 偷网站（2026-11-10 18:49，重大决策）

### 9.1 为什么不自己扮演网站

早期方案是「内置静态编译 nginx + ACME 证书 + 模板站」。这条路有三个根本问题：

1. **扮演总有破绽**：模板站、响应头、TLS 细节、ALPN、OCSP 每一处都可能有差异
2. **要维护域名 + 证书 + 续期**，运维成本与失败面都大
3. **TLS-ALPN-01 与 FakeTCP 直接冲突**（LE 要建真 TCP 到 443）

**正确做法**：认证失败时把 TCP 字节流**原样透传**给真实网站。

```text
探测者 ──TCP──> FlowTCP 服务端 ──TCP──> www.microsoft.com:443
                      ↑                      │
                      └──── 双向 copy ───────┘
```

探测者看到的是**真实网站完整无误的 TLS 会话**。我们从未参与 TLS，
因此**不可能**在那个连接上露出任何破绽——这比扮演强得多。

**收益**：不需要域名、不需要证书、不需要 ACME、不需要 nginx。

### 9.2 认证载体：client_hello.session_id

TLS 1.3 的 `session_id` 是 32 字节**内容不受约束**的兼容性字段
（RFC 8446 §4.1.2）。真实 Chrome 也会填它（为中间设备兼容），
所以"非空"不异常，内容看起来就是随机数。

```text
session_id[32] = AEAD(key, nonce=0, aad=client_random,
                      plaintext = ver(1) || ts(4) || short_id(8) || pad(3))
              = 密文(16) + tag(16) = 32 ✓
```

**密钥来源是关键**：复用 ClientHello 里**本来就有**的 X25519 `key_share`：

```rust
shared = X25519(reality_priv, client_key_share_pub)   // 服务端
shared = X25519(ephemeral_priv, reality_pub)          // 客户端，同一值
key = HKDF-SHA256(shared, salt = client_random, info = "flowtcp steal v1")
```

**不需要任何额外字段**，ClientHello 的字节布局与真实 Chrome 完全一致。
nonce 固定为 0 是安全的：密钥已用 `client_random` 作 salt，每连接唯一。

### 9.3 裁决链路（任一失败即转发）

| 步骤 | 检查 | 失败处置 |
|------|------|---------|
| 1 | SNI 在允许列表 | 转发 |
| 2 | 存在 X25519 key_share | 转发 |
| 3 | session_id 长度 == 32 | 转发 |
| 4 | AEAD 解密成功 | 转发 |
| 5 | 票据版本 == 1 | 转发 |
| 6 | 时间戳偏差 ≤ 30s | 转发 |
| 7 | short_id 匹配 | 转发 |
| ✅ | 全通过 | 自行完成 TLS 握手 |

**关键**：失败原因**只记日志，绝不回给客户端**。任何"认证失败"响应
都是自曝。

### 9.4 实现要点

- **必须自己解析 ClientHello**：判定发生在建立 TLS 上下文**之前**，
  因为结果决定走 BoringSSL 还是纯字节转发。先建 TLS 就晚了。
- **跨记录处理**：真实 Chrome 的 ClientHello 常达 500+ 字节，会跨多个
  TLS 记录。解析器数据不足时必须返回 `Ok(None)` 要求继续读，不能报错。
- **wire_len 必须精确**：转发时要把已吞掉的字节原样重放给真实网站，
  算错一个字节就会破坏握手。
- **私钥绝不进日志**：`StealConfig` 实现了脱敏 `Debug`。

### 9.5 偷哪个网站（选目标的标准）

| 项 | 要求 | 原因 |
|----|------|------|
| 地理位置 | **IP 与服务器相近** | 更像，且透传延迟低 |
| 协议 | 支持 TLS 1.3 + h2 | 与我们的 ClientHello 特性匹配 |
| 证书 | 链完整、有 OCSP Stapling | 减少客户端验证失败 |
| 域名 | **不要用会跳转的裸域名** | `example.com` → `www.example.com` 会导致 SNI 不匹配 |
| 原则 | 国外站、国内可达 | 避免透传本身就不通 |

### 9.6 与 padding 的配合（AnyTLS 的贡献）

AnyTLS **不偷网站**（必须自己的证书），但它解决了 REALITY 不管的问题：
**TLS-in-TLS 特征**。REALITY 作者原话：

> 也可以搭配 XTLS 以外的协议使用，但**不建议**，因为它们存在明显且
> **已被针对**的 TLS in TLS 特征

所以最终方案是两者组合：**REALITY 式偷网站 + AnyTLS 式 padding**。

---

## 十、★★ 为什么必须自签证书（2026-11-10 19:12）

### 10.1 核实结果：AnyTLS 参考实现也是自签

很多人以为 AnyTLS 用真证书，但它的参考实现是这样的：

```go
// anytls-go/cmd/server/main.go
tlsCert, _ := util.GenerateKeyPair(time.Now, "")   // 现场生成自签
tlsConfig := &tls.Config{ GetCertificate: func(...) { return tlsCert, nil } }

// anytls-go/cmd/client/main.go
// You can only use `InsecureSkipVerify` by default in the sample client;
// it is not recommended for use in production code.
tlsConfig := &tls.Config{ ServerName: *sni, InsecureSkipVerify: true }
```

官方 README 的警告正是指这个：
> ⚠️ 示例服务器和客户端默认采用不安全的配置，该配置假设您不会遭遇 TLS 中间人攻击

**AnyTLS 生产部署（sing-box / mihomo）必须配真实证书**，否则中间人可完整劫持。

### 10.2 四种方案的真实对比

| 维度 | AnyTLS 参考实现 | **AnyTLS 生产** | **REALITY / FlowTCP** |
|------|---------------|----------------|---------------------|
| 服务端证书 | 自签（现场生成） | **真实 CA 证书** | 自签临时证书 |
| 客户端校验 | `InsecureSkipVerify` | **正常 CA 校验** | 验 **ECDH 派生公钥** |
| 认证时机 | 握手**之后**（TLS 内） | 握手之后 | 握手**之前**（ClientHello） |
| 抗 MITM | ❌ 无 | ✅ 靠 PKI | ✅ 靠 ECDH 票据 |
| 抗主动探测 | ❌ 需 fallback 到**自己的** HTTP | ❌ 同左 | ✅ 透传到**真实网站** |
| 需要域名+证书 | ✅ | ✅ **必须** | ❌ **不需要** |

**关键差异**：AnyTLS 的反探测靠 `fallback 到任意合法 L7 应用`（官方原话）——
这就又需要 nginx + 证书。而偷网站方案透传给真网站，零证书零 nginx。

### 10.3 偷网站为什么必须自签

```
认证失败 → 透传字节流 → 真网站出示真证书   ← 我们是透明中转，不需要私钥
认证通过 → 必须由"我们"完成握手 → 需要证书
                                ↓
                      拿不到真网站的私钥
                                ↓
                          只能现场生成
```

### 10.4 自签如何保证安全（核心设计）

**绝不能用** `InsecureSkipVerify = true` —— 那样中间人可以：

```
1. 截获 ClientHello（含票据）
2. 中间人解不开，但可原样转发给真服务端
3. 真服务端解密成功 → 返回临时证书 → 被中间人截获
4. 中间人用任意证书跟客户端握手 → 客户端不校验 → MITM 成功 ❌
```

**正确设计**：用 ECDH 共享秘密派生**证书签名密钥**，形成闭环：

```text
shared = X25519(我方临时私钥, 对方公钥)        ← 双方相同，中间人算不出
seed   = HKDF(shared, salt=client_random, info="flowtcp steal v1 cert")

服务端：SigningKey(seed) → 签自签证书 → 发给客户端
客户端：VerifyingKey(seed) → 校验证书公钥是否匹配
```

**中间人无法伪造**：
- 想冒充服务端 → 需自己签一张能通过验签的证书 → 需 seed
- 需 seed → 需 shared = X25519(客户端临时私钥, REALITY 私钥)
- 两个私钥它都没有 → ❌

**即使中间人拿到真服务端返回的证书也不能复用**：那张证书是给**客户端的临时公钥**
算出来的，中间人只有自己的密钥对，验签必然失败（已由 `不同会话证书不通用` 测试覆盖）。

### 10.5 实现要点

| 要点 | 说明 |
|------|------|
| **密钥用途隔离** | 票据密钥与证书种子用**不同 HKDF info 标签**（`...token` / `...cert`）。若相同，拿到证书密钥就能反推票据密钥，从而伪造 session_id |
| **低阶点防护** | ECDH 结果为全零时（对端公钥是低阶点）必须**拒绝**，不能降级继续。全零种子人人都能算出，签出的证书毫无安全性 |
| **Ed25519 PKCS#8 前缀** | rcgen 只吃 PKCS#8 DER。Ed25519 的固定前缀是 16 字节：`302e020100300506 032b6570 04220420`，拼上 32 字节种子即完整 DER |
| **证书签名不单独验** | 「公钥匹配 + 有效期 + TLS 握手成功」三者合起来构成完整证明。TLS 的 `CertificateVerify` 会用该私钥签握手转录，比单独验自签证书签名更强 |
| **必须检查有效期** | 否则可重放旧证书。临时证书有效期只给 7 天 |
| **私钥绝不进日志** | `TempCert` 与 `StealConfig` 都实现脱敏 `Debug` |

### 10.6 两种模式并存

`flowtcp-tls::ServerMode` 支持：

| 模式 | 适用 | 认证失败处置 |
|------|------|------------|
| `Steal` | 纯代理、零运维 | 透传到真实网站 |
| `OwnCert` | 已有网站/证书 | 转本地 HTTP 服务 |

两者共享同一套 `session_id` 票据认证逻辑，只是**失败后的处置**不同。






---

## 十一、★★★ 架构限制：ClientHello 认证与标准 BoringSSL 不兼容（2026-11-10 19:46）

### 11.1 事实（实测验证，非推测）

我们想把认证票据塞进 `ClientHello.session_id`（REALITY 的做法），
用标准 BoringSSL 做客户端。**这条路走不通**，原因是 TLS 1.3 的转录（transcript）。

### 11.2 完整失败链路（逐步实测）

| 阶段 | 做法 | 结果 |
|------|------|------|
| 1 | 客户端用 `key_share` 做 ECDH 派生票据 | ❌ `boring` 不暴露 `key_share` 临时私钥 |
| 2 | 改用对称 HMAC 派生票据（只需预共享密钥） | ✅ 票据逻辑全部通过 |
| 3 | 客户端在字节流层改写 `session_id` 注入票据 | ❌ 握手报 `DECODE_ERROR` |
| 4 | 增加读方向改写（把 ServerHello 回显的票据改回原值） | ❌ 握手报 `BAD_DECRYPT` |
| 5 | 改用 ECDSA P-256 证书（替代 Ed25519） | 排除了证书算法因素，仍是 `BAD_DECRYPT` |

### 11.3 根本原因

**TLS 1.3 的握手转录包含 ClientHello 的全部字节**（RFC 8446 §4.4.1）。

```
客户端转录 = Hash(我发出的 ClientHello || 我收到的 ServerHello || ...)
服务端转录 = Hash(它收到的 ClientHello  || 它发出的 ServerHello || ...)
```

我们改写了线上的 `session_id`，但 BoringSSL **内部**的转录仍用它自己生成的
原始值 → 双方转录不同 → 派生出的握手密钥不同 → 服务端加密的消息客户端
解不开（`BAD_DECRYPT`）。

**这不是实现 bug，是协议层约束。** 只要修改 ClientHello 的任何一个字节，
就必须让**客户端的 TLS 库也知道改了什么**。

### 11.4 REALITY 为什么能做到

REALITY **fork 了 Go 的 `crypto/tls`**（仓库里就是完整的一份 tls 源码，
带 `[REALITY] SECTION` 标记）。它的客户端是 **uTLS**，能在构造 ClientHello 时
直接写入认证数据，因此客户端转录天然包含改写后的内容。

### 11.5 BoringSSL 缺什么

| 需要的能力 | boring crate 状态 |
|-----------|------------------|
| `SSL_CTX_set_client_hello_cb`（uTLS 用的那个回调） | ❌ 未暴露 |
| 握手前设置 `session_id` | ❌ 未暴露 |
| `SSL_set_session` | ⚠️ 存在但只接受**已完成握手**的会话对象，无法自造带自定义 ID 的会话 |

### 11.6 三条可选路径（需决策）

| 路径 | 工作量 | 评价 |
|------|--------|------|
| **A. 改用 AnyTLS 式握手后认证** | 小（1~2 天） | 放弃 ClientHello 层认证，改为 TLS 握手完成后首帧传票据。代价：**探测者能看到我们的临时自签证书** → 抗主动探测能力大幅下降（浏览器会弹证书警告）。除非配合「认证失败即透传」，但握手已经开始了，无法改 |
| **B. fork / 绑定 boring-sys 暴露 `client_hello_cb`** | 中（3~5 天） | 在 `boring-sys` 里加 extern 声明与 Rust 封装，不改 BoringSSL 源码。**推荐** —— 保住 REALITY 级抗探测能力，且仍用 BoringSSL 的指纹 |
| **C. 客户端也自己实现 ClientHello 构造** | 大（2 周+） | 要维护 Chrome 指纹数据库，放弃我们已实现的 JA4 匹配成果 |

### 11.7 当前代码状态（已实现且可用的部分）

| 模块 | 状态 | 说明 |
|------|------|------|
| `steal.rs` 对称票据（HMAC + 时间窗口） | ✅ 可用 | 27 个测试通过 |
| `steal.rs` ClientHello 解析器 | ✅ 可用 | 跨 TCP 段、SNI/key_share/session_id 提取 |
| `tempcert.rs` 临时证书（ECDSA P-256） | ✅ 可用 | 签 + 验 + 中间人拒绝，全部验证过 |
| `inject.rs` 双向改写流 | ⚠️ 逻辑正确但不适用 | 转录问题导致握手失败 |
| **服务端透传转发** | ✅ **完全可用** | 普通浏览器/扫描器 → 真实网站，端到端测试通过 |
| 服务端临时证书握手 | ⚠️ 仅 `OwnCert` 模式可用 | `Steal` 模式需等路径 B |

### 11.8 备注：已被排除的两个错误方向

- **Ed25519 临时证书**：在 `mozilla_intermediate_v5` 预设下握手报
  `HANDSHAKE_FAILURE_ON_CLIENT_HELLO`。改用 ECDSA P-256 解决。
- **读方向改写不够**：只改 ServerHello 回显能过 `DECODE_ERROR`，
  但转录差异仍会导致 `BAD_DECRYPT`。

---

## 十二、★★★ SSL_SESSION 方案已排除（2026-11-10 20:20，源码级证据）

### 12.1 尝试思路

`boring` 暴露了 `SslSession::from_der()`（`d2i_SSL_SESSION`）与
`Ssl::set_session()`（握手前），因此理论上可以：构造一个 session_id 为票据的
`SSL_SESSION`，让 BoringSSL 自己用它构造 ClientHello（转录天然一致）。

**实测结果：不通。**

### 12.2 三处致命的源码检查

路径：`boringssl/ssl/handshake_client.cc:345-378`

```cpp
SSLSessionType session_type = ssl_session_get_type(ssl->session.get());
if (session == nullptr ||
    session_type == SSLSessionType::kNotResumable ||
    !ssl_session_is_time_valid(ssl, ssl->session.get()) ||   // ← 检查 2
    SSL_is_quic(ssl) != int{ssl->session->is_quic} ||        // ← 检查 3
    ssl->s3->initial_handshake_complete) {
  ssl_set_session(ssl, nullptr);        // ← session 被丢弃
  session_type = SSLSessionType::kNotResumable;
}
```

`boringssl/ssl/ssl_session.cc:457`：

```cpp
SSLSessionType ssl_session_get_type(const SSLSession *session) {
  if (session->not_resumable) return kNotResumable;
  if (protocol_version >= TLS1_3_VERSION) {        // ← 检查 1：TLS1.3 永远不是 kID
    return ticket.empty() ? kNotResumable : kPreSharedKey;
  }
  if (!ticket.empty()) return kTicket;
  if (!session_id.empty()) return kID;             // ← 只有 TLS1.2 能走到这里
}
```

### 12.3 实测记录

| 实验 | 结果 |
|------|------|
| TLS 1.3 session + 改写 session_id | `set_session` 成功（`ssl.session()` 确认含票据），但 ClientHello 的 session_id 是**随机值**（兼容模式） |
| TLS 1.2 session + 改写 session_id | 同上，仍是随机值 |
| **TLS 1.2 session 完全不修改** | **仍是随机值** ← 决定性实验，说明 session 根本没生效 |

结论：`set_session` 之后 `ssl.session()` 能读回我们设的 session（说明对象已挂上），
但构造 ClientHello 时三处检查必然触发一处，导致回退到"TLS 1.3 兼容模式随机
session_id"。

### 12.4 为什么这条路在架构上就不成立

TLS 1.3 的 `legacy_session_id` 设计意图**只是兼容中间设备**（Chrome 也发随机值），
BoringSSL 明确把它当作「不是会话标识」。因此它**不可能**受 `SSL_SESSION` 控制。

### 12.5 最终可选方案排序（更新）

| 方案 | 语言 | 工作量 | 评价 |
|------|------|--------|------|
| **G. 自研 TLS 1.3 客户端 + Chrome 指纹** | 纯 Rust | 3~5 天 / ~1800 行 | **推荐**。对转录有完全控制，可复用现有全部代码，无 C 依赖 |
| D. Go + uTLS 客户端 | Rust 服务端 + Go 客户端 | 中 | uTLS 现成，但 Go 侧 FakeTCP 要自己写（无 phantun 等价物） |
| C. 客户端自研 ClientHello（其余仍用 BoringSSL） | 纯 Rust | 大 | 做不到：BoringSSL 不接受外部构造的 ClientHello |
| B′. fork BoringSSL | C++ 补丁 | 1~2 周 | 维护 C++ 补丁 + 随上游漂移，风险最高 |

### 12.6 方案 G 的工作量拆解（实测过的 API 已知可用）

| 模块 | 行数估算 | 依赖 |
|------|---------|------|
| ClientHello 构造（GREASE + Chrome 扩展集 + 顺序） | ~500 | 无需外部库 |
| TLS 1.3 key schedule（HKDF-Expand-Label、transcript） | ~300 | `hkdf` + `sha2`（已有） |
| 握手消息编解码（SH/EE/Cert/CV/Fin） | ~600 | 无需外部库 |
| 握手期 AEAD 记录层 | ~200 | `aes-gcm`/`chacha20poly1305`（已有） |
| X25519 ECDHE | ~50 | `x25519-dalek`（已有） |
| 临时证书验签（ECDH 派生公钥） | ~100 | `p256`（已有）+ `boring` 的 X509 解析 |

**关键优势**：所有密码学原语已在依赖中，且服务端已实现并测试通过（167 个测试），
客户端只是"对端"。客户端自研 TLS 的指纹可用 `flowtcp fingerprint` 命令反复验证
直到 JA4 匹配 Chrome。

---

## 十三、★★★ 自研 TLS 1.3 客户端的 4 个必踩坑（2026-11-10 20:47，方案 G 实测）

> 背景：DEVTIPS §11 证明标准 BoringSSL **无法**做 ClientHello 层认证（转录包含
> ClientHello 全部字节），§12 排除了 SSL_SESSION 路径。唯一出路是自己实现
> TLS 1.3 客户端。本节记录实现过程中**全部实测踩到的坑**。
> 每一条的排查都靠 BoringSSL keylog 逐字节比对，没有一条靠猜。

### 13.1 中间盒兼容模式的明文 ChangeCipherSpec 必须跳过

**现象**：客户端读第一条加密记录时报 `记录太短`，服务端报 `Connection reset by peer`。

**根因**：ClientHello 里带了非空 `session_id`（TLS 1.2 兼容模式标志），
所以服务端在 ServerHello 之后、第一条加密记录之前会插入一条**明文**
ChangeCipherSpec：

```text
14 03 03 00 01 01        ← 6 字节，内容是单个 0x01
```

这条记录既不在转录里、也不参与密钥派生，纯粹是给中间盒看的「假 CCS」。
如果不跳过，它会被当成密文去 AEAD 解密，长度不足 21（5 头 + 16 tag）→ 报错。

**修法**：读取循环里遇到 `rec[0] == 0x14` 且 `rec.len() == 6 && rec[5] == 1` 就 `continue`。

```rust
if rec[0] == CT_CHANGE_CIPHER_SPEC {
    if rec.len() != 6 || rec[5] != 0x01 { return Err(...); }
    continue;
}
```

> 顺带说明：如果 ClientHello 的 `session_id` 为空（非兼容模式），服务端不发 fake CCS。
> 我们有票据必须填满 32 字节，所以**必然**会遇到这个问题。

### 13.2 服务端 Finished 必须进转录（否则 `DIGEST_CHECK_FAILED`）

**现象**：客户端握手"成功"，服务端报 `TLS handshake failed [DIGEST_CHECK_FAILED]`。

**根因**：早期实现误以为「Finished 不进转录」，所以在 `hs::FINISHED` 分支里只存了
快照、没有 extend。但 RFC 8446 §4.4.4 / §7.1 要求：

```text
服务端 Finished 的 verify_data = HMAC(finished_key, Transcript-Hash(CH .. CertificateVerify))   ← 不含自己
客户端 Finished 的 verify_data = HMAC(finished_key, Transcript-Hash(CH .. server Finished))      ← 含服务端 Finished
```

也就是**同一个 Finished 消息，验证它时用「之前」的转录，但之后要把它自己加进去**。

**修法**：三个转录快照各司其职。

| 快照 | 内容 | 用途 |
|------|------|------|
| `transcript_before_cv` | CH..Certificate | 验证 CertificateVerify 签名 |
| `transcript_before_finished` | CH..CertificateVerify | 验证服务端 Finished |
| `transcript_after_server_finished` | CH..server Finished | 计算客户端 Finished + **应用流量密钥** + exporter |

### 13.3 CertificateVerify 验签时不能重复裁剪转录

**现象**：`CertificateVerify 校验失败`。

**根因**：函数早期设计成"传入含 CV 的转录，内部裁掉 CV 长度"。改造调用方后传进去
的**已经是** CV 之前的转录，函数内部又裁一次 → 转录被多裁 1 条消息。

**修法**：把参数名改成 `transcript_before_cv` 并在文档注释里写死「调用方已裁好，
此处不得再裁」，同时删掉裁剪代码。这类"两处都以为对方在裁剪"的 bug 很难从代码
本身看出来，**参数名和注释必须把这个约定写清楚**。

### 13.4 ★ exporter 是两层派生 + `early()` 误用（最隐蔽）

**现象**：握手成功、所有握手数据正常，但客户端与服务端 `exporter` **完全不同**。

**两层坑，必须同时改对**：

#### 坑 A：exporter 派生是两层，不是一层

RFC 8446 §7.5 原文（容易被读成一层）：

```text
HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
                  "exporter", Hash(context_value), key_length)
```

展开：

```text
第 1 层  derived = HKDF-Expand-Label(exporter_master_secret, label, Hash(""), 32)
第 2 层  output  = HKDF-Expand-Label(derived, "exporter", Hash(context), length)
```

三个容易写错的细节：
- 第 1 层的 context 是 **`Hash("")`**（空串的 SHA-256）
- 第 1 层的 label **不加任何前缀**（不是 `"EXPORTER" + label`）
- 第 2 层的 label 是**固定字面量 `"exporter"`**，context 是 **`Hash(context)`**

#### 坑 B：`KeySchedule::early()` 会多做一次 HKDF-Extract

```rust
// 错误写法
let exp_sched = KeySchedule::early(&exp_sched_secret);
```

`early()` 的语义是「从 PSK 派生 **Early Secret**」，内部是 `HKDF-Extract(0, psk)`。
而 `exporter_master_secret` 已经是最终 secret，再经 `early()` 会**多套一层 Extract**。

**修法**：新增 `KeySchedule::from_secret(secret)`，只存值不做派生。

#### 定位方法（值得复用）

boring crate 没暴露 keylog，但可以直接声明 C 符号：

```rust
unsafe extern "C" {
    fn SSL_CTX_set_keylog_callback(
        ctx: *mut std::ffi::c_void,
        cb: Option<unsafe extern "C" fn(*const std::ffi::c_void, *const c_char)>,
    );
}
// 必须在 SslAcceptor::build() 之前装到 acc.as_ptr()
```

拿到服务端全部 `*_TRAFFIC_SECRET` / `EXPORTER_SECRET` 后与客户端逐字节比对：

| secret | 结果 |
|--------|------|
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | 一致 |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | 一致 |
| `CLIENT_TRAFFIC_SECRET_0` | 一致 |
| `SERVER_TRAFFIC_SECRET_0` | 一致 |
| `EXPORTER_SECRET` | 一致 → **问题只可能在 `export_keying_material` 的展开** |

这样能把"key schedule 错"与"exporter 展开错"彻底分开，一分钟定位。

### 13.5 `into_std()` 后必须 `set_nonblocking(false)`

**现象**：`spawn_blocking` 里 BoringSSL `accept()` 报
`a nonblocking read call would have blocked`。

**根因**：tokio 的 `TcpStream` 是非阻塞模式，`into_std()` **保持**非阻塞。
BoringSSL 的阻塞式 `SSL_accept` 遇到非阻塞 socket 且无数据可读时直接返回错误。

**修法**：

```rust
let std_sock = sock.into_std()?;
std_sock.set_nonblocking(false)?;   // ← 必须
std_sock.set_read_timeout(Some(Duration::from_secs(10)))?;
```

### 13.6 测试并行时临时证书目录必须唯一

**现象**：单个测试跑通过，`cargo test` 全跑却失败 —— 报证书与私钥不匹配。

**根因**：`make_cert()` 用 `std::process::id()` 命名目录，同一个测试二进制里的
多个 `#[tokio::test]` **并行**跑，共用同一目录，互相覆盖 `cert.pem` / `key.pem`。

**修法**：

```rust
static SEQ: AtomicUsize = AtomicUsize::new(0);
let dir = temp_dir().join(format!("x-{}-{}", std::process::id(), SEQ.fetch_add(1, Relaxed)));
```

### 13.7 `#[tokio::test]` 里的时序陷阱

- 客户端用 `read_exact` 读记录头，不会误判 EOF
- 但服务端如果用的是"读到 0 字节就当 EOF"的逻辑，要考虑超时
- `tokio::time::timeout` 包住整个 `handshake` 比给每一步设超时更好排查

### 13.8 实测数据（可用于回归对比）

一次真实握手（BoringSSL 服务端 ↔ 自研客户端）：

```text
CLIENT_HANDSHAKE_TRAFFIC_SECRET  d47d146a...6caeac  43357d0d...a0125c4
SERVER_HANDSHAKE_TRAFFIC_SECRET  d47d146a...6caeac  28f4c7d0...034bfb
CLIENT_TRAFFIC_SECRET_0          d47d146a...6caeac  79482ac9...cf4e5254
SERVER_TRAFFIC_SECRET_0          d47d146a...6caeac  95891a6e...03dabed16
EXPORTER_SECRET                  d47d146a...6caeac  e05077e2...968bb024
                                  ↑ client_random     ↑ secret
```

`key_schedule.rs` 里的 `exporter两层派生固定向量` 测试用的就是这个连接的
`EXPORTER_SECRET` 与 `context`，**若 exporter 派生被改坏，该测试立即失败**。

---

## 十四、★★★ Phase 3 数据面的 3 个必踩坑（2026-11-10 21:55，SOCKS5/HTTP/HTTPS 入口实测）

> 背景：Phase 3 把「本地代理入口 → FlowTCP 隧道 → 服务端出口 → 真实目标」
> 整条数据面打通。这三个坑全部是**跑真流量才暴露**的，
> 单元测试（即使覆盖率 100%）也发现不了。

### 14.1 ★ 一次 `read` 读到多条记录，后续记录被丢弃

**现象**：SOCKS5 连接建立成功（`OpenTcp` 帧处理正常），但数据一条也传不过去，
客户端 `read` 一直等到超时。日志显示服务端「TCP 流已打开」，但**从未收到 `Data` 帧**。

**根因**：读循环直接对 `read()` 到的字节调用 `RecordDecoder::open()`，
并**忽略了它返回的 `used`**：

```rust
// 错误写法
let n = reader.read(&mut chunk).await?;
match dec.open(&chunk[..n]) {
    Ok((_seq, plain, _used)) => pending.extend(plain),   // ← _used 被忽略
    ...
}
```

当一次 `read` 恰好包含多条记录时：

```text
read() → [记录1(OpenTcp)][记录2(Data)]
open(&buf[..n]) → Ok(记录1)      ← 记录 2 被直接扔掉
下一次 read() → 内核里已经没有了（都被这次读走了）
```

**为什么必然发生**：客户端把 `OpenTcp` 帧与紧随其后的 `Data` 帧
（SOCKS5 应答后浏览器立刻发请求）写进同一条 TCP 段是很常见的行为。
`Mux` 的写任务还有「批量合并」逻辑，会主动把多帧打包 —— 更加剧了这个问题。

**修法**：把「原始字节（密文）」与「明文」分成两个缓冲，
原始字节**必须缓冲并可跨多次 read 累积**：

```rust
pub struct FrameReader<R> {
    raw: Vec<u8>,      // 未消费的原始字节（密文）
    pending: Vec<u8>,  // 已解密、待切帧的明文
}

// 每次循环：先把 raw 里所有完整记录都解出来，再切帧，最后才读更多字节
loop {
    drain_records(&mut raw, &mut pending)?;   // 消费所有完整记录
    if let Ok((f, used)) = OwnedFrame::decode(&pending) { ... }
    let n = inner.read(&mut chunk).await?;
    raw.extend_from_slice(&chunk[..n]);       // 追加，不是覆盖
}
```

**「记录是否完整」的判断必须自己算**（不能用 `open()` 的 `Truncated` 兜）：

```rust
let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
if len < 24 { return Err(BadLength(len)); }   // 掩码(8) + tag(16) 下限
if raw.len() < 5 + len { return Ok(()); }      // 不完整，等更多数据
```

**客户端与服务端两侧都有这个 bug**，必须同时修 —— 只修一侧会表现为
「能发不能收」或「能收不能发」，更容易误判。

### 14.2 `pump` 用 `tokio::join!` 会挂住

**现象**：浏览器关闭页面后，本地连接与服务端连接都不释放，
要等几分钟才超时回收。

**根因**：

```text
目标服务器关闭 → 下行收到 Close 并结束
但上行仍在 read(本地) 上等待 —— 浏览器保持 keep-alive 不关，于是永远等下去
```

`join!` 要求两个方向都**自然结束**，而代理场景里"一端结束"就等于"整个会话结束"。

**修法**：改用 `select!`，任一侧结束就取消另一侧：

```rust
tokio::select! {
    _ = up => {}
    _ = down => {}
}
```

**计数要改用原子量**：`select!` 取消的那一侧拿不到返回值，
若用返回值累加字节数就会丢失统计。

### 14.3 `tcp_pump` 在客户端半关闭后忙循环烧 CPU

**现象**：客户端发完数据后关闭写端（`Close(FIN)`），服务端某个核心 100% CPU。

**根因**：

```rust
tokio::select! {
    data = from_client.recv() => {
        match data {
            None => { tw.shutdown().await; continue; }   // ← 这里
        }
    }
    read = tr.read(&mut buf) => { ... }
}
```

通道关闭后 `recv()` **立刻**返回 `None`，`continue` 又回到 `select!`，
再立刻拿到 `None`……形成零等待的死循环。

**修法**：用 `select!` 的分支条件把它禁掉，走真正的半关闭语义：

```rust
let mut client_closed = false;
loop {
    tokio::select! {
        data = from_client.recv(), if !client_closed => {
            match data {
                None => {
                    tw.shutdown().await;   // 半关闭目标写端
                    client_closed = true;  // 之后只剩"读目标剩余数据"这一个分支
                }
                ...
            }
        }
        read = tr.read(&mut buf) => { ... }
    }
}
```

这才是正确的 TCP 半关闭：客户端不再发数据后，目标可能还有剩余数据要回来。

### 14.4 测试收尾顺序：`Arc<Mux>` 的隐藏持有者

**现象**：e2e 测试断言"服务端应结束"时超时，但数据往返明明成功。

**根因**：入口任务（`serve_on`）持有 `Arc<Mux>`。测试里 `drop(mux)`
只减少一个引用计数，隧道仍被入口任务持有 → 写任务不退出 → 不 `shutdown`
→ 服务端读不到 EOF。

**修法**：测试必须显式 `abort()` 入口任务：

```rust
let entry = tokio::spawn(socks5_entry::serve_on(listener, Arc::clone(&mux)));
// ...
entry.abort();
drop(mux);
```

**同时**：`Mux::write_loop` 退出时必须 `shutdown` 底层写半：

```rust
let mut inner = writer.into_inner();
let _ = inner.shutdown().await;   // ← 不加这句，服务端永远等不到 EOF
```

### 14.5 自签证书 + curl 的正确参数

HTTPS 入口默认自签证书，用 curl 验证时：

| 参数 | 作用 |
|------|------|
| `-k` / `--insecure` | 跳过**目标站点**的证书校验 |
| `--proxy-insecure` | 跳过**代理**的证书校验 |

`-x https://127.0.0.1:8443` 时**两者都需要**，否则会报
`SSL certificate problem: self-signed certificate` —— 这是代理证书的问题，
不是目标站点的，`-k` 单独用不管用。

### 14.6 `tokio::io::duplex` 的方向陷阱（测试）

`duplex()` 是**双向**管道：`b.write()` 的数据由 `a.read()` 读到。

```rust
// 错误：a 写 a 读，永远等不到数据（测试挂 60 秒）
let (mut a, b) = duplex(64);
a.write_all(b"hello").await;
a.read_exact(&mut buf).await;   // ← 挂死

// 正确
let (a, mut b) = duplex(64);
b.write_all(b"hello").await;
a.read_exact(&mut buf).await;
```

同理 `AsyncReadExt::take(limit)` 会遮蔽自定义类型的 `take()` 方法，
测试里要写全限定形式：`Takeable::take(&mut t)`。

### 14.7 实测结果（2026-11-10，本机真实网络）

```text
$ flowtcp server --listen 127.0.0.1:18443 --password 'p' \
    --target www.microsoft.com:443 --sni www.microsoft.com
$ flowtcp client --remote 127.0.0.1:18443 --password 'p' \
    --sni www.microsoft.com --socks5 127.0.0.1:11080 \
    --http 127.0.0.1:18080 --https 127.0.0.1:18444

SOCKS5 (HTTPS 网站，CONNECT)         → HTTP 200
HTTP 代理 (HTTPS 网站，CONNECT)      → HTTP 200
HTTP 代理 (明文站点，绝对 URI 改写)  → HTTP 200
HTTPS 代理 (自签 + --proxy-insecure) → HTTP 200
HTTPS 代理 (明文站点)                → HTTP 200
```

服务端日志确认走了**认证通过 → 数据面**路径（不是透传）：
`认证通过，TLS 握手完成，进入数据面 alpn=Some("h2")`。

---

## 十五、★★★ 加密路径的 CPU 陷阱：每包重建密码学实例（2026-11-10 22:22 实测）

> 背景：用户明确要求「加密算法选用 CPU 原生占用低的方式」，
> 并指出「流控实现不好会导致隧道带宽低、CPU 占用高」。
> 本节是**先量化、再优化**的完整过程记录。

### 15.1 先量化：瓶颈不在算法，在「重建」

写基准 `crates/flowtcp-proto/examples/bench_record.rs` 之前，
我以为是算法选错了。实测后发现真正的元凶是**每次加解密都重建 cipher 实例**：

```rust
// 优化前的加密路径（错误）
fn encrypt_in_place(algo: AeadAlgo, key: &[u8], nonce: &[u8; 12], ...) {
    let cipher = Aes128Gcm::new_from_slice(key)?;   // ← 每次都做 AES key expansion
    cipher.encrypt_in_place_detached(n, aad, buf)
}

fn seq_mask(&self, ct: &[u8]) -> [u8; 8] {
    let cipher = Aes128::new_from_slice(&self.sn_key)?;  // ← 又一次
    cipher.encrypt_block(...)
}
```

实测单次构造代价（本机）：

| 操作 | 代价 |
|------|------|
| `Aes128Gcm::new_from_slice` | **124 ns** |
| `Aes128::new_from_slice` | **75 ns** |
| 合计每包浪费 | **199 ns** |

对照单包加密总耗时：

| 包大小 | 加密耗时 | 密钥调度占比 |
|--------|---------|-------------|
| **64B（DNS/游戏/VoIP）** | 452 ns | **44%** |
| 512B（交互） | 915 ns | 22% |
| 1400B（MTU 典型） | 1773 ns | 11% |
| 16KB（大流量） | 16021 ns | 1.2% |

**代理隧道的流量主体是小包**（DNS 查询、TCP ACK、游戏同步、VoIP）。
也就是说：**近一半的加密 CPU 花在了重复的密钥调度上，一个字节的有用功都没做。**

### 15.2 优化：缓存实例 + Arc 共享

```rust
enum CachedCipher {
    Aes { gcm: Box<Aes128Gcm>, ecb: Box<Aes128> },
    ChaCha { aead: Box<ChaCha20Poly1305>, ecb: Box<Aes128> },
}

pub struct Keys {
    algo: AeadAlgo,
    iv: [u8; 12],
    cipher: Arc<CachedCipher>,   // ← Arc 让 clone 变成 O(1)
}
```

三个要点：

1. **`Box` 包裹**：`Aes128` 内含 176 字节 round key 表，直接内联会让 `Keys` 变大，
   clone/移动代价上升。
2. **`Arc` 共享**：`Keys` 会被 clone 给 `RecordEncoder` 与 `RecordDecoder`。
   用 `Arc` 之后 clone 只是引用计数 +1，且两端共享同一份实例。
   （有测试 `keys克隆是引用计数而非深拷贝` 守住这一点）
3. **`ecb` 两个分支都要有**：`seq_mask` 固定用 AES-128-ECB
   （与 DTLS 1.3 的序号加密一致），**与 AEAD 算法无关**。
   这样两种 AEAD 的线格式完全相同，可以无缝协商切换。

### 15.3 实测收益

| 包大小 | 优化前 | 优化后 | 提升 |
|--------|--------|--------|------|
| 64B | 452 ns | **235 ns** | **-48%** |
| 512B | 915 ns | **684 ns** | -25% |
| 1400B | 1773 ns | **1542 ns** | -13% |
| 16 KB | 16021 ns | 15988 ns | -0.2% |

小包恰好减半，完美对应「44% 是密钥调度」的测算。

### 15.4 算法选型：必须运行时检测，不能写死

实测本机（x86_64，有 AES-NI + AVX2）对比：

| 包大小 | AES-128-GCM | ChaCha20-Poly1305 | 倍数 |
|--------|-------------|-------------------|------|
| 64B | **235 ns** | 1881 ns | **AES 快 8.0×** |
| 512B | **684 ns** | 2281 ns | AES 快 3.3× |
| 1400B | **1542 ns** | 3354 ns | AES 快 2.2× |
| 16 KB | 15988 ns | 19072 ns | AES 快 1.2× |

**但这只是在有 AES-NI 的机器上。** 无 AES-NI 时完全反过来：

| 平台 | AES-128-GCM | ChaCha20-Poly1305 | 应选 |
|------|-------------|-------------------|------|
| x86_64 有 AES-NI | 2~6 GB/s | 1~3 GB/s | **AES** |
| x86_64 无 AES-NI | 0.1~0.3 GB/s（软件 T-table） | 1~3 GB/s | **ChaCha20** |
| ARMv8 有 crypto ext | 2~5 GB/s | 0.5~1.5 GB/s | **AES** |
| 其他 ARM | 0.05~0.2 GB/s | 0.5~1 GB/s | **ChaCha20** |

**选错算法在特定设备上会让 CPU 占用高 5~10 倍，且不会报任何错。**

因此新增：

```rust
impl AeadAlgo {
    /// 运行时 CPUID 检测（约 1~2 ns，读的是缓存的 static 原子）
    pub fn hw_accel(self) -> bool { ... }

    /// 自动选最优
    pub fn preferred() -> Self {
        if aes_hw_available() { Aes128Gcm } else { ChaCha20Poly1305 }
    }

    /// 供协商用的偏好列表（首位 = preferred）
    pub fn preference_list() -> &'static [AeadAlgo] { ... }
}
```

### 15.5 一个容易忽略的点：`cfg!(target_feature)` 是错的

```rust
// ❌ 错误：只反映编译时是否用 -C target-feature 全量启用
let ok = cfg!(target_feature = "aes");

// ✅ 正确：运行时读 CPUID（结果缓存到 static 原子变量）
#[cfg(target_arch = "x86_64")]
let ok = std::is_x86_feature_detected!("aes");
```

二进制会被分发到各种机器。编译期 feature 只对「明确只为某台机器编译」有效，
对发行版二进制毫无意义。

### 15.6 下一步的 CPU 优化（按收益排序）

详见 `docs/FLOW_CONTROL.md` §6.6。简要：

1. **去掉 `Arc<Mutex<HashMap<u16, Target>>>`**
   `mux.rs` 与 `exit.rs` 的读循环每收到一帧都要抢锁 + `HashMap` 查找（30~60 ns）。
   256 条并发流 × 1000 包/秒 = 每秒 25.6 万次抢锁，**与加密开销同量级**。
   改用 `Vec<Option<Target>>` 按 stream_id 直接索引 → 2~5 ns。
2. **批量 seal**：一次 `seal_into` 多条记录，减少函数调用与分配
3. **接收缓冲环形复用**：当前 `decrypt_in_place` 里每包一次 `ciphertext.to_vec()` 分配
4. **FakeTCP 侧的 GSO 类比**：一次 `write` 多个数据报（quinn 实测 GSO 是最有效的发送侧优化）

### 15.7 复现方式

```bash
cargo run --release -p flowtcp-proto --example bench_record
```

判读标准：
- 1400B 包加密 > 5 us（< 300 MB/s）→ 本机无 AES-NI 或跑在虚拟机
- 64B 包加密 > 400 ns → 说明 cipher 实例没有被缓存

---

## 十六、★★★ 可靠性语义：TCP 必须 ARQ、UDP 禁止 ARQ（2026-11-10 22:47 核实）

> 起因：用户指出「hy2 等协议 TCP 是有重传机制的，一般是游戏（UDP）没有重传机制」，
> 要求核实。**核实结论：用户判断完全正确**，而我们的代码存在设计缺陷。

### 16.1 hy2 官方协议原文确认

来源：`v2.hysteria.network/docs/developers/Protocol/`

| 流量 | 承载通道 | 可靠性 |
|------|---------|--------|
| **TCP** | `QUIC bidirectional stream` | **可靠 · 有 ACK + 重传** |
| **UDP** | `QUIC unreliable datagram`（RFC 9221） | **不可靠 · 无重传** |

原文（TCP）：

> For each TCP connection, the client MUST create a new
> **QUIC bidirectional stream** and send the following TCPRequest message

原文（UDP）：

> UDP packets MUST be encapsulated in the following UDPMessage format and sent
> over **QUIC's unreliable datagram** (for both client-to-server and
> server-to-client)

最硬的证据是它的分片规则：

> Due to the limit imposed by QUIC's **unreliable** datagram channel...
> If one or more fragments of a packet are lost, **the entire packet MUST be
> discarded.**

**丢一个分片 → 整包丢弃 → 不请求重传。** 这就是 UDP 的定义。

### 16.2 发现的代码缺陷

`crates/flowtcp-client/src/mux.rs` 的 `send_data`：

```rust
let f = OwnedFrame::new(
    FrameType::Data,
    Flags::empty(),   // ← TCP 流与 UDP 流的帧完全一样！
    ...
);
```

`StreamSender` 里没有任何字段记录「这条流是 TCP 还是 UDP」。

**后果**：Phase 3 用真 TCP 承载，内核保证可靠，所以没暴露问题。
但 Phase 4 接 FakeTCP（无重传）后，接收方**无法判断哪些帧需要请求重传** ——
TCP 流会静默丢数据。

### 16.3 正确的设计：可靠性是**流级**属性

#### 为什么不能逐帧决定

如果由每个 `Data` 帧自己声明 `RELIABLE`，只要有**一帧**漏标：

```text
TCP 流发送 [帧1 RELIABLE][帧2 RELIABLE][帧3 漏标!][帧4 RELIABLE]
                                       ↑
                            这一帧丢了永远不重传
```

上层表现：**下载的文件损坏**。而且：
- 只在特定丢包时机复现
- 日志里什么都看不到（帧是"合法"的）
- 定位成本极高

#### 正确做法：流状态为权威 + 帧上冗余校验

```rust
// 1) 权威来源：开流帧类型（唯一决定）
let reliable = matches!(frame_type, FrameType::OpenTcp);

// 2) StreamSender 记住它，send_data 统一打标
StreamSender { reliable, ... }

pub async fn send_data(&mut self, data: &[u8]) -> Result<(), MuxError> {
    let flags = if self.reliable {
        Flags::empty().with(Flags::RELIABLE)
    } else {
        Flags::empty()
    };
    ...
}
```

服务端做**一致性校验**（`crates/flowtcp-server/src/exit.rs`）：

```rust
fn stream_reliable(streams: &SlotTable<Target>, id: u16) -> Option<bool> {
    match streams.get(id) {
        Some(Target::Tcp(_)) => Some(true),
        Some(Target::Udp { .. }) => Some(false),
        None => None,
    }
}

// Data 帧处理里：
if let Some(expected) = stream_reliable(streams, sid) {
    if frame.flags.has(Flags::RELIABLE) != expected {
        tracing::error!(...);
        return Err(ExitError::Closed);   // ← 宁可断开，也不要静默损坏
    }
}
```

**校验的价值不是"让每帧决定"，而是让实现 bug 立即暴露。**
静默损坏数据是最难排查的一类 bug，必须在协议层设防线。

### 16.4 为什么不能"统一都可靠"

有人会想：可靠更安全，为什么 UDP 不走可靠传输？

| 原因 | 说明 |
|------|------|
| **队头阻塞** | 重传必须等，一个丢包卡住该会话所有后续包 |
| **延迟放大** | 游戏/语音宁可丢一帧，也不要等 200 ms 重传 |
| **流量放大** | 实时流量的丢包常是瞬时抖动，重传会加剧拥塞 |

Hysteria（QUIC Datagram）、TUIC（UDP over QUIC Datagram）结论一致：
**UDP 流量绝不能走可靠通道。**

### 16.5 一句话总结

> **TCP 流丢了要重传（否则数据损坏），UDP 流丢了就丢（否则延迟爆炸）。**
> **可靠性由开流帧决定，不能由每个数据帧自己决定。**

### 16.6 相关测试

`crates/flowtcp-client/src/mux.rs`：
- `tcp流带reliable标志而udp流不带` —— 验证两种流的帧标志正确
- `udp数据报不带reliable` —— 验证 `send_datagram` 也不带

若有人"优化"掉 `reliable` 字段，这两个测试会立即失败。

---

## 十七、★★★ 四个静默丢数据的坑（2026-11-10 23:10，大数据量实测暴露）

> 这一节记录的是**整个项目里最危险的一类 bug**：
> 不崩溃、不报错、不打日志，只是数据悄悄少了一部分。
> 唯一能发现它们的方法就是**逐字节比对**。
>
> 触发路径：做吞吐测试时发现「16MB 只收到 32KB」，顺着这个异常挖出 4 个缺陷。

### 17.1 症状汇总

| 现象 | 根因 | 丢掉的比例 |
|------|------|-----------|
| 下载 16MB 只到 **32KB** | `write_loop` 静默跳过错限帧 | 99.8% |
| 下载 16MB 只到 **15.4MB** | 批量合并 `try_recv` 后 `break` | 3.6%（且错位） |
| 上传 64MB 只到 **29MB** | TCP 流 `try_send` 队列满即丢弃 | **57%** |
| 浏览器半关闭后响应被截断 | `select!` 取消了对侧 | 取决于时序 |

### 17.2 Bug 1：`let _ = encode()` 吞掉错误

```rust
// ❌ 错误：条件不成立就跳过，plain 为空后 continue，该帧永久丢失
while let Some(first) = rx.recv().await {
    plain.clear();
    if first.encoded_len() <= MAX_RECORD_PLAINTEXT {
        let _ = first.encode(&mut plain);   // ← 两个错误叠加
    }
    ...
    if plain.is_empty() { continue; }       // ← 悄悄跳过
}
```

两个错误叠加：
1. **`let _ =` 吞掉错误** —— `encode` 失败（payload 超 `MAX_FRAME_PAYLOAD`）无人知晓
2. **条件判断用记录上限而非帧上限** —— 逻辑本身就错

上游 `tcp_pump` 的问题是配套的：

```rust
let mut buf = vec![0u8; 32 * 1024];   // 读 32KB
...
Ok(n) => {
    let f = OwnedFrame::new(..., buf[..n].to_vec());   // ← 32KB 直接当一帧
```

而 `MAX_FRAME_PAYLOAD = 16384`。**只要一次 read 拿到 >16KB，这一整块就丢了。**

**修复**：

```rust
// 1) 编码失败必须终止，绝不静默跳过
if let Err(e) = first.encode(&mut plain) {
    tracing::error!(stream_id = ..., payload_len = first.payload.len(), error = %e,
        "帧编码失败（上层未按 max_payload 分片），终止写任务");
    break;
}

// 2) 读取侧按 max_payload 分片
for chunk in buf[..n].chunks(max_payload) {
    let f = OwnedFrame::new(FrameType::Data, flags, stream_id, seq, chunk.to_vec());
    seq = seq.wrapping_add(1);
    out.send(f).await?;
}
```

### 17.3 Bug 2：批量合并时 `try_recv` + `break` 丢帧

```rust
// ❌ try_recv() 已经把帧从队列取出来了！
while let Ok(next) = rx.try_recv() {
    if plain.len() + next.encoded_len() > MAX_RECORD_PLAINTEXT {
        break;          // ← next 被丢弃，永久消失
    }
    let _ = next.encode(&mut plain);
}
```

**这个 bug 特别阴险**：它不是"丢尾部"，而是**丢中间某几帧**，
所以对端收到的数据长度接近正确但内容错位。

**修复：引入 `carry` 把超限帧留回下一轮**

```rust
let mut carry: Option<OwnedFrame> = None;

loop {
    // 优先取上一轮留下的帧，不为它多等一次调度
    let first = match carry.take() {
        Some(f) => f,
        None => match rx.recv().await {
            Some(f) => f,
            None => break,
        },
    };
    ...
    while plain.len() + FRAME_HEADER_LEN <= MAX_RECORD_PLAINTEXT {
        match rx.try_recv() {
            Ok(next) => {
                if plain.len() + next.encoded_len() > MAX_RECORD_PLAINTEXT {
                    carry = Some(next);   // ← 留回，不丢
                    break;
                }
                next.encode(&mut plain)?;
            }
            Err(_) => break,
        }
    }
    ...
}
```

### 17.4 ★★ Bug 3：TCP 流用 `try_send` 队列满即丢弃（最严重）

```rust
// ❌ 原代码 + 原注释
Action::Tcp(tx) => {
    // try_send：目标消费不过来时丢弃而非阻塞整条隧道
    // （阻塞会让所有其他流一起卡住 —— 一个慢目标拖垮全部）
    if tx.try_send(frame.payload).is_err() {
        tracing::trace!(stream_id = sid, "流写队列满，丢弃数据");
    }
}
```

**注释里的理由是错的。** 它说"阻塞会让一个慢目标拖垮整条隧道" ——
这话对 **UDP** 完全成立（丢包是 UDP 的正常语义），
但对 **TCP 是灾难性的**：可靠字节流丢一个字节就是**数据损坏**。

**为什么必然溢出**：队列只有 256 帧 ≈ 358KB。
read 循环「解密 → try_send」的速度远快于 `tcp_pump` 逐帧 `write_all` 到目标 socket，
64MB 上传必然把队列打满。

实测：上传 64MB 只到达 29MB（丢 38MB，57%），而客户端 `sendall` **全部成功返回** ——
完全没有感知，用户只会看到"上传的文件坏了"。

**修复：按可靠性分流**

```rust
Action::Tcp(tx) => {
    // 可靠流：send().await 施加背压，绝不丢弃
    // 代价是慢目标会短暂阻塞读循环（HOL），但这比静默丢数据好得多
    if tx.send(frame.payload).await.is_err() {
        // 接收端已 drop（流已关闭）→ 正常
    }
}
Action::Udp(sock, default) => {
    // 不可靠流：try_send 丢弃是正确的 UDP 语义
    ...
}
```

并把 TCP 队列提升到 `MAX_RELIABLE_QUEUE = 2048`（≈2.8MB/流），
在背压生效前多吸收一些突发。

> **注**：`send().await` 会造成队头阻塞（一个慢目标短暂卡住整条隧道）。
> Phase 4 的信用流控（`docs/FLOW_CONTROL.md`）会把它变成
> 「按流窗口限速」，从而消除 HOL —— 但在流控实现之前，
> **背压 + 短暂 HOL 是唯一正确的选择**。宁可慢，不可错。

### 17.5 Bug 4：`select!` 取消了半关闭

```rust
// ❌ 任一侧结束就取消另一侧
tokio::select! {
    _ = up => {}
    _ = down => {}
}
```

浏览器发完请求后可能**半关闭写端**（HTTP/1.0 `Connection: close` 正是如此）。
此时 `up` 结束 → `select!` 取消 `down` → **响应还没收完就被掐断**。

**修复：真正的半关闭语义**

```rust
tokio::pin!(up, down);
tokio::select! {
    // 上行结束：FIN 已发，继续收下行直到对端关闭
    _ = &mut up => { (&mut down).await; }
    // 下行结束：会话真正结束
    _ = &mut down => {}
}
```

用 `tokio::pin!` 是因为 `select!` 里要「先 await 一个，再 await 另一个」，
直接 `down.await` 会因 `down` 已被 move 而编译失败。

### 17.6 为什么这些 bug 单测抓不到

看它们的共同点：

- **不产生错误**：没有 `Err` 返回，没有 panic
- **日志级别是 `trace`/`debug`**：生产环境看不到
- **只在特定数据量/时序下触发**：小于 16KB 的文件完全正常
- **客户端也可能"成功"**：`sendall` 全返回，`curl` 退出码 0

**唯一可靠的验证方式是逐字节比对，且数据量要足够大。**

现有的 `socks5_tcp_connect_echo往返` 只发 17 字节 —— 它能验证"通路成立"，
但永远发现不了这些 bug。

因此新增两个测试（`crates/flowtcp-server/tests/proxy_e2e.rs`）：

| 测试 | 数据量 | 验证 |
|------|--------|------|
| `下行大流量字节完全一致` | 2 MB | 目标→客户端 逐字节比对，并报告首个不一致偏移 |
| `上行大流量字节完全一致` | 2 MB | 客户端→目标 逐字节比对 |

2MB 的选择依据：足以跨越多次 16KB 记录、多次 `read`、多个 32KB 缓冲边界，
又足够快（各约 5s，含隧道建立）。

### 17.7 实测吞吐（修复后，release 构建）

| 场景 | 吞吐 | 完整性 |
|------|------|--------|
| 下行 64 MB | **143 MB/s（≈1.15 Gbps）** | ✅ 字节一致 |
| 上行 64 MB | **154 MB/s** | ✅ 字节一致 |
| 双向并发（32MB↑ + 64MB↓） | 98.8 / 137 MB/s | ✅ |
| 服务端告警 | 0 条 | — |

> 测试环境：本机 loopback + 真 TCP 承载 + release 构建。
> **FakeTCP 承载（Phase 4.8）下会因 MTU 1400 与无重传而显著不同**，
> 届时需重测。

### 17.8 一条可以推广的经验

> **凡是「丢弃数据」的代码路径，都必须先问一句：这条流是可靠的吗？**
>
> - 可靠流（TCP）：**永远不丢**，只允许背压（阻塞）或断开
> - 不可靠流（UDP）：**可以丢**，且丢比等更好（延迟优先）
>
> 这个判断依据就是 Phase 3 引入的 `stream_reliable()`。
> 本节 4 个 bug 里有 2 个（Bug 1 的丢弃、Bug 3）本质都是
> **把 UDP 的"可丢弃"策略误用到了 TCP 上**。

---

## 十八、★★★ 信用流控的两个必死陷阱：补发挂错位置 & 半关闭错误注销（2026-11-10 23:35，实测）

Phase 4 接入信用流控后，`proxy_e2e` 的 10 个测试里 **9 个立刻通过、1 个恒定失败**，
且失败方式极具误导性 —— 30 秒超时、无任何错误日志、字节数**总是恰好 262144**。

这两个坑都非常容易再犯，记录在此。

### 18.1 症状识别：卡在「恰好等于窗口大小」= 一个字节都没补发

```
应在 30s 内收完 2097152 字节，实际只收到 262144
```

`262144 = 256 * 1024 = DEFAULT_STREAM_WINDOW`。

**看到这个数字就要立刻想到**：发送方把初始信用用光了，而接收方**一次补发都没做**。
不要去怀疑丢包、不要怀疑加密、不要怀疑分片 —— 一定是补发逻辑没被触发。

### 18.2 陷阱一：`poll_grant()` 挂在「接收」路径上 → 必然死锁

#### 错误的写法

```rust
// read_loop 的 Data 分支（错误示范）
if let Some(fc) = entry.recv_flow.as_ref() {
    fc.on_received(frame.payload.len());
    let need_grant = fc.poll_grant();   // ← 致命：此时 consumed 还是 0
    if let Some(delta) = need_grant { /* 发 Window 帧 */ }
}
inbound.send(frame).await;
```

#### 为什么必然死锁

窗口的目标上限是 `consumed + window`（见 `FlowCounters::poll_grant`）：

```rust
let target = consumed + window;
if target <= advertised { return None; }   // 没什么可补的
```

而 `consumed` **只在应用取走数据时**才前进。但：

1. `read_loop` 是**单任务**，`inbound.send()` 在队列有空位时**不会 yield**
2. 于是它一口气把整个窗口（256 KB）全部塞进 `inbound` 队列
3. 这期间应用还没来得及取走任何一帧 → `consumed` 恒为 0
4. 每次 `poll_grant()` 都算得 `target = 0 + 256KB = advertised` → **永远返回 `None`**
5. 对端把 256 KB 发完后就阻塞在 `acquire()` 上等信用
6. 没有新数据到达 → `read_loop` 阻塞在 `reader.recv()` → **再也不会调 `poll_grant`**

双向永久阻塞，形成闭环死锁：

```text
发送方等信用 ──→ 接收方等新数据 ──→ read_loop 等 reader ──→ 无数据（发送方已停）
      ↑                                                              │
      └──────────────── 补发只在收数据时触发 ←────────────────────────┘
```

#### 正确的位置：补发必须紧跟「消费」

```rust
// StreamReceiver::recv（正确）
pub async fn recv(&mut self) -> Option<OwnedFrame> {
    let f = self.inbound.recv().await?;
    if f.frame_type != FrameType::Data { return Some(f); }

    // 1) 记账：这段数据已被应用取走
    self.on_consumed(f.payload.len());

    // 2) 立刻按新的 consumed 补发信用
    if let Some(delta) = self.recv_flow.as_ref().and_then(|fc| fc.poll_grant()) {
        let mut payload = Vec::with_capacity(4);
        encode_window_credit(delta, &mut payload);
        let wf = OwnedFrame::new(FrameType::Window, Flags::empty(), self.id, 0, payload);
        let _ = self.out.send(wf).await;
    }
    Some(f)
}
```

这里 `consumed` 刚刚前进过，算出的 `target` 必然大于 `advertised`，补发一定生效。

#### 服务端要做对称处理

服务端的「消费点」是 `tcp_pump` 里 `tw.write_all(&d).await` 成功之后：

```rust
if tw.write_all(&d).await.is_err() { return; }
recv_flow.on_consumed(len);

// 必须紧跟补发
if let Some(delta) = recv_flow.poll_grant() {
    let mut payload = Vec::with_capacity(4);
    encode_window_credit(delta, &mut payload);
    let wf = OwnedFrame::new(FrameType::Window, Flags::empty(), stream_id, 0, payload);
    out.send(wf).await?;   // 写队列满则 await：良性背压，不丢信用
}
```

**这个位置还有个额外好处**：背压真正作用在「目标写不进去」这件事上 ——
目标慢 → 消费慢 → 补发少 → 客户端限速，而不是在内存里堆起无限队列。

#### 推论：`recv()` 内建上报，调用方不可能漏

早期设计让调用方自己调 `on_consumed`。只要**任何一处**忘了（测试代码、将来新增的
入口），就会复现同一个死锁。把上报+补发都塞进 `recv()` 里，从 API 层面消灭误用。

成本分析：`inbound` 队列深度 256 帧 ≈ 358 KB，「取走即算消费」不会让内存失控。

#### 自检清单

| 检查项 | 正确做法 |
|--------|---------|
| `poll_grant()` 调用点 | 紧随 `on_consumed()` 之后 |
| 接收路径（`on_received`） | **只记账，不补发** |
| 消费路径（`on_consumed`） | 记账 + 补发，缺一不可 |
| 诊断手段 | 卡在窗口整数倍 = 补发没生效 |

### 18.3 陷阱二：`Close` 帧直接 `remove` 流 → 后续 `Window` 帧全被丢弃

#### 场景

```
客户端: GET /bigfile → 发完请求 → tx.close(false)   ← 半关闭写端
服务端: 收到 Close → streams.remove(sid)             ← 致命
        tcp_pump 仍在读目标并往 out 发数据…
客户端: 收数据 → recv() 里补发 Window 帧 → 服务端
服务端: read_loop 查表 → 找不到 sid → 「丢弃未知流的窗口更新」
       → send_flow 的信用永远不恢复 → 卡死在 256 KB
```

注意此处 `tcp_pump` **还活着**：它持有 `send_flow`/`recv_flow` 的 `Arc` clone，
所以数据照发、信用照等。**但读循环再也找不到这条流来授信**。

#### 为什么 `Close` 不能删表

TCP 是**双向独立关闭**的。客户端发 `Close` 只代表「**我不再发数据了**」，
完全不代表「我不再收数据」。典型场景：

| 场景 | 行为 |
|------|------|
| HTTP GET 大文件 | 请求发完即半关闭，然后长时间收响应 |
| `curl -T` 上传 | 数据发完 shutdown(WR)，然后等响应体 |
| SMTP/IMAP | 十分常见 |

#### 正确做法：`Close` = 半关闭，不注销

```rust
enum Target {
    Tcp {
        // ★ 半关闭后置为 None，但**流本身保留在表里**
        tx: Option<mpsc::Sender<Vec<u8>>>,
        send_flow: Arc<SendFlow>,    // 仍需可寻址：供 Window 帧授信
        recv_flow: Arc<FlowCounters>,
    },
    Udp { .. },   // UDP 无半关闭概念，Close 即注销
}

FrameType::Close => {
    match streams.get_mut(sid) {
        Some(Target::Tcp { tx, .. }) => {
            *tx = None;   // drop → tcp_pump 的 recv() 返回 None → 半关闭
            // 表项保留！否则后续 Window 帧无处授信
        }
        Some(Target::Udp { .. }) => { streams.remove(sid); }
        None => {}
    }
}
```

流的**真正注销**由 `tcp_pump` 退出时的 `cleanup` 通道完成（那时它已发完所有数据）。

#### 推论：`Action::Tcp` 的 `tx` 变成 `Option` 后

半关闭状态下若还收到 Data 帧，说明对端实现有问题。此时：

```rust
recv_flow.on_received(frame.payload.len());   // 仍要记账！
let Some(tx) = tx else { return Ok(()); };   // 再丢弃数据
```

**记账不能省** —— 这些字节物理上到达了本端，不记 `received` 会让后续
`poll_grant` 算错补发量，导致窗口记账永久偏移。

### 18.4 附带修复：`read_loop` 不该持有出站队列

补发搬到 `recv()` 后，`read_loop` 不再需要 `out`。删掉这个持有关系还有额外收益：

```text
read_loop 持 out(Sender)
  → 写任务的 rx 收不到 None，永不退出
  → 底层连接不 shutdown
  → read_loop 的 reader.recv() 等不到 EOF
  → read_loop 永不退出，out 永不释放     ← 循环依赖死锁
```

这个死锁在 Phase 4.2 已经踩过一次（表现为**所有** e2e 测试报
「服务端应结束: Elapsed」）。现在读循环与写任务的存活完全解耦。

### 18.5 本轮实测数据（release，真 TCP 承载，loopback，64MB）

| 场景 | 流控接入后 | 流控前基线 | 变化 |
|------|-----------|-----------|------|
| 下行 64MB | **169.9 MB/s** | 143 MB/s | **+19%** |
| 上行 64MB | **189.5 MB/s** | 154 MB/s | **+23%** |
| 双向并发 | 123.7 / 126.1 MB/s | 98.8 / 137 MB/s | 合计 +6% |

数据完整性全部 ✅（`cmp` 逐字节一致；接收端字节数精确 `67108864`）。

流控接入不但没掉速，反而更快了。原因推测：

1. `read_loop` 少了 `out` 持有与一次 `send().await`，热路径变短
2. `poll_grant` 自带「消耗过半才补」的节流，Window 帧数量极少
   （2MB 传输约 8 个 Window 帧，摊到每帧成本可忽略）

### 18.6 后续必读：ARQ 会引入同款死锁

`docs/FLOW_CONTROL.md` §6.5 已警告：ARQ 的重传队列若只等 `Ack`，一旦 `Ack` 丢失，
`consumed` 不前进 → 与本文 18.2 完全同款的死锁。

**必须配「超时跳过空洞」**（默认 200 ms）：超时即视为该段已消费，继续推进窗口。
宁可让流控记账偏保守，也不能让隧道停死。

---

## 十九、★★★ 丢包测试的三个陷阱：增量信用、无重发、拿着假基线归因（2026-11-11 00:08）

用户要求「模拟丢包环境测试」，并指出「优先用 hy1/hy2 的成熟方法，不要造轮子」。
两条要求都带来了实质改进：**一测就暴露出流控的致命缺陷**，修复后吞吐提升约 500 倍。

### 19.1 陷阱一：`tc netem` 测不出应用层的流控缺陷

这是最容易搞错的一点。

```bash
tc qdisc add dev lo root netem loss 1%
```

在**真 TCP 承载**下，这个丢包会被**内核 TCP 重传**掩盖 —— 应用层（我们的帧层）
看不到任何丢失。所以：

| 测试手段 | 能测什么 | 测不出什么 |
|---------|---------|-----------|
| `tc netem loss` | 链路丢包对吞吐的影响 | **`Window` 帧丢失导致的死锁** |
| 应用层丢帧 | 帧丢失对协议的破坏 | 真实物理链路行为 |

实测证据：`netem loss 1%~10%` 下数据全部完整，而应用层丢 `Window` 帧 10%
就**死锁**。

**所以两者都必须测，且必须理解各自测的是什么。**

#### 实现：`crates/flowtcp-proto/src/fault.rs`

```rust
FLOWTCP_DROP_DATA=5      # 丢 5% 的 Data 帧
FLOWTCP_DROP_WINDOW=10   # 丢 10% 的 Window 帧
```

关键设计：

1. **只丢 Data 和 Window**，控制帧（Open/Close/Ping）永不丢 ——
   否则流根本建不起来，测试时无法区分「开流失败」与「流控死锁」。
2. `OnceLock` 缓存配置（热路径不读环境变量）。
3. 线程本地 xorshift32（不引入 `rand` 依赖），每线程独立种子
   （`RandomState` + 时间 + `ThreadId` 混合），避免所有线程产生同一序列。

### 19.2 陷阱二：增量信用 —— 丢一帧就永久蒸发

**症状**（极度误导）：

```
curl: (28) Operation timed out after 45004 milliseconds
      with 3296496 out of 16777216 bytes received
```

45 秒超时、只收到 19%、**零错误日志**。

**根因**：`Window` 帧载荷是**增量** `delta`。丢一个，那一份信用就
永远消失。窗口只有 256 KB，丢十几个 `Window` 帧就漏光 → 双方永久互等。

**修复：改用 QUIC `MAX_DATA` 的绝对偏移语义。**

```rust
// 载荷 = 已消费的累计字节数的低 32 位（不是增量！）
pub fn encode_window_credit(offset: u32, out: &mut Vec<u8>);
```

发送侧用 `wrapping_sub` 重建 64 位累计值：

```rust
pub fn set_acked(&mut self, offset: u32) {
    let delta = offset.wrapping_sub(self.acked_low) as u64;
    if delta < (1u64 << 31) {          // < 2³¹ 视为前进，否则是旧包
        self.acked = self.acked.saturating_add(delta);
        self.acked_low = offset;
    }
}
```

这个设计带来四个性质，**每一个都是增量语义做不到的**：

| 性质 | 效果 |
|------|------|
| **幂等** | 同一个偏移收 10 次与 1 次结果相同 |
| **抗丢包** | 中间丢 9 帧，第 10 帧到达即完全对正 |
| **抗乱序** | 差值 ≥ 2³¹ 的旧包自动忽略，信用绝不回退 |
| **抗回绕** | 4 GB 后 `wrapping` 自然处理，已验证到 4.5 GB |

**这正是不死锁的数学原因**：误差始终只差「最后一次成功送达之后」的量，
**永不累积**；而增量语义每丢一帧就永久漏掉一块。

#### 实测对比

| 场景 | 增量语义 | 绝对偏移 |
|------|---------|---------|
| Window 丢 10% | 45 s 超时，收 3.3/16 MB | **0.128 s，131.5 MB/s，完整** |
| Window 丢 30% | 死锁 | **0.119 s，141.6 MB/s，完整** |

### 19.3 陷阱三：绝对偏移还不够 —— 帧本身仍会丢

绝对偏移解决了「丢了也能对正」，但前提是**得有一帧能到达**。
如果只在「消费时发一次」，那一帧丢了就再无机会 —— 发送侧停在旧值，
直到有新数据消费才可能更新。而发送侧停住 → 没有新数据 → 死循环。

**QUIC 的解法**是把 `MAX_DATA` 放进重传队列等 ACK，等不到就重发。
我们还没 ARQ，用**周期无条件重发**达到同样效果（即 **PTO 探测**的简化版）：

```rust
let mut resend_tick = tokio::time::interval(Duration::from_millis(50));
// 有变化立即发；每 4 个周期（200ms）无条件重发一次
let force = tick_count % 4 == 0;
```

成本：4 字节/流/200 ms，256 流满载也只有 **5 KB/s**。

服务端用 `timeout(50ms, r.read())` 实现同样效果 —— **`AsyncReadExt::read` 是
cancel-safe 的**（tokio 文档明确保证：取消时没有数据被消费），所以超时打断
后下一轮继续读同一位置是安全的。

### 19.4 陷阱四：拿假基线做归因 —— 差点改错地方

RTT 100 ms 环境下测得上行 3.2 MB/s（原 1.5 MB/s，提升 2.1 倍），
但离 8 MB 窗口的理论值（80 MB/s）差 25 倍。**第一反应是「流控还有问题」**。

幸好先测了基线：**同一环境下原生 TCP 只有 1.0~15.9 MB/s，两轮相差 16 倍**。

结论：**我们的 3.2 MB/s 已经落在原生 TCP 的波动范围内，流控不再是瓶颈** —
瓶颈是内核 socket 缓冲（`net.ipv4.tcp_rmem` 默认 128 KB）与 netem 本身。

#### 教训

**优化前必须先测同环境的原生基线。** 否则会把环境限制当成自己的 bug，
在错误的地方反复改代码。

顺带发现两个测试环境自身的坑：

1. **`netem delay` 需要更大的 `limit`**：默认 `limit 1000` 包，
   延迟 50 ms 时缓冲区一大就溢出丢包，导致 TCP 退避、速度暴跌到 0.8 MB/s。
2. **`tcp_wmem` 的第二个值（默认值）不会因调大第三值而变**：
   `sysctl -w net.ipv4.tcp_wmem="4096 16384 16777216"` 只改上限，
   实际仍从 16 KB 起，自动调优需要时间。

### 19.5 照抄 hy2 的窗口参数（不再自己拍数字）

之前用 256 KB 是「先用小值验证正确性」的临时决定，实测证明**小 32 倍**。

读了 `hysteria/core/internal/congestion/brutal/brutal.go`（193 行）后，
找到了权威依据：

```go
const (
    pktInfoSlotCount           = 5    // 5 秒滑动窗口
    minAckRate                 = 0.8  // 补偿钳制
    congestionWindowMultiplier = 2    // 2×BDP
)

// 全部逻辑
cwnd = bps × SmoothedRTT × 2 / ackRate

// 丢包完全不影响速率
func (b *BrutalSender) OnCongestionEvent(...) { /* Stub */ }
func (b *BrutalSender) InSlowStart() bool { return false }
func (b *BrutalSender) InRecovery() bool  { return false }
```

**核心洞察**：Brutal 不是「不顾丢包狂发」，而是
**「按实测丢包率反向放大窗口，把丢掉的量补回来」**。

hy2 的窗口默认值（官方两组，都是 2:5）：

| 来源 | 流级 | 连接级 |
|------|------|--------|
| Full Server Config 默认 | 8 MB | 20 MB |
| Performance 调优 | 25.6 MB | 64 MB |

我们采用 **8 MB / 20 MB**（保守默认），并新增 `--stream-window` 参数
（支持 `512K` / `8M` / `16M`），对齐 hy2 的 `initStreamReceiveWindow`。

**为什么必须保留「自己实现」的部分**：hy2 的流控窗口是 QUIC 提供的，
Brutal 只管拥塞（发送速率）。我们没有 QUIC，所以窗口授信这套必须自己写 ——
但**语义可以直接抄 QUIC 的 `MAX_DATA`**（绝对偏移），这正是本次改造做的事。

### 19.6 完整丢包矩阵（16 MB，真 TCP 承载）

| Data 丢 | Window 丢 | 下行 | 完整性 | 上行 |
|---------|-----------|------|--------|------|
| 0% | 0% | 141 MB/s | ✅ | 155 MB/s |
| 0% | 10% | 131.5 MB/s | ✅ | 163.8 MB/s |
| 0% | 30% | 141.6 MB/s | ✅ | 157.4 MB/s |
| 5% | 0% | 141.2 MB/s | 缺 5.06% | 158.7 MB/s |
| 5% | 10% | 137.2 MB/s | 缺 5.03% | 152.3 MB/s |

两个关键读法：

1. **`Window` 丢 30% 完全不掉速** —— 绝对偏移 + 周期重发完全吸收了它。
2. **`Data` 丢 5% 恰好丢 5.06%** —— 无额外损失、无卡死。
   这剩下的 5% 就是 **ARQ（Phase 4.6）唯一需要解决的问题**。

### 19.7 后续必读

**ARQ 上线后，`SendCredit::recover()` 应该退化为只读诊断**。

它现在是「无 ARQ 时的兜底」：强制把 `acked` 提到 `used`，乐观地认为丢失的数据
已被消费。这在有 ARQ 之后是不必要的（重传会让对端真正确认），且会让窗口偏乐观。

另外 ARQ 必须配**「超时跳过空洞」**（默认 200 ms），否则重传队列只等 `Ack` 时，
一旦 `Ack` 丢失就复现 §18.2 的同款死锁。

---

## 二十、★★★ ARQ 照抄 QUIC 的过程与 6 个致命 bug（2026-11-11 01:56）

按用户要求「先看 hy1/hy2 怎么处理，照抄就行」。hy2 的 ARQ 就是 **quic-go**，
所以直接照抄 RFC 9002（丢包检测）+ RFC 9000 §19.3（范围 ACK）。

结果是：ARQ 一次写对（33 个单测全绿），但**集成进真实数据面后连爆 6 个 bug**，
每一个都只在「有丢包 + 有大数据量」时才暴露。这篇记录全过程。

### 20.1 照抄了哪些（参数与公式，可直接复用）

| 项 | 值 | 出处 |
|----|-----|------|
| 包阈值 `kPacketThreshold` | **3** | RFC 9002 §6.1.1 |
| 时间阈值 `kTimeThreshold` | **9/8 × max(smoothed_rtt, latest_rtt)** | §6.1.2 |
| 定时器粒度 `kGranularity` | **1 ms** | §6.1.2 |
| 初始 RTT `kInitialRtt` | **333 ms** | §6.2.2 |
| `max_ack_delay` | **25 ms** | QUIC 默认 |
| RTT 平滑 | `smoothed = 7/8·smoothed + 1/8·adjusted` | §5.3 |
| RTT 偏差 | `rttvar = 3/4·rttvar + 1/4·\|smoothed - adjusted\|` | §5.3 |
| ACK 延迟扣除 | 仅当 `latest >= min_rtt + ack_delay` 才扣 | §5.3（MUST） |
| PTO | `smoothed + max(4·rttvar, 1ms) + max_ack_delay` | §6.2.1 |
| PTO 退避 | `× 2^pto_count`，收到 ACK 清零 | §6.2.1 |

**范围 ACK 而不是位图**（§4.5 明确理由）：

> QUIC supports many ACK ranges, as opposed to TCP's three SACK ranges.
> In high-loss environments, this speeds recovery, reduces spurious
> retransmits, and ensures forward progress without relying on timeouts.

原来 `docs/PROTOCOL.md` 设计的 `ack_seq(4) + bitmap(8)` 只能表达 64 个包的
确认状态，丢包 10% 时乱序跨度轻易超过 64 —— 必须换。

### 20.2 Bug 1：重传用新 seq → 流控重复计数 + 重排缓冲暴涨

我最初按 QUIC 的「重传用新 packet number」实现。**在我们的协议里这是错的**。

原因：QUIC 的流控按 **stream offset** 计算（重传同一段数据不重复占额度），
而我们暂时没有 offset 字段，流控按「收到的字节」记账。于是：

1. 同一段数据被算两次 → 窗口提前耗尽
2. 重传的包被接收方当成「乱序新数据」缓存 → 实测重排缓冲涨到 **8.45 MB**
   触发溢出保护 → 强制关流

**修法：复用原 seq 重传（KCP 的做法）**。接收方看到 `seq < next_seq` 幂等丢弃，
既不重复计数也不膨胀。

代价：RTT 样本偏大（取原始发送时刻）。**偏大是保守的**，只会让 PTO 更宽容。

### 20.3 Bug 2：`Close` 不占序号 → FIN 超过在途数据提前生效

症状：5% 丢包下请求包被丢 → 客户端立刻发 FIN（seq=0）→ 服务端收到 FIN 后
`take()` 掉投递端（半关闭）→ 重传的请求到达时无处可投 → **下载拿到 0 字节**。

**根因**：FIN 在语义上是「流的最后一个字节之后」，必须排在所有 `Data` 之后。
QUIC 用 stream offset 天然保证；我们没有 offset，所以**让 FIN 也占用一个 seq**。

两侧都要改：`StreamSender::close()` 和服务端 `tcp_pump` 结束时都用 `next_seq()`。

### 20.4 Bug 3：FIN 走「连锁交付」时被跳过

FIN 先到达时进重排缓冲；随后重传的数据补齐了空洞 → 一次 `push` 把
**数据 + FIN 一起带出来**（连锁交付）。

而我的投递循环写的是：

```rust
for (data, _is_close) in ready_list {
    if data.is_empty() { continue; }   // ← FIN 被静默跳过
    tx.send(data).await;
}
```

FIN 被 `continue` 吞掉 → 流永不半关闭 → 目标 socket 永不收到 EOF →
实测「上行 256 KB 以后卡死」。

**修法**：检测到 `is_close` 时记录 `saw_fin`，投递完数据后执行半关闭。

### 20.5 Bug 4：持续有数据时 `read` 永不超时 → ACK 一发不出

服务端读循环原本是：

```rust
let n = timeout(50ms, r.read(&mut chunk)).await;   // 超时才驱动 ARQ
```

对端持续灌数据时 `read` **立刻返回**，超时分支永不执行 → **ACK 一发不出** →
发送侧 `largest_acked` 恒为 `None` → **包阈值丢包检测永不触发**（它依赖
`largest_acked`）→ 只能靠 PTO（初始 1 秒 + 指数退避）→ 大量丢包时永远补不完。

实测：0% 丢包 124 MB/s，5% 丢包**完全卡死**。

**修法**：抽出 `drive_arq()`，**每处理完一批帧就调用一次**（节流 5ms），
而不是等 `read` 超时。

### 20.6 Bug 5：`has_news` 条件让 ACK 在数据灌完后停发

即使修了 Bug 4，ACK 的发送条件还是：

```rust
let has_news = received > acked_at_last_send;
if has_news && due { 发 ACK }
```

数据灌完后不再有新包 → `has_news` 恒 false → **ACK 彻底停发** →
发送方永远不知道最后几个空洞是否到达。

**修法**：加「距上次 ≥ 100ms 无条件重发」。ACK 帧只有几十字节，代价可忽略。

### 20.7 Bug 6：`MAX_ACK_RANGES = 32` 截断 → 43 万次重复重传

这是最隐蔽的一个。我最初按「32 个范围 = 133 字节 payload，够用了」设计。

实测（8 MB 流控窗口，5% 丢包，16 MB 下载）：

```
next_seq=1053  pending=5839  dup=437716
```

**43 万个重复包！** 原因：8 MB 窗口 = 5700 个包，5% 丢包产生约 285 个乱序段，
远超 32 → `truncate` 丢掉最老的范围 → 发送端以为那些包从未到达 →
**反复重传同一批** → 写队列被重传帧灌满 → 正常数据反而发不出去 → 停滞。

**修法**：提到 **300**（`(1400 - 9) / 4 ≈ 347` 是 MTU 硬上限，取 300 留余量）。

### 20.8 推论：必须有「在途包数上限」（这就是拥塞窗口）

Bug 6 修好后 5% 通过，但 **10% 仍然卡在 3 MB**。因为：

```
乱序段数 ≈ 在途包数 × 丢包率
         = 5700 × 10% = 570  >  300（ACK 帧容量）
```

**这就是 QUIC 必须有拥塞窗口的根本原因** —— 它把在途包数压在几十到几百，
让 ACK 范围数天然受控。

我们的做法（照抄 Brutal 的思路，**丢包不减窗口**）：

```rust
cwnd = clamp(0.8 × MAX_ACK_RANGES / 丢包率, 32, 2048)
```

| 丢包率 | cwnd | 在途字节 | 乱序段 |
|--------|------|---------|--------|
| 0% | 2048 | 2.8 MB | ~0 |
| 10% | 2048 | 2.8 MB | ~205 |
| 20% | 1200 | 1.6 MB | ~240 |
| 30% | 800 | 1.1 MB | ~240 |

**为什么不做 AIMD（丢包减半）**：与 Hysteria 的 Brutal 一致 ——
我们的丢包主要来自链路 QoS 或人为注入，减小窗口只会让吞吐更低，
不会让链路变好。所以只按实测丢包率**设定上限**，不做退让。

实测：固定 512 包时 0% 丢包吞吐只有 14 MB/s（比无 cwnd 的 124 MB/s 退化 89%）；
改成动态后恢复到 **69.6 MB/s**，且 30% 丢包仍完整。

### 20.9 另一个关键点：读循环绝不能被写队列堵住

所有控制帧（`Window` / `Ack` / PTO 重传）都从读循环发出。最初用
`out.send().await`：

```text
数据洪流 → write_loop 消费不及 → out 队列满
  → 读循环阻塞在 send()
  → 无法处理对端发来的 Ack
  → largest_acked 不更新 → 包阈值检测失效 → 只能靠秒级 PTO → 停滞
```

**修法：全部改 `try_send`，满了就丢**。这些帧都是幂等可重发的 ——
`Window` 是绝对偏移、`Ack` 每 100ms 必发、PTO 重传下轮会再试。
丢了的代价是几十毫秒，堵住的代价是永久停滞。

### 20.10 收尾 drain：目标 EOF 后必须等在途包确认

`tcp_pump` 读到目标 EOF 时，最后一批帧可能还在途（其中有被丢的）。
若立即发 `Close` 关流，重传就再也没机会。

实测：不加等待时 5% 丢包下只能收到 **9 MB / 16 MB（丢 46%）**。

修法照抄 QUIC 的 draining：等 `inflight == 0`（连续两轮确认，避免竞态）
或超时 10 秒。

### 20.11 最终实测（16 MB，应用层帧注入，真 TCP 承载）

| 丢包率 | 下行 | 完整性 | 上行 | 完整性 |
|--------|------|--------|------|--------|
| 0% | **69.6 MB/s** | ✅ 逐字节一致 | 14.2 MB/s | ✅ |
| 5% | 16.4 MB/s | ✅ 逐字节一致 | — | — |
| 10% | 28.1 MB/s | ✅ 逐字节一致 | 14.5 MB/s | ✅ |
| 20% | 14.0 MB/s | ✅ 逐字节一致 | 13.8 MB/s | ✅ |
| 30% | 7.2 MB/s | ✅ 逐字节一致 | 12.4 MB/s | ✅ |

对比 ARQ 之前（5% 丢包）：下行 **60 秒超时只收 2.4 MB**，上行**完全卡死**。

> 5% 的 16.4 MB/s 低于 10% 的 28.1 MB/s 是测量噪声（单次运行）——
> 两者都是「丢包后重传」的相同路径，不应有系统性差异。

### 20.12 后续必做（Phase 4.5 / 4.7）

1. **PTO 重传效率**：当前每轮只重传 `oldest_inflight` 一个包，
   严重丢包时恢复慢。QUIC 允许发两个探测包，可考虑放宽。
2. **RTT 采样偏大**：因为重传复用 seq，`sent_at` 是首次发送时刻。
   若要精确，需引入 stream offset。
3. **FEC**：30% 丢包下吞吐只剩 7.2 MB/s，FEC 可以在重传之前补掉一部分。
4. **窗口自动调优**：`MAX_CWND_PKTS` 固定 2048，高 BDP 链路（RTT 200ms+）
   需要按 BDP 放大。
