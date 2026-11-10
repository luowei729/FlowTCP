//! 运行时网络自动配置：[`TUN`] 设备 + iptables 规则
//!
//! # 为什么必须自动化
//!
//! FakeTCP 用 raw socket 在用户态实现 TCP 栈，这意味着内核**不知道**这条连接存在。
//! 要让真实客户端（curl / 浏览器 / 扫描器）能连上，必须在启动时完成一整套网络准备：
//!
//! ```text
//! 真实 TCP SYN → 内核 netfilter → DNAT 到 TUN peer → 用户态 fake-tcp 收包
//!                                       ↓
//!            用户态回包 → TUN → 内核 → SNAT 成公网 IP → 客户端
//! ```
//!
//! 手动执行这套命令极易出错且不可重复，因此内置为 `flowtcp server` 的启动步骤。
//!
//! # 六个必须踩对的点（全部经过实测验证）
//!
//! | # | 要点 | 不做的后果 |
//! |---|------|-----------|
//! | 1 | `rp_filter` 设为 0 | 反向路径过滤会丢弃来自 TUN 的伪源地址包，表现为「握手成功但收不到数据」 |
//! | 2 | DNAT 同时配 `PREROUTING` 与 `OUTPUT` | 本机发起的连接走 OUTPUT 链，只配 PREROUTING 会导致本机测试直接 RST |
//! | 3 | **绝不能加 `NOTRACK`** | NAT 依赖 conntrack；`raw -j NOTRACK` 会让 DNAT 完全失效（实测踩过） |
//! | 4 | 规则用 `-I` 插到链首 | Docker 等环境会在 PREROUTING 前插入自己的链，`-A` 追加可能永远匹配不到 |
//! | 5 | 回程需 SNAT 成公网 IP | 否则客户端收到源地址为 `192.168.x.x` 的包，直接丢弃 |
//! | 6 | 清理时按精确规则删除 | 粗暴 `-F` 会破坏用户其他防火墙规则 |
//!
//! # 幂等性
//!
//! 每次 `apply()` 前用 `iptables -C` 检查规则是否已存在，避免重复插入造成规则堆积
//! （反复重启 100 次 = 100 条重复规则，转发性能线性下降）。

use std::net::Ipv4Addr;
use std::process::Command;

use thiserror::Error;

/// 网络配置参数。
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// 对外监听端口。可任意指定（不必是 443），只要防火墙放行。
    pub port: u16,
    /// TUN 设备上本端地址（内核侧）。
    pub tun_local: Ipv4Addr,
    /// TUN 设备上对端地址（FakeTCP 用户态栈侧），DNAT 的目标。
    pub tun_peer: Ipv4Addr,
    /// 本机对外暴露的公网/内网 IP。`None` 表示自动探测默认路由源地址。
    pub public_ip: Option<Ipv4Addr>,
    /// TUN 设备名。空字符串表示由内核分配（`tun0`、`tun1`…）。
    pub tun_name: String,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            port: 443,
            tun_local: Ipv4Addr::new(192, 168, 201, 1),
            tun_peer: Ipv4Addr::new(192, 168, 201, 2),
            public_ip: None,
            tun_name: String::new(),
        }
    }
}

impl NetConfig {
    /// 用指定端口创建配置。
    pub fn with_port(port: u16) -> Self {
        NetConfig {
            port,
            ..Default::default()
        }
    }
}

/// 一条 iptables 规则（表 + 链 + 规则参数），用于幂等增删。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    table: &'static str,
    chain: &'static str,
    /// 规则参数（不含 -t/-A/-C/-D 等动作）。
    spec: Vec<String>,
}

impl Rule {
    fn new(table: &'static str, chain: &'static str, spec: &[&str]) -> Self {
        Rule {
            table,
            chain,
            spec: spec.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 检查规则是否存在。
    fn exists(&self) -> Result<bool, NetError> {
        let mut args = vec!["-t", self.table, "-C", self.chain];
        args.extend(self.spec.iter().map(String::as_str));
        let out = run_iptables(&args)?;
        Ok(out)
    }

    /// 幂等插入到链首（`-I` 而非 `-A`，理由见模块文档第 4 点）。
    fn ensure(&self) -> Result<bool, NetError> {
        if self.exists()? {
            return Ok(false); // 已存在，无需重复添加
        }
        let mut args = vec!["-t", self.table, "-I", self.chain];
        args.extend(self.spec.iter().map(String::as_str));
        run_iptables(&args)?;
        Ok(true)
    }

    /// 删除规则（不存在则忽略）。
    fn remove(&self) -> Result<bool, NetError> {
        if !self.exists()? {
            return Ok(false);
        }
        let mut args = vec!["-t", self.table, "-D", self.chain];
        args.extend(self.spec.iter().map(String::as_str));
        run_iptables(&args)?;
        Ok(true)
    }
}

/// 运行 iptables，返回是否成功（不因非零退出而报错，便于 `-C` 检查）。
fn run_iptables(args: &[&str]) -> Result<bool, NetError> {
    let out = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|e| NetError::Spawn {
            cmd: format!("iptables {}", args.join(" ")),
            source: e,
        })?;
    if out.status.success() {
        return Ok(true);
    }
    // `-C` 未找到规则时返回非零，这是**正常**语义，不算错误。
    // 其他情况才把 stderr 一并报出，便于定位权限/语法问题。
    if args.contains(&"-C") {
        return Ok(false);
    }
    Err(NetError::Command {
        cmd: format!("iptables {}", args.join(" ")),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

/// 执行一条 sysctl 写入（例如把 rp_filter 设为 0）。
fn sysctl_write(key: &str, value: &str) -> Result<(), NetError> {
    let out = Command::new("sysctl")
        .args(["-w", &format!("{key}={value}")])
        .output()
        .map_err(|e| NetError::Spawn {
            cmd: format!("sysctl -w {key}={value}"),
            source: e,
        })?;
    if !out.status.success() {
        return Err(NetError::Command {
            cmd: format!("sysctl -w {key}={value}"),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// 读取 sysctl 当前值。
fn sysctl_read(key: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/{}", key.replace('.', "/")))
        .ok()
        .map(|s| s.trim().to_string())
}

/// 通过默认路由探测本机对外 IP。
///
/// 为什么不用 `hostname -I`：多网卡机器会返回全部地址，无法判断哪个是公网出口。
/// 用 `ip route get 8.8.8.8` 能精确得到「去往公网时内核选用的源地址」。
fn detect_public_ip() -> Result<Ipv4Addr, NetError> {
    let out = Command::new("ip")
        .args(["route", "get", "8.8.8.8"])
        .output()
        .map_err(|e| NetError::Spawn {
            cmd: "ip route get 8.8.8.8".into(),
            source: e,
        })?;
    if !out.status.success() {
        return Err(NetError::PublicIpDetect(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // 输出形如：`8.8.8.8 via 10.0.0.1 dev eth0 src 203.0.113.7 uid 0`
    for (i, tok) in text.split_whitespace().enumerate() {
        if tok == "src" {
            if let Some(v) = text.split_whitespace().nth(i + 1) {
                return v
                    .parse()
                    .map_err(|_| NetError::PublicIpDetect(v.to_string()));
            }
        }
    }
    Err(NetError::PublicIpDetect(format!(
        "解析失败: {}",
        text.trim()
    )))
}

/// 创建 TUN 设备（多队列，队列数 = CPU 核数）。
///
/// 为什么用多队列：fake-tcp 的 `Stack::new` 会为每个 Tun 起一个 reader task，
/// 多队列可让多个核心并行处理收包，单队列在万兆场景会成为瓶颈。
pub fn create_tun(cfg: &NetConfig, num_queues: usize) -> Result<Vec<tokio_tun::Tun>, NetError> {
    let tun = tokio_tun::TunBuilder::new()
        .name(&cfg.tun_name)
        .up()
        .address(std::net::IpAddr::V4(cfg.tun_local), 24)
        .destination(std::net::IpAddr::V4(cfg.tun_peer))
        .mtu(1500)
        .queues(num_queues.max(1))
        .build()
        .map_err(|e| NetError::TunCreate(e.to_string()))?;
    if tun.is_empty() {
        return Err(NetError::TunCreate("内核未返回任何队列".into()));
    }
    Ok(tun)
}

/// 已应用的网络配置句柄，用于后续清理。
///
/// 用 RAII 风格的显式句柄（而非 `Drop`）：
/// 清理需要 root 权限并可能失败，`Drop` 里吞掉错误会让排查变困难。
pub struct AppliedConfig {
    rules: Vec<Rule>,
    /// 需要恢复的 sysctl 原值（key, 原值）。
    sysctl_restore: Vec<(String, String)>,
    /// TUN 设备名（用于提示，实际删除由 Tun drop 完成）。
    pub tun_name: String,
    /// 已探测/指定的本机对外 IP（SNAT 目标）。
    pub public_ip: Ipv4Addr,
}

impl AppliedConfig {
    /// 生成全部所需规则。
    fn build_rules(port: u16, tun_peer: Ipv4Addr, public_ip: Ipv4Addr) -> Vec<Rule> {
        let port_s = port.to_string();
        let peer_s = tun_peer.to_string();
        vec![
            // ---- 1) 外部进来的连接：DNAT 到 TUN peer ----
            // 排在 nat PREROUTING 链首，确保先于 Docker 等自定义链命中。
            Rule::new(
                "nat",
                "PREROUTING",
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    &port_s,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{peer_s}:{port_s}"),
                ],
            ),
            // ---- 2) 本机发起的连接：同样 DNAT ----
            // 本机进程（含自测 curl）产生的包走 OUTPUT 链而非 PREROUTING，
            // 漏掉这条会导致「外部能连、本机不能连」的诡异现象。
            Rule::new(
                "nat",
                "OUTPUT",
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    &port_s,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{peer_s}:{port_s}"),
                ],
            ),
            // ---- 3) 回程：把 TUN peer 的源地址 SNAT 成公网 IP ----
            // 不做这一步，客户端会收到源 IP 为 192.168.x.x 的包并直接丢弃。
            Rule::new(
                "nat",
                "POSTROUTING",
                &[
                    "-p",
                    "tcp",
                    "-s",
                    &peer_s,
                    "--sport",
                    &port_s,
                    "-j",
                    "SNAT",
                    "--to-source",
                    &public_ip.to_string(),
                ],
            ),
        ]
    }

    /// 应用全部配置（幂等）。
    pub fn apply(cfg: &NetConfig) -> Result<Self, NetError> {
        let public_ip = match cfg.public_ip {
            Some(ip) => ip,
            None => detect_public_ip()?,
        };

        // ---- 步骤 1：关闭 rp_filter ----
        // 反向路径过滤会检查「源地址是否可经该接口回去」，
        // TUN 上的伪源地址必然通不过检查，包被丢弃。
        // 这是最难排查的坑：握手看起来成功，但数据收不到。
        let mut sysctl_restore = Vec::new();
        for key in [
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.tun0.rp_filter",
        ] {
            if let Some(old) = sysctl_read(key) {
                if old != "0" {
                    sysctl_write(key, "0")?;
                    // all.* 无法逐项还原（会影响新接口），只在退出时记录提示
                    if !key.starts_with("net.ipv4.conf.all") {
                        sysctl_restore.push((key.to_string(), old));
                    }
                }
            }
        }

        // ---- 步骤 2：DNAT / SNAT 规则 ----
        let rules = Self::build_rules(cfg.port, cfg.tun_peer, public_ip);
        let mut applied = Vec::new();
        for r in &rules {
            match r.ensure() {
                Ok(true) => {
                    tracing::info!(table = r.table, chain = r.chain, "已添加 iptables 规则");
                    applied.push(r.clone());
                }
                Ok(false) => {
                    tracing::debug!(table = r.table, chain = r.chain, "规则已存在，跳过");
                    applied.push(r.clone());
                }
                Err(e) => {
                    // 中途失败要把已加的规则回滚，避免留下半套配置
                    for done in applied.iter().rev() {
                        let _ = done.remove();
                    }
                    return Err(e);
                }
            }
        }

        tracing::info!(
            port = cfg.port,
            public_ip = %public_ip,
            tun_peer = %cfg.tun_peer,
            "网络配置完成：外部 TCP:{port} → TUN {peer} → 用户态 FakeTCP",
            port = cfg.port,
            peer = cfg.tun_peer
        );

        Ok(AppliedConfig {
            rules: applied,
            sysctl_restore,
            tun_name: cfg.tun_name.clone(),
            public_ip,
        })
    }

    /// 清理配置。
    pub fn cleanup(&self) {
        for r in self.rules.iter().rev() {
            match r.remove() {
                Ok(true) => {
                    tracing::info!(table = r.table, chain = r.chain, "已删除 iptables 规则")
                }
                Ok(false) => {}
                Err(e) => tracing::warn!(%e, "删除规则失败"),
            }
        }
        for (k, v) in &self.sysctl_restore {
            if let Err(e) = sysctl_write(k, v) {
                tracing::warn!(%e, key = %k, "恢复 sysctl 失败");
            }
        }
    }

    /// 打印配置摘要（供 `flowtcp doctor` / 日志使用）。
    pub fn summary(&self) -> String {
        format!(
            "TUN={} 公网IP={} 规则数={}",
            if self.tun_name.is_empty() {
                "<内核分配>"
            } else {
                &self.tun_name
            },
            self.public_ip,
            self.rules.len()
        )
    }
}

/// 网络配置错误。
#[derive(Debug, Error)]
pub enum NetError {
    /// 外部命令启动失败（多半是命令不存在）。
    #[error("无法执行 `{cmd}`: {source}（请确认 iptables / ip 命令已安装）")]
    Spawn {
        /// 命令
        cmd: String,
        /// 底层错误
        source: std::io::Error,
    },
    /// 外部命令执行失败。
    #[error("命令失败 `{cmd}`: {stderr}（需要 root 或 CAP_NET_ADMIN）")]
    Command {
        /// 命令
        cmd: String,
        /// 标准错误
        stderr: String,
    },
    /// 无法探测公网 IP。
    #[error("无法探测本机对外 IP: {0}（请显式指定 public_ip）")]
    PublicIpDetect(String),
    /// TUN 创建失败。
    #[error("创建 TUN 设备失败: {0}（检查 /dev/net/tun 与 CAP_NET_ADMIN）")]
    TunCreate(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规则参数拼接必须精确，否则 -C 检查与 -D 删除都会失配。
    #[test]
    fn 规则spec构造正确() {
        let rules = AppliedConfig::build_rules(
            8443,
            Ipv4Addr::new(192, 168, 201, 2),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].table, "nat");
        assert_eq!(rules[0].chain, "PREROUTING");
        assert_eq!(
            rules[0].spec,
            vec![
                "-p",
                "tcp",
                "--dport",
                "8443",
                "-j",
                "DNAT",
                "--to-destination",
                "192.168.201.2:8443"
            ]
        );

        // 必须有 OUTPUT 链（本机连接）
        assert_eq!(rules[1].chain, "OUTPUT");

        assert_eq!(rules[2].chain, "POSTROUTING");
        assert_eq!(
            rules[2].spec,
            vec![
                "-p",
                "tcp",
                "-s",
                "192.168.201.2",
                "--sport",
                "8443",
                "-j",
                "SNAT",
                "--to-source",
                "203.0.113.7"
            ]
        );
    }

    /// 端口可自定义（不硬编码 443）。
    #[test]
    fn 端口可自定义() {
        for port in [443u16, 8443, 2053, 65535] {
            let rules = AppliedConfig::build_rules(
                port,
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(198, 51, 100, 1),
            );
            let p = port.to_string();
            assert!(rules[0].spec.contains(&p));
            assert!(rules[2].spec.contains(&p));
        }
    }

    /// 默认配置使用 443，但结构上允许任意值。
    #[test]
    fn 默认配置() {
        let cfg = NetConfig::default();
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.tun_local, Ipv4Addr::new(192, 168, 201, 1));
        assert_eq!(cfg.tun_peer, Ipv4Addr::new(192, 168, 201, 2));

        let cfg2 = NetConfig::with_port(2053);
        assert_eq!(cfg2.port, 2053);
        assert_eq!(cfg2.tun_peer, cfg.tun_peer);
    }

    /// 规则中绝不能出现 NOTRACK（会让 DNAT 失效，实测踩过）。
    #[test]
    fn 不得包含notrack规则() {
        let rules = AppliedConfig::build_rules(
            443,
            Ipv4Addr::new(192, 168, 201, 2),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        for r in &rules {
            assert_ne!(r.table, "raw", "不得在 raw 表添加规则");
            assert!(
                !r.spec.iter().any(|s| s.contains("NOTRACK")),
                "NOTRACK 会绕过 conntrack 导致 DNAT 失效"
            );
        }
    }
}
