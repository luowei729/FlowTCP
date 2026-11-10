//! `flowtcp server` 子命令

use std::time::Duration;

use flowtcp_proto::steal::StealConfig;
use flowtcp_server::{ExitConfig, ServerConfig, TargetPolicy};
use flowtcp_tls::mode::{FallbackAction, ServerMode};
use tokio::sync::watch;

use crate::args::Args;

/// 运行服务端。
pub async fn run(args: &Args) -> Result<(), String> {
    let listen = args.addr("listen")?;
    let password = args.need("password")?;

    // ---- 构造运行模式 ----
    //
    // 两种模式二选一：
    // - 给了 `--cert` + `--key` → 自有证书（OwnCert）
    // - 否则必须给 `--target` → 偷网站（Steal，推荐）
    let mode = if let Some(cert) = args.get("cert") {
        let key = args.get("key").ok_or("使用 --cert 时必须同时提供 --key")?;
        let fallback = match args.get("fallback-http") {
            Some(addr) => FallbackAction::LocalHttp {
                addr: addr.to_string(),
            },
            None => FallbackAction::Close,
        };
        tracing::info!(%cert, %key, "自有证书模式");
        ServerMode::OwnCert {
            cert_path: cert.into(),
            key_path: key.into(),
            fallback,
        }
    } else {
        let target = args
            .need("target")
            .map_err(|_| "缺少 --target（偷网站目标，如 www.microsoft.com:443），或用 --cert/--key 走自有证书模式".to_string())?;
        // SNI 默认取 target 的主机部分（target 是 host:port 形式）
        let default_sni = target
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(target)
            .to_string();
        let sni = args.get("sni").unwrap_or(&default_sni).to_string();

        tracing::info!(%target, %sni, "偷网站模式（认证失败将透传给真实网站）");
        ServerMode::steal(StealConfig::from_password(
            target.to_string(),
            vec![sni],
            password,
        ))
    };

    // ---- 出口配置 ----
    let allow_private = args.has_flag("allow-private");
    if allow_private {
        tracing::warn!(
            "已关闭目标策略（--allow-private）：任何持有密码的人都能访问你的内网，\
             仅应在完全可信的环境中使用"
        );
    }
    let exit = ExitConfig {
        policy: if allow_private {
            TargetPolicy::AllowAll
        } else {
            TargetPolicy::DenyPrivate
        },
        max_streams: args.u16_of("max-streams")?.unwrap_or(256),
        max_payload: flowtcp_proto::max_payload_for_mtu(1500),
        connect_timeout: Duration::from_secs(args.u64_of("connect-timeout")?.unwrap_or(10)),
        // 单流窗口：默认 8 MB（对齐 hy2 的 initStreamReceiveWindow）。
        // **客户端必须用同一个值**，否则隐式初始信用会错位。
        stream_window: args
            .bytes_of("stream-window")?
            .unwrap_or(flowtcp_proto::flow::DEFAULT_STREAM_WINDOW),
    };

    let mut cfg = ServerConfig::new(listen, mode);
    cfg.exit = exit;
    if let Some(secs) = args.u64_of("idle-timeout")? {
        cfg.idle_timeout = Duration::from_secs(secs);
    }

    // ---- 优雅退出 ----
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = tx.send(true);
        }
    });

    let stats = flowtcp_server::run(cfg, rx)
        .await
        .map_err(|e| format!("服务端启动失败: {e}"))?;

    let (accepted, proxied, forwarded, closed, errored) = stats.snapshot();
    println!();
    println!("服务端已退出。统计：");
    println!("  接受连接   {accepted}");
    println!("  代理成功   {proxied}");
    println!("  透传网站   {forwarded}");
    println!("  直接关闭   {closed}");
    println!("  处理出错   {errored}");
    Ok(())
}

/// `server --help` 文本。
pub fn help() -> &'static str {
    "\
flowtcp server —— 启动 FlowTCP 服务端

用法:
  flowtcp server --listen <ADDR> --password <PASSWORD> <模式选项>

模式（二选一）:
  --target <HOST:PORT>   偷网站目标（推荐）。认证失败的连接会被原样透传给该网站，
                         探测者看到的是真实网站的完整 TLS 会话
  --cert <PATH>          自有证书模式的证书链 PEM（需同时给 --key）
  --key <PATH>           自有证书模式的私钥 PEM

常用选项:
  --listen <ADDR>        监听地址，如 0.0.0.0:443（必填）
  --password <PASSWORD>  与服务端共享的密码（必填，决定票据与临时证书）
  --sni <NAME>           允许的 SNI，默认取 --target 的主机名
  --allow-private        允许访问内网/环回（默认拒绝，防内网扫描）
  --max-streams <N>      单连接最大并发流数，默认 256
  --stream-window <SIZE> 单流流控窗口，默认 8M（支持 512K / 8M / 16M）
                         **客户端必须用同一个值**。高延迟链路调大，
                         小内存设备调小（如 2M）
  --idle-timeout <SECS>  会话最长存活秒数，默认 300
  --connect-timeout <S>  连接目标超时秒数，默认 10
  --fallback-http <ADDR> 自有证书模式下认证失败时转到的本地 HTTP 服务

示例:
  # 偷网站模式（无域名、无证书）
  flowtcp server --listen 0.0.0.0:443 --password 'my-secret' \\
      --target www.microsoft.com:443

  # 自有证书模式
  flowtcp server --listen 0.0.0.0:443 --password 'my-secret' \\
      --cert /etc/flowtcp/fullchain.pem --key /etc/flowtcp/privkey.pem
"
}
