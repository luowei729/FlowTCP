//! `flowtcp client` 子命令

use std::sync::Arc;

use flowtcp_client::config::HttpsCert;
use flowtcp_client::entry;
use flowtcp_client::{ClientConfig, Mux, TcpTransport, Transport, Tunnel};
use flowtcp_proto::steal::AuthKey;

use crate::args::Args;

/// 本地入口单条连接采用的单帧上限。
///
/// 取 MTU 1500 对应的 1400 字节：这是 FakeTCP 承载下的最终形态。
/// Phase 3 即便走真 TCP 也保持相同值，避免"测试通过但上 FakeTCP 就出问题"。
const MAX_PAYLOAD: usize = 1400;

/// 运行客户端。
pub async fn run(args: &Args) -> Result<(), String> {
    let remote = args.addr("remote")?;
    let password = args.need("password")?;
    let sni = args.need("sni")?;

    // ---- 入口 ----
    let socks5 = args.opt_addr("socks5")?;
    let http = args.opt_addr("http")?;
    let https = args.opt_addr("https")?;
    if socks5.is_none() && http.is_none() && https.is_none() {
        return Err("至少指定一个入口：--socks5 / --http / --https".into());
    }

    // ---- HTTPS 入口证书（默认自签，可指定）----
    let https_cert = match (args.get("cert"), args.get("key")) {
        (Some(cert), Some(key)) => {
            tracing::info!(%cert, %key, "HTTPS 入口使用指定证书");
            HttpsCert::Files {
                cert_path: cert.into(),
                key_path: key.into(),
            }
        }
        (None, None) => {
            tracing::info!("HTTPS 入口使用自签证书（首次连接浏览器会提示，需手动信任）");
            HttpsCert::default()
        }
        _ => {
            return Err("--cert 与 --key 必须同时提供（或都不提供以使用自签证书）".into());
        }
    };

    let mut cfg = ClientConfig::new(remote, sni, AuthKey::from_password(password));
    cfg.entries.socks5 = socks5;
    cfg.entries.http = http;
    cfg.entries.https = https;
    cfg.https_cert = https_cert;
    if let Some(n) = args.u16_of("max-streams")? {
        cfg.max_streams = n;
    }
    if let Some(secs) = args.u64_of("connect-timeout")? {
        cfg.connect_timeout = std::time::Duration::from_secs(secs);
    }
    cfg.validate()?;

    // ---- 建立隧道 ----
    let transport = TcpTransport::new(remote).with_timeout(cfg.connect_timeout);
    tracing::info!(%remote, %sni, "正在建立 FlowTCP 隧道…");
    let tunnel = Tunnel::handshake_on(
        Transport::connect(&transport, sni)
            .await
            .map_err(|e| format!("连接 {remote} 失败: {e}"))?,
        sni,
        &cfg.auth,
    )
    .await
    .map_err(|e| format!("隧道握手失败: {e}"))?;

    tracing::info!(
        alpn = ?tunnel.alpn.as_deref().map(String::from_utf8_lossy),
        exporter = %tunnel.exporter_fingerprint(),
        "隧道已建立"
    );

    // 单流窗口：默认 8 MB（对齐 hy2 的 initStreamReceiveWindow）。
    // **必须与服务端一致**，否则隐式初始信用会错位。
    let stream_window = args
        .bytes_of("stream-window")?
        .unwrap_or(flowtcp_proto::flow::DEFAULT_STREAM_WINDOW);
    let mux = Arc::new(Mux::spawn_with_window(
        tunnel,
        cfg.max_streams,
        MAX_PAYLOAD,
        stream_window,
    ));

    println!("FlowTCP 客户端已就绪：");
    if let Some(a) = cfg.entries.socks5 {
        println!("  SOCKS5  socks://{a}   (TCP CONNECT + UDP ASSOCIATE)");
    }
    if let Some(a) = cfg.entries.http {
        println!("  HTTP    http://{a}");
    }
    if let Some(a) = cfg.entries.https {
        println!("  HTTPS   https://{a}  (默认自签证书，浏览器需信任一次)");
    }
    println!();
    println!("按 Ctrl+C 退出。");

    // 入口任务是无限循环；Ctrl+C 由运行时统一取消
    entry::run_all(mux, cfg)
        .await
        .map_err(|e| format!("入口运行失败: {e}"))
}

/// `client --help` 文本。
pub fn help() -> &'static str {
    "\
flowtcp client —— 启动 FlowTCP 客户端（本地代理入口）

用法:
  flowtcp client --remote <ADDR> --password <PASSWORD> --sni <NAME> <入口选项>

必填:
  --remote <ADDR>        服务端地址，如 1.2.3.4:443
  --password <PASSWORD>  与服务端共享的密码
  --sni <NAME>           必须与服务端 --target 的域名一致

入口（至少一个）:
  --socks5 <ADDR>        SOCKS5 入口，如 127.0.0.1:1080（TCP + UDP）
  --http <ADDR>          HTTP 代理入口，如 127.0.0.1:8080
  --https <ADDR>         HTTPS 代理入口，如 127.0.0.1:8443

HTTPS 入口证书:
  （默认）               启动时生成自签证书（有效期 10 年）
  --cert <PATH>          改用指定的证书 PEM（需同时给 --key）
  --key <PATH>           指定的私钥 PEM

其他:
  --max-streams <N>      单隧道最大并发流数，默认 256
  --stream-window <SIZE> 单流流控窗口，默认 8M（支持 512K / 8M / 16M）
                         **必须与服务端一致**。高延迟链路调大，
                         小内存设备调小（如 2M）
  --connect-timeout <S>  连接服务端超时秒数，默认 10

示例:
  # 只用 SOCKS5（最常用）
  flowtcp client --remote 1.2.3.4:443 --password 'my-secret' \\
      --sni www.microsoft.com --socks5 127.0.0.1:1080

  # 同时开三个入口，HTTPS 用自己的证书
  flowtcp client --remote 1.2.3.4:443 --password 'my-secret' \\
      --sni www.microsoft.com \\
      --socks5 127.0.0.1:1080 --http 127.0.0.1:8080 --https 127.0.0.1:8443 \\
      --cert ./proxy.crt --key ./proxy.key
"
}
