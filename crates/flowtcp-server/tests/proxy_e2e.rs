//! Phase 3 端到端：三种本地入口 × 真实 FlowTCP 隧道 × 真实目标
//!
//! # 这个测试文件验证什么
//!
//! 每个测试都完整跑一遍**用户真实使用的链路**，一个环节都不跳过：
//!
//! ```text
//! 标准客户端（手写 SOCKS5 / HTTP / TLS）
//!      ↓
//! flowtcp_client::entry（真实入口实现）
//!      ↓
//! Mux + Tunnel（真实记录层 + 真实自研 TLS 握手）
//!      ↓ 真 TCP 承载
//! flowtcp_server::handle_connection（真实裁决 + 真实出口）
//!      ↓
//! 真实目标服务（echo / UDP echo）
//! ```
//!
//! # 为什么用"手写标准客户端"而不是现成库
//!
//! SOCKS5 的报文格式本身就是设备无关的标准字节序列。手写客户端能：
//! - 精确控制每个字节，验证服务端的解析边界（如域名长度、IPv6 形式）
//! - 不引入额外依赖（保持测试编译快）
//! - 出问题时能一眼看出是哪一方的字节错了

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flowtcp_client::entry::socks5::bind as socks5_bind;
use flowtcp_client::entry::{http as http_entry, https as https_entry, socks5 as socks5_entry};
use flowtcp_client::Mux;
use flowtcp_proto::frame::Address;
use flowtcp_server::session::handle_connection;
use flowtcp_server::{ExitConfig, TargetPolicy};
use flowtcp_tls::mode::{FallbackAction, ServerMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const SNI: &str = "flowtcp.test";
const PASSWORD: &str = "phase3-e2e-password-0123456789";

fn now() -> u64 {
    flowtcp_tls::now_unix()
}

/// 测试用出口配置：允许内网（所有目标都在 127.0.0.1）。
fn exit_cfg() -> ExitConfig {
    ExitConfig {
        policy: TargetPolicy::AllowAll,
        ..Default::default()
    }
}

/// 起一个 TCP echo 服务器，返回其地址。
async fn spawn_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    addr
}

/// 起一个 UDP echo 服务器，返回其地址。
async fn spawn_udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// 起一个 UDP【大写转换】服务器，用于验证"发往不同目标"能区分。
async fn spawn_udp_upper() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let upper: Vec<u8> = buf[..n].to_ascii_uppercase();
            let _ = s.send_to(&upper, from).await;
        }
    });
    addr
}

/// 起一个 HTTP 服务器，把收到的请求行回显出去（用于验证 URI 改写）。
async fn spawn_http_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let Ok(n) = s.read(&mut buf).await else {
                    return;
                };
                // 把收到的第一行原样写回，测试据此断言改写结果
                let text = String::from_utf8_lossy(&buf[..n]);
                let first_line = text.lines().next().unwrap_or("").to_string();
                let body = format!("LINE:{first_line}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// 起一对「FlowTCP 服务端 + 已连好的客户端 Mux」。
///
/// 返回客户端的 `Mux`，以及服务端任务句柄。
async fn spawn_tunnel() -> (
    Arc<Mux>,
    tokio::task::JoinHandle<Result<flowtcp_server::session::Outcome, String>>,
) {
    let cfg = flowtcp_proto::steal::StealConfig::from_password(
        format!("{SNI}:443"), // 透传目标（本测试不走透传路径）
        vec![SNI.to_string()],
        PASSWORD,
    );
    let auth = cfg.auth.clone();
    let mode = ServerMode::Steal {
        config: cfg,
        fallback: FallbackAction::Close,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
        handle_connection(sock, &mode, &exit_cfg(), now())
            .await
            .map_err(|e| e.to_string())
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let tunnel = flowtcp_client::Tunnel::handshake_on(sock, SNI, &auth)
        .await
        .expect("隧道握手应成功");

    let mux = Arc::new(Mux::spawn(tunnel, 64, 1400));
    (mux, server_task)
}

/// 把 `SocketAddr` 转成协议里的 `Address`（测试目标都是 IPv4）。
fn as_addr(a: SocketAddr) -> Address {
    match a {
        SocketAddr::V4(v4) => Address::V4(v4),
        SocketAddr::V6(v6) => Address::V6(v6),
    }
}

// ============================================================================
// ① SOCKS5 TCP CONNECT
// ============================================================================

#[tokio::test]
async fn socks5_tcp_connect_echo往返() {
    let echo = spawn_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = socks5_bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(socks5_entry::serve_on(listener, Arc::clone(&mux), None));

    // ---- 标准 SOCKS5 客户端 ----
    let mut s = TcpStream::connect(proxy).await.unwrap();
    // 方法协商：只提供「无认证」
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "服务端应选择无认证");

    // CONNECT 请求
    let mut req = vec![0x05, 0x01, 0x00];
    as_addr(echo).encode(&mut req).unwrap();
    s.write_all(&req).await.unwrap();

    // 应答：05 00 00 ATYP ADDR PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "CONNECT 应成功");
    let mut tail = vec![0u8; if head[3] == 0x01 { 6 } else { 18 }];
    s.read_exact(&mut tail).await.unwrap();

    // 现在这条连接是纯管道
    let payload = b"\x00\x01\x02 binary safe \xff";
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
        .await
        .expect("应在超时内收到回显")
        .expect("读取不应失败");
    assert_eq!(&got, payload, "二进制内容必须原样回显");

    // 收尾顺序很重要：入口任务持有 Arc<Mux>，必须先 abort 才能释放隧道
    drop(s);
    entry.abort();
    drop(mux);
    let outcome = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .expect("服务端应结束")
        .unwrap()
        .unwrap();
    assert!(matches!(
        outcome,
        flowtcp_server::session::Outcome::Proxied { .. }
    ));
}

// ============================================================================
// ② SOCKS5 UDP ASSOCIATE
// ============================================================================

#[tokio::test]
async fn socks5_udp_associate_双向与切目标() {
    let echo = spawn_udp_echo().await;
    let upper = spawn_udp_upper().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = socks5_bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(socks5_entry::serve_on(listener, Arc::clone(&mux), None));

    // ---- TCP 控制连接：UDP ASSOCIATE ----
    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    ctrl.read_exact(&mut resp).await.unwrap();

    // 客户端声明的源地址（这里给 0.0.0.0:0，让服务端从首个包学习）
    let mut req = vec![0x05, 0x03, 0x00];
    Address::V4("0.0.0.0:0".parse().unwrap())
        .encode(&mut req)
        .unwrap();
    ctrl.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    ctrl.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "UDP ASSOCIATE 应成功");
    assert_eq!(head[3], 0x01, "BND 应为 IPv4");
    let mut bnd = [0u8; 6];
    ctrl.read_exact(&mut bnd).await.unwrap();
    let relay_ip = std::net::Ipv4Addr::new(bnd[0], bnd[1], bnd[2], bnd[3]);
    let relay_port = u16::from_be_bytes([bnd[4], bnd[5]]);
    let relay = SocketAddr::new(relay_ip.into(), relay_port);
    assert_eq!(relay_ip, std::net::Ipv4Addr::LOCALHOST, "中继应在本机");

    // ---- UDP 客户端 ----
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(relay).await.unwrap();

    // 组包：RSV(2) FRAG(1) ATYP ADDR PORT DATA
    let pack = |target: &Address, data: &[u8]| {
        let mut v = vec![0x00, 0x00, 0x00];
        target.encode(&mut v).unwrap();
        v.extend_from_slice(data);
        v
    };

    // ① 发往 echo
    udp.send(&pack(&as_addr(echo), b"udp-echo-1"))
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), udp.recv(&mut buf))
        .await
        .expect("应在超时内收到 UDP 回包")
        .unwrap();
    // 回包头部：RSV(2) FRAG(1) ATYP ADDR PORT
    let (_addr, used) = Address::decode(&buf[3..n]).unwrap();
    assert_eq!(&buf[3 + used..n], b"udp-echo-1", "UDP echo 应原样返回");

    // ② 同一个 UDP 关联切到另一个目标（验证 HAS_ADDR 切换）
    udp.send(&pack(&as_addr(upper), b"upper")).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(10), udp.recv(&mut buf))
        .await
        .expect("切目标后也应收到回包")
        .unwrap();
    let (_addr, used) = Address::decode(&buf[3..n]).unwrap();
    assert_eq!(&buf[3 + used..n], b"UPPER", "第二个目标应是不同服务");

    // ---- 关闭控制连接 = 结束 UDP 关联 ----
    drop(ctrl);
    drop(udp);
    entry.abort();
    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(15), server_task).await;
}

// ============================================================================
// ③ HTTP CONNECT 隧道
// ============================================================================

#[tokio::test]
async fn http_connect建立隧道() {
    let echo = spawn_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = http_entry::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(http_entry::serve_on(listener, Arc::clone(&mux), None));

    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req =
        format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\nProxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();

    // 读应答头
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut one).await.unwrap();
        head.push(one[0]);
        assert!(head.len() < 4096, "应答头异常长");
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 200"), "实际应答: {text}");

    // 隧道建立后是纯管道
    s.write_all(b"tunnel-data").await.unwrap();
    let mut got = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
        .await
        .expect("应在超时内收到回显")
        .unwrap();
    assert_eq!(&got, b"tunnel-data");

    drop(s);
    entry.abort();
    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(15), server_task).await;
}

// ============================================================================
// ④ HTTP 绝对 URI：请求行必须被改写成 origin-form
// ============================================================================

#[tokio::test]
async fn http绝对uri被改写为origin_form() {
    let target = spawn_http_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = http_entry::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(http_entry::serve_on(listener, Arc::clone(&mux), None));

    let mut s = TcpStream::connect(proxy).await.unwrap();
    // 绝对 URI 形式（浏览器走明文 HTTP 时就是这样发的）
    let req = format!(
        "GET http://{target}/some/path?q=1 HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut resp))
        .await
        .expect("应在超时内收到响应")
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("LINE:GET /some/path?q=1 HTTP/1.1"),
        "请求行必须被改写成 origin-form，实际响应: {text}"
    );
    assert!(
        !text.contains("http://"),
        "改写后不应残留绝对 URI，实际: {text}"
    );

    entry.abort();
    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(15), server_task).await;
}

// ============================================================================
// ⑤ HTTPS 入口（默认自签证书 + 本地 TLS 终止）
// ============================================================================

#[tokio::test]
async fn https入口默认自签证书可用() {
    let echo = spawn_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = https_entry::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let proxy = listener.local_addr().unwrap();
    // 证书生成在任务内进行：`HttpsCert` 是借用参数，不能跨越 spawn 边界
    let cert = flowtcp_client::HttpsCert::default();
    let mux_for_entry = Arc::clone(&mux);
    let entry =
        tokio::spawn(
            async move { https_entry::serve_on(listener, mux_for_entry, &cert, None).await },
        );

    // ---- 本地 TLS 客户端（信任自签，因为这是本机链路）----
    let mut connector = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
    connector.set_verify(boring::ssl::SslVerifyMode::NONE);
    connector.set_alpn_protos(b"\x08http/1.1").ok();
    let connector = connector.build();

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let config = connector.configure().unwrap();
    let mut tls = tokio_boring::connect(config, "localhost", tcp)
        .await
        .expect("本地 TLS 握手应成功（默认自签证书）");

    // 走 CONNECT
    let req = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut one).await.unwrap();
        head.push(one[0]);
        assert!(head.len() < 4096);
    }
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
        "HTTPS 入口的 CONNECT 应成功"
    );

    tls.write_all(b"secure-tunnel").await.unwrap();
    let mut got = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut got))
        .await
        .expect("应在超时内收到回显")
        .unwrap();
    assert_eq!(&got, b"secure-tunnel");

    drop(tls);
    entry.abort();
    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(15), server_task).await;
}

// ============================================================================
// ⑥ 并发多流：一条隧道同时承载多条本地连接
// ============================================================================

#[tokio::test]
async fn 单隧道并发多流互不干扰() {
    let echo = spawn_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = socks5_bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(socks5_entry::serve_on(listener, Arc::clone(&mux), None));

    // 并发 8 条连接，各自 echo 不同内容
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        tasks.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(proxy).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            s.read_exact(&mut resp).await.unwrap();

            let mut req = vec![0x05, 0x01, 0x00];
            as_addr(echo).encode(&mut req).unwrap();
            s.write_all(&req).await.unwrap();
            let mut head = [0u8; 10];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], 0x00);

            let payload = vec![i; 200];
            s.write_all(&payload).await.unwrap();
            let mut got = vec![0u8; 200];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload, "流 {i} 的数据被串到了别的流");
            i
        }));
    }

    let mut done = Vec::new();
    for t in tasks {
        done.push(
            tokio::time::timeout(Duration::from_secs(20), t)
                .await
                .expect("并发流应在超时内完成")
                .unwrap(),
        );
    }
    done.sort_unstable();
    assert_eq!(done, (0..8u8).collect::<Vec<_>>());

    assert!(mux.total_opened() >= 8, "应至少开过 8 条流");

    entry.abort();
    drop(mux);
    let outcome = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .expect("服务端应结束")
        .unwrap()
        .unwrap();
    if let flowtcp_server::session::Outcome::Proxied { stats, .. } = outcome {
        assert_eq!(stats.streams_opened, 8, "服务端应看到 8 条流");
    } else {
        panic!("应为 Proxied");
    }
}

// ============================================================================
// ⑦ 目标被策略拒绝时，客户端必须明确感知失败
// ============================================================================

#[tokio::test]
async fn 目标被策略拒绝时流被重置() {
    // 这个测试故意用 DenyPrivate，验证"内网目标被拒"
    let cfg = flowtcp_proto::steal::StealConfig::from_password(
        format!("{SNI}:443"),
        vec![SNI.to_string()],
        PASSWORD,
    );
    let auth = cfg.auth.clone();
    let mode = ServerMode::Steal {
        config: cfg,
        fallback: FallbackAction::Close,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let deny_cfg = ExitConfig {
        policy: TargetPolicy::DenyPrivate,
        ..Default::default()
    };
    let server_task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle_connection(sock, &mode, &deny_cfg, now())
            .await
            .unwrap()
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let tunnel = flowtcp_client::Tunnel::handshake_on(sock, SNI, &auth)
        .await
        .unwrap();
    let mux = Mux::spawn(tunnel, 8, 1400);

    // 目标 127.0.0.1 属于环回 → DenyPrivate 应拒绝
    let mut handle = mux
        .open_tcp(Address::V4("127.0.0.1:80".parse().unwrap()))
        .await
        .unwrap();

    // 服务端应回 Close（非 FIN）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let f = tokio::time::timeout_at(deadline, handle.receiver.recv())
        .await
        .expect("应收到拒绝通知")
        .expect("通道不应关闭");
    assert_eq!(
        f.frame_type,
        flowtcp_proto::frame::FrameType::Close,
        "应收到 Close 帧"
    );
    assert!(!f.is_fin(), "拒绝应表现为 RST（不带 FIN）");

    // handle 内部持有发送通道，drop 后写任务才会结束 → 服务端读到 EOF
    drop(handle);
    drop(mux);
    let outcome = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .expect("服务端应结束")
        .unwrap();
    if let flowtcp_server::session::Outcome::Proxied { stats, .. } = outcome {
        assert_eq!(stats.denied, 1, "应记录 1 次策略拒绝");
    } else {
        panic!("应为 Proxied");
    }
}

// ============================================================================
// ⑧ 域名目标：服务端解析并连接
// ============================================================================

#[tokio::test]
async fn 域名目标由服务端解析() {
    let echo = spawn_echo().await;
    let (mux, server_task) = spawn_tunnel().await;

    let listener = socks5_bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let entry = tokio::spawn(socks5_entry::serve_on(listener, Arc::clone(&mux), None));

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();

    // 用「域名」形式指定目标：localhost:echo_port
    //
    // # 这里刻意保留 `localhost`（而不是换成 127.0.0.1）
    //
    // 它在不同机器的 /etc/hosts 里解析结果不同：
    //   - 本地：只有 `127.0.0.1 localhost`
    //   - GitHub runner：还有 `::1 localhost`（同时给出 v6 与 v4）
    //
    // 而 echo 只监听 127.0.0.1。所以这个测试**顺带覆盖了
    // 「多地址且首个不可用」的回退逻辑** —— 正是线上最常见的场景
    // （域名有 AAAA 但 IPv6 不通）。
    //
    // 历史上这里挂过一次 CI：早期 `resolve_addr` 只取第一个地址，
    // 在 runner 上拿到 `::1` 连不上，e2e 报 `early eof`。
    // 该缺陷已由 `connect_happy_eyeballs` 修复。
    let mut req = vec![0x05, 0x01, 0x00];
    Address::Domain("localhost".into(), echo.port())
        .encode(&mut req)
        .unwrap();
    s.write_all(&req).await.unwrap();
    let mut head = [0u8; 10];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "域名目标应能解析并连接");

    s.write_all(b"domain-ok").await.unwrap();
    let mut got = [0u8; 9];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"domain-ok");

    drop(s);
    entry.abort();
    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(15), server_task).await;
}

// ============================================================================
// ⑨ ★ 大数据量完整性：这类缺陷只有真跑大流量才暴露
// ============================================================================

/// 下行大流量：目标 → 客户端方向的字节必须**完全一致**。
///
/// # 这个测试守住三个曾真实发生过的静默丢数据 bug
///
/// 1. **服务端 `write_loop` 用 `let _ = encode()` 吞掉错误**
///    读缓冲 32KB 直接当单帧 payload，而帧上限 16KB → 超限帧被静默跳过。
///    症状：下载 16MB 只到 32KB。
/// 2. **`write_loop` 批量合并时 `try_recv()` 后 `break`**
///    帧已被取出队列，`break` 后永久丢失。
///    症状：16MB 只到 15.4MB，内容错位。
/// 3. **`pump` 用 `select!` 任一侧结束就取消另一侧**
///    浏览器半关闭写端后响应被掐断。
///
/// 三者都**不产生任何错误日志**，只能靠字节比对发现。因此这个测试
/// 必须比对完整内容，不能只比对长度。
#[tokio::test]
async fn 下行大流量字节完全一致() {
    // 2MB 足以跨越多次 16KB 记录、多次 read、多个 32KB 缓冲边界
    const SIZE: usize = 2 * 1024 * 1024;

    // 用确定性伪随机填充（便于定位首次不一致的偏移）
    let payload: Vec<u8> = (0..SIZE)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
        .collect();
    let expect = payload.clone();

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else {
            return;
        };
        // 一次性写出全部数据，然后关闭 → 与真实文件下载形态一致
        let _ = s.write_all(&payload).await;
        let _ = s.shutdown().await;
    });

    let (mux, server_task) = spawn_tunnel().await;
    let handle = mux.open_tcp(as_addr(addr)).await.expect("开流失败");
    let (tx, mut rx) = handle.split();

    // 客户端只读不写，但保持连接（读到 Close 为止）
    let _ = tx.close(false).await;

    let mut got = Vec::with_capacity(SIZE);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let f = match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(f)) => f,
            Ok(None) => break, // 通道关闭
            Err(_) => panic!("应在 30s 内收完 {SIZE} 字节，实际只收到 {}", got.len()),
        };
        match f.frame_type {
            flowtcp_proto::frame::FrameType::Data => got.extend_from_slice(&f.payload),
            flowtcp_proto::frame::FrameType::Close => break,
            _ => {}
        }
    }

    assert_eq!(
        got.len(),
        SIZE,
        "字节数不一致：期望 {SIZE}，实际 {}（丢了 {}）",
        got.len(),
        SIZE - got.len()
    );
    // 定位首个不一致偏移，便于排查
    if let Some(pos) = got.iter().zip(expect.iter()).position(|(a, b)| a != b) {
        panic!(
            "首个不一致位于偏移 {pos}：期望 {:#04x}，实际 {:#04x}",
            expect[pos], got[pos]
        );
    }

    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(10), server_task).await;
}

/// 上行大流量：客户端 → 目标方向的字节必须**完全一致**。
///
/// 守住「服务端 `try_send` 队列满就丢弃」这个 bug：
/// 它让上传 64MB 只到达 29MB（丢 57%），而客户端 `sendall` 全部成功返回，
/// 完全无感知。TCP 是可靠字节流，任何丢弃都是数据损坏。
#[tokio::test]
async fn 上行大流量字节完全一致() {
    const SIZE: usize = 2 * 1024 * 1024;

    // 目标端：把收到的全部数据回传给测试（通过 oneshot）
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else {
            return;
        };
        let mut buf = Vec::with_capacity(SIZE);
        let mut chunk = vec![0u8; 32 * 1024];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let _ = done_tx.send(buf);
    });

    let (mux, server_task) = spawn_tunnel().await;
    let handle = mux.open_tcp(as_addr(addr)).await.expect("开流失败");
    let (mut tx, _rx) = handle.split();

    let payload: Vec<u8> = (0..SIZE)
        .map(|i| (i.wrapping_mul(17) ^ (i >> 7)) as u8)
        .collect();
    let expect = payload.clone();

    // 分块写入，模拟真实 uploader（一次 32KB）
    for chunk in payload.chunks(32 * 1024) {
        tx.send_data(chunk).await.expect("发送失败");
    }
    tx.close(true).await.ok();
    drop(tx);

    let got = tokio::time::timeout(Duration::from_secs(30), done_rx)
        .await
        .expect("目标端应在 30s 内收完并回报")
        .expect("回报通道不应断开");

    assert_eq!(
        got.len(),
        SIZE,
        "上行字节数不一致：期望 {SIZE}，实际 {}（丢了 {}）",
        got.len(),
        SIZE - got.len()
    );
    if let Some(pos) = got.iter().zip(expect.iter()).position(|(a, b)| a != b) {
        panic!(
            "首个不一致位于偏移 {pos}：期望 {:#04x}，实际 {:#04x}",
            expect[pos], got[pos]
        );
    }

    drop(mux);
    let _ = tokio::time::timeout(Duration::from_secs(10), server_task).await;
}
