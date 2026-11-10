//! 偷网站流程的端到端集成测试
//!
//! # 验证目标
//!
//! 这组测试证明「抗主动探测」在真实 TCP 栈上成立：
//!
//! | 场景 | 期望行为 | 探测者看到 |
//! |------|---------|-----------|
//! | 普通浏览器 / 扫描器 | 透传给真实网站 | 真实网站的 TLS 会话 |
//! | FlowTCP 客户端 | 临时证书完成握手 | 我们的代理服务 |
//!
//! # 为什么必须真跑 TCP + 真 TLS
//!
//! 单元测试只能验证逻辑。这里有两个只有真跑才暴露的问题：
//! 1. ClientHello 跨 TCP 段（真实 Chrome 常拆成两个段）
//! 2. 判定阶段读走的字节必须完整还给下游，缺一个就握手失败

use std::time::Duration;

use flowtcp_proto::steal::AuthKey;
use flowtcp_server::session::{handle_connection, Outcome};
use flowtcp_tls::mode::{FallbackAction, ServerMode};
use flowtcp_tls::{FingerprintConfig, InjectPlan, InjectingStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SNI: &str = "flowtcp.test";
const PASSWORD: &str = "e2e-test-password-0123456789";

fn now() -> u64 {
    flowtcp_tls::now_unix()
}

/// 测试用出口配置：允许访问环回（测试的目标 echo 服务都在 127.0.0.1）。
///
/// 生产默认是 `DenyPrivate`（防 SSRF），这里必须显式放开。
fn exit_cfg() -> flowtcp_server::ExitConfig {
    flowtcp_server::ExitConfig {
        policy: flowtcp_server::TargetPolicy::AllowAll,
        ..Default::default()
    }
}

/// 构造偷网站模式的服务端配置。
fn steal_mode(fallback: FallbackAction) -> ServerMode {
    let (cfg, _pubkey) = StealConfigForTest::build();
    ServerMode::Steal {
        config: cfg,
        fallback,
    }
}

/// 测试用的配置构造封装。
struct StealConfigForTest;

impl StealConfigForTest {
    fn build() -> (flowtcp_proto::steal::StealConfig, [u8; 32]) {
        let cfg = flowtcp_proto::steal::StealConfig::from_password(
            format!("{SNI}:443"),
            vec![SNI.to_string()],
            PASSWORD,
        );
        // 对称方案不再需要公钥；保留返回值以兼容旧调用点
        (cfg, [0u8; 32])
    }
}

/// 生成一张模拟"真实网站"的证书，返回 (DER, cert_pem, key_pem)。
fn make_site_cert() -> (Vec<u8>, String, String) {
    let c = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let der = c.cert.der().to_vec();
    (der, c.cert.pem(), c.key_pair.serialize_pem())
}

/// 启动一个 mock "真实网站"（TLS 服务器），返回其地址与证书 DER。
async fn spawn_mock_site() -> (std::net::SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (der, cert_pem, key_pem) = make_site_cert();
    let der2 = der.clone();

    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let cfg = flowtcp_tls::ServerTlsConfig::from_pem(cert_pem, key_pem);
        if let Ok(mut hs) = flowtcp_tls::accept(sock, &cfg).await {
            let _ = hs.stream.write_all(b"SITE-OK").await;
            let _ = hs.stream.flush().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    (addr, der2, task)
}

/// ★ 场景 1：普通浏览器（无票据）必须被透传到真实网站。
#[tokio::test]
async fn 普通浏览器被透传到真实网站() {
    let (site_addr, site_cert_der, site_task) = spawn_mock_site().await;

    let mode = steal_mode(FallbackAction::ForwardToSite {
        target: site_addr.to_string(),
        proxy_protocol: None,
    });

    let our_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let our_addr = our_listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (sock, _) = our_listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    // 客户端：普通浏览器（用 BoringSSL 但**不注入票据**）
    let client_sock = TcpStream::connect(our_addr).await.unwrap();
    let fp = FingerprintConfig::chrome().danger_accept_invalid_certs();
    let hs = flowtcp_tls::connect(client_sock, SNI, &fp).await;

    // 客户端应看到 mock 网站的证书（证明透传生效，而非我们的临时证书）
    if let Ok(hs) = hs {
        if let Some(cert) = hs.stream.ssl().peer_certificate() {
            let got = cert.to_der().unwrap();
            assert_eq!(got, site_cert_der, "客户端应看到真实网站的证书");
        }
    }

    let outcome = tokio::time::timeout(Duration::from_secs(6), server_task)
        .await
        .expect("服务端应在超时内完成")
        .unwrap()
        .unwrap();

    assert!(
        matches!(outcome, Outcome::Forwarded { .. }),
        "普通浏览器必须被透传，实际: {outcome:?}"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), site_task).await;
}

/// ★★★ 场景 2（核心）：票据认证 + 完整数据面往返。
///
/// # Phase 3 的最终验收
///
/// 这个测试跑通整条链路，且**用的就是生产代码路径**（客户端的
/// `Tunnel` + `Mux`，服务端的 `handle_connection` + `exit`）：
///
/// ```text
/// ① 客户端定 client_random → 算 HMAC 票据 → 填进 ClientHello.session_id
/// ② 服务端 parse_client_hello → judge() → 票据匹配 → Accept
/// ③ 服务端签临时证书 → BoringSSL 握手 → 取回裸流
/// ④ 客户端自研 TLS 1.3 握手 → exporter 派生记录层密钥
/// ⑤ 客户端 OpenTcp(echo 地址) → 服务端连目标 → 双向搬运
/// ⑥ 客户端发 "hello" → echo 回 "hello" → 客户端收到
/// ⑦ 关闭流 → 服务端返回 Proxied
/// ```
///
/// 任何一环出错（票据、密钥、帧边界、流生命周期）都会让第 ⑥ 步失败。
#[tokio::test]
async fn 认证客户端完成完整数据面往返() {
    // ---- 起一个 echo 服务器作为"目标网站" ----
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
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

    // ---- 起 FlowTCP 服务端 ----
    let (cfg, _) = StealConfigForTest::build();
    let auth: AuthKey = cfg.auth.clone();
    let mode = ServerMode::Steal {
        config: cfg,
        // 必须成功：若被误判为失败会关闭连接，测试立即失败
        fallback: FallbackAction::Close,
    };

    let our_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let our_addr = our_listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (sock, _) = our_listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    // ---- 客户端：自研 TLS 1.3 握手 ----
    let sock = TcpStream::connect(our_addr).await.unwrap();
    let tunnel = tokio::time::timeout(
        Duration::from_secs(12),
        flowtcp_client::Tunnel::handshake_on(sock, SNI, &auth),
    )
    .await
    .expect("客户端握手不应超时")
    .expect("认证通过时应完成握手");

    // 客户端能拿到 exporter，说明 TLS 密钥链路完整
    assert!(
        !tunnel.exporter_fingerprint().is_empty(),
        "exporter 应已派生"
    );

    let mux = flowtcp_client::Mux::spawn(tunnel, 8, 1400);
    let mut handle = mux
        .open_tcp(flowtcp_proto::frame::Address::V4(match echo_addr {
            std::net::SocketAddr::V4(v4) => v4,
            other => panic!("echo 应为 IPv4: {other}"),
        }))
        .await
        .expect("开流不应失败");

    // ---- 数据往返 ----
    handle
        .sender
        .send_data(b"hello-flowtcp")
        .await
        .expect("发送不应失败");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut got = Vec::new();
    while got.len() < 13 {
        let f = tokio::time::timeout_at(deadline, handle.receiver.recv())
            .await
            .expect("应在超时内收到回显")
            .expect("通道不应关闭");
        if f.frame_type == flowtcp_proto::frame::FrameType::Data {
            got.extend_from_slice(&f.payload);
        }
    }
    assert_eq!(&got, b"hello-flowtcp", "echo 回显必须完全一致");

    // ---- 关闭 ----
    //
    // 必须显式 drop `mux`：只 drop handle 只是关掉**这条流**，
    // 隧道本身还开着，服务端的读循环会一直等数据。
    // drop(mux) → 写任务收到通道关闭 → shutdown 底层写半 → 服务端读到 EOF。
    handle.sender.close(true).await.ok();
    drop(handle);
    drop(mux);

    let outcome = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .expect("服务端应在超时内完成")
        .unwrap()
        .expect("服务端不应出错");

    match outcome {
        Outcome::Proxied { stats, .. } => {
            assert_eq!(stats.streams_opened, 1, "应打开 1 条流");
            assert!(
                stats.bytes_up >= 13,
                "上行字节数应 ≥13，实际 {}",
                stats.bytes_up
            );
            assert!(
                stats.bytes_down >= 13,
                "下行字节数应 ≥13，实际 {}",
                stats.bytes_down
            );
            assert_eq!(stats.denied, 0, "AllowAll 策略下不应有拒绝");
        }
        other => panic!("认证客户端应走代理路径，实际: {other:?}"),
    }
}

/// 场景 2b：临时证书必须能由共享密钥派生的公钥验证。
///
/// 与 2 的区别：这个测试专注证书本身，不做数据往返。
#[tokio::test]
async fn 临时证书可用派生公钥验证() {
    let (cfg, _) = StealConfigForTest::build();
    let auth: AuthKey = cfg.auth.clone();
    let mode = ServerMode::Steal {
        config: cfg,
        fallback: FallbackAction::Close,
    };

    let our_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let our_addr = our_listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (sock, _) = our_listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    let sock = TcpStream::connect(our_addr).await.unwrap();
    let hs = tokio::time::timeout(
        Duration::from_secs(12),
        flowtcp_tls::tls13_client::handshake(&mut { sock }, SNI, &auth),
    )
    .await
    .expect("不应超时")
    .expect("握手应成功");

    // client_random 就是 exporter_context 的前 32 字节
    let client_random: [u8; 32] = hs.exporter_context[..32].try_into().unwrap();
    let seed = auth.cert_seed(&client_random);

    assert_eq!(
        flowtcp_tls::verify_temp_cert(&hs.server_cert, &seed).unwrap(),
        flowtcp_tls::CertVerdict::Trusted,
        "服务端临时证书必须能由共享密钥派生的公钥验证"
    );

    // 服务端会因为客户端不发数据而等到隧道关闭
    drop(server_task);
}

/// 场景 3：非 TLS 数据（HTTP 探测）必须被优雅关闭，不得返回自定义响应。
#[tokio::test]
async fn http探测被优雅关闭() {
    let mode = steal_mode(FallbackAction::Close);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("服务端应快速返回")
        .unwrap()
        .unwrap();

    assert!(
        matches!(outcome, Outcome::Closed { .. }),
        "HTTP 探测应被关闭，实际: {outcome:?}"
    );

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
        .await
        .map(|r| r.unwrap_or(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "关闭前不得返回任何自定义响应（否则自曝）");
}

/// 场景 4：只建连不发数据，必须在超时后关闭。
#[tokio::test]
async fn 只建连不说话被超时关闭() {
    let mode = steal_mode(FallbackAction::Close);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    let _sock = TcpStream::connect(addr).await.unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .expect("应在 ClientHello 超时后返回")
        .unwrap()
        .unwrap();

    assert!(
        matches!(outcome, Outcome::Closed { .. }),
        "静默连接应被关闭，实际: {outcome:?}"
    );
}

/// 场景 5：错误密码的客户端必须被拒绝（转发或关闭，不能认证通过）。
#[tokio::test]
async fn 错误密码被拒绝() {
    let mode = steal_mode(FallbackAction::Close);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle_connection(sock, &mode, &exit_cfg(), now()).await
    });

    let client_sock = TcpStream::connect(addr).await.unwrap();
    let plan = InjectPlan {
        auth: AuthKey::from_password("wrong-password"),
        now_unix: now(),
    };
    let injecting = InjectingStream::new(client_sock, plan);
    let fp = FingerprintConfig::chrome().danger_accept_invalid_certs();
    // 握手必然失败（服务端关闭连接）
    let _ = tokio::time::timeout(
        Duration::from_secs(12),
        flowtcp_tls::connect(injecting, SNI, &fp),
    )
    .await;

    let outcome = tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .expect("服务端应在超时内完成")
        .unwrap()
        .unwrap();

    assert!(
        !matches!(outcome, Outcome::Proxied { .. }),
        "错误密码不得通过认证，实际: {outcome:?}"
    );
}
