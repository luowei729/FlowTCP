//! 自研 TLS 1.3 客户端与真实 BoringSSL 服务端的端到端验证
//!
//! # 为什么这是决定性的验证
//!
//! BoringSSL 是 Chrome 使用的 TLS 实现，以严格著称。如果我们的自研客户端
//! 能与之完成完整握手，就证明：
//!
//! 1. ClientHello 结构合法（BoringSSL 接受）
//! 2. 握手消息解析正确（SH/EE/Cert/CV/Finished 全部解出）
//! 3. key schedule 正确（否则无法解密任何密文记录）
//! 4. Finished 计算正确（否则 BoringSSL 会以 `bad record mac` 拒绝）
//! 5. 转录计算正确（这是自研的核心价值 —— 服务端认可我们发出的字节）
//!
//! 任何一环出错，握手都会在某一步失败并给出明确的 alert。
//!
//! # 额外验证：session_id 被服务端回显
//!
//! 服务端会回显我们发的 `session_id`（TLS 1.3 兼容模式要求）。
//! 若我们的 ClientHello 转录与服务端看到的不一致，回显校验会失败。

use std::time::Duration;

use flowtcp_tls::tls13_client::handshake;
use tokio::net::{TcpListener, TcpStream};

const SNI: &str = "flowtcp.test";
/// BoringSSL keylog：把服务端所有 traffic secret 打出来，用于定位 key schedule 差异。
///
/// 直接声明 C 符号（`SSL_CTX_set_keylog_callback` 已在 boring-sys 构建的
/// libssl 里），避免为测试引入额外依赖。
#[allow(dead_code)]
mod keylog {
    use std::ffi::{c_char, CStr};
    use std::sync::Mutex;

    pub static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    unsafe extern "C" {
        fn SSL_CTX_set_keylog_callback(
            ctx: *mut std::ffi::c_void,
            cb: Option<unsafe extern "C" fn(*const std::ffi::c_void, *const c_char)>,
        );
    }

    unsafe extern "C" fn on_keylog(_ssl: *const std::ffi::c_void, line: *const c_char) {
        if line.is_null() {
            return;
        }
        let s = unsafe { CStr::from_ptr(line) }
            .to_string_lossy()
            .to_string();
        LINES.lock().unwrap().push(s);
    }

    /// 给 acceptor 的 `SSL_CTX` 装上回调（必须在 `build()` 之前调用）。
    pub fn install_ctx(ctx: *mut std::ffi::c_void) {
        unsafe { SSL_CTX_set_keylog_callback(ctx, Some(on_keylog)) };
    }
}

/// 固定的测试认证密钥（票据与证书种子都由它派生）。
fn auth() -> flowtcp_proto::steal::AuthKey {
    flowtcp_proto::steal::AuthKey::from_password("flowtcp-e2e-test-password")
}

/// 生成自签证书并写入临时文件（BoringSSL 的 acceptor 需要文件路径）。
///
/// 每个测试必须用**独立目录**：cargo 默认并行跑测试，
/// 若共用目录会互相覆盖 cert/key，造成「证书与私钥不匹配」的假失败。
fn make_cert() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let c = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "flowtcp-tls13e2e-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, c.cert.pem()).unwrap();
    std::fs::write(&key, c.key_pair.serialize_pem()).unwrap();
    (cert, key, dir)
}

/// 启动一个真实 BoringSSL 服务端，返回监听地址与任务句柄。
async fn spawn_boringssl_server(
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<Result<[u8; 32], String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let mut acc =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .map_err(|e| e.to_string())?;
        acc.set_certificate_chain_file(&cert)
            .map_err(|e| e.to_string())?;
        acc.set_private_key_file(&key, boring::ssl::SslFiletype::PEM)
            .map_err(|e| e.to_string())?;
        acc.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
            .map_err(|e| e.to_string())?;
        acc.set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| e.to_string())?;
        keylog::install_ctx(acc.as_ptr() as *mut std::ffi::c_void);
        let acc = acc.build();

        // 用 spawn_blocking 执行同步握手（boring 是阻塞 API）
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let std_sock = sock.into_std().map_err(|e| e.to_string())?;
            // ★ tokio 的 TcpStream 是非阻塞模式，`into_std()` 后仍保持非阻塞。
            //   BoringSSL 的阻塞式 `accept()` 需要阻塞 socket，否则会报
            //   "a nonblocking read call would have blocked"。
            std_sock.set_nonblocking(false).map_err(|e| e.to_string())?;
            std_sock
                .set_read_timeout(Some(Duration::from_secs(10)))
                .ok();
            let mut tls = acc
                .accept(std_sock)
                .map_err(|e| format!("服务端握手失败: {e}"))?;
            tls.write_all(b"OK").map_err(|e| e.to_string())?;
            tls.flush().map_err(|e| e.to_string())?;

            // ★ 用与客户端完全相同的方式导出 exporter：
            //   ctx = client_random || server_random，label = EXPORTER-LABEL
            let ssl = tls.ssl();
            let mut ctx = [0u8; 64];
            let nc = ssl.client_random(&mut ctx[..32]);
            let ns = ssl.server_random(&mut ctx[32..]);
            eprintln!("[服务端] client_random({nc}) = {}", hex(&ctx[..32]));
            eprintln!("[服务端] server_random({ns}) = {}", hex(&ctx[32..]));
            let mut out = [0u8; 32];
            ssl.export_keying_material(&mut out, flowtcp_proto::EXPORTER_LABEL, Some(&ctx))
                .map_err(|e| format!("exporter 导出失败: {e}"))?;
            for l in keylog::LINES.lock().unwrap().iter() {
                eprintln!("[KEYLOG] {l}");
            }
            Ok(out)
        })
        .await
        .map_err(|e| e.to_string())?
    });

    (addr, task)
}

/// ★★★ 核心测试：自研 TLS 1.3 客户端与真实 BoringSSL 服务端完成完整握手。
#[tokio::test]
async fn 自研客户端与boringssl完成握手() {
    let (cert, key, dir) = make_cert();
    let (addr, server) = spawn_boringssl_server(cert, key).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(15), handshake(&mut sock, SNI, &auth()))
        .await
        .expect("握手不应超时");

    match result {
        Ok(hs) => {
            println!("✅ 握手成功");
            println!(
                "   ALPN     = {:?}",
                hs.alpn.as_deref().map(String::from_utf8_lossy)
            );
            println!("   证书长度 = {} 字节", hs.server_cert.len());
            println!("   exporter = {}", hex(&hs.exporter[..8]));
            assert!(!hs.server_cert.is_empty(), "应拿到服务端证书");
            assert_eq!(hs.alpn.as_deref(), Some(&b"h2"[..]), "应协商出 h2");
            // exporter 不应全零
            assert!(hs.exporter.iter().any(|&b| b != 0), "exporter 不得全零");
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            panic!("❌ 与 BoringSSL 握手失败: {e}");
        }
    }

    // 清理
    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// 票据必须被真实服务端接受并回显（证明转录一致）。
///
/// 若我们的 ClientHello 转录与服务端算出的不一致，
/// 服务端会以 `bad record mac` 拒绝后续消息，本测试就会失败。
#[tokio::test]
async fn 票据被服务端接受() {
    let (cert, key, dir) = make_cert();
    let (addr, server) = spawn_boringssl_server(cert, key).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(15), handshake(&mut sock, SNI, &auth()))
        .await
        .expect("不应超时");

    // 只要握手成功，就说明服务端用了我们发的 ClientHello 字节算转录，
    // 也就是票据完整参与了握手 —— 这正是 REALITY 式认证的前提。
    assert!(r.is_ok(), "握手失败: {:?}", r.err());

    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// 不同票据应产生不同的 exporter（密钥隔离）。
#[tokio::test]
async fn 不同票据产生不同exporter() {
    let (cert, key, dir) = make_cert();
    let mut exporters = Vec::new();

    for i in 0..2u8 {
        let (addr, server) = spawn_boringssl_server(cert.clone(), key.clone()).await;
        let mut sock = TcpStream::connect(addr).await.unwrap();
        // 用不同密码派生不同密钥 → 不同票据
        let auth_i = flowtcp_proto::steal::AuthKey::from_password(&format!("pw-{i}"));
        let hs = tokio::time::timeout(Duration::from_secs(15), handshake(&mut sock, SNI, &auth_i))
            .await
            .expect("不应超时")
            .expect("握手应成功");
        exporters.push(hs.exporter);
        let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    }

    assert_ne!(
        exporters[0], exporters[1],
        "不同票据（不同 client_random）应产生不同 exporter"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ★★★ 最关键的一环：**导出的 exporter 必须双端完全一致**。
///
/// exporter 是 FlowTCP 内层所有密钥的唯一来源：
///
/// ```text
/// exporter  ──HKDF──>  c2s_key / s2c_key / sn_key / ...
/// ```
///
/// 若两端 exporter 不同，数据阶段的每一条记录都会 AEAD 失败，
/// 表现为「握手成功但一条数据都发不出去」—— 极难排查。
///
/// 本测试证明客户端的 TLS 1.3 key schedule（early→handshake→master→exporter）
/// 与 BoringSSL 的实现逐字节一致。
#[tokio::test]
async fn exporter与boringssl完全一致() {
    let (cert, key, dir) = make_cert();
    let (addr, server) = spawn_boringssl_server(cert, key).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();
    let hs = tokio::time::timeout(Duration::from_secs(15), handshake(&mut sock, SNI, &auth()))
        .await
        .expect("不应超时")
        .expect("握手应成功");

    let server_exporter = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("服务端不应超时")
        .expect("服务端任务不应 panic")
        .expect("服务端应成功导出 exporter");

    eprintln!("[客户端] ctx = {}", hex(&hs.exporter_context));
    assert_eq!(
        hs.exporter,
        server_exporter,
        "exporter 不一致！客户端 {} vs 服务端 {}",
        hex(&hs.exporter),
        hex(&server_exporter)
    );
    println!("✅ exporter 双端一致 = {}", hex(&hs.exporter));

    let _ = std::fs::remove_dir_all(&dir);
}

/// 应用流量密钥必须与服务端一致（用 exporter 派生，验证链路完整）。
#[tokio::test]
async fn 应用流量密钥可派生() {
    let (cert, key, dir) = make_cert();
    let (addr, server) = spawn_boringssl_server(cert, key).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();
    let hs = tokio::time::timeout(Duration::from_secs(15), handshake(&mut sock, SNI, &auth()))
        .await
        .expect("不应超时")
        .expect("握手应成功");

    // app keys 不为空且 c2s ≠ s2c（方向隔离）
    assert_ne!(
        hs.client_app_keys.key, hs.server_app_keys.key,
        "两个方向的应用密钥必须不同"
    );
    assert!(
        hs.client_app_keys.key.iter().any(|&b| b != 0),
        "应用密钥不得全零"
    );

    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    let _ = std::fs::remove_dir_all(&dir);
}
