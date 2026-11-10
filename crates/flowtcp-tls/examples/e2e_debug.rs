//! 双向调试：打印客户端与服务端的真实错误
use std::io::{Read, Write};
use std::time::Duration;

fn main() {
    let c = rcgen::generate_simple_self_signed(vec!["flowtcp.test".to_string()]).unwrap();
    let dir = std::env::temp_dir().join("flowtcp-dbg");
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("c.pem");
    let key = dir.join("k.pem");
    std::fs::write(&cert, c.cert.pem()).unwrap();
    std::fs::write(&key, c.key_pair.serialize_pem()).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // 服务端线程
    let (cert2, key2) = (cert.clone(), key.clone());
    let h = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut acc =
            boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())
                .unwrap();
        acc.set_certificate_chain_file(&cert2).unwrap();
        acc.set_private_key_file(&key2, boring::ssl::SslFiletype::PEM)
            .unwrap();
        acc.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
            .unwrap();
        acc.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
        let acc = acc.build();
        eprintln!("[服务端] 开始握手...");
        match acc.accept(sock) {
            Ok(mut tls) => {
                eprintln!(
                    "[服务端] ✅ 握手成功 alpn={:?} ver={:?}",
                    tls.ssl().selected_alpn_protocol(),
                    tls.ssl().version_str()
                );
                tls.write_all(b"OK").ok();
                tls.flush().ok();
                let mut b = [0u8; 64];
                let n = tls.read(&mut b).unwrap_or(0);
                eprintln!("[服务端] 收到 {} 字节", n);
            }
            Err(e) => eprintln!("[服务端] ❌ 失败: {e}"),
        }
    });

    // 客户端
    let rt = tokio::runtime::Runtime::new().unwrap();
    let r = rt.block_on(async {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(15),
            flowtcp_tls::tls13_client::handshake(
                &mut s,
                "flowtcp.test",
                &flowtcp_proto::steal::AuthKey::from_password("flowtcp-e2e-test-password"),
            ),
        )
        .await
    });
    match r {
        Ok(Ok(hs)) => eprintln!(
            "[客户端] ✅ 握手成功 alpn={:?} cert={}B exporter={:02x?}",
            hs.alpn.as_deref().map(String::from_utf8_lossy),
            hs.server_cert.len(),
            &hs.exporter[..4]
        ),
        Ok(Err(e)) => eprintln!("[客户端] ❌ {e}"),
        Err(_) => eprintln!("[客户端] ❌ 超时"),
    }
    h.join().ok();
}
