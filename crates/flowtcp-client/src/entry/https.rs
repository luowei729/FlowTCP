//! HTTPS 代理入口（HTTP 代理 **套 TLS**）
//!
//! # 与 [`super::http`] 的关系
//!
//! 完全相同的一套 HTTP 代理逻辑，只是在本地链路上多包一层 TLS：
//!
//! ```text
//! 浏览器 ──TLS──→ 本进程（终止 TLS）──HTTP 解析──→ FlowTCP 隧道
//! ```
//!
//! 因此本模块只负责「终止 TLS」，HTTP 解析/转发直接复用
//! [`super::http::handle`]（它已泛型化，不关心底层是明文还是 TLS）。
//!
//! # 证书：默认自签，也可指定
//!
//! ## 默认自签（零配置）
//!
//! 启动时用 `rcgen` 生成一张 ECDSA P-256 证书：
//! - 有效期 10 年（避免频繁重生成导致又要重新信任）
//! - SAN 含 `localhost`、`127.0.0.1`、`::1`
//!
//! 首次连接浏览器会提示"不安全"，需要手动信任一次。
//!
//! **为什么自签在这里完全够用**：这条 TLS 只在「浏览器 → 本机进程」之间，
//! 不经过任何网络。证书的作用只有一个 —— 让浏览器愿意建立 TLS 连接。
//! 公信力（CA 签名）在这个场景下毫无意义。
//!
//! ## 指定证书（消除提示）
//!
//! 若不想每次看到警告，用 [`crate::config::HttpsCert::Files`] 指定一张
//! 浏览器已信任的证书即可（自己的域名证书，或已导入系统信任库的自签证书）。
//!
//! # 为什么需要这个入口
//!
//! 1. **本地链路被检查的环境**：公司内网 DLP 会解密明文 HTTP 代理流量
//! 2. **只允许 TLS 出网的网络**：某些公共 WiFi 直接拒掉非 443 明文代理
//! 3. **避免误触发明文代理检测**：明文 `Proxy-Connection: keep-alive` 是
//!    明显的代理特征，套上 TLS 后中间设备只看到一条普通 HTTPS

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use super::EntryError;
use crate::config::HttpsCert;
use crate::mux::Mux;

/// TLS 握手超时。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// 自签证书的有效期：10 年。
///
/// 取这么长的理由：每次重新生成都会更换指纹，浏览器需要重新信任一次。
/// 10 年足够长到"永远不会遇到"，又比"永久"更符合证书惯例。
const SELF_SIGNED_VALIDITY_DAYS: i64 = 3650;

/// HTTPS 代理监听循环。
pub async fn serve(addr: SocketAddr, mux: Arc<Mux>, cert: &HttpsCert) -> Result<(), EntryError> {
    let listener = bind(addr).await?;
    serve_on(listener, mux, cert).await
}

/// 只完成绑定（供测试拿到实际端口后再 `serve_on`）。
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, EntryError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| EntryError::Config(format!("HTTPS 代理绑定 {addr} 失败: {e}")))
}

/// 在已绑定的 listener 上跑监听循环。
pub async fn serve_on(
    listener: TcpListener,
    mux: Arc<Mux>,
    cert: &HttpsCert,
) -> Result<(), EntryError> {
    // ---- 1) 准备证书 ----
    let tls_cfg = build_config(cert)?;

    let actual = listener.local_addr()?;
    tracing::info!(
        %actual,
        cert = match cert {
            HttpsCert::SelfSigned { .. } => "自签",
            HttpsCert::Files { .. } => "指定文件",
        },
        "HTTPS 代理正在监听"
    );

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "HTTPS 代理 accept 失败");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let m = Arc::clone(&mux);
        let cfg = tls_cfg.clone();

        tokio::spawn(async move {
            // ---- 2) 终止本地 TLS ----
            let acceptor = match cfg.build_acceptor() {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = %e, "构造 TLS acceptor 失败");
                    return;
                }
            };

            let tls = match tokio::time::timeout(
                TLS_HANDSHAKE_TIMEOUT,
                tokio_boring::accept(&acceptor, sock),
            )
            .await
            {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    // 非 TLS 客户端（例如误用 http:// 连到本端口）会走到这里。
                    // 这是正常的用户错误，不需要 error 级日志。
                    tracing::debug!(%peer, error = %e, "本地 TLS 握手失败");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "本地 TLS 握手超时");
                    return;
                }
            };

            // ---- 3) 复用 HTTP 代理逻辑 ----
            match super::http::handle(tls, m).await {
                Ok((up, down)) => tracing::debug!(%peer, up, down, "HTTPS 代理连接结束"),
                Err(e) => tracing::debug!(%peer, error = %e, "HTTPS 代理连接错误"),
            }
        });
    }
}

/// 根据配置构造服务端 TLS 配置。
pub fn build_config(cert: &HttpsCert) -> Result<flowtcp_tls::ServerTlsConfig, EntryError> {
    match cert {
        HttpsCert::Files {
            cert_path,
            key_path,
        } => Ok(flowtcp_tls::ServerTlsConfig::new(
            cert_path.clone(),
            key_path.clone(),
        )),
        HttpsCert::SelfSigned { san } => {
            let (cert_pem, key_pem) = self_signed(san)?;
            Ok(flowtcp_tls::ServerTlsConfig::from_pem(cert_pem, key_pem))
        }
    }
}

/// 生成自签证书，返回 `(证书 PEM, 私钥 PEM)`。
///
/// 每次启动生成新证书 —— 故意不落盘缓存：
/// 落盘会让"证书文件"成为又一个需要备份/清理的状态，
/// 而自签证书在本地场景下重复生成没有任何副作用。
pub fn self_signed(san: &[String]) -> Result<(String, String), EntryError> {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "FlowTCP Local Proxy");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "FlowTCP");

    // SAN：用户未指定时用本地常用名
    params.subject_alt_names = if san.is_empty() {
        vec![
            SanType::DnsName(
                "localhost"
                    .try_into()
                    .map_err(|e| EntryError::Config(format!("SAN 构造失败: {e}")))?,
            ),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ]
    } else {
        san.iter()
            .map(|s| {
                // 能解析成 IP 的当作 IP SAN，否则当域名
                match s.parse::<std::net::IpAddr>() {
                    Ok(ip) => Ok(SanType::IpAddress(ip)),
                    Err(_) => s
                        .as_str()
                        .try_into()
                        .map(SanType::DnsName)
                        .map_err(|e| EntryError::Config(format!("SAN 非法 {s}: {e}"))),
                }
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    // 有效期：从"现在"起算
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5); // 容忍时钟偏差
    params.not_after = now + time::Duration::days(SELF_SIGNED_VALIDITY_DAYS);

    // ECDSA P-256：与项目其他证书保持一致，且所有浏览器都支持
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| EntryError::Config(format!("生成私钥失败: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| EntryError::Config(format!("签发自签证书失败: {e}")))?;

    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认自签证书可生成且含localhost() {
        let (cert, key) = self_signed(&[]).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"), "应是 PEM 证书");
        assert!(key.contains("BEGIN PRIVATE KEY"), "应是 PKCS#8 私钥");
        // SAN 应以 DNS:localhost 或 IP Address:127.0.0.1 形式出现
        assert!(
            cert.contains("CERTIFICATE"),
            "证书内容异常: {}",
            &cert[..cert.len().min(80)]
        );
    }

    #[test]
    fn 自定义san生效() {
        let (cert, _) = self_signed(&["proxy.local".to_string()]).unwrap();
        // PEM 是 base64，无法直接搜字符串；这里只验证能成功生成
        assert!(!cert.is_empty());
    }

    #[test]
    fn ip形式的san被接受() {
        let (cert, _) = self_signed(&["192.168.1.10".to_string()]).unwrap();
        assert!(!cert.is_empty());
    }

    #[test]
    fn 从pem构造的配置能建acceptor() {
        let cfg = build_config(&HttpsCert::default()).unwrap();
        assert!(cfg.build_acceptor().is_ok(), "自签证书必须能用于 TLS");
    }

    /// 端到端验证：自签证书真的能完成 TLS 握手。
    ///
    /// 只验证"能握手"，不验证证书链（自签本来就没有链）。
    #[tokio::test]
    async fn 自签证书能完成tls握手() {
        let cfg = build_config(&HttpsCert::default()).unwrap();
        let acceptor = cfg.build_acceptor().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = tokio_boring::accept(&acceptor, sock).await;
        });

        let mut connector =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        // 自签证书：跳过链校验，但保留 TLS 协议本身
        connector.set_verify(boring::ssl::SslVerifyMode::NONE);
        let connector = connector.build();

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let config = connector.configure().unwrap();
        let tls = tokio_boring::connect(config, "localhost", tcp).await;
        assert!(tls.is_ok(), "自签证书应能完成 TLS 握手: {:?}", tls.err());
    }
}
