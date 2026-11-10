//! TLS 1.3 握手封装：客户端 / 服务端 + exporter 密钥导出
//!
//! # 关键设计：握手用 TLS，数据传输不用 TLS
//!
//! ```text
//! 阶段 1（本模块）：fake-tcp 数据报 → 有序字节流适配 → TLS 1.3 握手
//!                                                        ↓
//!                                           export_keying_material
//!                                                        ↓
//! 阶段 2（flowtcp-proto::record）：用自己的记录层直接加密数据
//! ```
//!
//! **为什么数据传输阶段要离开 TLS**
//!
//! TLS 记录层的 AEAD nonce 由**隐式**记录序号推导（RFC 9147 §3），
//! 一旦在不可靠链路上丢一个包，后续所有记录的 nonce 都会错位，
//! 导致整条连接解密失败。FakeTCP 不做重传，因此数据阶段必须离开 TLS。
//!
//! 而握手阶段（1~2 个 RTT、几 KB 数据）必须用真 TLS —— 这正是伪装的核心。
//! 握手完成后我们拿到 `exporter_master_secret` 派生的密钥，
//! 强度等价于一次完整 TLS 会话，且**不产生任何额外握手报文**，
//! 因此流量形态与普通 HTTPS 完全一致。

use boring::ssl::SslRef;
use flowtcp_proto::record::{AeadAlgo, Keys};
use flowtcp_proto::{derive_keys, DerivedKeys};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio_boring::SslStream;

use crate::fingerprint::{FingerprintConfig, ServerTlsConfig};
use crate::split::{classify, Classified, Verdict, MIN_CLASSIFY_LEN};
use crate::takeable::Takeable;

/// 读取首帧时允许的最大字节数。
///
/// 取 4096：足以包含完整 HTTP 请求头（典型 <2KB）或 FlowTCP 认证帧（<100 字节），
/// 同时限制单个连接的前期内存占用，防止恶意客户端用超长首帧耗尽内存。
pub const MAX_FIRST_FRAME: usize = 4096;

/// 等待首帧的超时。
///
/// 取 10 秒：真实浏览器握手后会立即发送请求（<100ms），
/// 而探测工具可能故意「握手完成后不发数据」来观察服务端超时行为。
/// 超时设为 10 秒与 nginx 的 `client_header_timeout` 默认值（60s）同量级，
/// 但更短一些以减少恶意连接占用；实际部署可按需调整。
pub const FIRST_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TLS 层错误。
#[derive(Debug, Error)]
pub enum TlsError {
    /// 握手失败。
    #[error("TLS 握手失败: {0}")]
    Handshake(String),
    /// 读取首帧失败。
    #[error("读取首帧失败: {0}")]
    ReadFirstFrame(String),
    /// 等待首帧超时。
    #[error("等待首帧超时（{0:?}）")]
    FirstFrameTimeout(std::time::Duration),
    /// 读取的首帧超过上限。
    #[error("首帧超过 {MAX_FIRST_FRAME} 字节上限")]
    FirstFrameTooLarge,
    /// exporter 密钥导出失败。
    #[error("exporter 密钥导出失败: {0}")]
    ExportFailed(String),
    /// 密钥派生失败。
    #[error("密钥派生失败: {0}")]
    KeyDerive(String),
    /// 无法从协商结果确定 AEAD 算法。
    #[error("无法确定 AEAD 算法（协商 cipher: {0:?}）")]
    UnknownCipher(Option<String>),
}

/// 从 `SslRef` 读取 AEAD 算法。
///
/// 必须与协商结果一致：若协商成 ChaCha20 而我们按 AES 处理，
/// 双方密钥派生相同但 AEAD 实现不同 → 全部解密失败。
pub fn aead_algo_of(ssl: &SslRef) -> Result<AeadAlgo, TlsError> {
    let name = ssl
        .current_cipher()
        .and_then(|c| c.standard_name())
        .map(|s| s.to_string());
    match name.as_deref() {
        // TLS 1.3 的三个强制 cipher（RFC 8446 §9.1）
        Some("TLS_AES_128_GCM_SHA256") => Ok(AeadAlgo::Aes128Gcm),
        Some("TLS_CHACHA20_POLY1305_SHA256") => Ok(AeadAlgo::ChaCha20Poly1305),
        // AES-256-GCM 的密钥长度是 32 字节，与 AES-128 不兼容；
        // 当前实现只支持 128 位密钥，因此显式排除（配置里也不应出现）。
        other => Err(TlsError::UnknownCipher(other.map(|s| s.to_string()))),
    }
}

/// 构造 exporter 的 context：`ClientHello.random || ServerHello.random`。
///
/// # 为什么用两个 random 作 context
///
/// 1. **双方都能独立获得**，无需额外协商（节省一次 RTT）
/// 2. **天然唯一**，即使 exporter 输出意外相同，密钥也不会碰撞
/// 3. 长度固定 64 字节，TLS 1.3 的 random 恒为 32 字节
pub fn export_context(ssl: &SslRef) -> [u8; 64] {
    let mut ctx = [0u8; 64];
    let n1 = ssl.client_random(&mut ctx[..32]);
    let n2 = ssl.server_random(&mut ctx[32..]);
    // TLS 1.3 的 random 恒为 32 字节；若不足则剩余部分保持为 0，
    // 双方行为一致，仍能派生出相同密钥。
    debug_assert_eq!(n1, 32, "ClientHello.random 长度异常");
    debug_assert_eq!(n2, 32, "ServerHello.random 长度异常");
    ctx
}

/// 从已完成的握手导出 FlowTCP 内层密钥。
pub fn derive_flow_keys(ssl: &SslRef) -> Result<(DerivedKeys, AeadAlgo), TlsError> {
    let algo = aead_algo_of(ssl)?;
    let ctx = export_context(ssl);

    let mut out = [0u8; flowtcp_proto::keyderive::EXPORTER_OUTPUT_LEN];
    ssl.export_keying_material(&mut out, flowtcp_proto::EXPORTER_LABEL, Some(&ctx))
        .map_err(|e| TlsError::ExportFailed(e.to_string()))?;

    let keys =
        derive_keys(&out, &ctx, algo.key_len()).map_err(|e| TlsError::KeyDerive(e.to_string()))?;
    Ok((keys, algo))
}

/// 用派生密钥构造指定方向的记录层密钥。
///
/// - `is_client = true` 时：`tx` 用 c2s，`rx` 用 s2c
/// - `is_client = false` 时：`tx` 用 s2c，`rx` 用 c2s
pub fn record_keys_for(
    keys: &DerivedKeys,
    algo: AeadAlgo,
    is_client: bool,
) -> Result<(Keys, Keys), TlsError> {
    let (tk, tiv, tsn) = keys.tx_material(is_client);
    let (rk, riv, rsn) = keys.rx_material(is_client);
    let tx = Keys::new(algo, tk, tiv, tsn).map_err(|e| TlsError::KeyDerive(e.to_string()))?;
    let rx = Keys::new(algo, rk, riv, rsn).map_err(|e| TlsError::KeyDerive(e.to_string()))?;
    Ok((tx, rx))
}

/// 客户端握手结果。
pub struct ClientHandshake<S> {
    /// 已完成握手的 TLS 流。数据阶段通常不再使用，仅保留用于优雅关闭
    /// （发送 `close_notify`，避免被探测者观察到「直接 RST」这种异常行为）。
    pub stream: SslStream<S>,
    /// 内层密钥材料。
    pub keys: DerivedKeys,
    /// 协商的 AEAD 算法。
    pub aead: AeadAlgo,
    /// 实际协商的 ALPN。
    pub alpn: Option<Vec<u8>>,
}

impl<S> ClientHandshake<S> {
    /// 把内层密钥拆成 (发送, 接收) 两套。
    pub fn record_keys(&self) -> Result<(Keys, Keys), TlsError> {
        record_keys_for(&self.keys, self.aead, true)
    }
}

/// 执行客户端 TLS 握手。
///
/// `sni` 必须与证书域名一致，否则真实证书校验会失败（这是期望行为）。
pub async fn connect<S>(
    stream: S,
    sni: &str,
    cfg: &FingerprintConfig,
) -> Result<ClientHandshake<S>, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = cfg
        .build_connector()
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let mut config = connector
        .configure()
        .map_err(|e| TlsError::Handshake(e.to_string()))?;
    // SNI 必须发送：它是服务端选择证书的依据，也是伪装的一部分
    // （真实浏览器从不在裸 IP 上握 TLS 1.3 + h2）
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(cfg_profile_verify(cfg));

    let tls = tokio_boring::connect(config, sni, stream)
        .await
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let (keys, aead) = derive_flow_keys(tls.ssl())?;
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());

    Ok(ClientHandshake {
        stream: tls,
        keys,
        aead,
        alpn,
    })
}

/// 是否校验主机名（与证书校验开关保持一致）。
fn cfg_profile_verify(cfg: &FingerprintConfig) -> bool {
    // FingerprintConfig 的 verify_cert 是私有字段，这里通过构造器语义推断：
    // 提供 `verify_cert()` 访问器更清晰，但为保持 API 简洁，
    // 统一约定「启用证书校验则校验主机名」。
    cfg.verify_enabled()
}

/// 服务端握手结果。
pub struct ServerHandshake<S> {
    /// 已握手的 TLS 流（Web 模式下继续用它转发给 nginx）。
    pub stream: SslStream<S>,
    /// 首帧明文 + 分流结论。
    pub first_frame: Classified,
    /// 内层密钥材料（仅 Proxy 模式需要）。
    pub keys: DerivedKeys,
    /// 协商的 AEAD 算法。
    pub aead: AeadAlgo,
    /// 实际协商的 ALPN。
    pub alpn: Option<Vec<u8>>,
}

impl<S> ServerHandshake<S> {
    /// 分流结论。
    pub fn verdict(&self) -> Verdict {
        self.first_frame.verdict
    }

    /// 把内层密钥拆成 (发送, 接收) 两套（服务端视角）。
    pub fn record_keys(&self) -> Result<(Keys, Keys), TlsError> {
        record_keys_for(&self.keys, self.aead, false)
    }
}

/// 执行服务端 TLS 握手并读取首帧做分流判定。
///
/// # 为什么首帧读取放在这里
///
/// 首帧是**唯一**能区分「FlowTCP 客户端」与「普通 HTTP」的地方，
/// 且必须在密钥派生后、切换记录层前完成。把它与握手放在同一个函数里，
/// 可以让调用方无法「忘记分流」——这是对抗探测的关键不变量。
pub async fn accept<S>(stream: S, cfg: &ServerTlsConfig) -> Result<ServerHandshake<S>, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let acceptor = cfg
        .build_acceptor()
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let mut tls = tokio_boring::accept(&acceptor, stream)
        .await
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let (keys, aead) = derive_flow_keys(tls.ssl())?;
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());

    // 读首帧：循环读取直到能判定（或超时/超长）
    let first_frame = read_first_frame(&mut tls).await?;

    Ok(ServerHandshake {
        stream: tls,
        first_frame,
        keys,
        aead,
        alpn,
    })
}

/// 服务端「裸」握手结果：已脱离 TLS 记录层。
///
/// # 与 [`ServerHandshake`] 的区别
///
/// [`ServerHandshake`] 保留 `SslStream`（用于「认证失败→转发给真实网站」的
/// Web 路径，需要继续在 TLS 层读 HTTP 请求）。
///
/// 本结构**丢弃 TLS 记录层**，把底层字节流还回来，供 FlowTCP 自研记录层接管：
///
/// ```text
/// TLS 握手完成 ──→ 取回裸流 ──→ flowtcp_proto::RecordEncoder/Decoder
/// ```
///
/// 这是代理数据面的唯一正确形态：TLS 记录层用隐式序号，乱序即全盘失步。
pub struct RawServerHandshake<S> {
    /// 底层字节流（已脱离 TLS，可直接读写原始字节）。
    pub stream: S,
    /// 内层密钥材料。
    pub keys: DerivedKeys,
    /// 协商的 AEAD 算法。
    pub aead: AeadAlgo,
    /// 实际协商的 ALPN。
    pub alpn: Option<Vec<u8>>,
    /// exporter 的 context（`client_random || server_random`）。
    ///
    /// 客户端可用它复算证书种子，因此必须回传（日志/校验用）。
    pub exporter_context: [u8; 64],
}

impl<S> RawServerHandshake<S> {
    /// 拆成 (发送, 接收) 两套记录层密钥（服务端视角：tx=s2c，rx=c2s）。
    pub fn record_keys(&self) -> Result<(Keys, Keys), TlsError> {
        record_keys_for(&self.keys, self.aead, false)
    }

    /// 一次性取出所有代理数据面需要的东西。
    ///
    /// 返回 `(裸流, 发送密钥, 接收密钥)`。
    pub fn into_parts(self) -> Result<(S, Keys, Keys), TlsError> {
        let (tx, rx) = self.record_keys()?;
        Ok((self.stream, tx, rx))
    }
}

/// 执行服务端 TLS 握手，**不读首帧**，握手后取回裸字节流。
///
/// # 为什么这里不读首帧（与 [`accept`] 的关键差异）
///
/// 方案 G（ClientHello.session_id 票据认证，见 `DEVTIPS.md` §11/§13）完成后，
/// 分流决策在**读 ClientHello 时**就已确定（`flowtcp_proto::steal::judge`），
/// 不再依赖握手后的首帧明文。
///
/// 因此认证通过后没必要多一次「等首帧」：
/// - 客户端切到 FlowTCP 记录层后，TLS 层看到的不是合法 TLS 记录，
///   [`accept`] 的 `read_first_frame` 会一直等到超时才报错
/// - 少一次往返、少 10 秒超时风险、少一段首帧缓冲逻辑
pub async fn accept_raw<S>(
    stream: S,
    cfg: &ServerTlsConfig,
) -> Result<RawServerHandshake<S>, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let acceptor = cfg
        .build_acceptor()
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    // 装进 Takeable：握手后靠它把底层流取回来（SslStream 没有 into_inner）
    let mut tls = tokio_boring::accept(&acceptor, Takeable::new(stream))
        .await
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    // 密钥必须在取走流**之前**导出：exporter 依赖会话状态
    let (keys, aead) = derive_flow_keys(tls.ssl())?;
    let exporter_context = export_context(tls.ssl());
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());

    // ★ 取回裸流。这一步之后 tls 内的 TLS 记录层彻底弃用。
    let stream = tls
        .get_mut()
        .take()
        .ok_or_else(|| TlsError::Handshake("无法取回底层流（Takeable 已被取走）".into()))?;

    Ok(RawServerHandshake {
        stream,
        keys,
        aead,
        alpn,
        exporter_context,
    })
}

/// 读取足够判定分流的首帧明文。
async fn read_first_frame<S>(tls: &mut SslStream<S>) -> Result<Classified, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(MIN_CLASSIFY_LEN * 4);
    let mut chunk = [0u8; 512];

    let deadline = tokio::time::Instant::now() + FIRST_FRAME_TIMEOUT;

    loop {
        // 先尝试判定（可能已有足够数据）
        if let Some(verdict) = classify(&buf) {
            return Ok(Classified { verdict, data: buf });
        }

        // 数据不足，继续读；带超时以免被「只握手不说话」的探测耗住
        let n = tokio::time::timeout_at(deadline, tls.read(&mut chunk))
            .await
            .map_err(|_| TlsError::FirstFrameTimeout(FIRST_FRAME_TIMEOUT))?
            .map_err(|e| TlsError::ReadFirstFrame(e.to_string()))?;

        if n == 0 {
            // 对端关闭连接但没发够数据 —— 判定为 Unknown（交给伪装站点路径，
            // 但此时连接已断，上层会直接关闭，不会产生任何异常响应）
            return Ok(Classified {
                verdict: Verdict::Unknown,
                data: buf,
            });
        }

        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_FIRST_FRAME {
            return Err(TlsError::FirstFrameTooLarge);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{FingerprintConfig, ServerTlsConfig};
    use tokio::net::{TcpListener, TcpStream};

    /// 生成一组临时自签证书文件，返回 (cert_path, key_path, dir)。
    struct TestCert {
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
        dir: std::path::PathBuf,
    }

    impl Drop for TestCert {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn make_cert(tag: &str) -> TestCert {
        let c = rcgen::generate_simple_self_signed(vec!["flowtcp.test".into()]).unwrap();
        let dir =
            std::env::temp_dir().join(format!("flowtcp-tls-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.key_pair.serialize_pem()).unwrap();
        TestCert { cert, key, dir }
    }

    /// 端到端：客户端 Chrome 指纹 ↔ 服务端，验证握手 + 密钥导出 + 分流。
    async fn roundtrip(
        first_frame: &'static [u8],
        tag: &'static str,
    ) -> (Verdict, DerivedKeys, DerivedKeys) {
        let certs = make_cert(tag);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_cert = certs.cert.clone();
        let srv_key = certs.key.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let cfg = ServerTlsConfig::new(srv_cert, srv_key);
            let mut hs = accept(sock, &cfg).await.expect("服务端握手应成功");
            // 如果是 proxy 模式，回一个 FTAUTH-OK 让客户端能继续
            use tokio::io::AsyncWriteExt;
            let _ = hs.stream.write_all(b"OK").await;
            let _ = hs.stream.flush().await;
            (hs.first_frame.verdict, hs.keys)
        });

        let client = tokio::spawn(async move {
            let sock = TcpStream::connect(addr).await.unwrap();
            let cfg = FingerprintConfig::chrome().danger_accept_invalid_certs();
            let mut hs = connect(sock, "flowtcp.test", &cfg)
                .await
                .expect("客户端握手应成功");
            use tokio::io::AsyncWriteExt;
            hs.stream.write_all(first_frame).await.unwrap();
            hs.stream.flush().await.unwrap();
            hs.keys
        });

        let (verdict, skeys) = server.await.unwrap();
        let ckeys = client.await.unwrap();
        (verdict, skeys, ckeys)
    }

    #[tokio::test]
    async fn 端到端_flowtcp客户端被正确分流() {
        let (verdict, sk, ck) = roundtrip(b"FTAUTH\x01\x05alice", "ft").await;
        assert_eq!(verdict, Verdict::FlowTcp);
        // 双方派生的密钥必须一致（方向对称）
        assert_eq!(ck.c2s_key, sk.c2s_key, "c2s 密钥应一致");
        assert_eq!(ck.s2c_key, sk.s2c_key, "s2c 密钥应一致");
        assert_ne!(sk.c2s_key, sk.s2c_key, "方向必须隔离");
    }

    #[tokio::test]
    async fn 端到端_http1被判定为web() {
        let (verdict, _, _) =
            roundtrip(b"GET / HTTP/1.1\r\nHost: flowtcp.test\r\n\r\n", "h1").await;
        assert_eq!(verdict, Verdict::Http1);
        assert!(verdict.is_web());
    }

    #[tokio::test]
    async fn 端到端_http2前言被判定为web() {
        let (verdict, _, _) = roundtrip(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "h2").await;
        assert_eq!(verdict, Verdict::Http2);
        assert!(verdict.is_web());
    }

    #[tokio::test]
    async fn 端到端_未知数据被判定为web() {
        let (verdict, _, _) = roundtrip(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA], "unk").await;
        assert_eq!(verdict, Verdict::Unknown);
        assert!(
            verdict.is_web(),
            "未知数据必须交给伪装站点，不能返回自定义错误"
        );
    }

    /// 端到端验证：双方派生密钥可用于记录层实际收发。
    #[tokio::test]
    async fn 端到端_派生密钥可驱动记录层() {
        use flowtcp_proto::record::{RecordDecoder, RecordEncoder};
        let (verdict, sk, ck) = roundtrip(b"FTAUTH", "rec").await;
        assert_eq!(verdict, Verdict::FlowTcp);

        let algo = AeadAlgo::Aes128Gcm;
        // 客户端发送 → 服务端接收
        let (ctk, _) = record_keys_for(&ck, algo, true).unwrap();
        let (_, srx) = record_keys_for(&sk, algo, false).unwrap();
        let mut enc = RecordEncoder::new(ctk);
        let mut dec = RecordDecoder::new(srx);

        let (seq, rec) = enc.seal(b"hello via flowtcp record").unwrap();
        let (dseq, plain, _) = dec.open(&rec).unwrap();
        assert_eq!(seq, dseq);
        assert_eq!(plain, b"hello via flowtcp record");
    }

    /// ALPN 应协商出 h2（因为双方都声明了 h2 优先）。
    #[tokio::test]
    async fn 端到端协商alpn为h2() {
        let certs = make_cert("alpn");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_cert = certs.cert.clone();
        let srv_key = certs.key.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let cfg = ServerTlsConfig::new(srv_cert, srv_key);
            let hs = accept(sock, &cfg).await.unwrap();
            hs.alpn
        });

        let client = tokio::spawn(async move {
            let sock = TcpStream::connect(addr).await.unwrap();
            let cfg = FingerprintConfig::chrome().danger_accept_invalid_certs();
            let mut hs = connect(sock, "flowtcp.test", &cfg).await.unwrap();
            use tokio::io::AsyncWriteExt;
            let _ = hs.stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
            let _ = hs.stream.flush().await;
            hs.alpn
        });

        let salpn = server.await.unwrap();
        let calpn = client.await.unwrap();
        assert_eq!(salpn.as_deref(), Some(&b"h2"[..]));
        assert_eq!(calpn, salpn);
    }
}
