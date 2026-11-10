//! 单条 FlowTCP 隧道：TLS 握手 + 自研记录层 + 帧收发
//!
//! # 一条隧道的生命周期
//!
//! ```text
//! Transport::connect          → 拿到承载层字节流（真 TCP 或 FakeTCP）
//! tls13_client::handshake     → 自研 TLS 1.3 握手（方案 G）
//! derive_keys(exporter, ctx)  → 派生 FlowTCP 记录层密钥（方向隔离）
//! split()                     → 读半 / 写半各自独立任务
//!   写半：Frame::encode → RecordEncoder::seal → write
//!   读半：read → RecordDecoder::open → Frame::decode
//! ```
//!
//! # 为什么握手后要离开 TLS 记录层
//!
//! TLS 记录层的 AEAD nonce 由**隐式**记录序号推导，在不可靠链路上一旦丢包
//! 就整条连接失步。FlowTCP 的目标承载是 FakeTCP（不重传），因此数据面必须
//! 用带**显式序号**的自研记录层。
//!
//! 握手用真 TLS 的价值是：① 流量形态与普通 HTTPS 无法区分；② exporter
//! 提供的密钥强度等价于一次完整 TLS 会话，且不产生额外报文。
//!
//! # 帧如何跨记录边界
//!
//! 一条记录可以含多个帧，一个帧也可以跨多条记录 —— 因此读侧必须维护
//! `pending` 缓冲并按 `Frame::decode` 的 `consumed` 逐个切出。
//! 这个逻辑与时序无关，纯字节流处理，可在无网络下单元测试。

use std::io;

use flowtcp_proto::frame::{FrameError, OwnedFrame};
use flowtcp_proto::record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder, RecordError};
use flowtcp_proto::steal::AuthKey;
use flowtcp_proto::MAX_RECORD_PLAINTEXT;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::transport::Transport;

/// 隧道错误。
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// 承载层 IO 失败。
    #[error("承载层 IO 失败: {0}")]
    Io(#[from] io::Error),
    /// TLS 握手失败。
    #[error("TLS 握手失败: {0}")]
    Handshake(String),
    /// 记录层错误。
    #[error("记录层错误: {0}")]
    Record(#[from] RecordError),
    /// 密钥派生错误。
    #[error("密钥派生错误: {0}")]
    KeyDerive(#[from] flowtcp_proto::KeyDeriveError),
    /// 帧编解码错误。
    #[error("帧编解码错误: {0}")]
    Frame(#[from] FrameError),
    /// 对端关闭了隧道。
    ///
    /// 与 `Io(UnexpectedEof)` 区分开：这是**正常**的隧道终结，
    /// 上层应把它转成"所有本地连接关闭"而不是记错误日志。
    #[error("隧道已被对端关闭")]
    Closed,
    /// 收到的记录明文超过上限（可能是恶意对端或版本不匹配）。
    #[error("接收缓冲超过上限 {0} 字节")]
    ReceiveBufferOverflow(usize),
}

/// 帧写入半（持有记录层加密状态）。
pub struct FrameWriter<W> {
    inner: W,
    enc: RecordEncoder,
    /// 明文暂存（复用以减少分配）。
    plain: Vec<u8>,
    /// 密文暂存。
    sealed: Vec<u8>,
    /// 本半已写出的帧数（仅用于诊断）。
    frames_sent: u64,
}

impl<W> FrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// 构造。
    pub fn new(inner: W, keys: Keys) -> Self {
        FrameWriter {
            inner,
            enc: RecordEncoder::new(keys),
            plain: Vec::with_capacity(MAX_RECORD_PLAINTEXT),
            sealed: Vec::with_capacity(MAX_RECORD_PLAINTEXT + 64),
            frames_sent: 0,
        }
    }

    /// 已发送帧数。
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// 把一帧追加到明文缓冲。
    ///
    /// 若追加后会超出单条记录上限，先把已有内容封成记录写出去。
    /// 返回 `true` 表示本次发生了写出。
    pub async fn push(&mut self, frame: &OwnedFrame) -> Result<bool, TunnelError> {
        if !self.plain.is_empty() && self.plain.len() + frame.encoded_len() > MAX_RECORD_PLAINTEXT {
            self.flush_record().await?;
            // flush_record 后 plain 必为空
            debug_assert!(self.plain.is_empty());
            // 单帧本身超限：这是上层 bug（应分片），显式报错而非静默截断
            if frame.encoded_len() > MAX_RECORD_PLAINTEXT {
                return Err(TunnelError::Record(RecordError::PlaintextTooLarge(
                    frame.encoded_len(),
                )));
            }
            frame.encode(&mut self.plain)?;
            self.frames_sent += 1;
            return Ok(true);
        }

        if frame.encoded_len() > MAX_RECORD_PLAINTEXT {
            return Err(TunnelError::Record(RecordError::PlaintextTooLarge(
                frame.encoded_len(),
            )));
        }
        frame.encode(&mut self.plain)?;
        self.frames_sent += 1;
        Ok(false)
    }

    /// 把当前明文缓冲封成一条记录并写出。
    pub async fn flush_record(&mut self) -> Result<(), TunnelError> {
        if self.plain.is_empty() {
            return Ok(());
        }
        self.sealed.clear();
        self.enc.seal_into(&self.plain, &mut self.sealed)?;
        self.inner.write_all(&self.sealed).await?;
        self.inner.flush().await?;
        self.plain.clear();
        Ok(())
    }

    /// 发送单帧（便捷方法：push + flush_record）。
    pub async fn send(&mut self, frame: &OwnedFrame) -> Result<(), TunnelError> {
        self.push(frame).await?;
        self.flush_record().await
    }

    /// 取回底层流（用于优雅关闭）。
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// 帧读取半（持有记录层解密状态）。
///
/// # ★ 关键不变量：原始字节必须缓冲，不能"一次 read 只用一次"
///
/// 早期实现直接对 `read()` 到的字节调用 `RecordDecoder::open()`，
/// 并**忽略了它返回的 `used`**。这在一次 `read` 恰好包含多条记录时
/// 会丢弃第 2 条及之后的记录：
///
/// ```text
/// read() → [记录1][记录2][记录3]
/// open(&buf[..n]) → Ok(记录1)   ← 记录 2、3 被直接扔掉
/// 下一次 read() 从内核读 → 已经没有了
/// ```
///
/// 这不是理论问题：OpenTcp 帧与随后的 Data 帧几乎总在同一个 TCP 段里，
/// 实测表现是「连接建立了但数据一条都传不过去」，且只在特定时序下出现。
///
/// 因此这里分离两个缓冲：
/// - `raw`：未消费的**原始字节**（密文）
/// - `pending`：已解密、待切成帧的**明文**
pub struct FrameReader<R> {
    inner: R,
    dec: RecordDecoder,
    /// 未消费的原始字节（密文）。
    raw: Vec<u8>,
    /// 已解密、尚未切成完整帧的明文。
    pending: Vec<u8>,
    /// 读缓冲。
    chunk: Vec<u8>,
    /// 已解出的帧数（仅用于诊断）。
    frames_received: u64,
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// 构造。
    pub fn new(inner: R, keys: Keys) -> Self {
        FrameReader {
            inner,
            dec: RecordDecoder::new(keys),
            raw: Vec::with_capacity(16384),
            pending: Vec::with_capacity(MAX_RECORD_PLAINTEXT),
            chunk: vec![0u8; 8192],
            frames_received: 0,
        }
    }

    /// 已接收帧数。
    pub fn frames_received(&self) -> u64 {
        self.frames_received
    }

    /// 把 `raw` 里**所有完整记录**解密并移入 `pending`。
    ///
    /// 用 `std::mem::take` 把 `raw` 暂时取出，避免 `&self.raw` 与
    /// `&mut self.dec` 同时借用。
    fn drain_records(&mut self) -> Result<(), TunnelError> {
        let mut raw = std::mem::take(&mut self.raw);
        let result = self.drain_records_inner(&mut raw);
        self.raw = raw;
        result
    }

    fn drain_records_inner(&mut self, raw: &mut Vec<u8>) -> Result<(), TunnelError> {
        loop {
            // 记录头不足 5 字节：等更多数据
            if raw.len() < flowtcp_proto::record::RECORD_HEADER_LEN {
                return Ok(());
            }
            let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
            // length 必须至少容纳 掩码(8) + tag(16)
            if len < 24 {
                return Err(TunnelError::Record(RecordError::BadLength(len)));
            }
            let total = flowtcp_proto::record::RECORD_HEADER_LEN + len;
            // 记录不完整：等更多数据
            if raw.len() < total {
                return Ok(());
            }

            // 解密这一条（`used` 必定等于 total，但用返回值更安全）
            let (_, plain, used) = self.dec.open(&raw[..total])?;
            raw.drain(..used);

            if self.pending.len() + plain.len() > MAX_RECORD_PLAINTEXT * 8 {
                return Err(TunnelError::ReceiveBufferOverflow(
                    self.pending.len() + plain.len(),
                ));
            }
            self.pending.extend_from_slice(&plain);
        }
    }

    /// 读下一帧。
    ///
    /// 会一直读到能切出完整帧为止；对端关闭返回 [`TunnelError::Closed`]。
    pub async fn recv(&mut self) -> Result<OwnedFrame, TunnelError> {
        loop {
            // ---- 1) 尽量把 raw 里的完整记录都解出来 ----
            self.drain_records()?;

            // ---- 2) 尝试切帧 ----
            match OwnedFrame::decode(&self.pending) {
                Ok((f, used)) => {
                    self.pending.drain(..used);
                    self.frames_received += 1;
                    return Ok(f);
                }
                // 明文不够一帧：需要更多数据
                Err(FrameError::Truncated) => {}
                Err(e) => return Err(TunnelError::Frame(e)),
            }

            // ---- 3) 读更多原始字节（追加到 raw，保留未消费部分）----
            let n = self.inner.read(&mut self.chunk).await?;
            if n == 0 {
                return Err(TunnelError::Closed);
            }
            self.raw.extend_from_slice(&self.chunk[..n]);
        }
    }

    /// 取回底层流。
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// 一条已建立的 FlowTCP 隧道。
///
/// 建立后应立刻 [`Tunnel::split`] 成读写两半，分别交给写任务与读任务；
/// 不要把同一个 `Tunnel` 在多个任务间共享（会串行化且易死锁）。
pub struct Tunnel<S> {
    /// 写半。
    pub writer: FrameWriter<WriteHalf<S>>,
    /// 读半。
    pub reader: FrameReader<ReadHalf<S>>,
    /// 握手得到的 exporter（日志/调试用，**不要外传**）。
    exporter: [u8; 32],
    /// 握手得到的 exporter context。
    pub exporter_context: [u8; 64],
    /// 协商的 ALPN。
    pub alpn: Option<Vec<u8>>,
}

impl<S> Tunnel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// 在**已有**字节流上建立隧道。
    pub async fn handshake_on(
        mut stream: S,
        sni: &str,
        auth: &AuthKey,
    ) -> Result<Self, TunnelError> {
        // ---- 1) 自研 TLS 1.3 握手（方案 G：转录由我们控制，票据可自由填入）----
        let hs = flowtcp_tls::tls13_client::handshake(&mut stream, sni, auth)
            .await
            .map_err(|e| TunnelError::Handshake(e.to_string()))?;

        // ---- 2) 派生 FlowTCP 记录层密钥 ----
        //
        // 本客户端只协商 TLS_AES_128_GCM_SHA256（见 tls13_client 文档），
        // 因此 AEAD 恒为 AES-128-GCM、密钥长度恒为 16。
        let algo = AeadAlgo::Aes128Gcm;
        let keys = flowtcp_proto::derive_keys(&hs.exporter, &hs.exporter_context, algo.key_len())?;

        // 客户端视角：tx = c2s，rx = s2c
        let (tk, tiv, tsn) = keys.tx_material(true);
        let (rk, riv, rsn) = keys.rx_material(true);
        let tx_keys = Keys::new(algo, tk, tiv, tsn)?;
        let rx_keys = Keys::new(algo, rk, riv, rsn)?;

        // ---- 3) 拆成读写两半（各自由独立任务驱动，互不阻塞）----
        let (r, w) = tokio::io::split(stream);

        Ok(Tunnel {
            writer: FrameWriter::new(w, tx_keys),
            reader: FrameReader::new(r, rx_keys),
            exporter: hs.exporter,
            exporter_context: hs.exporter_context,
            alpn: hs.alpn,
        })
    }

    /// 通过承载层建立隧道。
    pub async fn open<T>(transport: &T, sni: &str, auth: &AuthKey) -> Result<Self, TunnelError>
    where
        T: Transport<Stream = S>,
    {
        let stream = transport.connect(sni).await?;
        Tunnel::handshake_on(stream, sni, auth).await
    }

    /// 测试专用：直接装配一个隧道（跳过 TLS 握手）。
    ///
    /// 单元测试关心的是数据面逻辑（帧边界、分片、流分发），
    /// 与 TLS 无关；真 TLS 握手由 `flowtcp-server` 的 e2e 测试覆盖。
    #[cfg(test)]
    pub(crate) fn for_test(
        writer: FrameWriter<WriteHalf<S>>,
        reader: FrameReader<ReadHalf<S>>,
        exporter: [u8; 32],
        exporter_context: [u8; 64],
    ) -> Self {
        Tunnel {
            writer,
            reader,
            exporter,
            exporter_context,
            alpn: None,
        }
    }

    /// exporter 的十六进制前缀（日志用，只暴露 8 字节防泄漏）。
    pub fn exporter_fingerprint(&self) -> String {
        self.exporter[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowtcp_proto::frame::{Flags, FrameType};
    use flowtcp_proto::record::{AeadAlgo, Keys};

    /// 构造「writer 加密 / reader 解密」用的同一套密钥。
    ///
    /// 这里是一对**直连**的 writer/reader（用 duplex 相连，没有真实的对端），
    /// 所以加密与解密必须用**同一份**材料。若误用 `rx_material`
    /// （即反方向），会得到 `RecordError::AuthFailed` —— 这个错误信息
    /// 已经明确提示"密钥不同步"，但真正原因是方向用错。
    fn keys_pair() -> (Keys, Keys) {
        let exporter = [0x7Bu8; 32];
        let ctx = [0x11u8; 64];
        let d = flowtcp_proto::derive_keys(&exporter, &ctx, AeadAlgo::Aes128Gcm.key_len()).unwrap();

        let (tk, tiv, tsn) = d.tx_material(true);
        let w = Keys::new(AeadAlgo::Aes128Gcm, tk, tiv, tsn).unwrap();
        let (rk, riv, rsn) = d.tx_material(true);
        let r = Keys::new(AeadAlgo::Aes128Gcm, rk, riv, rsn).unwrap();
        (w, r)
    }

    #[tokio::test]
    async fn 单帧往返() {
        let (txk, rxk) = keys_pair();
        let (a, b) = tokio::io::duplex(64 * 1024);

        let mut w = FrameWriter::new(a, txk);
        let mut r = FrameReader::new(b, rxk);

        let f = OwnedFrame::new(
            FrameType::OpenTcp,
            Flags::empty(),
            7,
            0,
            b"\x01\x7f\x00\x00\x01\x00\x50".to_vec(),
        );
        w.send(&f).await.unwrap();

        let got = r.recv().await.unwrap();
        assert_eq!(got, f);
    }

    #[tokio::test]
    async fn 多帧合并进一条记录() {
        let (txk, rxk) = keys_pair();
        let (a, b) = tokio::io::duplex(64 * 1024);

        let mut w = FrameWriter::new(a, txk);
        let mut r = FrameReader::new(b, rxk);

        // 三帧都不大，push 时不会触发 flush，最终合并为一条记录
        for i in 0..3u16 {
            let f = OwnedFrame::data(i, vec![i as u8; 10]);
            let flushed = w.push(&f).await.unwrap();
            assert!(!flushed, "小帧不应触发提前 flush");
        }
        assert_eq!(w.frames_sent(), 3);
        w.flush_record().await.unwrap();

        for i in 0..3u16 {
            let got = r.recv().await.unwrap();
            assert_eq!(got.stream_id, i);
            assert_eq!(got.payload, vec![i as u8; 10]);
        }
        assert_eq!(r.frames_received(), 3);
    }

    #[tokio::test]
    async fn 大帧触发独立记录() {
        let (txk, rxk) = keys_pair();
        let (a, b) = tokio::io::duplex(256 * 1024);

        let mut w = FrameWriter::new(a, txk);
        let mut r = FrameReader::new(b, rxk);

        // 每帧 9000 字节（含 10 字节头 = 9010），两帧共 18020 > 16384 → 必须 flush
        let big = vec![0xAAu8; 9000];
        let f1 = OwnedFrame::data(1, big.clone());
        let f2 = OwnedFrame::data(2, big.clone());

        w.push(&f1).await.unwrap();
        let flushed = w.push(&f2).await.unwrap();
        assert!(flushed, "超过单记录上限时必须先 flush");
        w.flush_record().await.unwrap();

        assert_eq!(r.recv().await.unwrap().payload.len(), 9000);
        assert_eq!(r.recv().await.unwrap().payload.len(), 9000);
    }

    #[tokio::test]
    async fn 超限单帧被拒绝() {
        let (txk, _rxk) = keys_pair();
        let (a, _b) = tokio::io::duplex(1024 * 1024);
        let mut w = FrameWriter::new(a, txk);

        // 单帧 payload 上限 16384，加 10 字节头必超
        let f = OwnedFrame::data(1, vec![0u8; 16384]);
        assert!(matches!(
            w.push(&f).await,
            Err(TunnelError::Record(RecordError::PlaintextTooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn 对端关闭时报closed() {
        let (txk, rxk) = keys_pair();
        let (a, b) = tokio::io::duplex(4096);
        drop(a);

        let mut r = FrameReader::new(b, rxk);
        let _ = txk;
        assert!(matches!(r.recv().await, Err(TunnelError::Closed)));
    }

    #[tokio::test]
    async fn 记录跨多次read能正确拼装() {
        let (txk, rxk) = keys_pair();
        let (a, b) = tokio::io::duplex(64 * 1024);

        let mut w = FrameWriter::new(a, txk);
        // 用一层"每次只放 3 字节"的包装模拟极碎的分片
        let slow = SlowReader::new(b, 3);
        let mut r = FrameReader::new(slow, rxk);

        let f = OwnedFrame::data(9, vec![0x5Au8; 500]);
        w.send(&f).await.unwrap();

        let got = r.recv().await.unwrap();
        assert_eq!(got.payload, vec![0x5Au8; 500]);
    }

    /// 每次最多读 `n` 字节的读包装，用于验证半条记录的拼装逻辑。
    struct SlowReader<R> {
        inner: R,
        n: usize,
    }

    impl<R> SlowReader<R> {
        fn new(inner: R, n: usize) -> Self {
            SlowReader { inner, n }
        }
    }

    impl<R: AsyncRead + Unpin> AsyncRead for SlowReader<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let n = self.n.min(buf.remaining());
            let mut tmp = vec![0u8; n];
            let mut tb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut tb) {
                std::task::Poll::Ready(Ok(())) => {
                    let filled = tb.filled().len();
                    buf.put_slice(&tmp[..filled]);
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }
}
