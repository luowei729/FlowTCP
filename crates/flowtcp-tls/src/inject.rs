//! 客户端票据注入流：拦截 ClientHello 并写入认证票据
//!
//! # 为什么需要拦截而不是自己构造 ClientHello
//!
//! 客户端必须让 ClientHello 与真实 Chrome **逐字节一致**（我们的 JA4 已实测
//! 匹配 `8daaf6152771`）。自己构造就得维护一份随 Chrome 版本变化的指纹数据库。
//!
//! 但 BoringSSL **没有暴露** `SSL_CTX_set_client_hello_cb`（uTLS 用的那个回调），
//! 因此无法在握手前拿到 ClientHello 去改 `session_id`。
//!
//! # 解法：在字节流层拦截
//!
//! ```text
//! BoringSSL 生成 ClientHello（指纹完美）
//!        ↓ write()
//! 本模块拦截首包 → 解析 random → 算票据 → 覆盖 session_id
//!        ↓ write() 改写后的字节
//! TCP
//! ```
//!
//! 因为 `session_id` 本来就是 32 字节随机值，替换后**长度与偏移全不变**，
//! 指纹完全不受影响。
//!
//! # ★ 必须双向改写（实测踩过的坑）
//!
//! TLS 1.3 规定服务端要在 `ServerHello` 里**回显客户端的 `session_id`**
//! （RFC 8446 §4.1.3）。客户端 BoringSSL 会校验这一项。
//!
//! 但我们把发出的 `session_id` 改成了票据，BoringSSL 内部仍记着它自己
//! 生成的原始值。服务端回显票据 → 客户端比对不一致 → 报
//! `DECODE_ERROR` 握手失败。
//!
//! 所以本模块**同时拦截读写**：
//!
//! ```text
//! 写：BoringSSL 的 ClientHello → 记下原始 sid → 填入票据
//! 读：服务端的 ServerHello → 把回显的票据改回原始 sid → 交给 BoringSSL
//! ```
//!
//! # 票据计算（对称方案）
//!
//! ```text
//! ticket = HMAC-SHA256(secret, "flowtcp v1 ticket" || client_random || window)
//! window = now_unix / 30
//! ```
//!
//! 只需预共享密钥，**不需要** `key_share` 私钥 —— 这正是选用对称方案的原因。
//!
//! # 为什么票据可以在此刻计算
//!
//! 票据的 AEAD salt 与 AAD 都用 `client_random`，而 `client_random` 就在
//! ClientHello 里。拦截到字节后先解析再计算，因此不需要提前知道它。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowtcp_proto::steal::{
    extract_hello_params, locate_server_hello_session_id, rewrite_server_hello_session_id,
    rewrite_session_id, AuthKey, TIME_WINDOW_SECS,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 票据注入计划（不含 `client_random`，它在拦截时才可知）。
#[derive(Clone)]
pub struct InjectPlan {
    /// 预共享认证密钥。
    pub auth: AuthKey,
    /// 票据时间戳（Unix 秒），用于计算时间窗口。
    ///
    /// 服务端接受当前窗口及前后各 1 个（±30 秒），因此客户端时钟
    /// 与服务端有几十秒偏差也能正常认证。
    pub now_unix: u64,
}

/// 脱敏 Debug：绝不输出密钥。
impl std::fmt::Debug for InjectPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectPlan")
            .field("auth", &"<已隐藏>")
            .field("now_unix", &self.now_unix)
            .finish()
    }
}

impl InjectPlan {
    /// 用给定 `client_random` 计算出应填入 `session_id` 的 32 字节票据。
    pub fn session_id_for(
        &self,
        client_random: &[u8; 32],
    ) -> [u8; flowtcp_proto::steal::SESSION_ID_LEN] {
        self.auth
            .ticket(client_random, self.now_unix / TIME_WINDOW_SECS)
    }
}

/// 注入状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// 等待首个写入（应当是 ClientHello）。
    AwaitingHello,
    /// 已注入，等待 ServerHello 以便还原 session_id。
    AwaitingServerHello,
    /// 全部完成，双向直通。
    Passthrough,
    /// 注入失败（例如首包不是完整 ClientHello），双向直通。
    Skipped,
}

/// 拦截 ClientHello 并注入票据的流包装器。
///
/// 读操作完全直通（服务端响应不需要处理）。
pub struct InjectingStream<S> {
    inner: S,
    plan: Option<InjectPlan>,
    state: State,
    /// 写方向：已累积但尚未改写的原始字节（`AwaitingHello` 期间使用）。
    write_accum: Vec<u8>,
    /// 写方向：已改写、待写出的字节。
    write_pending: Vec<u8>,
    /// `write_pending` 中已写出的位置。
    write_pending_pos: usize,
    /// 读方向：已累积但尚未改写的字节（`AwaitingServerHello` 期间使用）。
    read_accum: Vec<u8>,
    /// 读方向：已改写、待交付给调用方的字节。
    read_ready: Vec<u8>,
    /// `read_ready` 中已交付的位置。
    read_ready_pos: usize,
    /// BoringSSL 生成的原始 session_id（用于还原 ServerHello 的回显）。
    original_sid: Option<Vec<u8>>,
}

/// 单次写入可能未包含完整 ClientHello，累积上限。
///
/// 取 16KB（TLS 记录上限）：超过仍不完整说明对端不是我们预期的 TLS 客户端，
/// 放弃注入并直通，避免无限缓冲。
const MAX_PENDING: usize = 16 * 1024;

impl<S> InjectingStream<S> {
    /// 用注入计划包装底层流。
    pub fn new(inner: S, plan: InjectPlan) -> Self {
        InjectingStream {
            inner,
            plan: Some(plan),
            state: State::AwaitingHello,
            write_accum: Vec::new(),
            write_pending: Vec::new(),
            write_pending_pos: 0,
            read_accum: Vec::new(),
            read_ready: Vec::new(),
            read_ready_pos: 0,
            original_sid: None,
        }
    }

    /// 不注入，仅包装（用于对照测试或自有证书模式）。
    pub fn passthrough(inner: S) -> Self {
        InjectingStream {
            inner,
            plan: None,
            state: State::Passthrough,
            write_accum: Vec::new(),
            write_pending: Vec::new(),
            write_pending_pos: 0,
            read_accum: Vec::new(),
            read_ready: Vec::new(),
            read_ready_pos: 0,
            original_sid: None,
        }
    }

    /// 底层流引用。
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// 是否已完成注入（用于断言与日志）。
    pub fn injected(&self) -> bool {
        self.original_sid.is_some()
    }

    /// 尝试对累积字节做注入，返回待写出的字节。
    ///
    /// 返回 `None` 表示数据还不够，需要继续累积。
    fn try_inject(&mut self) -> Option<Vec<u8>> {
        let plan = self.plan.as_ref()?;

        // 必须能解析出 random 与 session_id 偏移，否则数据还不完整
        let (random, _sid_off) = extract_hello_params(&self.write_accum)?;
        let session_id = plan.session_id_for(&random);
        Some(rewrite_session_id(&self.write_accum, &session_id))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for InjectingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // ---- 1) 有已改写数据 → 交付并返回 ----
            //
            // 必须放在循环开头：改写完成后 `continue` 回到这里交付，
            // 而不是继续读底层（那会阻塞）。
            if this.read_ready_pos < this.read_ready.len() {
                let n = (this.read_ready.len() - this.read_ready_pos).min(buf.remaining());
                buf.put_slice(&this.read_ready[this.read_ready_pos..this.read_ready_pos + n]);
                this.read_ready_pos += n;
                if this.read_ready_pos >= this.read_ready.len() {
                    this.read_ready = Vec::new();
                    this.read_ready_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // ---- 2) 不需要改写 → 完全直通 ----
            if this.state != State::AwaitingServerHello || this.original_sid.is_none() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // ---- 3) 等待并改写 ServerHello 的 session_id ----
            let mut tmp = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let data = rb.filled();
                    if data.is_empty() {
                        // EOF：把累积的数据交付出去（若有），否则返回 EOF
                        if this.read_accum.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        this.read_ready = std::mem::take(&mut this.read_accum);
                        this.state = State::Passthrough;
                        continue;
                    }
                    this.read_accum.extend_from_slice(data);

                    // (a) 已能定位 ServerHello 的 session_id
                    if let Some((_off, len)) = locate_server_hello_session_id(&this.read_accum) {
                        match this.original_sid.clone() {
                            Some(orig) if orig.len() == len => {
                                this.read_ready =
                                    rewrite_server_hello_session_id(&this.read_accum, &orig);
                            }
                            _ => {
                                // 长度不匹配（理论上不会）：原样交付
                                this.read_ready = std::mem::take(&mut this.read_accum);
                            }
                        }
                        this.read_accum.clear();
                        this.state = State::Passthrough;
                        continue;
                    }

                    // (b) 首字节不是 handshake，或缓冲超限 → 放弃改写，原样交付
                    if this.read_accum.len() > MAX_PENDING
                        || this.read_accum.first().is_some_and(|&b| b != 0x16)
                    {
                        this.read_ready = std::mem::take(&mut this.read_accum);
                        this.state = State::Passthrough;
                        continue;
                    }

                    // (c) 数据不足：继续循环读更多
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // 此时 `read_ready` 必为空（分支 1 已处理），可以安全返回 Pending。
                //
                // ⚠️ 绝不能在这里 `continue` —— 底层刚返回 Pending，
                // 立即再次 poll 会造成忙轮询（实测会挂死测试）。
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for InjectingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // ---- 上次返回 Pending 时的续写 ----
        //
        // AsyncWrite 契约：返回 Pending 表示**没有消费任何字节**，
        // 调用方会用同一份 `buf` 重试。因此这里直接继续推进内部缓冲，
        // 不再 append（否则会重复累积）。
        if this.write_pending_pos < this.write_pending.len() {
            return match drive_writes(
                &mut this.inner,
                &this.write_pending,
                &mut this.write_pending_pos,
                cx,
            ) {
                Poll::Ready(Ok(())) => {
                    this.write_pending = Vec::new();
                    this.write_pending_pos = 0;
                    Poll::Ready(Ok(buf.len()))
                }
                other => other.map(|r| r.map(|_| 0)),
            };
        }

        match this.state {
            State::Passthrough | State::Skipped => Pin::new(&mut this.inner).poll_write(cx, buf),
            State::AwaitingServerHello => Pin::new(&mut this.inner).poll_write(cx, buf),
            State::AwaitingHello => {
                this.write_accum.extend_from_slice(buf);

                if let Some(rewritten) = this.try_inject() {
                    let total = this.write_accum.len();
                    debug_assert_eq!(rewritten.len(), total, "改写后长度必须不变");
                    // 记下原始 session_id，供读方向还原使用
                    this.original_sid =
                        extract_hello_params(&this.write_accum).and_then(|(_, off)| {
                            this.write_accum.get(off..off + 32).map(|s| s.to_vec())
                        });
                    this.write_accum.clear();
                    this.write_pending = rewritten;
                    this.write_pending_pos = 0;
                    this.state = State::AwaitingServerHello;
                    return match drive_writes(
                        &mut this.inner,
                        &this.write_pending,
                        &mut this.write_pending_pos,
                        cx,
                    ) {
                        Poll::Ready(Ok(())) => {
                            this.write_pending = Vec::new();
                            this.write_pending_pos = 0;
                            Poll::Ready(Ok(buf.len()))
                        }
                        other => other.map(|r| r.map(|_| 0)),
                    };
                }

                if this.write_accum.len() > MAX_PENDING {
                    // 超过上限仍解析不出：放弃注入
                    this.state = State::Skipped;
                    let data = std::mem::take(&mut this.write_accum);
                    return match drive_writes(&mut this.inner, &data, &mut 0usize, cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
                        other => other.map(|r| r.map(|_| 0)),
                    };
                }

                // 数据还不够：报告"已消费"，实际暂存，等凑齐后一次发出
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 写完残留数据
        if this.write_pending_pos < this.write_pending.len() {
            match drive_writes(
                &mut this.inner,
                &this.write_pending,
                &mut this.write_pending_pos,
                cx,
            ) {
                Poll::Ready(Ok(())) => {
                    this.write_pending = Vec::new();
                    this.write_pending_pos = 0;
                }
                other => return other.map(|r| r.map(|_| ())),
            }
        }

        // 还有未处理的累积数据：尝试注入后发出
        if this.state == State::AwaitingHello && !this.write_accum.is_empty() {
            let data = match this.try_inject() {
                Some(rewritten) => {
                    this.original_sid =
                        extract_hello_params(&this.write_accum).and_then(|(_, off)| {
                            this.write_accum.get(off..off + 32).map(|s| s.to_vec())
                        });
                    this.state = State::AwaitingServerHello;
                    rewritten
                }
                None => {
                    this.state = State::Skipped;
                    this.write_accum.clone()
                }
            };
            this.write_accum.clear();
            let mut pos = 0usize;
            match drive_writes(&mut this.inner, &data, &mut pos, cx) {
                Poll::Ready(Ok(())) => {}
                other => {
                    if pos < data.len() {
                        this.write_pending = data;
                        this.write_pending_pos = pos;
                    }
                    return other.map(|r| r.map(|_| ()));
                }
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 把 `data[pos..]` 全部写到底层，写完返回 `Ready(Ok(()))`。
///
/// 返回 `Pending` 时 `pos` 已推进到实际写出的位置，调用方需保留剩余数据重试。
fn drive_writes<S: AsyncWrite + Unpin>(
    inner: &mut S,
    data: &[u8],
    pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *pos < data.len() {
        match Pin::new(&mut *inner).poll_write(cx, &data[*pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "底层流无法写入",
                )))
            }
            Poll::Ready(Ok(n)) => *pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    const SECRET: &str = "inject-test-secret-0123456789";

    fn plan() -> InjectPlan {
        InjectPlan {
            auth: AuthKey::from_password(SECRET),
            now_unix: 1_700_000_000,
        }
    }

    /// 构造一个最小但结构合法的 ClientHello（含 32 字节 session_id）。
    fn fake_client_hello(random: [u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&[0xAAu8; 32]); // 占位 session_id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());

        let mut hs = vec![0x01u8];
        hs.extend_from_slice(&[
            ((body.len() >> 16) & 0xFF) as u8,
            ((body.len() >> 8) & 0xFF) as u8,
            (body.len() & 0xFF) as u8,
        ]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// 核心：写入 ClientHello 后，底层收到的字节应含票据而非占位值。
    #[tokio::test]
    async fn 注入票据到session_id() {
        let plan = plan();
        let random = [0x11u8; 32];
        let hello = fake_client_hello(random);

        let mut sink = Vec::new();
        {
            let mut s = InjectingStream::new(&mut sink, plan.clone());
            s.write_all(&hello).await.unwrap();
            s.flush().await.unwrap();
        }

        assert_eq!(sink.len(), hello.len(), "长度必须不变（只替换 32 字节）");

        let (_, sid_off) = extract_hello_params(&sink).unwrap();
        let actual = &sink[sid_off..sid_off + 32];
        assert_ne!(actual, &[0xAAu8; 32], "占位值应被替换");

        let expect = plan.session_id_for(&random);
        assert_eq!(actual, &expect[..], "票据应与独立计算一致");
    }

    /// random 字段必须保持原样。
    #[tokio::test]
    async fn random保持不变() {
        let random = [0x77u8; 32];
        let hello = fake_client_hello(random);

        let mut sink = Vec::new();
        {
            let mut s = InjectingStream::new(&mut sink, plan());
            s.write_all(&hello).await.unwrap();
            s.flush().await.unwrap();
        }

        let (got, _) = extract_hello_params(&sink).unwrap();
        assert_eq!(got, random);
    }

    /// 分多次写入（模拟 TCP 背压）也必须正确注入。
    #[tokio::test]
    async fn 分多次写入仍能注入() {
        let plan = plan();
        let random = [0x22u8; 32];
        let hello = fake_client_hello(random);

        let mut sink = Vec::new();
        {
            let mut s = InjectingStream::new(&mut sink, plan.clone());
            for chunk in hello.chunks(10) {
                s.write_all(chunk).await.unwrap();
            }
            s.flush().await.unwrap();
        }

        assert_eq!(sink.len(), hello.len());
        let (_, sid_off) = extract_hello_params(&sink).unwrap();
        let expect = plan.session_id_for(&random);
        assert_eq!(&sink[sid_off..sid_off + 32], &expect[..]);
    }

    /// passthrough 模式不得修改任何字节。
    #[tokio::test]
    async fn 直通模式不修改() {
        let hello = fake_client_hello([0x33u8; 32]);
        let mut sink = Vec::new();
        {
            let mut s = InjectingStream::passthrough(&mut sink);
            s.write_all(&hello).await.unwrap();
            s.flush().await.unwrap();
        }
        assert_eq!(sink, hello);
    }

    /// 注入计划不得在 Debug 中泄露密钥。
    #[test]
    fn 注入计划调试不泄露私钥() {
        let s = format!("{:?}", plan());
        assert!(s.contains("已隐藏"));
    }

    /// 空 session_id 的 ClientHello 不应被破坏。
    #[tokio::test]
    async fn 空session_id时原样保留() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x44u8; 32]);
        body.push(0); // 空 session_id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut hs = vec![0x01u8];
        hs.extend_from_slice(&[
            ((body.len() >> 16) & 0xFF) as u8,
            ((body.len() >> 8) & 0xFF) as u8,
            (body.len() & 0xFF) as u8,
        ]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let mut sink = Vec::new();
        {
            let mut s = InjectingStream::new(&mut sink, plan());
            s.write_all(&rec).await.unwrap();
            s.flush().await.unwrap();
        }
        assert_eq!(sink, rec, "无法定位 session_id 时必须原样发出");
    }

    /// 不同时间窗口产生不同票据（客户端应使用约定的窗口）。
    #[test]
    fn 不同时间窗口票据不同() {
        let a = InjectPlan {
            auth: AuthKey::from_password(SECRET),
            now_unix: 1_700_000_000,
        };
        let b = InjectPlan {
            auth: AuthKey::from_password(SECRET),
            now_unix: 1_700_000_100,
        };
        let random = [0x55u8; 32];
        assert_ne!(a.session_id_for(&random), b.session_id_for(&random));
    }

    /// 同一 30 秒窗口内的不同时刻，票据应相同。
    ///
    /// 窗口号 = now_unix / 30。1700000001/30 与 1700000010/30 都是同一个窗口，
    /// 因此票据一致 —— 这正是"客户端与服务端时钟有几十秒偏差仍能认证"的原理。
    #[test]
    fn 同窗口内票据相同() {
        let mk = |t: u64| InjectPlan {
            auth: AuthKey::from_password(SECRET),
            now_unix: t,
        };
        let w0 = 1_700_000_000u64;
        let window_start = (w0 / TIME_WINDOW_SECS) * TIME_WINDOW_SECS;
        // 同窗口内的两个时刻
        let a = mk(window_start + 1);
        let b = mk(window_start + TIME_WINDOW_SECS - 1);
        let random = [0x66u8; 32];
        assert_eq!(
            a.session_id_for(&random),
            b.session_id_for(&random),
            "同一窗口内的票据必须相同"
        );

        // 跨到下一窗口则不同
        let c = mk(window_start + TIME_WINDOW_SECS + 1);
        assert_ne!(a.session_id_for(&random), c.session_id_for(&random));
    }
}
