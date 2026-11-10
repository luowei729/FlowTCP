//! 预置缓冲流：把已读取的字节"还回"给下游消费者
//!
//! # 为什么需要它
//!
//! 服务端的判定流程是：
//!
//! ```text
//! 1. 从 TCP 流读若干个字节 → 解析出 ClientHello
//! 2. 用 ClientHello 里的 session_id 做认证裁决
//! 3a. 认证通过 → 交给 BoringSSL 完成 TLS 握手
//! 3b. 认证失败 → 把字节流透传给真实网站
//! ```
//!
//! 问题在第 3a 步：ClientHello 已经被我们**读走**了，而 BoringSSL 的握手
//! 是要自己从流里读 ClientHello 的。若不还回去，BoringSSL 会读到
//! ClientHello 之后的字节，握手必然失败。
//!
//! # 解法
//!
//! 用一层包装器把"已读前缀"放在逻辑流的最前面：
//!
//! ```text
//! 逻辑流 = [已读前缀 (N 字节)] ++ [底层流的剩余部分]
//! ```
//!
//! 读操作先消费前缀，前缀读完后自动透传到底层流。写操作直接透传。
//!
//! 这比"让 BoringSSL 支持外部注入 ClientHello"简单得多，且不侵入第三方库。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 带预置前缀的流包装器。
///
/// 对上层表现为「前缀 + 底层流」的连续字节流。
#[derive(Debug)]
pub struct PrebufferedStream<S> {
    /// 尚未被消费的前缀。
    prefix: Vec<u8>,
    /// 已消费到的位置（避免每次从 Vec 头部删除，O(n) 拷贝）。
    prefix_pos: usize,
    /// 底层流。
    inner: S,
}

impl<S> PrebufferedStream<S> {
    /// 用前缀包装底层流。
    ///
    /// `prefix` 会先于 `inner` 的任何字节被读出。
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrebufferedStream {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// 前缀中尚未消费的字节数。
    pub fn remaining_prefix(&self) -> usize {
        self.prefix.len().saturating_sub(self.prefix_pos)
    }

    /// 取回底层流（丢弃未消费前缀）。
    ///
    /// 用于「先探测再决定」的场景：若最终决定不用这个流，可拿回原始对象。
    /// **注意**：未消费的前缀会丢失，调用方需自行处理。
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 取回底层流，同时返回未消费的前缀。
    ///
    /// 这是更安全的版本：调用方可以拿到完整信息，避免数据丢失。
    pub fn into_parts(self) -> (Vec<u8>, S) {
        let rest = self.prefix[self.prefix_pos..].to_vec();
        (rest, self.inner)
    }

    /// 底层流的引用。
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// 底层流的可变引用。
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrebufferedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 优先消费前缀
        let remaining = this.prefix.len() - this.prefix_pos;
        if remaining > 0 {
            let n = remaining.min(buf.remaining());
            buf.put_slice(&this.prefix[this.prefix_pos..this.prefix_pos + n]);
            this.prefix_pos += n;

            // 前缀消费完毕后释放内存：ClientHello 可达数 KB，
            // 几十万并发连接下这个 Vec 不释放会占用大量内存。
            if this.prefix_pos >= this.prefix.len() {
                this.prefix = Vec::new();
                this.prefix_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 前缀已空，透传到底层
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrebufferedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn 前缀先于底层被读出() {
        // 底层流用 io::Cursor 模拟（内存中的可读数据）
        let inner = std::io::Cursor::new(b"WORLD".to_vec());
        let mut s = PrebufferedStream::new(b"HELLO".to_vec(), inner);

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out, b"HELLOWORLD");
    }

    #[tokio::test]
    async fn 前缀为空时等同底层() {
        let inner = std::io::Cursor::new(b"DATA".to_vec());
        let mut s = PrebufferedStream::new(Vec::new(), inner);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out, b"DATA");
    }

    #[tokio::test]
    async fn 小缓冲多次读取() {
        let inner = std::io::Cursor::new(b"0123456789".to_vec());
        let mut s = PrebufferedStream::new(b"ABCDE".to_vec(), inner);

        // 每次只读 2 字节，验证跨前缀/底层边界时不丢数据
        let mut all = Vec::new();
        let mut buf = [0u8; 2];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&all, b"ABCDE0123456789");
    }

    #[tokio::test]
    async fn 剩余前缀计数正确() {
        let inner = std::io::Cursor::new(Vec::new());
        let mut s = PrebufferedStream::new(b"12345".to_vec(), inner);
        assert_eq!(s.remaining_prefix(), 5);
        let mut buf = [0u8; 2];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(s.remaining_prefix(), 3);
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(s.remaining_prefix(), 0);
    }

    #[tokio::test]
    async fn 可取回未消费前缀() {
        let inner = std::io::Cursor::new(b"XYZ".to_vec());
        let mut s = PrebufferedStream::new(b"ABC".to_vec(), inner);
        let mut buf = [0u8; 1];
        let _ = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"A");

        let (rest, _inner) = s.into_parts();
        assert_eq!(&rest, b"BC");
    }

    #[tokio::test]
    async fn 写入直接透传() {
        let mut inner = Vec::new();
        {
            let mut s = PrebufferedStream::new(b"prefix".to_vec(), &mut inner);
            s.write_all(b"written").await.unwrap();
            s.flush().await.unwrap();
        }
        assert_eq!(&inner, b"written");
    }
}
