//! 可「掏空」的流包装：让 TLS 握手结束后能取回底层字节流
//!
//! # 为什么需要它（Phase 3 的关键基建）
//!
//! FlowTCP 的核心设计是「**握手用 TLS，数据传输不用 TLS**」：
//!
//! ```text
//! ① TLS 1.3 握手          → 认证 + exporter 派生密钥（形态像真 HTTPS）
//! ② 握手完成后取回裸字节流  → 改用自研记录层（显式序号，容忍乱序）
//! ```
//!
//! 但 `tokio_boring::SslStream<S>` **独占**着底层流：它只有 `get_ref()` /
//! `get_mut()`，**没有 `into_inner()`**。也就是说，握手完成后我们拿不回 `S`，
//! 只能继续用 TLS 记录层收发 —— 那就丧失了乱序容忍（TLS 记录层用隐式序号，
//! 丢一个包后续全部失步），项目核心价值直接归零。
//!
//! # 解法
//!
//! 握手前把 `S` 装进 `Takeable`，握手后用 `SslStream::get_mut()` 拿到
//! `&mut Takeable<S>`，再 `take()` 把 `S` 取走：
//!
//! ```text
//! let mut tls = accept(&acceptor, Takeable::new(tcp)).await?;
//! let keys    = derive_flow_keys(tls.ssl())?;
//! let raw     = tls.get_mut().take();   // ★ 拿回 TcpStream
//! ```
//!
//! # 安全性
//!
//! - 全程无 `unsafe`（本 crate 有 `#![deny(unsafe_code)]`）
//! - `take()` 只能成功一次；之后任何 IO 都返回明确错误而非 panic
//!   （panic 会带着整条连接上下文崩溃，排查困难）

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 可被取走内部流的一次性包装。
///
/// 只在「TLS 握手 → 切换记录层」这个过渡期使用，不要用于常规 IO 路径。
pub struct Takeable<S> {
    inner: Option<S>,
}

impl<S> Takeable<S> {
    /// 包装一个流。
    pub fn new(stream: S) -> Self {
        Takeable {
            inner: Some(stream),
        }
    }

    /// 取回内部流。
    ///
    /// 只能成功调用一次。第二次返回 `None` —— 用 `Option` 而非 `expect`
    /// 让调用方显式处理「重复取走」这种编程错误。
    pub fn take(&mut self) -> Option<S> {
        self.inner.take()
    }

    /// 是否已被取走。
    pub fn is_taken(&self) -> bool {
        self.inner.is_none()
    }

    /// 内部流的只读引用（未取走时）。
    pub fn peek(&self) -> Option<&S> {
        self.inner.as_ref()
    }
}

/// 已被取走后的统一错误。
///
/// 选择返回 `Other` 而不是 `BrokenPipe`：这是**我们自己的编程错误**，
/// 不是对端断连，日志里需要能一眼区分。
fn taken_error() -> io::Error {
    io::Error::other("Takeable 内部流已被取走（TLS 握手后不应再对该流做 IO）")
}

impl<S: AsyncRead + Unpin> AsyncRead for Takeable<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(s) => Pin::new(s).poll_read(cx, buf),
            None => Poll::Ready(Err(taken_error())),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Takeable<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.inner.as_mut() {
            Some(s) => Pin::new(s).poll_write(cx, buf),
            None => Poll::Ready(Err(taken_error())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(s) => Pin::new(s).poll_flush(cx),
            None => Poll::Ready(Err(taken_error())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.as_mut() {
            Some(s) => Pin::new(s).poll_shutdown(cx),
            None => Poll::Ready(Ok(())), // 已取走视为已关闭，不算错误
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn 取走后io返回明确错误() {
        let (a, _b) = tokio::io::duplex(64);
        let mut t = Takeable::new(a);
        assert!(!t.is_taken());
        assert!(t.peek().is_some());

        let taken = t.take();
        assert!(taken.is_some());
        assert!(t.is_taken());
        assert!(t.peek().is_none());

        // 第二次取走必须返回 None（不 panic）
        assert!(t.take().is_none());

        // 取走后写入必须报错且错误信息可读
        use tokio::io::AsyncWriteExt;
        let err = t.write_all(b"x").await.expect_err("应报错");
        assert!(
            err.to_string().contains("已被取走"),
            "错误信息应能一眼识别，实际: {err}"
        );
    }

    #[tokio::test]
    async fn 未取走时io正常() {
        // 注意：`AsyncReadExt` 里也有 `take(limit)` 方法，会遮蔽本类型的 `take()`。
        // 这里只导入需要的 trait，避免同名方法解析歧义。
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // ★ duplex 是**双向**管道：`b.write` 的数据才由 `a.read` 读到。
        //   若写成 `a.write_all("hello")` 再 `a.read_exact(..)`，会永远等不到数据
        //   —— 这正是本测试最初挂起 60 秒的原因。
        let (a, mut b) = tokio::io::duplex(64);

        // ① 未取走时 Takeable 的读能正常工作
        b.write_all(b"hello").await.unwrap();
        let mut t = Takeable::new(a);
        let mut buf = [0u8; 5];
        t.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // ② 未取走时的写也能正常到达对端
        t.write_all(b"world").await.unwrap();
        let mut buf2 = [0u8; 5];
        b.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"world");

        // ③ 取回底层流后仍可继续读写（证明 take 没有破坏连接）
        b.write_all(b"after").await.unwrap();
        let taken = Takeable::take(&mut t).expect("应能取回");
        let mut a2 = taken;
        let mut buf3 = [0u8; 5];
        a2.read_exact(&mut buf3).await.unwrap();
        assert_eq!(&buf3, b"after");
    }
}
