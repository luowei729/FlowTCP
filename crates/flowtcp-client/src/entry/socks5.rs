//! SOCKS5 入口（RFC 1928 + RFC 1929 无认证 + UDP ASSOCIATE）
//!
//! # 支持的子命令
//!
//! | CMD | 名称 | 本实现 |
//! |-----|------|--------|
//! | 0x01 | CONNECT | ✅ 映射为 `OpenTcp` + 双向搬运 |
//! | 0x02 | BIND | ❌ 回 `0x07 Command not supported`（代理场景无意义） |
//! | 0x03 | UDP ASSOCIATE | ✅ 映射为 `OpenUdp` + SOCKS5 UDP 报文中继 |
//!
//! # UDP ASSOCIATE 的协议细节（最容易写错的地方）
//!
//! SOCKS5 的 UDP **不在** TCP 连接上传输。流程是：
//!
//! ```text
//! ① 客户端建 TCP 连接，发 05 03（UDP ASSOCIATE）
//! ② 服务端回复自己**另一个** UDP 端口的地址（BND.ADDR:BND.PORT）
//! ③ 客户端把 UDP 包发到那个地址，每个包自带目标地址头：
//!      +-----+------+------+----------+----------+----------+
//!      | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//!      +-----+------+------+----------+----------+----------+
//!      |  2  |  1   |  1   | Variable |    2     | Variable |
//! ④ **那条 TCP 连接必须保持打开** —— 它关闭即代表 UDP 关联结束
//! ```
//!
//! 第 ④ 点极易遗漏：如果实现里只处理 UDP 而让 TCP 立即关闭，
//! 浏览器会在几秒后停止发送 UDP（认为关联失效）。
//!
//! # 为什么默认启用 UDP
//!
//! 现代上网大量依赖 UDP：QUIC（HTTP/3）、DNS、WebRTC、游戏。
//! 只支持 TCP 的代理会让浏览器整体降级到 HTTP/2，且游戏/语音完全不可用。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use flowtcp_proto::frame::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::EntryError;
use crate::mux::Mux;

/// SOCKS 版本号。
const SOCKS5: u8 = 0x05;

/// 子命令。
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// 应答码。
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// 握手阶段超时。
///
/// 取 30 秒：远大于任何正常客户端（本机只需微秒），
/// 但足以让"只连不发"的探测连接被回收，不占端口。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// SOCKS5 监听循环。
pub async fn serve(addr: SocketAddr, mux: Arc<Mux>) -> Result<(), EntryError> {
    let listener = bind(addr).await?;
    serve_on(listener, mux).await
}

/// 只完成绑定（供测试拿到实际端口后再 `serve_on`）。
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, EntryError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| EntryError::Config(format!("SOCKS5 绑定 {addr} 失败: {e}")))
}

/// 在已绑定的 listener 上跑监听循环。
pub async fn serve_on(listener: TcpListener, mux: Arc<Mux>) -> Result<(), EntryError> {
    let actual = listener.local_addr()?;
    tracing::info!(%actual, "SOCKS5 正在监听");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // accept 失败通常是 fd 耗尽或瞬时错误，记录后继续
                tracing::warn!(error = %e, "SOCKS5 accept 失败");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);

        let m = Arc::clone(&mux);
        tokio::spawn(async move {
            match handle(sock, m, actual).await {
                Ok((up, down)) => {
                    tracing::debug!(%peer, up, down, "SOCKS5 连接结束");
                }
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "SOCKS5 连接错误");
                }
            }
        });
    }
}

/// 处理单个 SOCKS5 连接。
async fn handle(
    mut sock: TcpStream,
    mux: Arc<Mux>,
    listen_addr: SocketAddr,
) -> Result<(u64, u64), EntryError> {
    // ---- 1) 方法协商 ----
    tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate(&mut sock))
        .await
        .map_err(|_| EntryError::Protocol("SOCKS5 方法协商超时".into()))??;

    // ---- 2) 读请求 ----
    let req = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut sock))
        .await
        .map_err(|_| EntryError::Protocol("SOCKS5 请求读取超时".to_string()))??;

    match req.cmd {
        CMD_CONNECT => connect(sock, mux, req.target).await,
        CMD_UDP_ASSOCIATE => udp_associate(sock, mux, listen_addr, req.target).await,
        CMD_BIND => {
            // BIND 用于让代理监听一个端口供对端回连（FTP 主动模式等）。
            // FlowTCP 的模型是"客户端主动开流"，无法表达"让服务端回连"，
            // 因此明确拒绝而不是假装成功（假装会让客户端卡死等超时）。
            reply(&mut sock, REP_CMD_NOT_SUPPORTED, None).await?;
            Err(EntryError::Protocol("SOCKS5 BIND 不支持".into()))
        }
        other => {
            reply(&mut sock, REP_CMD_NOT_SUPPORTED, None).await?;
            Err(EntryError::Protocol(format!(
                "未知 SOCKS5 命令 0x{other:02X}"
            )))
        }
    }
}

/// 方法协商：只接受「无认证」。
///
/// # 为什么不做用户名/密码认证
///
/// 本地入口监听在 `127.0.0.1`（或用户明确指定的内网地址），
/// 使用者就是本机用户，再加一层密码只会让配置变复杂而不增加安全性。
/// 若确实需要，应在系统层用防火墙限制来源。
async fn negotiate(sock: &mut TcpStream) -> Result<(), EntryError> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != SOCKS5 {
        return Err(EntryError::Protocol(format!(
            "不是 SOCKS5（版本 0x{:02X}）",
            head[0]
        )));
    }
    let n = head[1] as usize;
    if n == 0 {
        return Err(EntryError::Protocol(
            "SOCKS5 客户端未提供任何认证方法".into(),
        ));
    }
    let mut methods = vec![0u8; n];
    sock.read_exact(&mut methods).await?;

    // 0x00 = 无认证。若客户端不支持，按 RFC 应回 0xFF
    if !methods.contains(&0x00) {
        sock.write_all(&[SOCKS5, 0xFF]).await?;
        return Err(EntryError::Protocol(
            "客户端不支持无认证方法（本代理仅支持 0x00）".into(),
        ));
    }
    sock.write_all(&[SOCKS5, 0x00]).await?;
    Ok(())
}

/// 已解析的 SOCKS5 请求。
struct Request {
    cmd: u8,
    target: Address,
}

/// 读 SOCKS5 请求。
///
/// 报文：`VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT`
///
/// 跳过前 3 字节后剩余部分与 [`Address::decode`] 的格式**完全一致**
/// （当初设计地址编码时就是按 SOCKS5 对齐的，因此这里零转换开销）。
async fn read_request(sock: &mut TcpStream) -> Result<Request, EntryError> {
    let mut head = [0u8; 3];
    sock.read_exact(&mut head).await?;
    if head[0] != SOCKS5 {
        return Err(EntryError::Protocol(format!(
            "请求版本异常 0x{:02X}",
            head[0]
        )));
    }
    let cmd = head[1];

    // 先读 1 字节 atyp，据此决定后续长度
    let mut atyp_buf = [0u8; 1];
    sock.read_exact(&mut atyp_buf).await?;

    let addr_len = match atyp_buf[0] {
        0x01 => 4,  // IPv4
        0x04 => 16, // IPv6
        0x03 => {
            // 域名：先读 1 字节长度
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => {
            reply(sock, REP_ATYP_NOT_SUPPORTED, None).await?;
            return Err(EntryError::Protocol(format!(
                "不支持的地址类型 0x{other:02X}"
            )));
        }
    };

    let mut rest = vec![0u8; addr_len + 2]; // + 端口 2 字节
    sock.read_exact(&mut rest).await?;

    // 拼成 Address::decode 期望的完整格式
    let mut full = Vec::with_capacity(1 + rest.len());
    full.push(atyp_buf[0]);
    if atyp_buf[0] == 0x03 {
        // 域名的长度字节也要带上
        full.push(addr_len as u8);
    }
    full.extend_from_slice(&rest);

    let (target, _used) = Address::decode(&full)
        .map_err(|e| EntryError::Protocol(format!("目标地址解析失败: {e}")))?;

    Ok(Request { cmd, target })
}

/// CONNECT：开一条 TCP 流并搬运。
async fn connect(
    mut sock: TcpStream,
    mux: Arc<Mux>,
    target: Address,
) -> Result<(u64, u64), EntryError> {
    let handle = mux.open_tcp(target.clone()).await?;

    // 成功应答：BND.ADDR/PORT 在代理语义下无意义，回全零即可
    // （真实 SOCKS5 服务器也普遍如此；浏览器不会校验它）
    reply(&mut sock, REP_SUCCESS, None).await?;

    super::pump(sock, handle).await
}

/// UDP ASSOCIATE：绑一个 UDP 端口，双向中继。
async fn udp_associate(
    mut sock: TcpStream,
    mux: Arc<Mux>,
    listen_addr: SocketAddr,
    _req_target: Address,
) -> Result<(u64, u64), EntryError> {
    // _req_target 通常是 0.0.0.0:0（客户端还不知道会用什么源地址），
    // 因此实际采用「从第一个 UDP 包学到源地址」的策略（见下）。

    // ---- 1) 绑定 UDP 端口 ----
    //
    // 绑定 IP 的选择：若 TCP 监听在 0.0.0.0，UDP 就绑 127.0.0.1 ——
    // 回给客户端 0.0.0.0 是非法目标地址，而客户端几乎总是从本机发起，
    // 127.0.0.1 是唯一可靠的通达地址。
    let bind_ip: IpAddr = match listen_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        other => other,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .map_err(|e| EntryError::Config(format!("UDP ASSOCIATE 绑定失败: {e}")))?;
    let udp_addr = udp.local_addr()?;
    let udp = Arc::new(udp);

    // ---- 2) 应答 BND = 刚绑定的 UDP 地址 ----
    reply(&mut sock, REP_SUCCESS, Some(udp_addr)).await?;

    // ---- 3) 开一条 UDP 会话流 ----
    //
    // 默认目标用一个占位地址：真正的目标在每帧的 HAS_ADDR 里带。
    // （SOCKS5 的 UDP 允许每个包发往不同目标，所以不能依赖默认目标。）
    let handle = mux
        .open_udp(Address::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))
        .await?;
    let (mut tx, mut rx) = handle.split();

    // 客户端 UDP 源地址：在收到第一个包时学到
    let peer: Arc<tokio::sync::Mutex<Option<SocketAddr>>> = Arc::new(tokio::sync::Mutex::new(None));

    // ---- 4) 上行：UDP socket → 隧道 ----
    let udp_up = Arc::clone(&udp);
    let peer_up = Arc::clone(&peer);
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut total = 0u64;
        loop {
            let (n, from) = match udp_up.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::trace!(error = %e, "UDP 接收失败");
                    break;
                }
            };

            // 学习客户端源地址（只接受第一个来源，防止被第三方注入）
            {
                let mut p = peer_up.lock().await;
                if p.is_none() {
                    *p = Some(from);
                } else if p.as_ref() != Some(&from) {
                    tracing::trace!(%from, "丢弃非关联源的 UDP 包");
                    continue;
                }
            }

            // 解析 SOCKS5 UDP 头：RSV(2) FRAG(1) ATYP ADDR PORT DATA
            if n < 4 {
                continue;
            }
            let frag = buf[2];
            if frag != 0 {
                // FRAG != 0 表示分片，本实现不支持（实际几乎无人使用）
                tracing::trace!(frag, "丢弃分片 UDP 包");
                continue;
            }
            let (target, used) = match Address::decode(&buf[3..n]) {
                Ok(v) => v,
                Err(e) => {
                    tracing::trace!(error = %e, "UDP 目标地址解析失败");
                    continue;
                }
            };
            let data = &buf[3 + used..n];

            if tx.send_datagram(&target, data).await.is_err() {
                break;
            }
            total += data.len() as u64;
        }
        total
    });

    // ---- 5) 下行：隧道 → UDP socket ----
    let udp_down = Arc::clone(&udp);
    let peer_down = Arc::clone(&peer);
    let down_task = tokio::spawn(async move {
        let mut total = 0u64;
        while let Some(f) = rx.recv().await {
            if f.frame_type == flowtcp_proto::frame::FrameType::Close {
                break;
            }
            if f.frame_type != flowtcp_proto::frame::FrameType::Data {
                continue;
            }

            // 组 SOCKS5 UDP 响应头
            let mut out = Vec::with_capacity(f.payload.len() + 22);
            out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
            out.extend_from_slice(&f.payload); // 服务端回包已带 HAS_ADDR 前缀

            let dest = *peer_down.lock().await;
            if let Some(dest) = dest {
                if udp_down.send_to(&out, dest).await.is_err() {
                    break;
                }
                total += f.payload.len() as u64;
            }
        }
        total
    });

    // ---- 6) 等 TCP 连接关闭（它代表 UDP 关联的生命周期）----
    //
    // 这是最容易漏的一步：UDP 关联的存活**由 TCP 连接的打开状态表达**。
    // 客户端关掉 TCP 就说明不再需要 UDP 中继，此时必须一并结束 UDP 任务，
    // 否则会留下一个永不回收的 UDP 端口和两条后台任务。
    let mut discard = [0u8; 1024];
    loop {
        match sock.read(&mut discard).await {
            Ok(0) => break,    // 客户端关闭
            Ok(_) => continue, // 忽略 TCP 上的任何内容
            Err(_) => break,
        }
    }

    up_task.abort();
    down_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let _ = up_task.await;
        let _ = down_task.await;
    })
    .await;

    tracing::debug!(%udp_addr, "UDP 关联结束");
    Ok((0, 0))
}

/// 发送 SOCKS5 应答。
///
/// `bnd` 为 `None` 时回 `0.0.0.0:0`。
async fn reply(sock: &mut TcpStream, code: u8, bnd: Option<SocketAddr>) -> Result<(), EntryError> {
    let mut out = vec![SOCKS5, code, 0x00];
    match bnd {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    sock.write_all(&out).await?;
    sock.flush().await?;
    Ok(())
}

/// 通用失败应答（供内部错误路径使用）。
pub async fn reply_failure(sock: &mut TcpStream) -> Result<(), EntryError> {
    reply(sock, REP_GENERAL_FAILURE, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个「浏览器」连接到给定 SOCKS5 服务端并走完协商。
    async fn socks5_handshake(addr: SocketAddr, cmd: u8, target: &Address) -> (TcpStream, Vec<u8>) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        // 方法协商
        s.write_all(&[SOCKS5, 1, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [SOCKS5, 0x00]);

        // 请求
        let mut req = vec![SOCKS5, cmd, 0x00];
        target.encode(&mut req).unwrap();
        s.write_all(&req).await.unwrap();

        // 读应答头
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let tail_len = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                l[0] as usize + 2
            }
            other => panic!("未知 atyp {other}"),
        };
        let mut tail = vec![0u8; tail_len];
        s.read_exact(&mut tail).await.unwrap();
        (s, head.to_vec())
    }

    #[tokio::test]
    async fn 拒绝非socks5客户端() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let mux = crate::testutil::mux_for_tests();

        tokio::spawn(async move { serve_accept_once(l, mux).await });

        let mut s = TcpStream::connect(addr).await.unwrap();
        // 发 HTTP 请求（不是 SOCKS5）
        s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 2];
        // 服务端应直接关闭
        let n = s.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "非 SOCKS5 应被关闭而不是回包");
    }

    /// 只 accept 一次然后处理（避免测试里起无限循环）。
    async fn serve_accept_once(l: TcpListener, mux: Arc<Mux>) {
        let (sock, _) = l.accept().await.unwrap();
        let addr = sock.local_addr().unwrap();
        let _ = handle(sock, mux, addr).await;
    }

    #[tokio::test]
    async fn bind命令被拒绝() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let mux = crate::testutil::mux_for_tests();
        tokio::spawn(async move { serve_accept_once(l, mux).await });

        let (_s, head) =
            socks5_handshake(addr, CMD_BIND, &Address::V4("1.2.3.4:80".parse().unwrap())).await;
        assert_eq!(head[1], REP_CMD_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn 不支持的地址类型被拒绝() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let mux = crate::testutil::mux_for_tests();
        tokio::spawn(async move { serve_accept_once(l, mux).await });

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[SOCKS5, 1, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.unwrap();

        // atyp = 0x02（非法）
        s.write_all(&[SOCKS5, CMD_CONNECT, 0x00, 0x02, 1, 2, 3, 4])
            .await
            .unwrap();
        let mut head = [0u8; 4];
        let r = s.read_exact(&mut head).await;
        // 服务端可能先回应答再断开
        if r.is_ok() {
            assert_eq!(head[1], REP_ATYP_NOT_SUPPORTED);
        }
    }
}
