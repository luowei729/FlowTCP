//! HTTP 代理入口（明文）
//!
//! # 支持的两类请求
//!
//! ## ① CONNECT 隧道（HTTPS 网站的标准做法）
//!
//! ```text
//! C→S: CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n
//! S→C: HTTP/1.1 200 Connection Established\r\n\r\n
//! C→S: <任意字节流（TLS 等）>
//! ```
//!
//! 协商完成后这条连接变成**纯字节管道**，与 SOCKS5 CONNECT 等价。
//!
//! ## ② 绝对 URI 转发（明文 HTTP 网站）
//!
//! ```text
//! C→S: GET http://www.example.com/a?b=1 HTTP/1.1\r\nHost: www.example.com\r\n\r\n
//! ```
//!
//! 需要把请求行里的**绝对 URI 改写为 origin-form**（`GET /a?b=1`）再转发，
//! 否则真实服务器会返回 400 —— 它只认 `GET /path`。
//!
//! # 已知限制（有意为之）
//!
//! **只改写首个请求**。之后的 keep-alive 请求如果是 origin-form 可正常工作
//! （浏览器在同一个 CONNECT 隧道里发的都是 origin-form）；
//! 但某些工具会在同一条连接上连续发**绝对 URI** 请求，此时第二个请求会
//! 带着绝对 URI 被转发出去，服务器返回 400。
//!
//! 为什么不实现完整的 HTTP 字节流解析器：
//! - 需要处理 chunked、100-continue、WebSocket 升级、h2 前言等大量分支
//! - 每条分支都是潜在的解析漏洞（HTTP 请求走私）
//! - 而收益极小：现代流量 99% 是 HTTPS，走 CONNECT 分支
//!
//! 需要完整 HTTP 代理能力时，正确做法是用成熟实现（如 hyper）专门做一层，
//! 而不是在协议栈里手写半个解析器。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flowtcp_proto::frame::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::base64;
use super::EntryError;
use crate::config::ProxyAuth;
use crate::mux::Mux;

/// 头部读取上限。
///
/// 取 32KB：远超正常请求头（通常 <2KB，甚至 <8KB 的极端 cookie 也够），
/// 同时限制单连接内存，防止恶意客户端用超长头部耗尽内存。
pub const MAX_HEADER: usize = 32 * 1024;

/// 读取请求头的超时。
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP 代理监听循环。
pub async fn serve(
    addr: SocketAddr,
    mux: Arc<Mux>,
    auth: Option<Arc<ProxyAuth>>,
) -> Result<(), EntryError> {
    let listener = bind(addr).await?;
    serve_on(listener, mux, auth).await
}

/// 只完成绑定（供测试拿到实际端口后再 `serve_on`）。
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, EntryError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| EntryError::Config(format!("HTTP 代理绑定 {addr} 失败: {e}")))
}

/// 在已绑定的 listener 上跑监听循环。
pub async fn serve_on(
    listener: TcpListener,
    mux: Arc<Mux>,
    auth: Option<Arc<ProxyAuth>>,
) -> Result<(), EntryError> {
    let actual = listener.local_addr()?;
    if auth.is_some() {
        tracing::info!(%actual, "HTTP 代理正在监听（已启用 Basic 认证）");
    } else {
        tracing::info!(%actual, "HTTP 代理正在监听");
    }

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "HTTP 代理 accept 失败");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let m = Arc::clone(&mux);
        let a = auth.clone();
        tokio::spawn(async move {
            match handle(sock, m, a).await {
                Ok((up, down)) => tracing::debug!(%peer, up, down, "HTTP 代理连接结束"),
                Err(e) => tracing::debug!(%peer, error = %e, "HTTP 代理连接错误"),
            }
        });
    }
}

/// 处理单个 HTTP 代理连接。
///
/// 泛型化是为了让 HTTPS 入口复用同一套逻辑：
/// HTTPS 入口只是在 `TcpStream` 之上多包一层 TLS，
/// 之后的 HTTP 解析与转发完全一致。
pub async fn handle<S>(
    mut sock: S,
    mux: Arc<Mux>,
    auth: Option<Arc<ProxyAuth>>,
) -> Result<(u64, u64), EntryError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // ---- 1) 读请求头 ----
    let (head, rest) = tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut sock))
        .await
        .map_err(|_| EntryError::Protocol("读取 HTTP 请求头超时".into()))??;

    let text = String::from_utf8_lossy(&head);

    // ---- 1.5) 代理认证（RFC 7235 Basic）----
    //
    // 必须在解析请求行之前完成：认证失败时不该泄漏任何"这个代理能做什么"
    // 的信息（连请求行是否合法都不该回应）。
    if let Some(a) = auth.as_deref() {
        if !check_proxy_auth(&text, a) {
            // 407 + 挑战头。stale=FALSE 表示凭据本身错，重新输入即可。
            let body = b"407 Proxy Authentication Required";
            let resp = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"FlowTCP\"\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
            tracing::warn!("HTTP 代理认证失败（缺少或错误的 Proxy-Authorization）");
            return Err(EntryError::Protocol("HTTP 代理认证失败".into()));
        }
    }

    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or("HTTP/1.1");

    // ---- 2) CONNECT：直接建隧道 ----
    if method.eq_ignore_ascii_case("CONNECT") {
        let addr = parse_host_port(target)?;
        let handle = mux.open_tcp(addr).await?;
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;

        // 头部读取时可能已多读到客户端的首批数据（TLS ClientHello），
        // 必须原样转发，否则握手会卡住 —— 这是最容易漏的一步。
        let mut tx_rx = handle;
        if !rest.is_empty() {
            tx_rx.sender.send_data(&rest).await?;
        }
        return super::pump(sock, tx_rx).await;
    }

    // ---- 3) 绝对 URI：改写请求行后转发 ----
    let (addr, path) = parse_absolute_uri(target)?;
    let handle = mux.open_tcp(addr).await?;

    // 重建请求头：请求行换成 origin-form，其余头部原样保留
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
    for line in lines {
        // 空行之后是 body，不属于头部（read_header 已按 \r\n\r\n 切开，这里是最后一段）
        if line.is_empty() {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rest);

    let mut handle = handle;
    handle.sender.send_data(&out).await?;
    super::pump(sock, handle).await
}

/// 校验请求头里的 `Proxy-Authorization`。
///
/// # 报文
///
/// ```text
/// Proxy-Authorization: Basic <base64(username:password)>
/// ```
///
/// # 三个实现细节
///
/// 1. **头名大小写不敏感**（RFC 7230 §3.2）：HTTP 头名不区分大小写，
///    浏览器实际发的可能是 `proxy-authorization`。
/// 2. **常量时间比较**：解码后逐字节异或累加，不提前返回
///    （与 SOCKS5 认证保持一致的实现标准）。
/// 3. **拒绝非 Basic 方案**：Bearer / Digest / Negotiate 一律当失败。
///    只接受我们声明支持的那一种，避免未来被加入未测试的认证路径。
fn check_proxy_auth(head: &str, auth: &ProxyAuth) -> bool {
    const PREFIX: &str = "proxy-authorization:";

    let mut value = None;
    for line in head.split("\r\n") {
        // 只按第一个 ':' 切分（头值里可能含冒号，如 base64 本身不会但不该假设）
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(PREFIX.trim_end_matches(':')) {
            value = Some(val.trim());
            break;
        }
    }
    let Some(value) = value else {
        return false;
    };

    // 必须是指定方案（大小写不敏感），后接任意数量空白
    let Some((scheme, encoded)) = value.split_once(char::is_whitespace) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }

    let Some(raw) = base64::decode(encoded.trim()) else {
        return false;
    };
    let Some((user, pass)) = split_credentials(&raw) else {
        return false;
    };

    let user_ok = super::ct_eq(user, auth.username.as_bytes());
    let pass_ok = super::ct_eq(pass, auth.password.as_bytes());
    user_ok & pass_ok
}

/// 把 `user:pass` 字节串按**第一个**冒号切开。
///
/// 与 [`ProxyAuth::parse`] 保持一致的语义：密码里允许含冒号。
fn split_credentials(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = raw.iter().position(|&b| b == b':')?;
    Some((&raw[..pos], &raw[pos + 1..]))
}

/// 读 HTTP 请求头，返回 `(含 \r\n\r\n 的头部, 其后已读到的字节)`。
///
/// # 为什么必须返回 `rest`
///
/// TCP 是字节流，一次 `read` 很可能把「请求头 + body 开头」一起读进来。
/// 如果只保留头部而丢弃 `rest`，POST 请求会丢 body，
/// CONNECT 请求会丢 TLS ClientHello 的前几个字节 —— 两者都表现为
/// "连接建立了但对面一直不响应"，极难排查。
async fn read_header<S>(sock: &mut S) -> Result<(Vec<u8>, Vec<u8>), EntryError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Err(EntryError::Protocol("连接在 HTTP 请求头完成前关闭".into()));
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = find_header_end(&buf) {
            let head = buf[..pos].to_vec();
            let rest = buf[pos..].to_vec();
            return Ok((head, rest));
        }
        if buf.len() > MAX_HEADER {
            return Err(EntryError::Protocol(format!(
                "HTTP 请求头超过 {MAX_HEADER} 字节"
            )));
        }
    }
}

/// 查找 `\r\n\r\n` 的位置，返回**分隔符之后**的下标。
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// 解析 `host:port`（CONNECT 目标）。
///
/// 端口缺省补 443（CONNECT 绝大多数是 HTTPS）。
fn parse_host_port(s: &str) -> Result<Address, EntryError> {
    // IPv6 字面量：[::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_part, after) = rest
            .split_once(']')
            .ok_or_else(|| EntryError::Protocol(format!("IPv6 目标格式错误: {s}")))?;
        let ip: std::net::Ipv6Addr = ip_part
            .parse()
            .map_err(|e| EntryError::Protocol(format!("IPv6 地址非法 {ip_part}: {e}")))?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);
        return Ok(Address::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)));
    }

    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            let port: u16 = port_str
                .parse()
                .map_err(|_| EntryError::Protocol(format!("端口非法: {port_str}")))?;
            // 主机是 IP 还是域名？
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                Ok(Address::V4(std::net::SocketAddrV4::new(ip, port)))
            } else {
                Ok(Address::Domain(host.to_string(), port))
            }
        }
        None => {
            if s.is_empty() {
                return Err(EntryError::Protocol("CONNECT 目标为空".into()));
            }
            Ok(Address::Domain(s.to_string(), 443))
        }
    }
}

/// 解析绝对 URI，返回 `(目标地址, origin-form 路径)`。
///
/// 例：`http://example.com/a?b=1` → `(Domain("example.com", 80), "/a?b=1")`
fn parse_absolute_uri(uri: &str) -> Result<(Address, String), EntryError> {
    let rest = uri
        .strip_prefix("http://")
        .ok_or_else(|| EntryError::Protocol(format!("不支持的 URI 形式: {uri}")))?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(EntryError::Protocol(format!("URI 缺少主机: {uri}")));
    }

    // 绝对 URI 的默认端口是 80（HTTPS 走 CONNECT，不会到这里）
    let addr = if authority.contains(':') {
        parse_host_port(authority)?
    } else {
        parse_host_port(&format!("{authority}:80"))?
    };

    Ok((addr, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[test]
    fn 解析connect目标() {
        assert_eq!(
            parse_host_port("example.com:443").unwrap(),
            Address::Domain("example.com".into(), 443)
        );
        assert_eq!(
            parse_host_port("1.2.3.4:8080").unwrap(),
            Address::V4("1.2.3.4:8080".parse().unwrap())
        );
        // 缺省端口补 443
        assert_eq!(
            parse_host_port("example.com").unwrap(),
            Address::Domain("example.com".into(), 443)
        );
        // IPv6
        assert_eq!(
            parse_host_port("[::1]:8443").unwrap(),
            Address::V6("[::1]:8443".parse().unwrap())
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]").unwrap(),
            Address::V6("[2001:db8::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn 解析绝对uri() {
        assert_eq!(
            parse_absolute_uri("http://example.com/a?b=1").unwrap(),
            (
                Address::Domain("example.com".into(), 80),
                "/a?b=1".to_string()
            )
        );
        // 无路径
        assert_eq!(
            parse_absolute_uri("http://example.com").unwrap(),
            (Address::Domain("example.com".into(), 80), "/".to_string())
        );
        // 带端口
        assert_eq!(
            parse_absolute_uri("http://example.com:8080/x").unwrap(),
            (
                Address::Domain("example.com".into(), 8080),
                "/x".to_string()
            )
        );
        // 非 http:// 前缀必须报错（https 走 CONNECT）
        assert!(parse_absolute_uri("https://example.com/").is_err());
        assert!(parse_absolute_uri("/just/a/path").is_err());
    }

    #[test]
    fn 查找头部结束位置() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(find_header_end(b"\r\n\r\nbody"), Some(4));
    }

    #[test]
    fn 端口非法时报错() {
        assert!(parse_host_port("example.com:abc").is_err());
        assert!(parse_host_port("").is_err());
    }

    #[tokio::test]
    async fn 读头部时保留多余字节() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();

        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            read_header(&mut s).await.unwrap()
        });

        let mut c = TcpStream::connect(addr).await.unwrap();
        // 一次性写入「头部 + body」，模拟真实客户端
        c.write_all(b"POST /x HTTP/1.1\r\nHost: a\r\n\r\nBODY")
            .await
            .unwrap();

        let (head, rest) = h.await.unwrap();
        assert_eq!(head, b"POST /x HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(rest, b"BODY", "头部之后的多余字节必须保留");
    }

    // ---- HTTP Basic 代理认证（RFC 7235）----

    /// 启动一个启用认证的 HTTP 代理，返回监听地址。
    async fn serve_with_auth() -> SocketAddr {
        let (client, _server) = crate::testutil::tunnel_pair();
        let mux = Arc::new(Mux::spawn(client, 8, 1400));
        let l = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = l.local_addr().unwrap();
        let auth = Arc::new(ProxyAuth {
            username: "admin".into(),
            password: "abcd1234".into(),
        });
        tokio::spawn(async move { serve_on(l, mux, Some(auth)).await });
        addr
    }

    /// 发一段原始请求，返回完整响应（读到 EOF）。
    async fn raw_request(addr: SocketAddr, req: &[u8]) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn 无凭据返回407并带挑战头() {
        let addr = serve_with_auth().await;
        let resp = raw_request(
            addr,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "应返回 407，实际: {resp}");
        assert!(
            resp.contains("Proxy-Authenticate: Basic"),
            "必须带 Basic 挑战头，否则客户端不知道该发什么凭据"
        );
    }

    #[tokio::test]
    async fn 错误的basic凭据返回407() {
        let addr = serve_with_auth().await;
        // base64("admin:wrongpass") = "YWRtaW46d3JvbmdwYXNz"
        let req = b"CONNECT example.com:443 HTTP/1.1\r\n\
                    Proxy-Authorization: Basic YWRtaW46d3JvbmdwYXNz\r\n\r\n";
        let resp = raw_request(addr, req).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "错误密码应 407");
    }

    #[tokio::test]
    async fn 非法base64返回407() {
        let addr = serve_with_auth().await;
        let req = b"CONNECT example.com:443 HTTP/1.1\r\n\
                    Proxy-Authorization: Basic !!!notbase64!!!\r\n\r\n";
        let resp = raw_request(addr, req).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "非法 base64 应 407");
    }

    #[tokio::test]
    async fn 非basic方案被拒绝() {
        let addr = serve_with_auth().await;
        let req = b"CONNECT example.com:443 HTTP/1.1\r\n\
                    Proxy-Authorization: Bearer sometoken\r\n\r\n";
        let resp = raw_request(addr, req).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "只支持 Basic，其他方案应 407");
    }

    #[tokio::test]
    async fn 头名大小写不敏感() {
        // RFC 7230 §3.2：HTTP 头名不区分大小写
        let addr = serve_with_auth().await;
        let req = b"CONNECT example.com:443 HTTP/1.1\r\n\
                    proxy-authorization: basic YWRtaW46YWJjZDEyMzQ=\r\n\r\n";
        let resp = raw_request(addr, req).await;
        // 凭据正确 → 不应是 407（会尝试建隧道，可能因 DNS 失败而空响应）
        assert!(
            !resp.starts_with("HTTP/1.1 407"),
            "小写头名 + 小写 basic 应通过认证，实际: {resp}"
        );
    }

    #[test]
    fn 凭据切分按第一个冒号() {
        assert_eq!(
            split_credentials(b"admin:abcd1234"),
            Some((&b"admin"[..], &b"abcd1234"[..]))
        );
        // 密码含冒号
        assert_eq!(
            split_credentials(b"u:p:a:ss"),
            Some((&b"u"[..], &b"p:a:ss"[..]))
        );
        assert_eq!(split_credentials(b"nocolon"), None);
        // 空用户名/密码也要能切出来（由上层决定是否合法）
        assert_eq!(split_credentials(b":x"), Some((&b""[..], &b"x"[..])));
    }

    #[test]
    fn 认证头解析各种变体() {
        let auth = ProxyAuth {
            username: "admin".into(),
            password: "abcd1234".into(),
        };
        let good = "YWRtaW46YWJjZDEyMzQ=";

        // 标准形式
        assert!(check_proxy_auth(
            &format!("GET / HTTP/1.1\r\nProxy-Authorization: Basic {good}\r\n"),
            &auth
        ));
        // 头名与方案都小写
        assert!(check_proxy_auth(
            &format!("GET / HTTP/1.1\r\nproxy-authorization: basic {good}\r\n"),
            &auth
        ));
        // 前后多余空白
        assert!(check_proxy_auth(
            &format!("GET / HTTP/1.1\r\nProxy-Authorization:  Basic  {good}  \r\n"),
            &auth
        ));
        // 没有该头
        assert!(!check_proxy_auth("GET / HTTP/1.1\r\nHost: x\r\n", &auth));
        // 方案缺失
        assert!(!check_proxy_auth(
            &format!("GET / HTTP/1.1\r\nProxy-Authorization: {good}\r\n"),
            &auth
        ));
    }
}
