//! TLS 指纹自检：把本客户端的 ClientHello 指纹送到外部检测服务，验证是否像 Chrome
//!
//! # 为什么需要这个命令
//!
//! 「指纹配好了」和「指纹真的像 Chrome」是两件事。BoringSSL 的参数只影响
//! ClientHello 的一部分维度，最终 JA3/JA4 由**实际发出的字节**决定。
//!
//! 本命令连接到公开的指纹检测 API（`tls.peet.ws` / `tls.browserleaks.com`），
//! 让服务端把收到的 ClientHello 解析成 JA3/JA4 返回，从而用**第三方视角**
//! 客观判断伪装是否成功 —— 这比自测可靠得多。
//!
//! # JA4 判断依据
//!
//! JA4 格式：`t13d1516h2_<cipher+ext 哈希>_<sigalg 哈希>`
//!
//! - `t13`：TLS 1.3
//! - `d`：域名 SNI
//! - `15`：cipher 数量
//! - `16`：extension 数量
//! - `h2`：ALPN 首个值
//! - 第二段是排序后的 cipher+extension 列表哈希 —— **这是 Chrome 的核心特征**
//!
//! Chrome 桌面版的该哈希稳定为 `8daaf6152771`（135+ 版本系列）。
//!
//! # 局限（必须诚实说明）
//!
//! - 检测服务会终结 TLS，因此只能看到 ClientHello 的**静态特征**
//! - GREASE 值随机 + extension 顺序随机化会让**数量**稳定、**顺序**每次不同，
//!   这正是 Chrome 的真实行为
//! - 若目标站点做主动探测（连回我们），JA4 不适用 —— 那是另一层防御

use std::time::Duration;

use flowtcp_tls::{FingerprintConfig, FingerprintProfile};

/// 默认检测端点（返回 JSON）。
const DEFAULT_ENDPOINT: &str = "tls.peet.ws";

/// 超时。
const TIMEOUT: Duration = Duration::from_secs(15);

/// 指纹自检错误。
#[derive(Debug, thiserror::Error)]
pub enum FpError {
    /// 连接失败（含 DNS 解析、超时）。
    #[error("连接 {addr} 失败: {source}")]
    Connect {
        /// 目标地址
        addr: String,
        /// 底层错误
        source: std::io::Error,
    },
    /// TLS 握手失败。
    #[error("TLS 握手失败: {0}")]
    Handshake(String),
    /// HTTP 请求/响应失败。
    #[error("HTTP 交互失败: {0}")]
    Http(String),
}

/// 执行指纹自检。
///
/// `endpoint` 形如 `tls.peet.ws`（不带 scheme）。
pub async fn check(endpoint: Option<&str>, profile: FingerprintProfile) -> Result<String, FpError> {
    let host = endpoint.unwrap_or(DEFAULT_ENDPOINT);
    let addr = format!("{host}:443");

    let stream = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| FpError::Connect {
            addr: addr.clone(),
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "连接超时"),
        })?
        .map_err(|source| FpError::Connect {
            addr: addr.clone(),
            source,
        })?;
    stream
        .set_nodelay(true)
        .map_err(|source| FpError::Connect {
            addr: addr.clone(),
            source,
        })?;

    let cfg = match profile {
        FingerprintProfile::Chrome => FingerprintConfig::chrome(),
        FingerprintProfile::Plain => FingerprintConfig::plain(),
    };

    let mut hs = flowtcp_tls::connect(stream, host, &cfg)
        .await
        .map_err(|e| FpError::Handshake(e.to_string()))?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 发一个最小 HTTP/1.1 请求。检测服务只看 ClientHello，所以路径无所谓。
    let req = format!("GET /api/all HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n");
    hs.stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| FpError::Http(e.to_string()))?;
    hs.stream
        .flush()
        .await
        .map_err(|e| FpError::Http(e.to_string()))?;

    // 读取完整响应（带总超时，避免对端不关连接导致挂死）
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, hs.stream.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).to_string();

    Ok(format_report(&text, host, hs.alpn.as_deref()))
}

/// 从 HTTP 响应中提取 JSON body。
fn body_of(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[i + 4..],
        None => resp,
    }
}

/// 从 JSON 文本中按 key 取出字符串值。
///
/// 手写极简提取器而不是引入 serde_json：
/// 本命令只用于人类阅读诊断，取错字段的后果只是显示不准，
/// 不值得为此增加一个依赖（本项目命令行工具体积敏感）。
fn json_str(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = json.find(&pat)?;
    let rest = &json[i + pat.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 格式化自检报告。
fn format_report(resp: &str, host: &str, alpn: Option<&[u8]>) -> String {
    let body = body_of(resp);
    let ja3 = json_str(body, "ja3").unwrap_or_else(|| "<未返回>".into());
    let ja3_hash = json_str(body, "ja3_hash").unwrap_or_else(|| "<未返回>".into());
    let ja4 = json_str(body, "ja4").unwrap_or_else(|| "<未返回>".into());

    let mut out = String::new();
    out.push_str(&format!("TLS 指纹自检（检测端点: {host}）\n\n"));
    out.push_str(&format!(
        "  协商 ALPN   : {}\n",
        alpn.map(|a| String::from_utf8_lossy(a).to_string())
            .unwrap_or_else(|| "<无>".into())
    ));
    out.push_str(&format!("  JA3         : {ja3}\n"));
    out.push_str(&format!("  JA3 哈希    : {ja3_hash}\n"));
    out.push_str(&format!("  JA4         : {ja4}\n"));

    // JA4 第二段是 Chrome 的核心特征
    if let Some(ja4_core) = ja4.split('_').nth(1) {
        out.push('\n');
        if ja4_core == "8daaf6152771" {
            out.push_str("  ✅ JA4 cipher/extension 哈希与 Chrome 一致（8daaf6152771）\n");
        } else {
            out.push_str(&format!(
                "  ⚠️  JA4 哈希为 {ja4_core}，Chrome 桌面版通常为 8daaf6152771\n"
            ));
            out.push_str("      可能原因：BoringSSL 版本差异、或目标网络插入了中间设备\n");
        }
    }

    // ALPN 必须含 h2
    out.push('\n');
    match alpn {
        Some(a) if a == b"h2" => out.push_str("  ✅ ALPN 协商为 h2\n"),
        Some(a) => out.push_str(&format!(
            "  ⚠️  ALPN 为 {}，Chrome 会优先 h2\n",
            String::from_utf8_lossy(a)
        )),
        None => out.push_str("  ⚠️  未协商出 ALPN\n"),
    }

    out.push_str("\n  提示：JA4 仅反映 ClientHello 静态特征。\n");
    out.push_str("        主动探测抗性还需要服务端「真证书 + 真网站 fallback」配合。\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 提取http响应体() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ja4\":\"x\"}";
        assert_eq!(body_of(resp), "{\"ja4\":\"x\"}");
    }

    #[test]
    fn 提取json字段() {
        let json = r#"{"ja3":"771,4865","ja3_hash":"abc","ja4":"t13d1516h2_8daaf6152771_xyz"}"#;
        assert_eq!(json_str(json, "ja3").as_deref(), Some("771,4865"));
        assert_eq!(json_str(json, "ja3_hash").as_deref(), Some("abc"));
        assert_eq!(
            json_str(json, "ja4").as_deref(),
            Some("t13d1516h2_8daaf6152771_xyz")
        );
        assert_eq!(json_str(json, "missing"), None);
    }

    #[test]
    fn 报告识别chrome哈希() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n{\"ja3\":\"771,1\",\"ja3_hash\":\"h\",\"ja4\":\"t13d1516h2_8daaf6152771_sig\"}";
        let r = format_report(resp, "tls.peet.ws", Some(b"h2"));
        assert!(r.contains("Chrome 一致"));
        assert!(r.contains("ALPN 协商为 h2"));
    }

    #[test]
    fn 报告识别非chrome哈希() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n{\"ja3\":\"771,1\",\"ja3_hash\":\"h\",\"ja4\":\"t13d3112h2_e8f1e7e78f70_sig\"}";
        let r = format_report(resp, "tls.peet.ws", Some(b"h2"));
        assert!(r.contains("Chrome 桌面版通常为"));
        assert!(r.contains("e8f1e7e78f70"));
    }

    #[test]
    fn 报告处理缺失字段() {
        let r = format_report("HTTP/1.1 500\r\n\r\n", "x", None);
        assert!(r.contains("<未返回>"));
        assert!(r.contains("未协商出 ALPN"));
    }
}
