//! 客户端配置

use std::net::SocketAddr;
use std::path::PathBuf;

use flowtcp_proto::steal::AuthKey;

/// HTTPS 入口的证书来源。
///
/// # 默认自签的理由
///
/// 本地 HTTPS 代理是「浏览器 ↔ 本机进程」的连接，**不经过公网**，
/// 因此证书的公信力毫无意义 —— 它的唯一作用是让浏览器愿意建立 TLS。
///
/// 默认自签的好处：零配置、零申请流程，第一次启动就可用。
/// 代价是浏览器会提示「不安全」，需要用户手动信任一次
/// （或把证书导入系统信任库，一次永久生效）。
///
/// 若要完全消除提示，用 [`HttpsCert::Files`] 指定一张浏览器已信任的证书
/// （例如自己的域名证书，或导入过系统信任库的自签证书）。
#[derive(Debug, Clone)]
pub enum HttpsCert {
    /// 自签证书：启动时生成，有效期 10 年。
    ///
    /// `san` 为空时自动使用 `localhost` + `127.0.0.1`。
    SelfSigned {
        /// 证书 SAN（域名列表）。空则用默认值。
        san: Vec<String>,
    },
    /// 用户指定的证书与私钥（PEM 文件）。
    Files {
        /// 证书链 PEM 路径。
        cert_path: PathBuf,
        /// 私钥 PEM 路径。
        key_path: PathBuf,
    },
}

impl Default for HttpsCert {
    fn default() -> Self {
        HttpsCert::SelfSigned { san: Vec::new() }
    }
}

/// 各入口监听地址。
///
/// 全部为 `Option`：只要至少启用一个即可。默认只开 SOCKS5
/// （最通用、无证书问题、系统级代理设置都支持）。
#[derive(Debug, Clone, Default)]
pub struct EntryAddrs {
    /// SOCKS5 入口（TCP CONNECT + UDP ASSOCIATE）。
    pub socks5: Option<SocketAddr>,
    /// HTTP 代理入口（明文）。
    pub http: Option<SocketAddr>,
    /// HTTPS 代理入口（HTTP 代理套 TLS）。
    pub https: Option<SocketAddr>,
}

impl EntryAddrs {
    /// 是否有任何入口启用。
    pub fn any(&self) -> bool {
        self.socks5.is_some() || self.http.is_some() || self.https.is_some()
    }

    /// 全部启用的入口数量（用于日志）。
    pub fn count(&self) -> usize {
        usize::from(self.socks5.is_some())
            + usize::from(self.http.is_some())
            + usize::from(self.https.is_some())
    }
}

/// 客户端配置。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 远端 FlowTCP 服务端地址。
    pub remote: SocketAddr,
    /// 认证密钥（与服务端共享的密码派生）。
    pub auth: AuthKey,
    /// TLS SNI。
    ///
    /// # 必须与偷网站目标的域名一致
    ///
    /// 服务端会用这个 SNI 判断「是不是允许的站点」，并在认证失败时把连接
    /// 透传给该站点的真实 IP。因此它必须是一个**真实存在**的域名，
    /// 而不是随便编的（编的会在 ClientHello 阶段就被判为可疑）。
    pub sni: String,
    /// 本地入口监听地址。
    pub entries: EntryAddrs,
    /// HTTPS 入口的证书来源。
    pub https_cert: HttpsCert,
    /// 单条隧道允许的最大并发流数。
    ///
    /// 取 256 的理由：浏览器单站点并发 6~10，256 足够覆盖多标签页；
    /// 同时把 `u16` 的 stream_id 空间限制在合理范围，避免单连接吃满。
    pub max_streams: u16,
    /// 建立隧道连接的超时。
    pub connect_timeout: std::time::Duration,
}

impl ClientConfig {
    /// 构造最小配置（只开 SOCKS5）。
    pub fn new(remote: SocketAddr, sni: impl Into<String>, auth: AuthKey) -> Self {
        ClientConfig {
            remote,
            auth,
            sni: sni.into(),
            entries: EntryAddrs::default(),
            https_cert: HttpsCert::default(),
            max_streams: 256,
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }

    /// 设置 SOCKS5 入口。
    pub fn with_socks5(mut self, addr: SocketAddr) -> Self {
        self.entries.socks5 = Some(addr);
        self
    }

    /// 设置 HTTP 入口。
    pub fn with_http(mut self, addr: SocketAddr) -> Self {
        self.entries.http = Some(addr);
        self
    }

    /// 设置 HTTPS 入口。
    pub fn with_https(mut self, addr: SocketAddr) -> Self {
        self.entries.https = Some(addr);
        self
    }

    /// 设置 HTTPS 入口证书。
    pub fn with_https_cert(mut self, cert: HttpsCert) -> Self {
        self.https_cert = cert;
        self
    }

    /// 校验配置，返回人类可读的错误。
    pub fn validate(&self) -> Result<(), String> {
        if !self.entries.any() {
            return Err("未启用任何入口（至少指定 socks5 / http / https 之一）".into());
        }
        if self.sni.is_empty() {
            return Err("SNI 不能为空（必须是真实存在的域名）".into());
        }
        if self.max_streams == 0 {
            return Err("max_streams 不能为 0".into());
        }
        // HTTPS 指定文件时必须两个都给
        if let HttpsCert::Files {
            cert_path,
            key_path,
        } = &self.https_cert
        {
            if !cert_path.exists() {
                return Err(format!("证书文件不存在: {}", cert_path.display()));
            }
            if !key_path.exists() {
                return Err(format!("私钥文件不存在: {}", key_path.display()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ClientConfig {
        ClientConfig::new(
            "1.2.3.4:443".parse().unwrap(),
            "www.example.com",
            AuthKey::from_password("test"),
        )
    }

    #[test]
    fn 默认只开socks5时校验通过() {
        let c = cfg().with_socks5("127.0.0.1:1080".parse().unwrap());
        assert!(c.validate().is_ok());
        assert_eq!(c.entries.count(), 1);
    }

    #[test]
    fn 未启用任何入口时校验失败() {
        let e = cfg().validate().unwrap_err();
        assert!(e.contains("未启用任何入口"), "实际: {e}");
    }

    #[test]
    fn sni为空时校验失败() {
        let c = ClientConfig::new(
            "1.2.3.4:443".parse().unwrap(),
            "",
            AuthKey::from_password("test"),
        )
        .with_socks5("127.0.0.1:1080".parse().unwrap());
        assert!(c.validate().unwrap_err().contains("SNI"));
    }

    #[test]
    fn 三个入口可同时启用() {
        let c = cfg()
            .with_socks5("127.0.0.1:1080".parse().unwrap())
            .with_http("127.0.0.1:8080".parse().unwrap())
            .with_https("127.0.0.1:8443".parse().unwrap());
        assert_eq!(c.entries.count(), 3);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn https文件不存在时校验失败() {
        let c = cfg()
            .with_socks5("127.0.0.1:1080".parse().unwrap())
            .with_https("127.0.0.1:8443".parse().unwrap())
            .with_https_cert(HttpsCert::Files {
                cert_path: "/nonexistent/cert.pem".into(),
                key_path: "/nonexistent/key.pem".into(),
            });
        assert!(c.validate().unwrap_err().contains("证书文件不存在"));
    }

    #[test]
    fn 默认https证书是自签() {
        assert!(matches!(HttpsCert::default(), HttpsCert::SelfSigned { .. }));
    }
}
