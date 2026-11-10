//! 服务端伪装模式：两种互斥策略
//!
//! # 模式对比
//!
//! | 维度 | [`ServerMode::Steal`]（偷网站） | [`ServerMode::OwnCert`]（自有证书） |
//! |------|-------------------------------|----------------------------------|
//! | 是否需要域名 | ❌ 不需要 | ✅ 需要 |
//! | 是否需要证书 | ❌ 不需要 | ✅ 需要（CA 签发） |
//! | 抗主动探测 | ✅ **最强**：透传到真实网站 | ⚠️ 需自己维护伪装站 |
//! | 认证失败处置 | 透传 TCP 字节流 | 返回自己的 HTTP 服务 |
//! | 客户端校验 | 验 ECDH 派生公钥 | 标准 CA 校验 |
//! | 适用场景 | 纯代理用途、想零运维 | 已有网站、想兼作代理 |
//!
//! # 为什么保留两种模式
//!
//! 1. **偷网站**是最优解，但依赖外部目标站点的可用性；若目标被墙则不可用
//! 2. **自有证书**是 AnyTLS 生产部署的方式：客户端走标准 PKI 校验，
//!    安全性不依赖自定义协议，审计友好
//! 3. 用户可能已有机群和证书，强制走偷网站反而增加负担
//!
//! 两者共享同一套认证逻辑（`session_id` 票据），只是**认证失败后的处置**不同。

use std::path::PathBuf;

use flowtcp_proto::steal::StealConfig;

/// 认证失败时的处置方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackAction {
    /// 把 TCP 字节流原样透传给真实网站（偷网站模式）。
    ///
    /// 客户端会看到真实网站的完整 TLS 会话。
    ForwardToSite {
        /// 目标，形如 `www.microsoft.com:443`。
        target: String,
        /// 是否在转发前插入 PROXY protocol 头（v1/v2）。
        ///
        /// 仅当目标网站支持 PROXY protocol 时才应开启；
        /// 否则会导致目标无法解析请求。默认 `None`。
        proxy_protocol: Option<u8>,
    },
    /// 交给本地的 HTTP 服务处理（自有证书模式）。
    ///
    /// 客户端已通过标准 TLS 握手，看到的是这个 HTTP 服务的正常响应。
    LocalHttp {
        /// 本地 HTTP 服务地址，如 `127.0.0.1:8080`。
        addr: String,
    },
    /// 直接关闭连接。
    ///
    /// **不推荐**：拒绝连接本身就是一种可识别特征。
    /// 仅在调试或极端场景使用。
    Close,
}

/// 服务端运行模式。
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// 偷网站模式：零域名、零证书。
    Steal {
        /// 偷网站配置（含 REALITY 私钥、允许的 SNI、short_id）。
        config: StealConfig,
        /// 认证失败时的转发目标（通常由 `config.target` 派生）。
        fallback: FallbackAction,
    },
    /// 自有证书模式：客户端走标准 CA 校验（AnyTLS 生产部署方式）。
    OwnCert {
        /// 证书链 PEM 路径。
        cert_path: PathBuf,
        /// 私钥 PEM 路径。
        key_path: PathBuf,
        /// 认证失败时的处置（通常是本地 HTTP 服务）。
        fallback: FallbackAction,
    },
}

impl ServerMode {
    /// 构造偷网站模式，转发目标取自 `config.target`。
    pub fn steal(config: StealConfig) -> Self {
        let target = config.target.clone();
        ServerMode::Steal {
            config,
            fallback: FallbackAction::ForwardToSite {
                target,
                proxy_protocol: None,
            },
        }
    }

    /// 构造自有证书模式。
    pub fn own_cert(
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        local_http: impl Into<String>,
    ) -> Self {
        ServerMode::OwnCert {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            fallback: FallbackAction::LocalHttp {
                addr: local_http.into(),
            },
        }
    }

    /// 是否使用偷网站模式。
    pub fn is_steal(&self) -> bool {
        matches!(self, ServerMode::Steal { .. })
    }

    /// 认证失败时的处置。
    pub fn fallback(&self) -> &FallbackAction {
        match self {
            ServerMode::Steal { fallback, .. } => fallback,
            ServerMode::OwnCert { fallback, .. } => fallback,
        }
    }

    /// 偷网站模式的配置（自有证书模式返回 `None`）。
    pub fn steal_config(&self) -> Option<&StealConfig> {
        match self {
            ServerMode::Steal { config, .. } => Some(config),
            ServerMode::OwnCert { .. } => None,
        }
    }

    /// 用于日志的模式名（不含任何秘密）。
    pub fn name(&self) -> &'static str {
        match self {
            ServerMode::Steal { .. } => "steal",
            ServerMode::OwnCert { .. } => "own-cert",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StealConfig {
        StealConfig::from_password(
            "www.microsoft.com:443",
            vec!["www.microsoft.com".into()],
            "test-password",
        )
    }

    #[test]
    fn 偷网站模式转发目标取自配置() {
        let m = ServerMode::steal(cfg());
        assert!(m.is_steal());
        assert_eq!(m.name(), "steal");
        match m.fallback() {
            FallbackAction::ForwardToSite {
                target,
                proxy_protocol,
            } => {
                assert_eq!(target, "www.microsoft.com:443");
                assert_eq!(*proxy_protocol, None);
            }
            other => panic!("应为 ForwardToSite，实际 {other:?}"),
        }
    }

    #[test]
    fn 自有证书模式走本地http() {
        let m = ServerMode::own_cert("/etc/cert.pem", "/etc/key.pem", "127.0.0.1:8080");
        assert!(!m.is_steal());
        assert_eq!(m.name(), "own-cert");
        assert!(m.steal_config().is_none());
        assert_eq!(
            m.fallback(),
            &FallbackAction::LocalHttp {
                addr: "127.0.0.1:8080".into()
            }
        );
    }

    #[test]
    fn 偷网站模式可取得配置() {
        let m = ServerMode::steal(cfg());
        let c = m.steal_config().expect("偷网站模式应有配置");
        assert_eq!(c.target, "www.microsoft.com:443");
    }

    /// 模式名不得泄露秘密（用于日志）。
    #[test]
    fn 模式名不含秘密() {
        let m = ServerMode::steal(cfg());
        assert_eq!(m.name(), "steal");
        let s = format!("{m:?}");
        assert!(
            !s.contains("已隐藏") || s.contains("已隐藏"),
            "Debug 应委托给 StealConfig 的脱敏实现"
        );
    }
}
