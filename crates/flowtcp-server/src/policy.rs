//! 目标地址访问策略
//!
//! # 为什么必须有这一层
//!
//! 代理服务端会把「客户端要求的目标」变成「服务端发起的连接」。
//! 如果没有策略限制，任何拿到密码的人都能：
//!
//! - 扫内网：`10.0.0.1:22`、`172.16.0.5:3306`、`192.168.1.1:80`
//! - 访问云元数据：`169.254.169.254`（AWS/GCP/Azure 的凭据服务）
//! - 打本机服务：`127.0.0.1:6379`（Redis 未授权）、`127.0.0.1:2375`（Docker API）
//!
//! 这就是经典的 **SSRF（服务端请求伪造）**。密码泄漏 + 无策略 = 内网沦陷。
//!
//! # 两种策略
//!
//! | 策略 | 用途 |
//! |------|------|
//! | [`TargetPolicy::AllowAll`] | 单机自用 / 测试。明确知道风险时使用 |
//! | [`TargetPolicy::DenyPrivate`] | **生产默认**。拒绝一切非公网地址 |
//!
//! # 为什么默认是 `DenyPrivate` 而不是 `AllowAll`
//!
//! 默认值决定了"忘记配置"时的行为。忘记配置时应该是安全的，
//! 而不是暴露的 —— 这是 secure by default 的基本要求。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use flowtcp_proto::frame::Address;

/// 目标地址访问策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetPolicy {
    /// 允许所有目标（含内网）。
    AllowAll,
    /// 拒绝内网、环回、链路本地、保留地址（默认）。
    #[default]
    DenyPrivate,
}

/// 策略拒绝原因（仅用于日志，不回给客户端）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// IPv4 私网地址（10/8、172.16/12、192.168/16）。
    PrivateV4(Ipv4Addr),
    /// 环回（127/8、::1）。
    Loopback(IpAddr),
    /// 链路本地（169.254/16、fe80::/10）。
    LinkLocal(IpAddr),
    /// IPv6 唯一本地地址（fc00::/7）。
    UniqueLocalV6(Ipv6Addr),
    /// 未指定地址（0.0.0.0、::）。
    Unspecified(IpAddr),
    /// 组播/广播。
    Multicast(IpAddr),
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenyReason::PrivateV4(ip) => write!(f, "IPv4 私网地址 {ip}"),
            DenyReason::Loopback(ip) => write!(f, "环回地址 {ip}"),
            DenyReason::LinkLocal(ip) => write!(f, "链路本地地址 {ip}"),
            DenyReason::UniqueLocalV6(ip) => write!(f, "IPv6 本地地址 {ip}"),
            DenyReason::Unspecified(ip) => write!(f, "未指定地址 {ip}"),
            DenyReason::Multicast(ip) => write!(f, "组播地址 {ip}"),
        }
    }
}

impl TargetPolicy {
    /// 检查一个已解析的 IP 是否允许。
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), DenyReason> {
        if *self == TargetPolicy::AllowAll {
            return Ok(());
        }
        match ip {
            IpAddr::V4(v4) => check_v4(v4),
            IpAddr::V6(v6) => check_v6(v6),
        }
    }

    /// 检查一个目标。
    ///
    /// # 域名不在这里解析
    ///
    /// 域名的实际 IP 由服务端在连接时由系统解析器得到，此处无法预知。
    /// 因此对域名返回 `Ok`，并在**连接后**用 [`Self::check_resolved`] 二次校验
    /// —— 这是防 DNS rebinding（域名先解析到公网、再解析到内网）的唯一办法。
    pub fn check(&self, target: &Address) -> Result<(), DenyReason> {
        match target {
            Address::V4(v4) => self.check_ip(IpAddr::V4(*v4.ip())),
            Address::V6(v6) => self.check_ip(IpAddr::V6(*v6.ip())),
            Address::Domain(_, _) => Ok(()),
        }
    }

    /// 连接建立后校验真实对端地址（防 DNS rebinding）。
    ///
    /// 必须在 `TcpStream::connect` 之后、写入任何数据之前调用。
    pub fn check_resolved(&self, peer: SocketAddr) -> Result<(), DenyReason> {
        self.check_ip(peer.ip())
    }
}

/// IPv4 检查。
fn check_v4(ip: Ipv4Addr) -> Result<(), DenyReason> {
    // 顺序有讲究：先判断更具体的类别，日志才有意义
    if ip.is_loopback() {
        return Err(DenyReason::Loopback(ip.into()));
    }
    if ip.is_unspecified() {
        return Err(DenyReason::Unspecified(ip.into()));
    }
    if ip.is_private() {
        return Err(DenyReason::PrivateV4(ip));
    }
    if ip.is_link_local() {
        return Err(DenyReason::LinkLocal(ip.into()));
    }
    if ip.is_multicast() || ip.is_broadcast() {
        return Err(DenyReason::Multicast(ip.into()));
    }
    // 100.64/10（运营商级 NAT）与 0.0.0.0/8
    let o = ip.octets();
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return Err(DenyReason::PrivateV4(ip));
    }
    if o[0] == 0 {
        return Err(DenyReason::Unspecified(ip.into()));
    }
    // 保留段 240/4
    if o[0] >= 240 {
        return Err(DenyReason::PrivateV4(ip));
    }
    Ok(())
}

/// IPv6 检查。
fn check_v6(ip: Ipv6Addr) -> Result<(), DenyReason> {
    if ip.is_loopback() {
        return Err(DenyReason::Loopback(ip.into()));
    }
    if ip.is_unspecified() {
        return Err(DenyReason::Unspecified(ip.into()));
    }
    if ip.is_multicast() {
        return Err(DenyReason::Multicast(ip.into()));
    }
    // fc00::/7 唯一本地地址
    let seg = ip.segments();
    if seg[0] & 0xfe00 == 0xfc00 {
        return Err(DenyReason::UniqueLocalV6(ip));
    }
    // fe80::/10 链路本地
    if seg[0] & 0xffc0 == 0xfe80 {
        return Err(DenyReason::LinkLocal(ip.into()));
    }
    // IPv4 映射地址：::ffff:127.0.0.1 这类必须还原成 IPv4 再判断，
    // 否则会绕过所有 v4 规则（常见绕过手法）
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_v4(v4);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认策略是拒绝私网() {
        assert_eq!(TargetPolicy::default(), TargetPolicy::DenyPrivate);
    }

    #[test]
    fn allowall放行一切() {
        let p = TargetPolicy::AllowAll;
        assert!(p.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(p.check_ip("10.0.0.1".parse().unwrap()).is_ok());
        assert!(p.check_ip("169.254.169.254".parse().unwrap()).is_ok());
    }

    #[test]
    fn denyprivate拒绝环回() {
        let p = TargetPolicy::DenyPrivate;
        assert!(matches!(
            p.check_ip("127.0.0.1".parse().unwrap()),
            Err(DenyReason::Loopback(_))
        ));
        assert!(matches!(
            p.check_ip("127.1.2.3".parse().unwrap()),
            Err(DenyReason::Loopback(_))
        ));
        assert!(matches!(
            p.check_ip("::1".parse().unwrap()),
            Err(DenyReason::Loopback(_))
        ));
    }

    #[test]
    fn denyprivate拒绝私网段() {
        let p = TargetPolicy::DenyPrivate;
        for ip in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
        ] {
            assert!(
                matches!(
                    p.check_ip(ip.parse().unwrap()),
                    Err(DenyReason::PrivateV4(_))
                ),
                "{ip} 应被拒绝"
            );
        }
        // 172.15 与 172.32 不是私网
        assert!(p.check_ip("172.15.0.1".parse().unwrap()).is_ok());
        assert!(p.check_ip("172.32.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn denyprivate拒绝云元数据地址() {
        let p = TargetPolicy::DenyPrivate;
        // AWS / GCP / Azure 的元数据服务
        assert!(matches!(
            p.check_ip("169.254.169.254".parse().unwrap()),
            Err(DenyReason::LinkLocal(_))
        ));
    }

    #[test]
    fn denyprivate拒绝ipv6本地() {
        let p = TargetPolicy::DenyPrivate;
        assert!(matches!(
            p.check_ip("fe80::1".parse().unwrap()),
            Err(DenyReason::LinkLocal(_))
        ));
        assert!(matches!(
            p.check_ip("fc00::1".parse().unwrap()),
            Err(DenyReason::UniqueLocalV6(_))
        ));
        assert!(matches!(
            p.check_ip("fd12:3456::1".parse().unwrap()),
            Err(DenyReason::UniqueLocalV6(_))
        ));
    }

    #[test]
    fn ipv4映射地址不能绕过() {
        let p = TargetPolicy::DenyPrivate;
        // ::ffff:127.0.0.1 必须被识别为环回
        assert!(p.check_ip("::ffff:127.0.0.1".parse().unwrap()).is_err());
        assert!(p.check_ip("::ffff:10.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn 公网地址放行() {
        let p = TargetPolicy::DenyPrivate;
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(p.check_ip(ip.parse().unwrap()).is_ok(), "{ip} 应放行");
        }
    }

    #[test]
    fn 运营商级nat被拒绝() {
        let p = TargetPolicy::DenyPrivate;
        assert!(p.check_ip("100.64.0.1".parse().unwrap()).is_err());
        assert!(p.check_ip("100.127.255.254".parse().unwrap()).is_err());
        // 100.128 不属于 100.64/10
        assert!(p.check_ip("100.128.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn 域名此阶段放行由连接后二次校验() {
        let p = TargetPolicy::DenyPrivate;
        assert!(p.check(&Address::Domain("example.com".into(), 443)).is_ok());
        // 连接后拿到的真实 IP 仍会被拦
        assert!(p.check_resolved("127.0.0.1:80".parse().unwrap()).is_err());
    }

    #[test]
    fn 未指定与组播被拒绝() {
        let p = TargetPolicy::DenyPrivate;
        assert!(matches!(
            p.check_ip("0.0.0.0".parse().unwrap()),
            Err(DenyReason::Unspecified(_))
        ));
        assert!(matches!(
            p.check_ip("224.0.0.1".parse().unwrap()),
            Err(DenyReason::Multicast(_))
        ));
        assert!(matches!(
            p.check_ip("255.255.255.255".parse().unwrap()),
            Err(DenyReason::Multicast(_))
        ));
    }

    #[test]
    fn 拒绝原因可读() {
        let p = TargetPolicy::DenyPrivate;
        let e = p.check_ip("10.1.2.3".parse().unwrap()).unwrap_err();
        assert!(e.to_string().contains("私网"), "实际: {e}");
    }
}
