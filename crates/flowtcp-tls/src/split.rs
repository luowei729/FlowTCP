//! 首帧分流判定：区分「FlowTCP 客户端」与「普通 HTTP 流量」
//!
//! # 为什么判定只能在这里
//!
//! 抗主动探测的唯一正确判定点，是 **TLS 握手完成后的第一个 application_data
//! 记录的明文**。原因：
//!
//! | 判定位置 | 是否可被识别 |
//! |---------|------------|
//! | ClientHello 加私有 extension | ❌ 扩展集合多出一项，可统计 |
//! | 特定 cipher suite 顺序 | ❌ 指纹偏离真实浏览器 |
//! | key_share 特殊值 | ❌ 需要自定义，极易识别 |
//! | session_id 编码秘密 | ❌ 长度/内容异常 |
//! | **握手后首帧明文** | ✅ **探测者无法看到**（需要会话密钥） |
//!
//! 握手阶段两者字节级完全一致，因此真正的「不可区分」只能建立在这里。
//!
//! # 判定输入是什么
//!
//! TLS 解密后的应用层明文。真实浏览器会发送：
//! - HTTP/2：`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`（连接前言）
//! - HTTP/1.1：`GET / HTTP/1.1\r\n...`
//!
//! 而 FlowTCP 客户端发送 [`flowtcp_proto::AUTH_MAGIC`] = `FTAUTH`。

use flowtcp_proto::AUTH_MAGIC;

/// 首帧分流结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 是 FlowTCP 客户端（握手后首帧以 `FTAUTH` 开头）。
    FlowTcp,
    /// 是 HTTP/1.x 请求，应转发给伪装站点。
    Http1,
    /// 是 HTTP/2 连接前言，应转发给伪装站点。
    Http2,
    /// 无法识别：可能是其他协议、畸形数据或探测行为。
    ///
    /// **处理方式**：仍转发给伪装站点，由其返回标准的 nginx 400/404 页面。
    /// 绝不能返回「协议错误」之类的自定义响应——那等于自曝。
    Unknown,
}

impl Verdict {
    /// 是否应交给代理路径处理。
    pub fn is_proxy(self) -> bool {
        self == Verdict::FlowTcp
    }

    /// 是否应交给伪装站点处理。
    pub fn is_web(self) -> bool {
        matches!(self, Verdict::Http1 | Verdict::Http2 | Verdict::Unknown)
    }
}

/// 判定所需的最小字节数。
///
/// 取 6 是因为：
/// - [`AUTH_MAGIC`] 长 6 字节，必须完整比对
/// - 所有 HTTP 方法前缀（`GET `、`POST` 等）都不超过 4 字节 + 分隔，5 字节足够
///
/// 少于 6 字节时无法安全区分 `FTAUTH` 与 `FT...` 开头的其他数据，
/// 必须继续等待（但要有超时，见 [`classify_with_timeout`] 的说明）。
pub const MIN_CLASSIFY_LEN: usize = 6;

/// HTTP/1.x 方法前缀表。
///
/// # 为什么每项都要带分隔符（空格或方法全称）
///
/// 若只匹配 `POST`（4 字节），则 `POSTX` 这种非 HTTP 数据会被误判为 HTTP。
/// 虽然误判方向是「转给伪装站点」不会自曝，但会掩盖真实的协议错误。
///
/// 长度不一致是正常的：`GET ` 只需 4 字节即可判定，而 `CONNECT` 必须收全 7 字节
/// 才能与 `CONN` 开头的其他数据区分。匹配逻辑对长短前缀都做了处理。
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE", b"OPTIONS", b"PATCH ", b"CONNECT", b"TRACE ",
];

/// HTTP/2 连接前言（RFC 9113 §3.4）。
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 对首帧明文做分流判定。
///
/// # 返回值语义
///
/// - 数据不足 `MIN_CLASSIFY_LEN` 字节且不构成完整 HTTP/2 前言 → 返回 `None`
///   表示**需要更多数据**才能判定，调用方应继续读取（并设置超时）
/// - 否则返回确定的 [`Verdict`]
///
/// # 为什么 HTTP/2 前言要特殊处理
///
/// `PRI ` 只有 4 字节，与 `FTAUTH` 的前 4 字节 `FTAU` 不同，但 `PRI ` 后面还有
/// 长串固定内容。若只按 6 字节比对 `PRI * ` 也能正确区分，
/// 但完整比对 24 字节前言能进一步降低误判概率（几乎为零成本）。
pub fn classify(data: &[u8]) -> Option<Verdict> {
    if data.is_empty() {
        return None;
    }

    // ---- 1) HTTP/2 连接前言：优先判断，因为它最长最明确 ----
    if data.len() >= H2_PREFACE.len() {
        if &data[..H2_PREFACE.len()] == H2_PREFACE {
            return Some(Verdict::Http2);
        }
    } else if H2_PREFACE.starts_with(data) {
        // 是前言的前缀，但还没收全 —— 继续等
        return None;
    }

    // ---- 2) FlowTCP 认证魔数 ----
    if data.len() >= AUTH_MAGIC.len() {
        if &data[..AUTH_MAGIC.len()] == AUTH_MAGIC {
            return Some(Verdict::FlowTcp);
        }
    } else if AUTH_MAGIC.starts_with(data) {
        // 是 FTAUTH 的前缀，可能是 FlowTCP，继续等
        return None;
    }

    // ---- 3) HTTP/1.x 方法 ----
    // (a) 完整匹配：数据长度已足够覆盖方法前缀（含分隔符）
    for m in HTTP_METHODS {
        if data.len() >= m.len() && data.starts_with(m) {
            return Some(Verdict::Http1);
        }
    }
    // (b) 前缀等待：数据可能是某个方法的前缀，还不够长
    for m in HTTP_METHODS {
        if data.len() < m.len() && m.starts_with(data) {
            return None;
        }
    }

    // ---- 4) 其他 ----
    if data.len() < MIN_CLASSIFY_LEN {
        // 不足最小长度且不匹配任何已知前缀 —— 可能是任意短数据
        // 保守起见再等一点（例如 TLS 空记录、心跳）
        return None;
    }

    Some(Verdict::Unknown)
}

/// 判定结果 + 已消费的字节数。
#[derive(Debug, Clone)]
pub struct Classified {
    /// 判定结论。
    pub verdict: Verdict,
    /// 已读入的明文（**必须原样交给下游**，不能丢弃）。
    pub data: Vec<u8>,
}

impl Classified {
    /// 已读入的字节数。
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 识别flowtcp认证() {
        assert_eq!(classify(b"FTAUTH\x01\x00"), Some(Verdict::FlowTcp));
        assert_eq!(classify(b"FTAUTH"), Some(Verdict::FlowTcp));
        // 后面跟更多数据不影响判定
        let mut d = b"FTAUTH".to_vec();
        d.extend_from_slice(&[0u8; 100]);
        assert_eq!(classify(&d), Some(Verdict::FlowTcp));
    }

    #[test]
    fn 识别http1各方法() {
        for req in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"POST /api HTTP/1.1\r\n",
            b"HEAD / HTTP/1.1\r\n",
            b"PUT /x HTTP/1.1\r\n",
            b"DELETE /x HTTP/1.1\r\n",
            b"OPTIONS * HTTP/1.1\r\n",
            b"PATCH /x HTTP/1.1\r\n",
            b"CONNECT x:443 HTTP/1.1\r\n",
            b"TRACE / HTTP/1.1\r\n",
        ] {
            assert_eq!(
                classify(req),
                Some(Verdict::Http1),
                "应识别为 HTTP/1: {req:?}"
            );
        }
    }

    #[test]
    fn 识别http2前言() {
        assert_eq!(classify(H2_PREFACE), Some(Verdict::Http2));
        // 前言 + 后续帧数据
        let mut d = H2_PREFACE.to_vec();
        d.extend_from_slice(&[0, 0, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(classify(&d), Some(Verdict::Http2));
    }

    /// 数据不足时必须返回 None（等待），不能武断判定。
    #[test]
    fn 数据不足时等待() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(b"F"), None); // FTAUTH 前缀
        assert_eq!(classify(b"FTAU"), None);
        assert_eq!(classify(b"FT"), None);
        assert_eq!(classify(b"PRI"), None); // h2 前言前缀
        assert_eq!(classify(b"PRI * HTTP/2.0\r\n"), None); // 前言未收全
        assert_eq!(classify(b"GE"), None); // GET 前缀
        assert_eq!(classify(b"GET"), None);
    }

    /// 关键反例：不能因为首字母是 F 就误判为 FlowTCP。
    #[test]
    fn ft前缀但非认证不误判() {
        // "FOObar" 不是 FTAUTH
        assert_eq!(classify(b"FOObar"), Some(Verdict::Unknown));
        // "FTAUTHX" 前 6 字节确实是 FTAUTH → 判定为 FlowTCP（合理，
        // 因为协议规定认证帧以 FTAUTH 开头，后续字节属于认证帧内容）
        assert_eq!(classify(b"FTAUTHX"), Some(Verdict::FlowTcp));
    }

    /// 关键反例：不能因为首字母是 P 就误判为 HTTP/2。
    #[test]
    fn p前缀但非前言不误判() {
        assert_eq!(classify(b"PRI * HTTP/1.1\r\n"), Some(Verdict::Unknown));
        // 注意 POST 后必须跟空格；`POSTXYZ` 不是 HTTP 方法
        assert_eq!(classify(b"POSTXYZ"), Some(Verdict::Unknown));
        // 5 字节不足最小判定长度，应等待
        assert_eq!(classify(b"POSTX"), None);
    }

    /// 未知协议不应崩溃，且不会被误判为代理。
    #[test]
    fn 未知数据判定为unknown() {
        assert_eq!(
            classify(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA]),
            Some(Verdict::Unknown)
        );
        // TLS record 头（5 字节）+ 1 字节，共 6 字节才够判定
        assert_eq!(
            classify(b"\x16\x03\x01\x00\x05\x01"),
            Some(Verdict::Unknown)
        );
        assert_eq!(
            classify(b"\x00\x00\x00\x00\x00\x00"),
            Some(Verdict::Unknown)
        );
    }

    /// 数据不足最小长度时必须等待，不能武断判定为 Unknown。
    #[test]
    fn 不足最小长度时等待() {
        // 5 字节的 TLS record 头还不够
        assert_eq!(classify(b"\x16\x03\x01\x00\x05"), None);
        assert_eq!(classify(b"\xFF\xFE\xFD\xFC\xFB"), None);
    }

    /// 分流结论的路由语义。
    #[test]
    fn 路由语义正确() {
        assert!(Verdict::FlowTcp.is_proxy());
        assert!(!Verdict::FlowTcp.is_web());

        for v in [Verdict::Http1, Verdict::Http2, Verdict::Unknown] {
            assert!(!v.is_proxy());
            assert!(v.is_web(), "{v:?} 应交给伪装站点");
        }
    }

    /// 逐个长度验证：从 1 字节开始增长，判定结果必须稳定且符合预期。
    ///
    /// 这个测试能捕获「短数据误判」这类边界 bug。
    #[test]
    fn 逐长度判定稳定() {
        let full = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        for n in 1..=full.len() {
            let v = classify(&full[..n]);
            if n >= 4 {
                assert_eq!(v, Some(Verdict::Http1), "长度 {n} 应识别为 HTTP/1");
            } else {
                assert_eq!(v, None, "长度 {n} 应等待更多数据");
            }
        }

        let ft = b"FTAUTH\x01\x02\x03";
        for n in 1..=ft.len() {
            let v = classify(&ft[..n]);
            if n >= 6 {
                assert_eq!(v, Some(Verdict::FlowTcp), "长度 {n} 应识别为 FlowTCP");
            } else {
                assert_eq!(v, None, "长度 {n} 应等待更多数据");
            }
        }
    }

    /// 魔数与 HTTP 方法首字母必须不同，否则分流存在歧义。
    #[test]
    fn 魔数与方法首字节不冲突() {
        let first = AUTH_MAGIC[0];
        for m in HTTP_METHODS {
            assert_ne!(
                first,
                m[0],
                "FTAUTH 首字节与 {:?} 冲突",
                String::from_utf8_lossy(m)
            );
        }
        assert_ne!(first, H2_PREFACE[0], "FTAUTH 与 h2 前言首字节冲突");
    }
}
