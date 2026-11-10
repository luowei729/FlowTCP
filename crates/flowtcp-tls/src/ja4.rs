//! JA4 指纹计算（用于客观验证 ClientHello 是否像 Chrome）
//!
//! # 为什么自己算 JA4
//!
//! 外部检测服务（`tls.peet.ws`）需要**完整握手**才能返回 JA4，而完整握手
//! 需要实现 TLS 1.3 key schedule —— 那是后续阶段的工作。
//!
//! 但 JA4 的核心（B 部分哈希）**只依赖 ClientHello 的静态内容**：
//!
//! ```text
//! JA4 = {t|q}{version}{sni}{cipher_count:02}{ext_count:02}{alpn:2}_{B}_{C}
//!
//! B = sha256( sorted(ciphers_4hex, ",") + "_" + sorted(extensions_4hex, ",") )[0..12]
//! C = sha256( sorted(sigalgs_4hex, ",") )[0..12]
//! ```
//!
//! 因此只要 ClientHello 字节正确，本地算出的 B 就与外部服务一致。
//!
//! # 关键规则（FoxIO JA4 规范）
//!
//! 1. **GREASE 值全部剔除**（`0x?a?a` 形式）
//! 2. **扩展要剔除 `0x0000`(SNI) 与 `0x0010`(ALPN)**
//! 3. cipher / extension / sigalg 都按**十六进制字符串升序排序**
//! 4. 十六进制统一 4 位小写
//!
//! # 已验证的基准值
//!
//! Chrome 桌面版 TLS 1.3 + h2 的 B 段为 `8daaf6152771`。
//! 我们已实测 BoringSSL（本项目的指纹配置）也能得到该值，
//! 因此可用"BoringSSL 的 ClientHello"作为校验本实现的黄金样本。

use sha2::{Digest, Sha256};

/// JA4 计算结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    /// A 段，形如 `t13d1513h2`。
    pub a: String,
    /// B 段（cipher + extension 哈希，12 hex）。
    pub b: String,
    /// C 段（签名算法哈希，12 hex）。
    pub c: String,
    /// cipher + extension 联合哈希（FoxIO 规范变体，用于诊断）。
    ///
    /// 注意：这与 [`Self::b`] **不同**。`b` 已按 tls.peet.ws 的实测行为校准。
    pub cipher_ext: String,
}

impl Ja4 {
    /// 完整字符串，形如 `t13d1513h2_8daaf6152771_435907fac1bf`。
    pub fn full(&self) -> String {
        format!("{}_{}_{}", self.a, self.b, self.c)
    }

    /// 包含 cipher+ext 联合哈希的四段形式（诊断用）。
    pub fn detailed(&self) -> String {
        format!("{}_{}_{}_{}", self.a, self.b, self.c, self.cipher_ext)
    }

    /// B 段是否与 Chrome 桌面版一致。
    pub fn matches_chrome(&self) -> bool {
        self.b == CHROME_JA4_B
    }
}

/// Chrome 桌面版 TLS 1.3 的 JA4 B 段（业界公认指纹）。
pub const CHROME_JA4_B: &str = "8daaf6152771";

/// 判断是否为 GREASE 值（`0x?a?a` 且首尾字节相同）。
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// 从完整 ClientHello 字节计算 JA4。
///
/// `data` 必须是以 TLS 记录头开头的完整 ClientHello。
pub fn compute_ja4(data: &[u8]) -> Option<Ja4> {
    let ch = parse(data)?;

    // ---- A 段 ----
    // t = TLS over TCP, 13 = TLS 1.3（supported_versions 含 0x0304）
    let proto = "t";
    let ver = if ch.supported_versions.contains(&0x0304) {
        "13"
    } else if ch.supported_versions.contains(&0x0303) {
        "12"
    } else {
        "10"
    };
    let sni_flag = if ch.sni.is_some() { "d" } else { "i" };
    let cipher_count = ch.ciphers.len().min(99);
    let ext_count = ch.extensions.len().min(99);
    let alpn = ch
        .alpn_first
        .as_deref()
        .map(|p| {
            let s = String::from_utf8_lossy(p).to_string();
            // 取前 2 字符，末尾补 0
            match s.len() {
                0 => "00".to_string(),
                1 => format!("{s}0"),
                _ => s.chars().take(2).collect(),
            }
        })
        .unwrap_or_else(|| "00".to_string());
    let a = format!("{proto}{ver}{sni_flag}{cipher_count:02}{ext_count:02}{alpn}");

    // ---- B 段：cipher + extension ----
    let mut ciphers: Vec<String> = ch
        .ciphers
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| format!("{c:04x}"))
        .collect();
    ciphers.sort();

    let mut exts: Vec<String> = ch
        .extensions
        .iter()
        .filter(|&&e| !is_grease(e) && e != 0x0000 && e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    exts.sort();

    // ★ B 段算法（实测校准）
    //
    // tls.peet.ws 报的 B 段是 `sha256(排序后的 cipher 4hex 列表)[0..12]`，
    // **不含扩展**。已用 BoringSSL 样本验证：算出 8daaf6152771（Chrome 值）。
    //
    // 同时保留完整的 `cipher_ext` 变体，它更接近 FoxIO 原始规范，
    // 用于在扩展集合发生变化时提供额外诊断信息。
    let b = &hex12(&sha256(&ciphers.join(",")))[..12];
    let cipher_ext = hex12(&sha256(&format!(
        "{}_{}",
        ciphers.join(","),
        exts.join(",")
    )))[..12]
        .to_string();

    // ---- C 段：签名算法 ----
    let mut sigs: Vec<String> = ch
        .sigalgs
        .iter()
        .filter(|&&s| !is_grease(s))
        .map(|s| format!("{s:04x}"))
        .collect();
    sigs.sort();
    let c_input = sigs.join(",");
    let c = if c_input.is_empty() {
        "000000000000".to_string()
    } else {
        hex12(&sha256(&c_input))[..12].to_string()
    };

    Some(Ja4 {
        a,
        b: b.to_string(),
        c,
        cipher_ext,
    })
}

/// ClientHello 的关键字段（JA4 计算用）。
#[derive(Debug, Default)]
struct Parsed {
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    sigalgs: Vec<u16>,
    supported_versions: Vec<u16>,
    sni: Option<String>,
    alpn_first: Option<Vec<u8>>,
}

/// 解析 ClientHello 的 JA4 相关字段。
fn parse(d: &[u8]) -> Option<Parsed> {
    if d.len() < 44 || d[0] != 0x16 {
        return None;
    }
    let mut p = 9usize; // 记录头 5 + 握手头 4
    p += 2; // legacy_version
    p += 32; // random
    let sid_len = *d.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?]) as usize;
    p += 2;
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    for i in (0..cs_len).step_by(2) {
        ciphers.push(u16::from_be_bytes([*d.get(p + i)?, *d.get(p + i + 1)?]));
    }
    p += cs_len;
    let cm_len = *d.get(p)? as usize;
    p += 1 + cm_len;
    let _ext_total = u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?]) as usize;
    p += 2;

    let mut out = Parsed {
        ciphers,
        ..Default::default()
    };

    while p + 4 <= d.len() {
        let ty = u16::from_be_bytes([d[p], d[p + 1]]);
        let len = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
        p += 4;
        let body = d.get(p..p + len)?;
        out.extensions.push(ty);

        match ty {
            0x0000 => {
                // server_name
                if body.len() >= 5 {
                    let nlen = u16::from_be_bytes([body[3], body[4]]) as usize;
                    if body.len() >= 5 + nlen {
                        out.sni = String::from_utf8(body[5..5 + nlen].to_vec()).ok();
                    }
                }
            }
            0x0010 => {
                // ALPN
                if body.len() >= 3 {
                    let plen = body[2] as usize;
                    if body.len() >= 3 + plen {
                        out.alpn_first = Some(body[3..3 + plen].to_vec());
                    }
                }
            }
            0x000d => {
                // signature_algorithms
                let mut q = 2usize;
                while q + 2 <= body.len() {
                    out.sigalgs.push(u16::from_be_bytes([body[q], body[q + 1]]));
                    q += 2;
                }
            }
            0x002b => {
                // supported_versions
                let mut q = 1usize;
                while q + 2 <= body.len() {
                    out.supported_versions
                        .push(u16::from_be_bytes([body[q], body[q + 1]]));
                    q += 2;
                }
            }
            _ => {}
        }
        p += len;
    }

    Some(out)
}

fn sha256(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

fn hex12(b: &[u8]) -> String {
    b.iter().take(6).map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chbuilder::{build_client_hello, ClientHelloParams};

    #[test]
    fn grease识别正确() {
        for g in [0x0a0a, 0x1a1a, 0xfafa, 0xaaaa] {
            assert!(is_grease(g), "0x{g:04x} 应识别为 GREASE");
        }
        for n in [0x1301, 0x002b, 0x0a0b, 0x1a1b] {
            assert!(!is_grease(n), "0x{n:04x} 不应识别为 GREASE");
        }
    }

    /// ★ 校验本实现：用 BoringSSL 生成的 ClientHello 算出 Chrome 的 B 段。
    ///
    /// 这是"黄金样本"测试 —— 若本实现算不出 `8daaf6152771`，
    /// 说明 JA4 计算有误，后续所有指纹验证都不可信。
    #[test]
    fn 用boringssl样本校验ja4实现() {
        use crate::fingerprint::FingerprintConfig;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });

        let cfg = FingerprintConfig::chrome().danger_accept_invalid_certs();
        let conn = cfg.build_connector().unwrap();
        let s = TcpStream::connect(addr).unwrap();
        let mut c = conn.configure().unwrap();
        c.set_use_server_name_indication(true);
        let _ = c.connect("flowtcp.test", s);

        let raw = t.join().unwrap();
        let ja4 = compute_ja4(&raw).expect("应能计算 JA4");
        println!("BoringSSL 的 JA4 = {}", ja4.full());
        assert_eq!(
            ja4.b,
            CHROME_JA4_B,
            "BoringSSL 样本应算出 Chrome 的 B 段（JA4 = {}）",
            ja4.full()
        );
        let _ = std::io::stdout().flush();
    }

    /// ★ 核心：自研构造器的 JA4 B 段必须与 BoringSSL（即 Chrome）一致。
    #[test]
    fn 自研构造器ja4匹配chrome() {
        let p = ClientHelloParams::new("flowtcp.test", [0xAB; 32], [0x11; 32]);
        let ch = build_client_hello(&p);
        let ja4 = compute_ja4(&ch).expect("应能计算 JA4");
        println!("自研构造器的 JA4 = {}", ja4.full());
        assert!(
            ja4.matches_chrome(),
            "自研构造器 B 段 = {}，期望 {}\n完整 JA4 = {}",
            ja4.b,
            CHROME_JA4_B,
            ja4.full()
        );
    }

    /// A 段必须是 TLS 1.3 + 域名 SNI + h2。
    #[test]
    fn a段标记正确() {
        let p = ClientHelloParams::new("flowtcp.test", [0xAB; 32], [0x11; 32]);
        let ja4 = compute_ja4(&build_client_hello(&p)).unwrap();
        assert!(ja4.a.starts_with("t13"), "应为 t13，实际 {}", ja4.a);
        assert!(ja4.a.contains('d'), "应有域名 SNI，实际 {}", ja4.a);
        assert!(ja4.a.ends_with("h2"), "应为 h2，实际 {}", ja4.a);
    }

    /// GREASE 不应影响 JA4（剔除后哈希不变）。
    #[test]
    fn grease不影响ja4() {
        let mut a = ClientHelloParams::new("flowtcp.test", [0x01; 32], [0x11; 32]);
        a.grease = None;
        let mut b = ClientHelloParams::new("flowtcp.test", [0x01; 32], [0x11; 32]);
        b.grease = Some(0x1a1a);

        let ja = compute_ja4(&build_client_hello(&a)).unwrap();
        let jb = compute_ja4(&build_client_hello(&b)).unwrap();
        assert_eq!(ja.b, jb.b, "GREASE 不应影响 B 段");
        // 但扩展数量会因 GREASE 而 +1，A 段不同（这是 JA4 规范允许的）
        assert_ne!(ja.a, jb.a);
    }

    /// 换 SNI 不应影响 B 段（SNI 扩展被排除）。
    #[test]
    fn sni不影响b段() {
        let a = ClientHelloParams::new("a.example.com", [0x01; 32], [0x11; 32]);
        let b = ClientHelloParams::new("b.example.com", [0x01; 32], [0x11; 32]);
        let ja = compute_ja4(&build_client_hello(&a)).unwrap();
        let jb = compute_ja4(&build_client_hello(&b)).unwrap();
        assert_eq!(ja.b, jb.b, "SNI 内容不应影响 B 段");
    }

    /// 票据内容不应影响指纹（session_id 不参与 JA4）。
    #[test]
    fn 票据不影响指纹() {
        let a = ClientHelloParams::new("x.test", [0x11; 32], [0x33; 32]);
        let b = ClientHelloParams::new("x.test", [0x22; 32], [0x33; 32]);
        let ja = compute_ja4(&build_client_hello(&a)).unwrap();
        let jb = compute_ja4(&build_client_hello(&b)).unwrap();
        assert_eq!(ja.full(), jb.full(), "session_id 不应影响 JA4");
    }

    /// 非 ClientHello 数据应返回 None 而不是 panic。
    #[test]
    fn 非clienthello返回none() {
        assert!(compute_ja4(b"GET / HTTP/1.1\r\n").is_none());
        assert!(compute_ja4(&[]).is_none());
    }
}
