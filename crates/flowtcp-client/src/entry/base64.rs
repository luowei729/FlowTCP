//! Base64 编解码（只实现 Standard 字母表，带 `=` 填充）。
//!
//! # 为什么自己写而不是加 `base64` 依赖
//!
//! 我们只需要 RFC 4648 §4 的 Standard 变体，用途单一：
//! - 解码 HTTP `Proxy-Authorization: Basic <base64>`
//! - 编码用于测试与文档示例
//!
//! 一个不带变长输出的解码器只有几十行，比引入依赖（及其构建时间、
//! 依赖审计成本）更划算。本项目一直刻意保持依赖精简 —— 密码学相关的
//! 才用现成库（`aes-gcm` / `chacha20poly1305`），格式转换类尽量自写。
//!
//! # 安全性
//!
//! 解码是**严格**的：任何非法字符、错误长度、错误填充一律返回 `None`。
//! 宽松解码（忽略空白、容忍缺失填充）是许多解析漏洞的来源，
//! 而 HTTP 头部里不该出现这类变体。

/// 字母表（Standard，RFC 4648 §4）。
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 解码表：字节值 → 6 位值，`0xFF` = 非法。
///
/// 用编译期常量表而不是每次查找 `ALPHABET`：解码在认证路径上，
/// 虽然频率低，但常量表更简单也更不容易写错。
static DECODE: [u8; 256] = build_decode_table();

/// 编译期构造解码表。
const fn build_decode_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let mut i = 0usize;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
}

/// Base64 编码。
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        // 第 2/3 个字符在输入不足时用 '=' 填充
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3F] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Base64 解码。
///
/// 严格模式：非法字符、长度非 4 的倍数、填充位置错误 → 返回 `None`。
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    // 必须是 4 的倍数
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);

    for (idx, quad) in bytes.chunks(4).enumerate() {
        let is_last = idx == bytes.len() / 4 - 1;

        // 统计本组的填充数（只允许出现在最后一组的末尾）
        let pad = match (quad[2], quad[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if pad > 0 && !is_last {
            return None; // 填充只能出现在末尾
        }

        let mut n = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let v = if c == b'=' {
                // '=' 只允许出现在本组末尾连续位置
                if i < 4 - pad {
                    return None;
                }
                0u32
            } else {
                let d = DECODE[c as usize];
                if d == 0xFF {
                    return None; // 非法字符
                }
                d as u32
            };
            n = (n << 6) | v;
        }

        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 编码符合rfc4648测试向量() {
        // RFC 4648 §10 的标准测试向量
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn 解码符合rfc4648测试向量() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn 编解码往返() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len)
                .map(|i: usize| (i.wrapping_mul(37) ^ 0x5A) as u8)
                .collect();
            let enc = encode(&data);
            assert_eq!(decode(&enc).unwrap(), data, "长度 {len} 往返失败");
        }
    }

    #[test]
    fn 实际认证串往返() {
        // 用户实际要用的凭据
        let raw = b"admin:abcd1234";
        assert_eq!(encode(raw), "YWRtaW46YWJjZDEyMzQ=");
        assert_eq!(decode("YWRtaW46YWJjZDEyMzQ=").unwrap(), raw);
    }

    #[test]
    fn 拒绝非法输入() {
        assert!(decode("Zm9").is_none(), "长度非 4 的倍数");
        assert!(decode("Zm9v!").is_none(), "非法字符");
        assert!(decode("Zm 9v").is_none(), "含空格");
        assert!(decode("Zg==Zg==").is_none(), "填充出现在非末尾");
        assert!(decode("=m9v").is_none(), "填充在开头");
        assert!(decode("Z===").is_none(), "过多填充");
        // 含非 ASCII（多字节 UTF-8）
        assert!(decode("中文").is_none());
    }

    #[test]
    fn 处理二进制全字节范围() {
        let all: Vec<u8> = (0..=255u8).collect();
        let enc = encode(&all);
        assert_eq!(decode(&enc).unwrap(), all);
    }
}
