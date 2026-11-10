//! 命令行参数解析（手写，零依赖）
//!
//! # 为什么继续手写而不引入 clap
//!
//! Phase 3 后子命令从 3 个增至 5 个、选项从 3 个增至 15 个，确实到了
//! "该用 clap"的边界。但当前手写解析已能满足需求，且有三点实际收益：
//!
//! 1. **零新增依赖**：clap + derive 会让编译时间增加约 8 秒、二进制增大约 700KB
//! 2. **错误信息完全可控**：可以写出与项目文档风格一致的中文提示
//! 3. **`--help` 与 README 保持同步成本低**：只有一处需要维护
//!
//! 真正需要 clap 的信号是"需要 shell 补全 / 复杂子命令嵌套 / 配置文件合并"，
//! 到那时再迁移。

use std::collections::{HashMap, HashSet};

/// 解析后的参数。
#[derive(Debug, Default)]
pub struct Args {
    /// `--key value` 形式的选项。
    options: HashMap<String, String>,
    /// `--flag` 形式的开关。
    flags: HashSet<String>,
    /// 位置参数（不含子命令本身）。
    positional: Vec<String>,
}

impl Args {
    /// 解析 `argv`（不含程序名与子命令）。
    ///
    /// 支持 `--key value` 与 `--key=value` 两种写法。
    pub fn parse(argv: &[String]) -> Result<Self, String> {
        let mut args = Args::default();
        let mut i = 0;

        while i < argv.len() {
            let a = &argv[i];

            if let Some(rest) = a.strip_prefix("--") {
                if let Some((k, v)) = rest.split_once('=') {
                    // --key=value
                    args.options.insert(k.to_string(), v.to_string());
                } else if is_flag(rest) {
                    args.flags.insert(rest.to_string());
                } else {
                    // --key value
                    let v = argv.get(i + 1).ok_or_else(|| {
                        format!("选项 --{rest} 缺少取值（用法：--{rest} <value>）")
                    })?;
                    args.options.insert(rest.to_string(), v.clone());
                    i += 1;
                }
            } else if a.starts_with('-') && a.len() > 1 {
                // 短选项统一当作 flag（目前只有 -h / -v）
                args.flags.insert(a.trim_start_matches('-').to_string());
            } else {
                args.positional.push(a.clone());
            }
            i += 1;
        }

        Ok(args)
    }

    /// 取选项值。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(String::as_str)
    }

    /// 取必填选项，缺失时报错。
    pub fn need(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .ok_or_else(|| format!("缺少必填选项 --{key}（用 --help 查看用法）"))
    }

    /// 是否有某个开关。
    pub fn has_flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }

    /// 位置参数。
    ///
    /// 目前所有子命令都用命名选项，没有位置参数；
    /// 保留这个访问器是为了测试能验证解析正确，以及将来加 `flowtcp bench <url>`
    /// 这类带位置参数的命令。
    #[allow(dead_code)]
    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// 解析为 `SocketAddr`。
    pub fn addr(&self, key: &str) -> Result<std::net::SocketAddr, String> {
        let v = self.need(key)?;
        v.parse()
            .map_err(|e| format!("--{key} 不是合法地址 `{v}`: {e}"))
    }

    /// 解析可选的 `SocketAddr`。
    pub fn opt_addr(&self, key: &str) -> Result<Option<std::net::SocketAddr>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|e| format!("--{key} 不是合法地址 `{v}`: {e}")),
        }
    }

    /// 解析为 `u16`。
    pub fn u16_of(&self, key: &str) -> Result<Option<u16>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|e| format!("--{key} 不是合法数字 `{v}`: {e}")),
        }
    }

    /// 解析为 `u64`。
    pub fn u64_of(&self, key: &str) -> Result<Option<u64>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|e| format!("--{key} 不是合法数字 `{v}`: {e}")),
        }
    }

    /// 解析带单位的字节数：`524288`、`512K`、`8M`、`1G`（大小写不敏感）。
    ///
    /// # 为什么需要它
    ///
    /// 窗口大小动辄几 MB，让用户手写 `8388608` 极易出错。
    /// 对齐 Hysteria 2 的做法：它的 `initStreamReceiveWindow` 虽然是纯字节数，
    /// 但带宽字段支持 `mbps`/`gbps` 后缀 —— 可读单位是这类参数的标准体验。
    ///
    /// 单位按 **1024 进制**（`8M` = 8 × 1024 × 1024 = 8388608），
    /// 与内存/缓冲区语义一致，而非网络速率的 1000 进制。
    pub fn bytes_of(&self, key: &str) -> Result<Option<u64>, String> {
        let Some(raw) = self.get(key) else {
            return Ok(None);
        };
        parse_bytes(raw).map(Some).map_err(|e| format!("--{key} {e}"))
    }
}

/// 解析 `"8M"` / `"512K"` / `"1048576"` 这类字节数。
fn parse_bytes(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("不能为空".into());
    }
    // 找出最后一个非数字字符，判断是否有单位后缀
    let (num, mult) = match s.chars().last() {
        Some(c) if c.eq_ignore_ascii_case(&'k') => (&s[..s.len() - 1], 1024u64),
        Some(c) if c.eq_ignore_ascii_case(&'m') => (&s[..s.len() - 1], 1024 * 1024),
        Some(c) if c.eq_ignore_ascii_case(&'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("`{s}` 不是合法字节数（可用 8M / 512K / 1048576）"))?;
    n.checked_mul(mult)
        .filter(|v| *v > 0)
        .ok_or_else(|| format!("`{s}` 超出范围或为 0"))
}

/// 哪些选项是"开关"（后面不跟取值）。
///
/// 必须显式列出：否则 `--allow-private --socks5 1.2.3.4:1080` 会把
/// `--socks5` 当成 `--allow-private` 的取值，导致诡异的解析结果。
fn is_flag(name: &str) -> bool {
    matches!(name, "allow-private" | "verbose" | "help" | "quiet")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn 解析键值对() {
        let a = Args::parse(&v(&["--listen", "0.0.0.0:443", "--password", "x"])).unwrap();
        assert_eq!(a.get("listen"), Some("0.0.0.0:443"));
        assert_eq!(a.get("password"), Some("x"));
    }

    #[test]
    fn 支持等号写法() {
        let a = Args::parse(&v(&["--listen=0.0.0.0:443"])).unwrap();
        assert_eq!(a.get("listen"), Some("0.0.0.0:443"));
    }

    #[test]
    fn 开关不吞后面的选项() {
        let a = Args::parse(&v(&["--allow-private", "--socks5", "127.0.0.1:1080"])).unwrap();
        assert!(a.has_flag("allow-private"));
        assert_eq!(a.get("socks5"), Some("127.0.0.1:1080"));
    }

    #[test]
    fn 位置参数被收集() {
        let a = Args::parse(&v(&["selftest", "--verbose"])).unwrap();
        assert_eq!(a.positional(), &["selftest".to_string()]);
        assert!(a.has_flag("verbose"));
    }

    #[test]
    fn 缺少取值时报错() {
        let e = Args::parse(&v(&["--listen"])).unwrap_err();
        assert!(e.contains("缺少取值"), "实际: {e}");
    }

    #[test]
    fn need缺失时报错() {
        let a = Args::parse(&v(&["--listen", "1.2.3.4:1"])).unwrap();
        assert!(a.need("password").unwrap_err().contains("缺少必填"));
    }

    #[test]
    fn 地址解析() {
        let a = Args::parse(&v(&["--listen", "0.0.0.0:443"])).unwrap();
        assert_eq!(a.addr("listen").unwrap().port(), 443);
        assert!(a.opt_addr("socks5").unwrap().is_none());
        assert!(Args::parse(&v(&["--listen", "bad"]))
            .unwrap()
            .addr("listen")
            .is_err());
    }

    #[test]
    fn 短选项识别为开关() {
        let a = Args::parse(&v(&["-v"])).unwrap();
        assert!(a.has_flag("v"));
    }

    // ---- 字节数单位解析（--stream-window 使用）----

    #[test]
    fn 解析带单位的字节数() {
        assert_eq!(parse_bytes("8M").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_bytes("8m").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_bytes("512K").unwrap(), 512 * 1024);
        assert_eq!(parse_bytes("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1048576").unwrap(), 1048576);
        assert_eq!(parse_bytes(" 16M ").unwrap(), 16 * 1024 * 1024);
    }

    #[test]
    fn 拒绝非法与零值() {
        // 0 会让流一开就卡死（窗口为 0 → 永远没信用），必须拒绝
        assert!(parse_bytes("0").is_err());
        assert!(parse_bytes("0M").is_err());
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("abc").is_err());
        assert!(parse_bytes("-8M").is_err());
        // 溢出 u64
        assert!(parse_bytes("99999999999G").is_err());
    }
}
