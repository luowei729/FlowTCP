//! AnyTLS 式流量整形（padding / 分包）
//!
//! # 要解决的问题：TLS-in-TLS 特征
//!
//! 我们内层承载的往往是**另一个 TLS 会话**（HTTPS 流量）。这会形成
//! 「TLS 记录套 TLS 记录」的结构，其尺寸分布有极强的可识别性：
//!
//! ```text
//! 内层 ClientHello ≈ 517 字节 → 外层 TLS 记录 = 5 + 8 + 517 + 16 = 546
//! 内层 ServerHello ≈ 1300 字节 → 外层 = ~1329
//! ...
//! ```
//!
//! 这些**固定数值**在流量中反复出现，任何统计型 DPI 都能识别。
//! REALITY 作者的原话：
//!
//! > 也可以搭配 XTLS 以外的协议使用，但**不建议**这样做，
//! > 因为它们存在明显且**已被针对**的 TLS in TLS 特征
//!
//! # AnyTLS 的解法
//!
//! 按「第几个写入」施加确定的**分片 + 填充**策略，使线上包长分布
//! 与真实浏览行为一致。策略用文本描述，可由服务端下发：
//!
//! ```text
//! stop=8
//! 0=30-30
//! 1=100-400
//! 2=400
//! 500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
//! 3=9-9,500-1000
//! ```
//!
//! 语义：
//! - `stop=8`：只对第 0~7 次写入做整形，之后直通
//! - `N=<规则>`：第 N 次写入的规则
//! - `a-b`：随机拆出一个 `a..=b` 字节的分片
//! - `c`：检查符号 —— 若此时用户数据已发完，直接返回，不再发后续填充
//! - `stop` 之前的包若无规则，则直通
//!
//! # 为什么只整形前几个包
//!
//! 1. **握手阶段才是特征最明显的地方**（ClientHello/ServerHello 尺寸固定）
//! 2. 数据阶段整形会**严重损害吞吐**（把大包拆小 = 更多 header 开销）
//! 3. 真实浏览器也只在前几个包有特征性尺寸，之后就是变长的数据流
//!
//! # 与「多倍发包 / FEC」的关系
//!
//! 两者目标不同但可以叠加：
//! - padding：**改尺寸分布**，对抗统计型 DPI
//! - FEC：**加冗余**，对抗丢包
//!
//! 注意 padding 会**增加带宽**（填充字节是纯浪费），默认只在握手阶段启用。

use std::ops::RangeInclusive;

use thiserror::Error;

/// 单个整形步骤。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PadStep {
    /// 拆出一个指定范围（含端点）大小的分片。
    Split(RangeInclusive<usize>),
    /// 检查符号 `c`：若此时用户数据已发送完毕，则停止后续步骤。
    Check,
}

/// 单次写入的整形规则。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PadRule {
    /// 按顺序执行的步骤。
    pub steps: Vec<PadStep>,
}

/// 完整的整形方案。
#[derive(Debug, Clone)]
pub struct PaddingScheme {
    /// 在「第几次写入」之后停止整形（此后直通）。
    stop: u32,
    /// 按写入序号索引的规则。`None` 表示该序号直通。
    rules: Vec<Option<PadRule>>,
}

/// AnyTLS 的默认方案（原样采用，已被实践验证）。
///
/// 保留原始文本形式而不是硬编码结构，便于服务端下发替换方案
/// （AnyTLS 的设计意图：默认方案一旦被列入黑名单，服务端可即时更换）。
///
/// # 关于续行
///
/// AnyTLS 官方文档里的默认方案存在**无序号续行**：
///
/// ```text
/// 2=400
/// 500,c,500-1000,c,500-1000,c,500-1000,c,500-1000      ← 无 "N=" 前缀
/// ```
///
/// 这是第 2 个包的规则（文档说明"包 2 将分成 5 个尺寸在 400-500/500-1000 的包"）。
/// 本实现的解析器**支持续行**：无 `=` 的行追加到最近一个已声明序号。
/// 若该序号已有规则，则以续行内容覆盖（符合"后写优先"直觉）。
pub const DEFAULT_SCHEME_TEXT: &str = "\
stop=8
0=30-30
1=100-400
2=500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// 整形方案解析/使用错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PaddingError {
    /// `stop` 缺失或非法。
    #[error("缺少或非法 stop 定义（应为 stop=<正整数>）")]
    BadStop,
    /// 规则行格式错误。
    #[error("规则行格式错误: {0:?}")]
    BadRuleLine(String),
    /// 范围格式错误。
    #[error("范围格式错误: {0:?}（应为 a-b）")]
    BadRange(String),
    /// 范围颠倒（下界大于上界）。
    #[error("范围颠倒: {0}-{1}")]
    ReversedRange(usize, usize),
    /// 序号超出 stop 上限。
    #[error("规则序号 {0} 超出 stop 上限 {1}")]
    IndexBeyondStop(usize, u32),
}

impl PaddingScheme {
    /// 使用 AnyTLS 默认方案。
    pub fn default_scheme() -> Self {
        // 默认方案是硬编码常量，解析失败属于程序错误而非输入错误
        Self::parse(DEFAULT_SCHEME_TEXT).expect("内置默认 padding 方案必须可解析")
    }

    /// 不做任何整形的方案（用于性能优先场景）。
    pub fn none() -> Self {
        PaddingScheme {
            stop: 0,
            rules: Vec::new(),
        }
    }

    /// 从 AnyTLS 格式的文本解析。
    ///
    /// 支持无序号续行：形如 `500,c,500-1000` 的行会追加到最近一个 `N=` 声明的序号。
    pub fn parse(text: &str) -> Result<Self, PaddingError> {
        let mut stop: Option<u32> = None;
        let mut raw_rules: Vec<(usize, String)> = Vec::new();
        // 最近一个声明的序号，用于续行归属
        let mut last_idx: Option<usize> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(v) = line.strip_prefix("stop=") {
                stop = Some(v.trim().parse().map_err(|_| PaddingError::BadStop)?);
                continue;
            }
            if let Some((idx, rest)) = line.split_once('=') {
                let idx: usize = idx
                    .trim()
                    .parse()
                    .map_err(|_| PaddingError::BadRuleLine(line.to_string()))?;
                raw_rules.push((idx, rest.trim().to_string()));
                last_idx = Some(idx);
            } else {
                // 无序号续行：归属最近的序号
                match last_idx {
                    Some(idx) => {
                        if let Some(slot) = raw_rules.iter_mut().find(|(i, _)| *i == idx) {
                            slot.1.push(',');
                            slot.1.push_str(line);
                        }
                    }
                    None => return Err(PaddingError::BadRuleLine(line.to_string())),
                }
            }
        }

        let stop = stop.ok_or(PaddingError::BadStop)?;
        let mut rules: Vec<Option<PadRule>> = vec![None; stop as usize];

        for (idx, rest) in raw_rules {
            if idx >= stop as usize {
                return Err(PaddingError::IndexBeyondStop(idx, stop));
            }
            let mut steps = Vec::new();
            for token in rest.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if token == "c" || token == "C" {
                    steps.push(PadStep::Check);
                } else if let Some((a, b)) = token.split_once('-') {
                    let lo: usize = a
                        .trim()
                        .parse()
                        .map_err(|_| PaddingError::BadRange(token.to_string()))?;
                    let hi: usize = b
                        .trim()
                        .parse()
                        .map_err(|_| PaddingError::BadRange(token.to_string()))?;
                    if lo > hi {
                        return Err(PaddingError::ReversedRange(lo, hi));
                    }
                    steps.push(PadStep::Split(lo..=hi));
                } else {
                    // 单个数字视为 a-a
                    let v: usize = token
                        .parse()
                        .map_err(|_| PaddingError::BadRange(token.to_string()))?;
                    steps.push(PadStep::Split(v..=v));
                }
            }
            rules[idx] = Some(PadRule { steps });
        }

        Ok(PaddingScheme { stop, rules })
    }

    /// 在「第几次写入」之后停止整形。
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// 该写入序号是否需要整形。
    pub fn should_shape(&self, write_index: u32) -> bool {
        write_index < self.stop
            && self
                .rules
                .get(write_index as usize)
                .is_some_and(|r| r.is_some())
    }

    /// 为第 `write_index` 次写入、共 `data_len` 字节的数据规划分片大小。
    ///
    /// 返回 `None` 表示**无需整形**（直通原样写出）。
    ///
    /// 返回 `Some(sizes)` 时，`sizes` 之和可能：
    /// - **小于** `data_len`：剩余数据由调用方在最后一次性写出
    /// - **大于** `data_len`：多出的部分为填充字节（调用方需补零）
    ///
    /// # `Check` 符号的处理
    ///
    /// `Check` 表示「若用户数据已发完则提前结束」。
    /// 例如规则 `500,c,500-1000` 在 `data_len=600` 时：
    /// 1. 拆出 500 → 剩余 100
    /// 2. 遇到 `c`，但还有 100 字节未发 → 继续
    /// 3. 拆出 500~1000 → 超出剩余，最后一包补填充
    ///
    /// 而在 `data_len=500` 时：
    /// 1. 拆出 500 → 剩余 0
    /// 2. 遇到 `c`，无剩余 → **停止**，不再产生后续填充包
    pub fn plan(&self, write_index: u32, data_len: usize) -> Option<Vec<usize>> {
        if write_index >= self.stop {
            return None;
        }
        let rule = self.rules.get(write_index as usize)?.as_ref()?;
        if rule.steps.is_empty() {
            return None;
        }

        let mut sizes = Vec::new();
        let mut remaining = data_len;
        // 确定性抖动：用包序号与长度派生，保证同一输入可复现（便于测试与回放）
        let mut lcg = (write_index as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(data_len as u64);

        for step in &rule.steps {
            match step {
                PadStep::Check => {
                    if remaining == 0 {
                        break;
                    }
                }
                PadStep::Split(range) => {
                    let lo = *range.start();
                    let hi = *range.end();
                    // xorshift 取随机值，范围 [lo, hi]
                    lcg ^= lcg << 13;
                    lcg ^= lcg >> 7;
                    lcg ^= lcg << 17;
                    let span = hi - lo + 1;
                    let pick = lo + (lcg % span as u64) as usize;
                    sizes.push(pick);
                    remaining = remaining.saturating_sub(pick);
                }
            }
        }

        if sizes.is_empty() {
            None
        } else {
            Some(sizes)
        }
    }
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::default_scheme()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认方案可解析() {
        let s = PaddingScheme::default_scheme();
        assert_eq!(s.stop(), 8);
    }

    #[test]
    fn 解析简单方案() {
        let s = PaddingScheme::parse("stop=3\n0=100-100\n1=c,200-200\n2=5").unwrap();
        assert_eq!(s.stop(), 3);
        assert_eq!(
            s.rules[0].as_ref().unwrap().steps,
            vec![PadStep::Split(100..=100)]
        );
        assert_eq!(
            s.rules[1].as_ref().unwrap().steps,
            vec![PadStep::Check, PadStep::Split(200..=200)]
        );
        assert_eq!(
            s.rules[2].as_ref().unwrap().steps,
            vec![PadStep::Split(5..=5)]
        );
    }

    #[test]
    fn 缺少stop报错() {
        assert_eq!(
            PaddingScheme::parse("0=100-100").unwrap_err(),
            PaddingError::BadStop
        );
    }

    #[test]
    fn 序号超界报错() {
        assert_eq!(
            PaddingScheme::parse("stop=2\n5=100-100").unwrap_err(),
            PaddingError::IndexBeyondStop(5, 2)
        );
    }

    #[test]
    fn 范围颠倒报错() {
        assert_eq!(
            PaddingScheme::parse("stop=2\n0=500-100").unwrap_err(),
            PaddingError::ReversedRange(500, 100)
        );
    }

    #[test]
    fn 格式错误报错() {
        assert!(matches!(
            PaddingScheme::parse("stop=2\nnoequalsign"),
            Err(PaddingError::BadRuleLine(_))
        ));
        assert!(matches!(
            PaddingScheme::parse("stop=2\n0=abc"),
            Err(PaddingError::BadRange(_))
        ));
    }

    #[test]
    fn 超出stop不再整形() {
        let s = PaddingScheme::default_scheme();
        assert!(s.should_shape(0));
        assert!(s.should_shape(7));
        assert!(!s.should_shape(8));
        assert!(!s.should_shape(100));
        assert_eq!(s.plan(8, 10000), None);
        assert_eq!(s.plan(100, 10000), None);
    }

    #[test]
    fn 无规则包直通() {
        let s = PaddingScheme::parse("stop=4\n0=30-30").unwrap();
        // 序号 1/2/3 无规则 → 直通
        assert!(!s.should_shape(1));
        assert_eq!(s.plan(1, 1000), None);
    }

    #[test]
    fn 空方案直通() {
        let s = PaddingScheme::none();
        assert_eq!(s.stop(), 0);
        assert_eq!(s.plan(0, 1000), None);
    }

    /// Check 符号的核心语义：数据发完就停，不再产生填充包。
    #[test]
    fn check符号在数据发完时提前结束() {
        let s = PaddingScheme::parse("stop=2\n1=500,c,500-1000").unwrap();

        // data_len=500：第一片正好发完 → Check 命中 → 停止（只有 1 个分片）
        let p = s.plan(1, 500).unwrap();
        assert_eq!(p, vec![500], "数据已发完，不应再产生填充分片");

        // data_len=600：第一片 500 后剩 100 → Check 不命中 → 继续拆第二片
        let p = s.plan(1, 600).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], 500);
        assert!((500..=1000).contains(&p[1]));
    }

    /// 单个数字（无范围）必须精确匹配。
    #[test]
    fn 定长分片() {
        let s = PaddingScheme::parse("stop=2\n0=30-30").unwrap();
        assert_eq!(s.plan(0, 1000).unwrap(), vec![30]);
        // 即使数据只有 10 字节，也要求写 30 字节（后续 20 字节为填充）
        assert_eq!(s.plan(0, 10).unwrap(), vec![30]);
    }

    /// 默认方案第 0 包固定 30 字节（认证帧的填充特征）。
    #[test]
    fn 默认方案第0包固定30字节() {
        let s = PaddingScheme::default_scheme();
        assert_eq!(s.plan(0, 34).unwrap(), vec![30]);
    }

    /// 同一输入必须产生同一规划（确定性抖动，便于回放与测试）。
    #[test]
    fn 规划可复现() {
        let s = PaddingScheme::default_scheme();
        for idx in 0..8u32 {
            let a = s.plan(idx, 2000);
            let b = s.plan(idx, 2000);
            assert_eq!(a, b, "序号 {idx} 的规划应可复现");
        }
    }

    /// 随机范围必须落在区间内。
    #[test]
    fn 随机范围在区间内() {
        let s = PaddingScheme::parse("stop=2\n1=100-400").unwrap();
        for len in [10usize, 500, 5000] {
            let p = s.plan(1, len).unwrap();
            assert_eq!(p.len(), 1);
            assert!(
                (100..=400).contains(&p[0]),
                "分片 {} 不在 100..=400 内",
                p[0]
            );
        }
    }

    /// 默认方案能处理任意输入长度而不 panic。
    #[test]
    fn 默认方案鲁棒性() {
        let s = PaddingScheme::default_scheme();
        for idx in 0..10u32 {
            for len in [0usize, 1, 30, 34, 517, 1000, 16384, 100000] {
                let _ = s.plan(idx, len);
            }
        }
    }

    /// 注释与空行必须被忽略（便于运维在配置里做说明）。
    #[test]
    fn 忽略注释与空行() {
        let s = PaddingScheme::parse("stop=2\n# 这是注释\n\n0=30-30\n").unwrap();
        assert_eq!(s.stop(), 2);
        assert!(s.rules[0].is_some());
    }

    /// ★ 支持无序号续行（AnyTLS 官方默认方案的写法）。
    #[test]
    fn 支持无序号续行() {
        let text = "stop=3\n2=400\n500,c,500-1000";
        let s = PaddingScheme::parse(text).unwrap();
        let steps = &s.rules[2].as_ref().unwrap().steps;
        // 续行内容应被追加：400, 500, c, 500-1000
        assert_eq!(steps.len(), 4, "实际: {steps:?}");
        assert_eq!(steps[0], PadStep::Split(400..=400));
        assert_eq!(steps[1], PadStep::Split(500..=500));
        assert_eq!(steps[2], PadStep::Check);
    }

    /// 无序号且无前置序号 → 报错。
    #[test]
    fn 孤立续行报错() {
        assert!(matches!(
            PaddingScheme::parse("stop=2\n500,c"),
            Err(PaddingError::BadRuleLine(_))
        ));
    }
}
