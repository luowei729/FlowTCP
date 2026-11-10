//! 密钥派生：从 TLS 1.3 exporter 输出派生方向性密钥
//!
//! # 为什么要复用 TLS exporter，而不是重新协商密钥
//!
//! 单次 TLS 1.3 握手完成后，双方已通过 ECDHE 建立了强共享秘密。
//! 若为数据面再跑一次 DH（或再套一层 TLS），会带来：
//!
//! 1. **双倍 CPU**：握手密钥交换 + 双层 AEAD
//! 2. **TLS-in-TLS 流量特征**：内层有完整的 TLS 记录结构，DPI 可识别
//! 3. **额外 RTT**：第二层握手必须串行完成
//!
//! RFC 8446 §7.5 提供的 TLS Exporter 正是为此设计：
//!
//! ```text
//! exporter_master_secret = 握手完成后由 key schedule 导出的秘密
//! output = HKDF-Expand-Label(exporter_master_secret,
//!                            "EXPORTER" + label,
//!                            context_hash + Hash(""),
//!                            length)
//! ```
//!
//! 用它派生数据面密钥，等价于「复用同一次握手的密码学强度」，
//! 且**不产生任何额外握手报文**，因此流量形态与普通 HTTPS 完全一致。
//!
//! # 为什么必须做方向隔离
//!
//! 客户端→服务端 与 服务端→客户端 若用同一套密钥：
//!
//! - **反射攻击**：攻击者把收到的密文原样回放给发送方，发送方会误认为
//!   是自己的入站数据并成功解密（因为密钥相同），造成状态混乱。
//! - **序号空间冲突**：双方序号都从 0 开始，nonce 会重复，
//!   直接破坏 AEAD 的安全性（nonce 重用 = 密钥流重用）。
//!
//! 因此必须派生 **4 组独立材料 × 2 个方向 = 6 段密钥**。

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// TLS exporter 标签。必须与服务端实现严格一致。
///
/// 命名采用 `EXPORTER-<Protocol>-v<Major>` 惯例，版本号嵌入标签中，
/// 使得协议主版本升级时密钥天然隔离（旧版本无法解密新版本流量）。
pub const EXPORTER_LABEL: &str = "EXPORTER-FlowTCP-v1";

/// exporter 输出长度（作为后续 HKDF 的 PRK）。
///
/// 取 32 字节 = SHA-256 输出长度，正好是 HKDF-Extract 的自然输出长度。
pub const EXPORTER_OUTPUT_LEN: usize = 32;

/// 派生出的完整密钥材料。
///
/// 字段顺序刻意保证「读密钥」与「写密钥」成对出现且命名对称，
/// 减少实现时把 c2s/s2c 弄反的概率（这是最易犯且最难排查的错误）。
pub struct DerivedKeys {
    /// 客户端→服务端的 AEAD 密钥。
    pub c2s_key: Vec<u8>,
    /// 客户端→服务端的 nonce 基线（12 字节）。
    pub c2s_iv: [u8; 12],
    /// 客户端→服务端的序号掩码密钥（16 字节）。
    pub c2s_sn_key: [u8; 16],

    /// 服务端→客户端的 AEAD 密钥。
    pub s2c_key: Vec<u8>,
    /// 服务端→客户端的 nonce 基线（12 字节）。
    pub s2c_iv: [u8; 12],
    /// 服务端→客户端的序号掩码密钥（16 字节）。
    pub s2c_sn_key: [u8; 16],
}

/// 脱敏 Debug：只输出各段长度，**绝不输出密钥内容**。
///
/// 为什么不直接 `#[derive(Debug)]`：派生结构体会把密钥字节完整打印，
/// 而 `tracing::debug!("{:?}", keys)` 这类写法在排错时极易出现，
/// 一旦发生就是密钥直接落进日志文件。这里从类型层面阻断该风险。
impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("c2s_key", &format!("<{} 字节,已隐藏>", self.c2s_key.len()))
            .field("c2s_iv", &"<12 字节,已隐藏>")
            .field("c2s_sn_key", &"<16 字节,已隐藏>")
            .field("s2c_key", &format!("<{} 字节,已隐藏>", self.s2c_key.len()))
            .field("s2c_iv", &"<12 字节,已隐藏>")
            .field("s2c_sn_key", &"<16 字节,已隐藏>")
            .finish()
    }
}

impl DerivedKeys {
    /// 按「本端角色」取出发送方向密钥。
    ///
    /// 这样调用方无需自己判断方向：
    /// - 客户端发送 → 用 c2s
    /// - 服务端发送 → 用 s2c
    pub fn tx_material(&self, is_client: bool) -> (&[u8], &[u8; 12], &[u8; 16]) {
        if is_client {
            (&self.c2s_key, &self.c2s_iv, &self.c2s_sn_key)
        } else {
            (&self.s2c_key, &self.s2c_iv, &self.s2c_sn_key)
        }
    }

    /// 按「本端角色」取接收方向密钥（与发送方向相反）。
    pub fn rx_material(&self, is_client: bool) -> (&[u8], &[u8; 12], &[u8; 16]) {
        if is_client {
            (&self.s2c_key, &self.s2c_iv, &self.s2c_sn_key)
        } else {
            (&self.c2s_key, &self.c2s_iv, &self.c2s_sn_key)
        }
    }
}

/// 从 TLS exporter 输出派生全部方向性密钥材料。
///
/// # 参数
///
/// - `exporter_output`：`export_keying_material(label, context, 32)` 的结果
/// - `context`：exporter 上下文，必须双方一致。用 `ClientHello.random || ServerHello.random`，
///   天然唯一且双方都有，无需额外协商。
/// - `key_len`：AEAD 密钥长度（AES-128-GCM 为 16，ChaCha20-Poly1305 为 32）
///
/// # 为什么用 HKDF 而不是直接切分 exporter 输出
///
/// exporter 只有 32 字节，而我们需要 16+12+16 = 44 字节（单方向）。
/// 直接切分会导致密钥复用（更高安全等级需要更大输出）。
/// HKDF-Expand 可以用任意 label 从同一个 PRK 无限导出**密码学独立**的密钥流，
/// 这是 RFC 5869 的标准用法。
pub fn derive(
    exporter_output: &[u8],
    context: &[u8],
    key_len: usize,
) -> Result<DerivedKeys, KeyDeriveError> {
    if exporter_output.len() != EXPORTER_OUTPUT_LEN {
        return Err(KeyDeriveError::BadExporterLen(exporter_output.len()));
    }
    // exporter 输出已是均匀随机的伪随机密钥，直接作为 HKDF 的 PRK 使用，
    // 跳过 Extract 阶段（避免不必要的 HKDF-Extract 开销）。
    let hk = Hkdf::<Sha256>::from_prk(exporter_output)
        .map_err(|_| KeyDeriveError::BadExporterLen(exporter_output.len()))?;

    // context 参与每个 label 的派生：把双方 random 的哈希拼进 info，
    // 确保即使 exporter 输出意外相同（理论上不会），不同会话的密钥也不同。
    let ctx_hash = sha256(context);

    let mut c2s_key = vec![0u8; key_len];
    let mut s2c_key = vec![0u8; key_len];
    let mut c2s_iv = [0u8; 12];
    let mut s2c_iv = [0u8; 12];
    let mut c2s_sn_key = [0u8; 16];
    let mut s2c_sn_key = [0u8; 16];

    expand(&hk, b"flowtcp c2s key", &ctx_hash, &mut c2s_key)?;
    expand(&hk, b"flowtcp s2c key", &ctx_hash, &mut s2c_key)?;
    expand(&hk, b"flowtcp c2s iv", &ctx_hash, &mut c2s_iv)?;
    expand(&hk, b"flowtcp s2c iv", &ctx_hash, &mut s2c_iv)?;
    expand(&hk, b"flowtcp c2s sn", &ctx_hash, &mut c2s_sn_key)?;
    expand(&hk, b"flowtcp s2c sn", &ctx_hash, &mut s2c_sn_key)?;

    Ok(DerivedKeys {
        c2s_key,
        c2s_iv,
        c2s_sn_key,
        s2c_key,
        s2c_iv,
        s2c_sn_key,
    })
}

/// HKDF-Expand，info = label || ctx_hash。
#[inline]
fn expand(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    ctx_hash: &[u8; 32],
    out: &mut [u8],
) -> Result<(), KeyDeriveError> {
    let mut info = Vec::with_capacity(label.len() + ctx_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(ctx_hash);
    hk.expand(&info, out)
        .map_err(|_| KeyDeriveError::ExpandFailed {
            requested: out.len(),
        })
}

/// SHA-256。
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 密钥派生错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyDeriveError {
    /// exporter 输出长度不是 32。
    #[error("exporter 输出长度异常: {0}（应为 32）")]
    BadExporterLen(usize),
    /// HKDF 扩展输出超出上限（255 * HashLen = 8160 字节）。
    #[error("HKDF 扩展失败，请求长度 {requested} 超出上限")]
    ExpandFailed {
        /// 请求的输出长度
        requested: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_exporter(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// 相同输入必须得到相同输出（双方可复现）。
    #[test]
    fn 派生可复现() {
        let ex = fake_exporter(0xAA);
        let ctx = b"clienthello.random||serverhello.random";
        let a = derive(&ex, ctx, 16).unwrap();
        let b = derive(&ex, ctx, 16).unwrap();
        assert_eq!(a.c2s_key, b.c2s_key);
        assert_eq!(a.s2c_key, b.s2c_key);
        assert_eq!(a.c2s_iv, b.c2s_iv);
        assert_eq!(a.c2s_sn_key, b.c2s_sn_key);
    }

    /// 所有 6 段材料必须互不相同。
    #[test]
    fn 六段材料互不相同() {
        let d = derive(&fake_exporter(0x55), b"ctx", 16).unwrap();
        let mut all: Vec<Vec<u8>> = vec![
            d.c2s_key.clone(),
            d.s2c_key.clone(),
            d.c2s_iv.to_vec(),
            d.s2c_iv.to_vec(),
            d.c2s_sn_key.to_vec(),
            d.s2c_sn_key.to_vec(),
        ];
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n, "存在重复的密钥材料");
    }

    /// 不同 context（不同会话）必须派生出不同密钥。
    #[test]
    fn 不同上下文派生不同密钥() {
        let ex = fake_exporter(0x11);
        let a = derive(&ex, b"session-A", 16).unwrap();
        let b = derive(&ex, b"session-B", 16).unwrap();
        assert_ne!(a.c2s_key, b.c2s_key);
        assert_ne!(a.c2s_iv, b.c2s_iv);
    }

    /// 不同 exporter 输出（不同握手）必须派生不同密钥。
    #[test]
    fn 不同exporter派生不同密钥() {
        let a = derive(&fake_exporter(0x11), b"ctx", 16).unwrap();
        let b = derive(&fake_exporter(0x22), b"ctx", 16).unwrap();
        assert_ne!(a.c2s_key, b.c2s_key);
    }

    /// 方向隔离：客户端发送密钥 == 服务端接收密钥，反之亦然。
    #[test]
    fn 方向隔离正确() {
        let d = derive(&fake_exporter(0x77), b"ctx", 16).unwrap();

        // 客户端视角：tx = c2s, rx = s2c
        let (ctx_key, _, _) = d.tx_material(true);
        let (crx_key, _, _) = d.rx_material(true);
        // 服务端视角：tx = s2c, rx = c2s
        let (stx_key, _, _) = d.tx_material(false);
        let (srx_key, _, _) = d.rx_material(false);

        // 客户端的发送必须能被服务端接收
        assert_eq!(ctx_key, srx_key);
        // 服务端的发送必须能被客户端接收
        assert_eq!(stx_key, crx_key);
        // 两个方向必须不同（否则存在反射攻击风险）
        assert_ne!(ctx_key, stx_key);
    }

    /// 支持两种 AEAD 密钥长度。
    #[test]
    fn 支持两种密钥长度() {
        let ex = fake_exporter(0x33);
        assert_eq!(derive(&ex, b"ctx", 16).unwrap().c2s_key.len(), 16);
        assert_eq!(derive(&ex, b"ctx", 32).unwrap().c2s_key.len(), 32);
    }

    #[test]
    fn 拒绝错误exporter长度() {
        assert!(matches!(
            derive(&[0u8; 16], b"ctx", 16).unwrap_err(),
            KeyDeriveError::BadExporterLen(16)
        ));
        assert!(matches!(
            derive(&[0u8; 64], b"ctx", 16).unwrap_err(),
            KeyDeriveError::BadExporterLen(64)
        ));
    }

    /// 端到端：派生密钥 → 记录层收发必须能互通。
    #[test]
    fn 与记录层集成() {
        use crate::record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder};

        let d = derive(&fake_exporter(0x99), b"e2e-ctx", 16).unwrap();

        // 客户端发送端
        let (ck, civ, csn) = d.tx_material(true);
        let mut c_enc = RecordEncoder::new(Keys::new(AeadAlgo::Aes128Gcm, ck, civ, csn).unwrap());
        // 服务端接收端
        let (rk, riv, rsn) = d.rx_material(false);
        let mut s_dec = RecordDecoder::new(Keys::new(AeadAlgo::Aes128Gcm, rk, riv, rsn).unwrap());

        let (seq, rec) = c_enc.seal(b"hello from client").unwrap();
        let (dseq, plain, _) = s_dec.open(&rec).unwrap();
        assert_eq!(seq, dseq);
        assert_eq!(plain, b"hello from client");
    }

    /// 反向：服务端 → 客户端 也必须互通，且与正向使用不同密钥。
    #[test]
    fn 反向传输同样互通() {
        use crate::record::{AeadAlgo, Keys, RecordDecoder, RecordEncoder};

        let d = derive(&fake_exporter(0xAB), b"e2e-ctx", 16).unwrap();

        let (sk, siv, ssn) = d.tx_material(false);
        let mut s_enc = RecordEncoder::new(Keys::new(AeadAlgo::Aes128Gcm, sk, siv, ssn).unwrap());
        let (ck, civ, csn) = d.rx_material(true);
        let mut c_dec = RecordDecoder::new(Keys::new(AeadAlgo::Aes128Gcm, ck, civ, csn).unwrap());

        let (_, rec) = s_enc.seal(b"hello from server").unwrap();

        // 用错误方向的解密器必须失败（验证方向隔离在真实数据上生效）
        let (wk, wiv, wsn) = d.rx_material(false); // 服务端 rx，即 c2s
        let mut wrong_dec =
            RecordDecoder::new(Keys::new(AeadAlgo::Aes128Gcm, wk, wiv, wsn).unwrap());
        assert!(wrong_dec.open(&rec).is_err(), "用错方向密钥竟然解密成功");

        // 正确方向必须成功
        let (_, plain, _) = c_dec.open(&rec).unwrap();
        assert_eq!(plain, b"hello from server");
    }

    /// 双向并发各 100 条记录，序号空间相互独立。
    #[test]
    fn 双向序号空间独立() {
        use crate::record::{AeadAlgo, Keys, RecordEncoder};

        let d = derive(&fake_exporter(0xCD), b"ctx", 16).unwrap();

        let (ck, civ, csn) = d.tx_material(true);
        let mut c_enc = RecordEncoder::new(Keys::new(AeadAlgo::Aes128Gcm, ck, civ, csn).unwrap());
        let (sk, siv, ssn) = d.tx_material(false);
        let mut s_enc = RecordEncoder::new(Keys::new(AeadAlgo::Aes128Gcm, sk, siv, ssn).unwrap());

        // 双方序号都从 0 开始，但密钥不同，因此不会冲突
        for i in 0..100u32 {
            let (cs, crec) = c_enc.seal(&i.to_be_bytes()).unwrap();
            let (ss, srec) = s_enc.seal(&i.to_be_bytes()).unwrap();
            assert_eq!(cs, i as u64);
            assert_eq!(ss, i as u64);
            assert_ne!(crec, srec, "双向密文不应相同");
        }
    }
}
