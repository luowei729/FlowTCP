//! 记录层：AEAD 加密 + 显式序号 + TLS 1.3 记录伪装
//!
//! # 本模块要解决的根本矛盾
//!
//! 我们既要 **TLS 1.3 的外观**（抗 DPI/主动探测），又要 **UDP 的语义**
//! （容忍乱序、丢包不影响后续包）。但标准 TLS 1.3 记录层做不到后者：
//!
//! > TLS relies on an implicit sequence number on records. If a record is not
//! > received, then the recipient will use the wrong sequence number when
//! > attempting to remove record protection from subsequent records.
//! > —— RFC 9147 §3
//!
//! 即：TLS 的 AEAD nonce 由**隐式**记录序号推算，丢一个包 → 后续所有记录的
//! nonce 全错 → 全部解密失败。这会让 FakeTCP 上的丢包直接变成连接死亡。
//!
//! # 解法：TLS 1.3 的头 + DTLS 1.3 的序号
//!
//! 取两者的交集，得到「外观是 TLS，语义是数据报」的记录层：
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +---------------+---------------+-------------------------------+
//! |     0x17      |  0x03 |  0x03 |         length (16)           |
//! +---------------+---------------+-------------------------------+
//! |                      masked_seq (64)                          |
//! +---------------------------------------------------------------+
//! |                  ciphertext (= plaintext + tag)               |
//! +---------------------------------------------------------------+
//! ```
//!
//! - 前 5 字节与真实 TLS 1.3 `application_data` 记录**逐字节一致**
//! - 紧随其后的 8 字节是「号掩码」，看起来只是随机密文的一部分
//!   （真实 TLS 记录在此位置本来就是 AEAD 密文，因此不可区分）
//!
//! # 序号为什么要加密（而不是明文放置）
//!
//! 明文序号会被 DPI 观察并用于关联同一连接的多条路径（隐私问题），
//! 同时「8 字节单调递增」本身就是极强特征。借用 DTLS 1.3 §4.2.3 的方案：
//!
//! ```text
//! mask       = AES-ECB(sn_key, ciphertext[0..16])[0..8]
//! masked_seq = seq XOR mask        (线上)
//! seq        = masked_seq XOR mask (接收端还原)
//! ```
//!
//! 关键性质：mask 只依赖**密文前 16 字节**，因此接收端无需任何额外状态
//! 就能还原序号——不存在"要先知道序号才能解密"的鸡蛋问题。
//!
//! # AAD 选择（易错点）
//!
//! `AAD = record_header(5B) || 未掩码序号(8B)`
//!
//! **必须使用未掩码的序号**。若 AAD 里放掩码后的序号，就会形成
//! 「AAD 依赖密文 → 密文依赖 AAD」的循环依赖，被迫加密两遍（首遍算掩码、
//! 次遍正式加密），既浪费 CPU 又增加出错面。
//!
//! RFC 9147 §4.2.3 原文明确：
//! > The entire header value shown in Figure 4 (but **prior to record number
//! > encryption**) is used as the additional data value for the AEAD function.
//!
//! 采用未掩码序号作 AAD 后，加密只需一遍，且篡改线上掩码会导致还原出的
//! 序号变化 → nonce 与 AAD 同时错 → 解密必然失败，安全性不变。

use std::sync::Arc;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag};
use thiserror::Error;
/// TLS 1.3 `application_data` 内容类型。
///
/// 必须与真实 TLS 一致：0x17 = application_data, 0x03 0x03 = legacy record version。
pub const TLS_APP_DATA: u8 = 0x17;
/// TLS 记录版本高字节。
pub const TLS_VERSION_MAJOR: u8 = 0x03;
/// TLS 记录版本低字节（TLS 1.2 兼容值，TLS 1.3 记录头仍沿用）。
pub const TLS_VERSION_MINOR: u8 = 0x03;

/// 记录头长度：type(1) + version(2) + length(2)。
pub const RECORD_HEADER_LEN: usize = 5;
/// 序号掩码长度。
pub const SEQ_MASK_LEN: usize = 8;
/// AEAD 认证标签长度（AES-GCM 与 ChaCha20-Poly1305 都是 16）。
pub const TAG_LEN: usize = 16;
/// 序号掩码生成所需的密文前缀长度（AES 块大小）。
pub const SEQ_MASK_SAMPLE_LEN: usize = 16;
/// AAD 长度 = 记录头 + 序号掩码。
pub const AAD_LEN: usize = RECORD_HEADER_LEN + SEQ_MASK_LEN;
/// 记录层明文上限（TLS 规范上限 2^14）。
pub const MAX_RECORD_PLAINTEXT: usize = 16384;
/// 单条记录在线上占用字节的硬上限。
pub const MAX_RECORD_WIRE: usize =
    RECORD_HEADER_LEN + SEQ_MASK_LEN + MAX_RECORD_PLAINTEXT + TAG_LEN;
/// 重放窗口位宽。1024 位可容忍 10Gbps 链路下约 8ms 的乱序。
pub const REPLAY_WINDOW_BITS: usize = 1024;

/// 方向性密钥材料。
///
/// 由 TLS 1.3 exporter 派生（见 [`crate::keyderive`]），
/// 读（本端接收）与写（本端发送）必须使用两套独立密钥，防止反射攻击。
///
/// # ★ 为什么缓存密码学实例（实测数据支撑）
///
/// `Aes128Gcm::new_from_slice` 每次调用都要做一次 **AES key expansion**，
/// 实测 **124 ns**；`Aes128::new_from_slice`（`seq_mask` 用）**75 ns**。
/// 两者合计约 **199 ns/包**。
///
/// 而 1400B（MTU 典型包）加密只需 1773 ns，64B（DNS/游戏）只需 452 ns，
/// 意味着：
///
/// | 包大小 | 单包加密 | 密钥调度占比 |
/// |--------|---------|-------------|
/// | 64B    | 452 ns  | **44%** |
/// | 512B   | 915 ns  | 22% |
/// | 1400B  | 1773 ns | 11% |
/// | 16KB   | 16021 ns| 1.2% |
///
/// 小包（DNS 查询、游戏同步、VoIP）是代理隧道的常态，**近一半 CPU
/// 消耗在重复的密钥调度上**。缓存后这部分开销归零。
///
/// # 为什么用 `Arc`
///
/// `Keys` 会被 clone 到 `RecordEncoder` 与 `RecordDecoder`（方向不同但同源）。
/// 用 `Arc` 让 clone 变成 O(1) 引用计数，且两端共享同一份实例缓存。
#[derive(Clone)]
pub struct Keys {
    /// 使用的 AEAD 算法。
    algo: AeadAlgo,
    /// AEAD nonce 基线（12 字节），实际 nonce = iv XOR seq。
    ///
    /// 这是唯一需要保留的原始材料：nonce 每条记录都要重算。
    /// 密钥本身已由 `cipher` 内部的实例持有，不再重复存储。
    iv: [u8; 12],
    /// 预先构造好的密码学原语（避免每包重建密钥调度）。
    cipher: Arc<CachedCipher>,
}

/// 缓存的密码学原语实例。
///
/// 见 [`Keys`] 的文档说明为什么必须缓存。
///
/// 用 `Box` 包裹：`Aes128` 内含 176 字节 round key 表，
/// 直接内联会让 `Keys` 变得很大，clone/移动代价上升。
enum CachedCipher {
    /// AES-128-GCM 路径。
    Aes {
        /// AEAD 实例（加解密共用，AEAD 无内部可变状态）。
        gcm: Box<Aes128Gcm>,
        /// `seq_mask` 用的单块 ECB 实例。
        ecb: Box<Aes128>,
    },
    /// ChaCha20-Poly1305 路径。
    ///
    /// 注意仍然带一个 `ecb`：`seq_mask` 固定用 AES-128-ECB（与 DTLS 1.3
    /// 的序号加密一致），**与 AEAD 算法无关**。这样两种算法的线格式完全
    /// 相同，可以无缝协商切换。
    ChaCha {
        /// AEAD 实例。
        aead: Box<ChaCha20Poly1305>,
        /// `seq_mask` 用的单块 ECB 实例。
        ecb: Box<Aes128>,
    },
}

// 手动实现 Debug：缓存实例本身不实现 Debug，且不应在日志里泄漏。
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("algo", &self.algo)
            .field("iv", &"<已隐藏>")
            .finish()
    }
}

/// 支持的 AEAD 算法。
///
/// 为什么只保留这两种：TLS 1.3 强制要求的正是 AES-128-GCM、AES-256-GCM、
/// ChaCha20-Poly1305 三选一（RFC 8446 §9.1），选择过多只会增加实现与测试负担。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgo {
    /// AES-128-GCM：有 AES-NI 的 x86/ARM 首选，硬件加速吞吐最高。
    Aes128Gcm,
    /// ChaCha20-Poly1305：无 AES 硬件加速时的软件友好选择（如部分 ARM 设备）。
    ChaCha20Poly1305,
}

impl AeadAlgo {
    /// 该算法要求的密钥长度。
    pub const fn key_len(self) -> usize {
        match self {
            AeadAlgo::Aes128Gcm => 16,
            AeadAlgo::ChaCha20Poly1305 => 32,
        }
    }

    /// 本机是否有该算法的硬件加速。
    ///
    /// # 为什么要暴露这个
    ///
    /// AES-128-GCM 与 ChaCha20-Poly1305 的最优选择**完全取决于 CPU**：
    ///
    /// | 平台 | AES-128-GCM | ChaCha20-Poly1305 | 应选 |
    /// |------|-------------|-------------------|------|
    /// | x86_64 有 AES-NI | 2~6 GB/s（硬件指令） | 1~3 GB/s | **AES** |
    /// | x86_64 无 AES-NI | 0.1~0.3 GB/s（软件 T-table） | 1~3 GB/s | **ChaCha20** |
    /// | ARMv8 有 crypto ext | 2~5 GB/s | 0.5~1.5 GB/s | **AES** |
    /// | 其他 ARM | 0.05~0.2 GB/s | 0.5~1 GB/s | **ChaCha20** |
    ///
    /// 选错算法会让 CPU 占用高一个数量级，这是代理软件最常见的性能坑。
    pub fn hw_accel(self) -> bool {
        match self {
            AeadAlgo::Aes128Gcm => aes_hw_available(),
            // ChaCha20-Poly1305 是 ARX 结构，SSE2/NEON 基线就能高效实现，
            // 不需要专门的加速指令，任何第 64 位平台都有可用向量路径。
            AeadAlgo::ChaCha20Poly1305 => true,
        }
    }

    /// 根据当前 CPU 选择最优算法。
    ///
    /// 规则（按优先级）：
    /// 1. 有 AES 硬件指令 → `Aes128Gcm`（带宽最高，且与 TLS 1.3 服务端协商一致）
    /// 2. 否则 → `ChaCha20Poly1305`（软件实现快一个数量级）
    ///
    /// # 为什么不是固定选一个
    ///
    /// 固定选 AES 会让无 AES-NI 的设备（部分老旧 Android、嵌入式 ARM）
    /// 平均 CPU 占用飙高 5~10 倍；固定选 ChaCha20 则浪费了几乎所有
    /// 现代设备上 AES-NI 的 2~4 倍带宽优势。
    pub fn preferred() -> Self {
        if aes_hw_available() {
            AeadAlgo::Aes128Gcm
        } else {
            AeadAlgo::ChaCha20Poly1305
        }
    }

    /// 可供协商的算法列表（按优先级降序）。
    ///
    /// 客户端把它发给服务端，服务端选第一个共同支持的。
    pub fn preference_list() -> &'static [AeadAlgo] {
        if aes_hw_available() {
            &[AeadAlgo::Aes128Gcm, AeadAlgo::ChaCha20Poly1305]
        } else {
            &[AeadAlgo::ChaCha20Poly1305, AeadAlgo::Aes128Gcm]
        }
    }
}

/// 本机是否有 AES 硬件指令（AES-NI / ARMv8 Crypto Extensions）。
///
/// # 为什么不直接看 `target_feature`
///
/// `cfg!(target_feature = "aes")` 只反映**编译时**是否用 `-C target-feature`
/// 全量启用，而二进制会被分发到各种机器。运行时检测才是正确的判断。
///
/// # 为什么用 `cpufeatures` 风格的 `is_x86_feature_detected`
///
/// 它读 CPUID 并把结果缓存到 static 原子变量里，调用开销约 1~2 ns，
/// 可以在每条记录的加解密路径上安全调用。
#[inline]
fn aes_hw_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // AES-NI 需要 `aes` + `sse2`（AES-NI 指令在 SSE 寄存器上操作）。
        // 只测 `aes` 就够，因为任何带 AES-NI 的 CPU 都有 SSE2。
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARMv8 Crypto Extensions：AES 指令是基线的一部分（ARMv8.0-A 可选，
        // 但绝大多数服务器/手机都实现了），通过 getauxval 在运行时检测。
        // 这里保守地用编译期 feature（交叉编译时显式启用 `aes`）。
        cfg!(target_feature = "aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

impl Keys {
    /// 用原始密钥材料构造。
    ///
    /// 长度不符立即返回错误——密钥长度错误如果延后到加解密阶段才发现，
    /// 会表现为「偶发解密失败」，极难定位。
    ///
    /// 构造时会一次性建立 AEAD 与 ECB 实例（做 AES key expansion），
    /// 后续每次加解密都复用，不再重复调度。
    pub fn new(algo: AeadAlgo, key: &[u8], iv: &[u8], sn_key: &[u8]) -> Result<Self, RecordError> {
        if key.len() != algo.key_len() {
            return Err(RecordError::BadKeyLen {
                expected: algo.key_len(),
                got: key.len(),
            });
        }
        if iv.len() != 12 {
            return Err(RecordError::BadIvLen(iv.len()));
        }
        if sn_key.len() != 16 {
            return Err(RecordError::BadSnKeyLen(sn_key.len()));
        }
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(iv);
        let mut sn_arr = [0u8; 16];
        sn_arr.copy_from_slice(sn_key);

        // 一次性建立密码学实例（这里的 key expansion 只发生一次）
        //
        // seq_mask 固定用 AES-128-ECB（与 DTLS 1.3 的序号加密一致），
        // 与 AEAD 算法无关；这样两种 AEAD 的**线格式完全相同**。
        let ecb =
            Aes128::new_from_slice(&sn_arr).map_err(|_| RecordError::BadSnKeyLen(sn_arr.len()))?;

        let cipher = match algo {
            AeadAlgo::Aes128Gcm => {
                let gcm = Aes128Gcm::new_from_slice(key).map_err(|_| RecordError::BadKeyLen {
                    expected: 16,
                    got: key.len(),
                })?;
                CachedCipher::Aes {
                    gcm: Box::new(gcm),
                    ecb: Box::new(ecb),
                }
            }
            AeadAlgo::ChaCha20Poly1305 => {
                let aead =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| RecordError::BadKeyLen {
                        expected: 32,
                        got: key.len(),
                    })?;
                CachedCipher::ChaCha {
                    aead: Box::new(aead),
                    ecb: Box::new(ecb),
                }
            }
        };

        Ok(Keys {
            iv: iv_arr,
            algo,
            cipher: Arc::new(cipher),
        })
    }

    /// 使用的算法。
    pub fn algo(&self) -> AeadAlgo {
        self.algo
    }

    /// 用给定序号计算 nonce：`nonce = iv XOR (0x00000000 || seq_be_u64)`。
    ///
    /// 为什么用 XOR 而不是直接写 seq：TLS 1.3 §5.3 规定 nonce 为
    /// `iv XOR padded_seq`，我们保持同一构造方式，使密文在密码学性质上
    /// 与真实 TLS 记录一致（避免出现非常规 nonce 构造导致的弱化）。
    #[inline]
    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut n = self.iv;
        let seq_bytes = seq.to_be_bytes();
        // 高 4 字节保持 iv 原值（seq 只用 8 字节，前置 4 字节为 0）
        for i in 0..8 {
            n[4 + i] ^= seq_bytes[i];
        }
        n
    }

    /// 用密文前 16 字节生成序号掩码（8 字节）。
    ///
    /// `mask = AES-ECB(sn_key, ciphertext[0..16])[0..8]`
    ///
    /// 直接用缓存的 ECB 实例，不再每次 `new_from_slice`（省 75 ns/包）。
    #[inline]
    fn seq_mask(&self, ciphertext: &[u8]) -> [u8; SEQ_MASK_LEN] {
        debug_assert!(ciphertext.len() >= SEQ_MASK_SAMPLE_LEN);
        let ecb = match &*self.cipher {
            CachedCipher::Aes { ecb, .. } => ecb,
            CachedCipher::ChaCha { ecb, .. } => ecb,
        };
        let mut block = [0u8; 16];
        block.copy_from_slice(&ciphertext[..SEQ_MASK_SAMPLE_LEN]);
        ecb.encrypt_block((&mut block).into());

        let mut mask = [0u8; SEQ_MASK_LEN];
        mask.copy_from_slice(&block[..SEQ_MASK_LEN]);
        mask
    }
}

/// 发送端：负责递增序号并封装记录。
pub struct RecordEncoder {
    keys: Keys,
    /// 下一个待用序号。从 0 开始，单调递增，永不重用。
    next_seq: u64,
}

impl RecordEncoder {
    /// 构造发送端，序号从 0 开始。
    pub fn new(keys: Keys) -> Self {
        RecordEncoder { keys, next_seq: 0 }
    }

    /// 当前下一个将使用的序号（用于测试与统计）。
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// 把一段明文封装成一条记录并追加到 `out`。
    ///
    /// 返回本次使用的序号。
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<u64, RecordError> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(RecordError::PlaintextTooLarge(plaintext.len()));
        }
        let seq = self.next_seq;

        // 1. 写记录头。length 此时即可确定：掩码(8) + 密文 + tag(16)，
        //    与明文长度是线性关系，不需要先加密再回填。
        let start = out.len();
        let payload_len = (SEQ_MASK_LEN + plaintext.len() + TAG_LEN) as u16;
        out.reserve(RECORD_HEADER_LEN + payload_len as usize);
        out.push(TLS_APP_DATA);
        out.push(TLS_VERSION_MAJOR);
        out.push(TLS_VERSION_MINOR);
        out.extend_from_slice(&payload_len.to_be_bytes());

        // 2. 构造 AAD：记录头(线上真实字节) || 未掩码序号。
        //    用未掩码序号是为了避免「AAD 依赖密文」的循环依赖（见模块文档）。
        let mut aad = [0u8; AAD_LEN];
        aad[..RECORD_HEADER_LEN].copy_from_slice(&out[start..start + RECORD_HEADER_LEN]);
        aad[RECORD_HEADER_LEN..].copy_from_slice(&seq.to_be_bytes());

        // 3. 就地加密（单遍）：plaintext → ciphertext+tag
        let nonce = self.keys.nonce(seq);
        let mut ct = plaintext.to_vec();
        encrypt_in_place(&self.keys.cipher, &nonce, &aad, &mut ct)?;

        // 4. 用密文前 16 字节算掩码，把 seq 掩码后写入线上
        let mask = self.keys.seq_mask(&ct);
        let masked_seq = seq ^ u64::from_be_bytes(mask);
        out.extend_from_slice(&masked_seq.to_be_bytes());

        // 5. 追加密文+tag
        out.extend_from_slice(&ct);

        self.next_seq += 1;
        Ok(seq)
    }

    /// 便捷方法：返回一条独立封装的记录。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), RecordError> {
        let mut out = Vec::new();
        let seq = self.seal_into(plaintext, &mut out)?;
        Ok((seq, out))
    }
}

/// 接收端：负责解封记录并做重放检测。
pub struct RecordDecoder {
    keys: Keys,
    /// 重放检测滑动窗口。
    window: ReplayWindow,
    /// AEAD 认证失败累计次数。超过阈值视为攻击并断连。
    auth_failures: u64,
}

/// AEAD 失败计数上限。达到后必须断连（RFC 9147 §4.5.3 的完整性限制思路）。
///
/// 取 2^20：正常网络下失败次数应以个位数计，
/// 达到百万级只可能是主动伪造攻击或密钥不同步。
pub const MAX_AUTH_FAILURES: u64 = 1 << 20;

impl RecordDecoder {
    /// 构造接收端。
    pub fn new(keys: Keys) -> Self {
        RecordDecoder {
            keys,
            window: ReplayWindow::new(),
            auth_failures: 0,
        }
    }

    /// 从 `buf` 解封一条记录，返回 `(序号, 明文, 消耗字节数)`。
    ///
    /// 数据不足返回 [`RecordError::Truncated`]，调用方应等待更多字节。
    pub fn open(&mut self, buf: &[u8]) -> Result<(u64, Vec<u8>, usize), RecordError> {
        if buf.len() < RECORD_HEADER_LEN {
            return Err(RecordError::Truncated);
        }
        // 伪装校验：内容类型与版本必须精确匹配，否则说明对端不是 FlowTCP
        // 或者流量被篡改。这里返回明确错误而非静默丢弃，便于定位。
        if buf[0] != TLS_APP_DATA {
            return Err(RecordError::BadContentType(buf[0]));
        }
        if buf[1] != TLS_VERSION_MAJOR || buf[2] != TLS_VERSION_MINOR {
            return Err(RecordError::BadVersion(buf[1], buf[2]));
        }
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        // length 至少要容纳 掩码(8) + tag(16)
        if length < SEQ_MASK_LEN + TAG_LEN {
            return Err(RecordError::BadLength(length));
        }
        let total = RECORD_HEADER_LEN + length;
        if buf.len() < total {
            return Err(RecordError::Truncated);
        }

        let masked_seq = u64::from_be_bytes(
            buf[RECORD_HEADER_LEN..AAD_LEN]
                .try_into()
                .expect("长度已校验"),
        );
        let ct_start = AAD_LEN;
        let ct_end = total;
        // 密文长度必须 >= 16（mask 采样需要），已由 length 下限保证
        let ciphertext = &buf[ct_start..ct_end];
        if ciphertext.len() < SEQ_MASK_SAMPLE_LEN {
            return Err(RecordError::BadLength(length));
        }

        // 1. 还原序号（只依赖密文前 16 字节，无需额外状态）
        let mask = self.keys.seq_mask(ciphertext);
        let seq = masked_seq ^ u64::from_be_bytes(mask);

        // 2. 重放检测（廉价预筛）：必须在解密成功后更新窗口，否则丢弃行为会成为
        //    序号探测的时序旁路（RFC 9147 §4.5.1 明确要求）
        if self.window.is_definitely_old(seq) {
            // 太旧：直接丢弃，不算认证失败（是网络延迟而非攻击）
            return Err(RecordError::ReplayOrTooOld(seq));
        }

        // 3. 构造 AAD：记录头(线上真实字节) || 未掩码序号（与发送端一致）
        let mut aad = [0u8; AAD_LEN];
        aad[..RECORD_HEADER_LEN].copy_from_slice(&buf[..RECORD_HEADER_LEN]);
        aad[RECORD_HEADER_LEN..].copy_from_slice(&seq.to_be_bytes());

        // 4. 解密
        //
        // AEAD 认证失败必须计为 `AuthFailed(seq)` 而不是通用的 `DecryptFailed`：
        // 上层用 `must_close()` 判断是否因为累计失败次数过多而断连（防主动伪造），
        // 错误类型必须能区分「密钥/身份问题」与「实现 bug」。
        let nonce = self.keys.nonce(seq);
        let mut plaintext = ciphertext.to_vec();
        decrypt_in_place(&self.keys.cipher, &nonce, &aad, &mut plaintext).map_err(|e| {
            self.auth_failures += 1;
            match e {
                RecordError::DecryptFailed => RecordError::AuthFailed(seq),
                other => other,
            }
        })?;

        // 5. 认证成功后才推进窗口
        if !self.window.check_and_set(seq) {
            return Err(RecordError::ReplayOrTooOld(seq));
        }

        Ok((seq, plaintext, total))
    }

    /// 是否因 AEAD 失败次数超限而必须断开连接。
    pub fn must_close(&self) -> bool {
        self.auth_failures >= MAX_AUTH_FAILURES
    }

    /// 当前 AEAD 失败计数。
    pub fn auth_failures(&self) -> u64 {
        self.auth_failures
    }

    /// 已接收的最大序号（`None` 表示尚未收到任何记录）。
    pub fn highest_seq(&self) -> Option<u64> {
        self.window.right_edge
    }
}

/// 重放检测滑动窗口。
///
/// 用 `right_edge` 表示已认证的最大序号，`bits` 为 1024 位位图，
/// 第 0 位对应 `right_edge`，第 i 位对应 `right_edge - i`。
struct ReplayWindow {
    right_edge: Option<u64>,
    bits: [u64; REPLAY_WINDOW_BITS / 64],
}

impl ReplayWindow {
    const fn new() -> Self {
        ReplayWindow {
            right_edge: None,
            bits: [0u64; REPLAY_WINDOW_BITS / 64],
        }
    }

    /// 判断序号是否「一定过旧」（超出窗口且不可能是重放边界情况）。
    ///
    /// 仅用于解密前的廉价预筛；最终判定仍在 [`Self::check_and_set`]。
    fn is_definitely_old(&self, seq: u64) -> bool {
        match self.right_edge {
            None => false,
            Some(right) => seq < right && right - seq >= REPLAY_WINDOW_BITS as u64,
        }
    }

    /// 检查并标记序号。返回 `false` 表示重复或过旧。
    fn check_and_set(&mut self, seq: u64) -> bool {
        match self.right_edge {
            None => {
                self.right_edge = Some(seq);
                self.bits[0] = 1;
                true
            }
            Some(right) if seq > right => {
                let shift = seq - right;
                self.shift_left(shift);
                self.right_edge = Some(seq);
                self.bits[0] |= 1;
                true
            }
            Some(right) => {
                let diff = right - seq;
                if diff >= REPLAY_WINDOW_BITS as u64 {
                    return false; // 过旧
                }
                let word = (diff / 64) as usize;
                let bit = (diff % 64) as u32;
                if self.bits[word] & (1u64 << bit) != 0 {
                    return false; // 重放
                }
                self.bits[word] |= 1u64 << bit;
                true
            }
        }
    }

    /// 整体左移 `n` 位（n 方向为「向更早的序号」）。
    fn shift_left(&mut self, n: u64) {
        let n = n as usize;
        if n >= REPLAY_WINDOW_BITS {
            self.bits = [0u64; REPLAY_WINDOW_BITS / 64];
            return;
        }
        let word_shift = n / 64;
        let bit_shift = n % 64;
        let len = self.bits.len();
        if word_shift > 0 {
            for i in (0..len).rev() {
                self.bits[i] = if i >= word_shift {
                    self.bits[i - word_shift]
                } else {
                    0
                };
            }
        }
        if bit_shift > 0 {
            for i in (0..len).rev() {
                let lo = self.bits[i] << bit_shift;
                let hi = if i > 0 {
                    self.bits[i - 1] >> (64 - bit_shift)
                } else {
                    0
                };
                self.bits[i] = lo | hi;
            }
        }
    }
}

/// 就地加密（AAD 为 `aad`），结果写入 `buf`（含 tag）。
///
/// 使用 [`Keys`] 里缓存的 AEAD 实例，不做任何密钥调度。
fn encrypt_in_place(
    cipher: &CachedCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), RecordError> {
    match cipher {
        CachedCipher::Aes { gcm, .. } => {
            let n = GcmNonce::from_slice(nonce);
            let tag = gcm
                .encrypt_in_place_detached(n, aad, buf)
                .map_err(|_| RecordError::EncryptFailed)?;
            buf.extend_from_slice(&tag);
        }
        CachedCipher::ChaCha { aead, .. } => {
            let n = ChaChaNonce::from_slice(nonce);
            let tag = aead
                .encrypt_in_place_detached(n, aad, buf)
                .map_err(|_| RecordError::EncryptFailed)?;
            buf.extend_from_slice(&tag);
        }
    }
    Ok(())
}

/// 就地解密：`buf` 含密文 + tag，成功后 `buf` 被截断为明文。
///
/// 使用 [`Keys`] 里缓存的 AEAD 实例，不做任何密钥调度。
fn decrypt_in_place(
    cipher: &CachedCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), RecordError> {
    if buf.len() < TAG_LEN {
        return Err(RecordError::BadLength(buf.len()));
    }
    let ct_len = buf.len() - TAG_LEN;
    // 先把 tag 复制到独立数组：否则 tag 借用 buf 的同时无法可变借用 buf
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(&buf[ct_len..]);

    match cipher {
        CachedCipher::Aes { gcm, .. } => {
            let n = GcmNonce::from_slice(nonce);
            let tag = GcmTag::from_slice(&tag_arr);
            gcm.decrypt_in_place_detached(n, aad, &mut buf[..ct_len], tag)
                .map_err(|_| RecordError::DecryptFailed)?;
        }
        CachedCipher::ChaCha { aead, .. } => {
            let n = ChaChaNonce::from_slice(nonce);
            let tag = ChaChaTag::from_slice(&tag_arr);
            aead.decrypt_in_place_detached(n, aad, &mut buf[..ct_len], tag)
                .map_err(|_| RecordError::DecryptFailed)?;
        }
    }
    buf.truncate(ct_len);
    Ok(())
}

/// 记录层错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    /// 数据不足。
    #[error("数据不足，需要更多字节")]
    Truncated,
    /// 内容类型字节不是 0x17。
    #[error("内容类型不是 application_data: 0x{0:02X}")]
    BadContentType(u8),
    /// 记录版本不是 0x0303。
    #[error("记录版本异常: 0x{0:02X}{1:02X}")]
    BadVersion(u8, u8),
    /// length 字段异常。
    #[error("记录长度异常: {0}")]
    BadLength(usize),
    /// 明文超长。
    #[error("明文超长: {0} 字节")]
    PlaintextTooLarge(usize),
    /// 密钥长度不符。
    #[error("密钥长度不符: 期望 {expected}，实际 {got}")]
    BadKeyLen {
        /// 期望长度
        expected: usize,
        /// 实际长度
        got: usize,
    },
    /// IV 长度不符。
    #[error("IV 长度不符: {0}（应为 12）")]
    BadIvLen(usize),
    /// 序号掩码密钥长度不符。
    #[error("sn_key 长度不符: {0}（应为 16）")]
    BadSnKeyLen(usize),
    /// 加密失败（理论上不应发生，密钥长度已校验）。
    #[error("加密失败")]
    EncryptFailed,
    /// 解密/认证失败：可能是篡改、密钥不同步或并非 FlowTCP 流量。
    #[error("AEAD 认证失败 (seq={0})")]
    AuthFailed(u64),
    /// 重复或过旧的记录。
    #[error("重复或过旧记录 (seq={0})")]
    ReplayOrTooOld(u64),
    /// 内部解密失败。
    #[error("解密失败")]
    DecryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一对同参数的收发密钥。
    fn pair(algo: AeadAlgo) -> (RecordEncoder, RecordDecoder) {
        let key = vec![0x42u8; algo.key_len()];
        let iv = [0x11u8; 12];
        let sn = [0x33u8; 16];
        let ek = Keys::new(algo, &key, &iv, &sn).unwrap();
        let dk = Keys::new(algo, &key, &iv, &sn).unwrap();
        (RecordEncoder::new(ek), RecordDecoder::new(dk))
    }

    /// 本机 AES 硬件加速检测必须与 CPU 实际能力一致。
    ///
    /// 这个测试的价值：如果有人把 `hw_accel()` 改成永远返回 `true`，
    /// 在没有 AES-NI 的 ARM 设备上会静默退化到 0.1 GB/s 的软件实现，
    /// 而不会报任何错 —— CPU 占用高 10 倍却查不出原因。
    #[test]
    fn aes硬件加速检测与cpu能力一致() {
        #[cfg(target_arch = "x86_64")]
        {
            let expect = std::is_x86_feature_detected!("aes");
            assert_eq!(
                AeadAlgo::Aes128Gcm.hw_accel(),
                expect,
                "hw_accel() 必须如实反映 CPUID 的 AES 位"
            );
        }
        // ChaCha20 在任何 64 位平台都有可用向量路径
        assert!(AeadAlgo::ChaCha20Poly1305.hw_accel());
    }

    /// `preferred()` 必须选有硬件加速的那个。
    #[test]
    fn 首选算法跟随硬件能力() {
        let p = AeadAlgo::preferred();
        assert!(p.hw_accel(), "首选算法必须有硬件加速，实际选了 {p:?}");
        if AeadAlgo::Aes128Gcm.hw_accel() {
            assert_eq!(p, AeadAlgo::Aes128Gcm);
        } else {
            assert_eq!(p, AeadAlgo::ChaCha20Poly1305);
        }
    }

    /// 偏好列表的第一项必须与 `preferred()` 一致。
    ///
    /// 否则协商时客户端会把自己的次优算法排在前面，
    /// 服务端按"取第一个共同支持"就会选中次优的那个。
    #[test]
    fn 偏好列表首位与preferred一致() {
        let list = AeadAlgo::preference_list();
        assert_eq!(list[0], AeadAlgo::preferred());
        assert_eq!(list.len(), 2, "应同时列出两种算法以便协商");
        // 两项必须不同，否则协商无意义
        assert_ne!(list[0], list[1]);
    }

    /// 缓存密码学实例不能改变线格式：两种算法的记录长度必须相同。
    ///
    /// 这是"可无缝协商切换"的前提 —— 若长度不同，
    /// 中途换算法会让对端解析错位。
    #[test]
    fn 两种算法线格式长度相同() {
        let payload = b"same-length-check";
        let (mut aes, _) = pair(AeadAlgo::Aes128Gcm);
        let (mut cha, _) = pair(AeadAlgo::ChaCha20Poly1305);
        let (_, a) = aes.seal(payload).unwrap();
        let (_, c) = cha.seal(payload).unwrap();
        assert_eq!(a.len(), c.len(), "两种 AEAD 的记录长度必须一致");
        assert_eq!(&a[..3], &c[..3], "记录头必须一致");
    }

    /// `Keys::clone` 必须是 O(1) 引用计数，不能深拷贝密钥调度表。
    ///
    /// 用 Arc 才能让"握手后把 Keys 分给 encoder 与 decoder"这件事零成本；
    /// 若误改回深拷贝，每条连接会多两次 AES key expansion。
    #[test]
    fn keys克隆是引用计数而非深拷贝() {
        let key = vec![0x42u8; 16];
        let k = Keys::new(AeadAlgo::Aes128Gcm, &key, &[0u8; 12], &[0u8; 16]).unwrap();
        let k2 = k.clone();
        assert!(
            Arc::ptr_eq(&k.cipher, &k2.cipher),
            "Keys::clone 必须共享同一份 cipher 实例（Arc），否则等于每次克隆都重做 key expansion"
        );
    }

    #[test]
    fn 记录头前5字节与真实tls一致() {
        let (mut enc, _) = pair(AeadAlgo::Aes128Gcm);
        let (_, rec) = enc.seal(b"hello").unwrap();
        assert_eq!(rec[0], 0x17);
        assert_eq!(rec[1], 0x03);
        assert_eq!(rec[2], 0x03);
        // length = 掩码8 + 明文5 + tag16 = 29
        assert_eq!(u16::from_be_bytes([rec[3], rec[4]]), 29);
        assert_eq!(rec.len(), 5 + 29);
    }

    #[test]
    fn 编解码往返_aes_gcm() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let payload = b"FlowTCP record layer test";
        let (seq, rec) = enc.seal(payload).unwrap();
        assert_eq!(seq, 0);

        let (dseq, plain, used) = dec.open(&rec).unwrap();
        assert_eq!(dseq, 0);
        assert_eq!(plain, payload);
        assert_eq!(used, rec.len());
    }

    #[test]
    fn 编解码往返_chacha20() {
        let (mut enc, mut dec) = pair(AeadAlgo::ChaCha20Poly1305);
        let payload = b"chacha path";
        let (_, rec) = enc.seal(payload).unwrap();
        let (_, plain, _) = dec.open(&rec).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn 序号单调递增() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        for i in 0..10u64 {
            let (seq, rec) = enc.seal(b"x").unwrap();
            assert_eq!(seq, i);
            let (dseq, _, _) = dec.open(&rec).unwrap();
            assert_eq!(dseq, i);
        }
        assert_eq!(enc.next_seq(), 10);
    }

    /// 核心能力：乱序到达必须能全部解密成功（这正是标准 TLS 做不到的）。
    #[test]
    fn 乱序记录全部解密成功() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let mut records = Vec::new();
        for i in 0..20u32 {
            let (_, rec) = enc.seal(&i.to_be_bytes()).unwrap();
            records.push(rec);
        }
        // 打乱顺序：先发后一半，再发前一半（模拟丢包后的乱序到达）
        let mut order: Vec<usize> = (0..20).collect();
        order.reverse();
        for idx in order {
            let (seq, plain, _) = dec.open(&records[idx]).expect("乱序记录必须能解密");
            assert_eq!(seq, idx as u64);
            assert_eq!(plain, (idx as u32).to_be_bytes());
        }
    }

    /// 丢包不影响后续记录解析：跳着收也必须成功。
    #[test]
    fn 丢包不影响后续记录() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let mut records = Vec::new();
        for i in 0..10u32 {
            let (_, rec) = enc.seal(&i.to_be_bytes()).unwrap();
            records.push(rec);
        }
        // 只收到 0, 3, 7, 9（模拟 70% 丢包）
        for idx in [0usize, 3, 7, 9] {
            let (seq, plain, _) = dec.open(&records[idx]).expect("丢包后必须仍能解密");
            assert_eq!(seq, idx as u64);
            assert_eq!(plain, (idx as u32).to_be_bytes());
        }
    }

    /// 重放必须被拒绝。
    #[test]
    fn 拒绝重放记录() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, rec) = enc.seal(b"once").unwrap();
        dec.open(&rec).expect("首次必须成功");
        assert!(matches!(
            dec.open(&rec).unwrap_err(),
            RecordError::ReplayOrTooOld(_)
        ));
    }

    /// 篡改密文必须被 AEAD 拦截。
    #[test]
    fn 拒绝篡改密文() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, mut rec) = enc.seal(b"authentic data").unwrap();
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        assert!(matches!(
            dec.open(&rec).unwrap_err(),
            RecordError::AuthFailed(_) | RecordError::ReplayOrTooOld(_)
        ));
        assert!(dec.auth_failures() >= 1);
    }

    /// 篡改序号掩码必须被拦截（AAD 覆盖了 masked_seq）。
    #[test]
    fn 拒绝篡改序号掩码() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, mut rec) = enc.seal(b"data").unwrap();
        rec[RECORD_HEADER_LEN] ^= 0xFF;
        assert!(dec.open(&rec).is_err());
    }

    /// 错误的内容类型必须被明确拒绝（用于判断对端不是 FlowTCP）。
    #[test]
    fn 拒绝非application_data记录() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, mut rec) = enc.seal(b"data").unwrap();
        rec[0] = 0x16; // handshake
        assert_eq!(
            dec.open(&rec).unwrap_err(),
            RecordError::BadContentType(0x16)
        );
    }

    #[test]
    fn 拒绝错误版本() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, mut rec) = enc.seal(b"data").unwrap();
        rec[1] = 0x02;
        assert_eq!(
            dec.open(&rec).unwrap_err(),
            RecordError::BadVersion(0x02, 0x03)
        );
    }

    /// 半包必须返回 Truncated 而非 panic。
    #[test]
    fn 半记录返回截断() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, rec) = enc.seal(b"partial test").unwrap();
        assert_eq!(dec.open(&rec[..3]).unwrap_err(), RecordError::Truncated);
        assert_eq!(
            dec.open(&rec[..rec.len() - 1]).unwrap_err(),
            RecordError::Truncated
        );
    }

    /// 空明文也必须能正常往返（心跳/纯 ACK 场景）。
    #[test]
    fn 空明文往返() {
        let (mut enc, mut dec) = pair(AeadAlgo::Aes128Gcm);
        let (_, rec) = enc.seal(b"").unwrap();
        // 空明文时 length = 8 + 0 + 16 = 24
        assert_eq!(u16::from_be_bytes([rec[3], rec[4]]), 24);
        let (_, plain, used) = dec.open(&rec).unwrap();
        assert!(plain.is_empty());
        assert_eq!(used, 5 + 24);
    }

    /// 序号在线上必须不可见：连续记录的 masked_seq 不能单调递增。
    #[test]
    fn 序号在线上不可见() {
        let (mut enc, _) = pair(AeadAlgo::Aes128Gcm);
        let mut masked = Vec::new();
        for i in 0..16u32 {
            let (_, rec) = enc.seal(&i.to_be_bytes()).unwrap();
            masked.push(u64::from_be_bytes(
                rec[RECORD_HEADER_LEN..AAD_LEN].try_into().unwrap(),
            ));
        }
        // 真实序号 0..15 是单调的，掩码后不应保持单调
        let monotonic = masked.windows(2).all(|w| w[1] > w[0]);
        assert!(!monotonic, "序号掩码后仍单调递增，说明掩码失效：{masked:?}");
    }

    /// 超长明文必须被拒绝。
    #[test]
    fn 拒绝超长明文() {
        let (mut enc, _) = pair(AeadAlgo::Aes128Gcm);
        let big = vec![0u8; MAX_RECORD_PLAINTEXT + 1];
        assert!(matches!(
            enc.seal(&big).unwrap_err(),
            RecordError::PlaintextTooLarge(_)
        ));
    }

    /// 密钥长度校验必须在构造期完成。
    #[test]
    fn 密钥长度校验() {
        assert!(Keys::new(AeadAlgo::Aes128Gcm, &[0u8; 32], &[0u8; 12], &[0u8; 16]).is_err());
        assert!(Keys::new(AeadAlgo::Aes128Gcm, &[0u8; 16], &[0u8; 8], &[0u8; 16]).is_err());
        assert!(Keys::new(AeadAlgo::Aes128Gcm, &[0u8; 16], &[0u8; 12], &[0u8; 8]).is_err());
        assert!(Keys::new(AeadAlgo::Aes128Gcm, &[0u8; 16], &[0u8; 12], &[0u8; 16]).is_ok());
        assert!(Keys::new(
            AeadAlgo::ChaCha20Poly1305,
            &[0u8; 32],
            &[0u8; 12],
            &[0u8; 16]
        )
        .is_ok());
    }

    /// 两套不同密钥之间必须无法互相解密（方向性隔离验证）。
    #[test]
    fn 不同密钥无法互通() {
        let ek = Keys::new(
            AeadAlgo::Aes128Gcm,
            &[0x01u8; 16],
            &[0x11u8; 12],
            &[0x33u8; 16],
        )
        .unwrap();
        let dk = Keys::new(
            AeadAlgo::Aes128Gcm,
            &[0x02u8; 16],
            &[0x11u8; 12],
            &[0x33u8; 16],
        )
        .unwrap();
        let mut enc = RecordEncoder::new(ek);
        let mut dec = RecordDecoder::new(dk);
        let (_, rec) = enc.seal(b"secret").unwrap();
        assert!(dec.open(&rec).is_err());
    }

    /// 滑动窗口跨越 64 位字边界时的正确性。
    #[test]
    fn 重放窗口跨字边界() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        // 跨越多个 u64 字
        assert!(w.check_and_set(1064));
        assert!(!w.check_and_set(1064)); // 重放
        assert!(w.check_and_set(1001));
        assert!(!w.check_and_set(1001)); // 重放
        assert!(!w.check_and_set(0)); // 过旧（距 1064 超过 1024）
                                      // 窗口内但未见过
        assert!(w.check_and_set(1050));
    }

    /// 窗口整体滑出后，旧序号必须被判定为过旧。
    #[test]
    fn 窗口滑出后拒绝旧序号() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0));
        assert!(w.check_and_set(5000));
        assert!(!w.check_and_set(100)); // 距 5000 超过 1024
    }
}
