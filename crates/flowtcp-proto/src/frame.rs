//! 内层帧编解码（L4 复用层）
//!
//! # 为什么需要这一层
//!
//! 一条 FakeTCP 连接要同时承载多个 TCP 流和多个 UDP 会话，
//! 因此需要一个内层帧格式来标识「这一字节属于哪个 stream」。
//!
//! # 线格式（大端序 / 网络字节序）
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | type(1)|flags(1)|   stream_id(2)    |            pkt_seq(4)             |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! |  payload_len(2)   |            payload (payload_len 字节)              |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! ```
//!
//! 帧头固定 **10 字节**。多个帧可串联在同一个记录层明文内（流水线化），
//! 以减少 TLS 记录头（5B）与 AEAD tag（16B）的边际开销。
//!
//! # 为什么用 10 字节而不是更小
//!
//! | 字段 | 必要性 |
//! |------|--------|
//! | type | 必须，区分 OPEN/DATA/CLOSE/ACK 等 |
//! | flags | 必须，承载 RELIABLE / FIN / HAS_ADDR 等语义 |
//! | stream_id | 必须，多路复用核心；16 位支持 65535 并发流，足够 |
//! | pkt_seq | 必须，ARQ 重传与去重依赖；32 位在 1M pps 下可用约 71 分钟，足够 |
//! | payload_len | 必须，TCP 是字节流，没有长度就无法定界 |
//!
//! 若要压缩到 8 字节，只能牺牲 pkt_seq 位宽（ARQ 会受限）或 stream_id 位宽
//! （并发流数量受限），两者都会带来实际功能损失，因此选择 10 字节。

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

/// 帧头固定长度（字节）。所有编解码与 MTU 计算都必须引用此常量，禁止硬编码。
pub const FRAME_HEADER_LEN: usize = 10;

/// 单帧 payload 的最大长度。
///
/// 16 位 length 字段理论上限 65535，但实际受记录层明文上限
/// （TLS 记录 2^14 = 16384）与链路 MTU 约束，取 16384 作为硬上限。
/// 真实可用值通常更小（由 MTU 预算决定，见 `max_payload_for_mtu`）。
pub const MAX_FRAME_PAYLOAD: usize = 16384;

/// 帧类型。
///
/// 数值一旦发布不可更改（协议兼容性），新增类型只能追加。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// 打开一条 TCP 流。payload = 目标地址编码。
    OpenTcp = 0x01,
    /// 打开一个 UDP 会话。payload = 默认目标地址编码（后续帧同目标时省略地址）。
    OpenUdp = 0x02,
    /// 数据帧。TCP 流为原始字节；UDP 会话在 flags.HAS_ADDR 时前置地址。
    Data = 0x03,
    /// 关闭流。flags 区分正常关闭与异常重置。
    Close = 0x04,
    /// ARQ 确认。payload = ack_seq(4) + rcv_nxt(4) + bitmap(8)。
    Ack = 0x05,
    /// 心跳请求。payload 长度随机（8~32），用于流量伪装。
    Ping = 0x06,
    /// 心跳响应。
    Pong = 0x07,
    /// FEC 冗余包。payload = group_id(4) + count(1) + max_len(2) + parity。
    Fec = 0x08,
    /// 流控窗口更新（预留，默认关闭）。
    Window = 0x09,
    /// 错误通知。payload = code(2) + 人类可读消息。
    Error = 0x0A,
}

impl FrameType {
    /// 从原始字节解析。未知类型返回 `None`，由调用方决定是丢弃还是断连。
    ///
    /// 为什么返回 Option 而不是报错：未知帧类型可能是对端版本更新导致的，
    /// 直接断连会妨碍协议演进；调用方通常应跳过并计数。
    pub fn from_u8(v: u8) -> Option<Self> {
        use FrameType::*;
        Some(match v {
            0x01 => OpenTcp,
            0x02 => OpenUdp,
            0x03 => Data,
            0x04 => Close,
            0x05 => Ack,
            0x06 => Ping,
            0x07 => Pong,
            0x08 => Fec,
            0x09 => Window,
            0x0A => Error,
            _ => return None,
        })
    }
}

/// 帧标志位（位掩码）。
///
/// 用结构体而非 bitflags crate，是为了显式控制语义并提供中文文档，
/// 避免依赖膨胀（本 crate 只依赖密码学与基础工具库）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    /// 要求对端 ACK 并在丢失时重传（ARQ 生效）。
    pub const RELIABLE: u8 = 0x01;
    /// FEC 分组的最后一个数据包，接收端据此结束本组校验。
    pub const LAST: u8 = 0x02;
    /// 流结束标志（配合 Close 帧）。
    pub const FIN: u8 = 0x04;
    /// 允许发送侧合并小包（CORK），降低 header 开销。
    pub const CORK: u8 = 0x08;
    /// payload 前置了目标地址（UDP 会话切换目标时使用）。
    ///
    /// 为什么不总是带地址：UDP ASSOCIATE 下绝大多数包都发往同一目标，
    /// 每包重复地址会浪费 7~19 字节（占小包比例很高）。
    pub const HAS_ADDR: u8 = 0x10;

    /// 无标志。
    pub const fn empty() -> Self {
        Flags(0)
    }

    /// 构造并校验：未定义的位必须为 0，防止对端用未定义位传递隐蔽信息。
    pub fn new(bits: u8) -> Result<Self, FrameError> {
        const DEFINED: u8 =
            Flags::RELIABLE | Flags::LAST | Flags::FIN | Flags::CORK | Flags::HAS_ADDR;
        if bits & !DEFINED != 0 {
            return Err(FrameError::UndefinedFlagBits(bits & !DEFINED));
        }
        Ok(Flags(bits))
    }

    /// 判断某个标志位是否置位。
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// 返回置位后的新 Flags（便于链式构造）。
    pub const fn with(self, bit: u8) -> Self {
        Flags(self.0 | bit)
    }

    /// 原始位值。
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// 目标地址编码（与 SOCKS5 地址格式对齐，便于零转换映射）。
///
/// ```text
/// +--------+---------------------------+-----------+
/// | atyp(1)| addr(var)                 | port(2)   |
/// +--------+---------------------------+-----------+
/// atyp: 0x01=IPv4(4B)  0x03=域名(1B len + n)  0x04=IPv6(16B)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// IPv4 地址。
    V4(SocketAddrV4),
    /// 域名 + 端口。服务端负责解析，客户端不做 DNS（避免泄漏）。
    Domain(String, u16),
    /// IPv6 地址。
    V6(SocketAddrV6),
}

/// 地址类型常量（与 SOCKS5 保持一致）。
pub mod atyp {
    /// IPv4。
    pub const IPV4: u8 = 0x01;
    /// 域名。
    pub const DOMAIN: u8 = 0x03;
    /// IPv6。
    pub const IPV6: u8 = 0x04;
}

impl Address {
    /// 序列化地址到 `out`，返回写入字节数。
    ///
    /// 域名长度上限 255（1 字节长度字段），这是 SOCKS5 的既有约束。
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<usize, FrameError> {
        let start = out.len();
        match self {
            Address::V4(sa) => {
                out.push(atyp::IPV4);
                out.extend_from_slice(&sa.ip().octets());
                out.extend_from_slice(&sa.port().to_be_bytes());
            }
            Address::V6(sa) => {
                out.push(atyp::IPV6);
                out.extend_from_slice(&sa.ip().octets());
                out.extend_from_slice(&sa.port().to_be_bytes());
            }
            Address::Domain(host, port) => {
                if host.len() > 255 {
                    return Err(FrameError::DomainTooLong(host.len()));
                }
                out.push(atyp::DOMAIN);
                out.push(host.len() as u8);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out.len() - start)
    }

    /// 从字节流解析地址，返回 `(地址, 消耗字节数)`。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FrameError> {
        if buf.is_empty() {
            return Err(FrameError::Truncated);
        }
        match buf[0] {
            atyp::IPV4 => {
                if buf.len() < 1 + 4 + 2 {
                    return Err(FrameError::Truncated);
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Address::V4(SocketAddrV4::new(ip, port)), 7))
            }
            atyp::IPV6 => {
                if buf.len() < 1 + 16 + 2 {
                    return Err(FrameError::Truncated);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((
                    Address::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0)),
                    19,
                ))
            }
            atyp::DOMAIN => {
                if buf.len() < 2 {
                    return Err(FrameError::Truncated);
                }
                let len = buf[1] as usize;
                if buf.len() < 2 + len + 2 {
                    return Err(FrameError::Truncated);
                }
                // 域名必须是合法 UTF-8：非 UTF-8 的"域名"只可能是攻击或协议错乱
                let host = std::str::from_utf8(&buf[2..2 + len])
                    .map_err(|_| FrameError::InvalidDomainEncoding)?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
                Ok((Address::Domain(host, port), 2 + len + 2))
            }
            other => Err(FrameError::UnknownAtyp(other)),
        }
    }

    /// 编码后的字节长度（用于 MTU 预算与 payload 上限计算）。
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::V4(_) => 7,
            Address::V6(_) => 19,
            Address::Domain(h, _) => 2 + h.len() + 2,
        }
    }

    /// 端口。
    pub fn port(&self) -> u16 {
        match self {
            Address::V4(sa) => sa.port(),
            Address::V6(sa) => sa.port(),
            Address::Domain(_, p) => *p,
        }
    }

    /// 若是 IP 直连地址，转换为 `SocketAddr`（域名返回 `None`，需服务端解析）。
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Address::V4(sa) => Some(SocketAddr::V4(*sa)),
            Address::V6(sa) => Some(SocketAddr::V6(*sa)),
            Address::Domain(_, _) => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::V4(sa) => write!(f, "{sa}"),
            Address::V6(sa) => write!(f, "[{}]:{}", sa.ip(), sa.port()),
            Address::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// 一个内层帧。
///
/// `payload` 借用输入缓冲区以避免拷贝——这是数据面热路径，禁止不必要的分配。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// 帧类型。
    pub frame_type: FrameType,
    /// 标志位。
    pub flags: Flags,
    /// 流标识。0 保留给控制流。
    pub stream_id: u16,
    /// 该 stream 内的包序号，从 0 递增。用于 ARQ 与去重。
    pub pkt_seq: u32,
    /// 载荷。
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// 构造一个帧。
    pub fn new(
        frame_type: FrameType,
        flags: Flags,
        stream_id: u16,
        pkt_seq: u32,
        payload: &'a [u8],
    ) -> Self {
        Frame {
            frame_type,
            flags,
            stream_id,
            pkt_seq,
            payload,
        }
    }

    /// 计算编码后的总长度。
    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN + self.payload.len()
    }

    /// 编码到 `out`（追加写入）。
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }
        out.reserve(self.encoded_len());
        out.push(self.frame_type as u8);
        out.push(self.flags.bits());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.pkt_seq.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(self.payload);
        Ok(())
    }

    /// 从缓冲区解析一个帧，返回 `(帧, 消耗字节数)`。
    ///
    /// 缓冲区不足时返回 `FrameError::Truncated`，调用方应保留数据等待更多字节
    /// （TCP 是字节流，半包是常态而非异常）。
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        let frame_type = FrameType::from_u8(buf[0]).ok_or(FrameError::UnknownFrameType(buf[0]))?;
        let flags = Flags::new(buf[1])?;
        let stream_id = u16::from_be_bytes([buf[2], buf[3]]);
        let pkt_seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let payload_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;

        // 长度上限校验：防止恶意对端用超长 length 造成内存放大攻击
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(payload_len));
        }
        let total = FRAME_HEADER_LEN + payload_len;
        if buf.len() < total {
            return Err(FrameError::Truncated);
        }
        Ok((
            Frame {
                frame_type,
                flags,
                stream_id,
                pkt_seq,
                payload: &buf[FRAME_HEADER_LEN..total],
            },
            total,
        ))
    }
}

/// 拥有自己 payload 的帧。
///
/// # 为什么需要它（Phase 3 数据面的必需件）
///
/// [`Frame`] 的 `payload: &'a [u8]` 借用了输入缓冲，无法跨越 `await` 点
/// （异步任务栈不能持有指向其他栈帧的引用）。而数据面必然要：
///
/// ```text
/// 读出记录 → 切出帧 → await 写入目标 socket   ← 帧必须活过 await
/// ```
///
/// 因此提供一个 `payload: Vec<u8>` 的所有权版本。代价是一次拷贝，
/// 但只在**帧边界**发生（不是逐字节），实测开销可忽略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    /// 帧类型。
    pub frame_type: FrameType,
    /// 标志位。
    pub flags: Flags,
    /// 流 ID。
    pub stream_id: u16,
    /// 流内包序号。
    pub pkt_seq: u32,
    /// 载荷（拥有所有权）。
    pub payload: Vec<u8>,
}

impl OwnedFrame {
    /// 构造。
    pub fn new(
        frame_type: FrameType,
        flags: Flags,
        stream_id: u16,
        pkt_seq: u32,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        OwnedFrame {
            frame_type,
            flags,
            stream_id,
            pkt_seq,
            payload: payload.into(),
        }
    }

    /// 便捷构造：无标志、pkt_seq=0 的数据帧。
    ///
    /// Phase 3 的数据面（真 TCP 承载）不需要 ARQ 序号，因此 seq 恒为 0；
    /// Phase 4 接入 FakeTCP 后由 ARQ 层填充。
    pub fn data(stream_id: u16, payload: impl Into<Vec<u8>>) -> Self {
        OwnedFrame::new(
            FrameType::Data,
            Flags::empty(),
            stream_id,
            0,
            payload.into(),
        )
    }

    /// 便捷构造：关闭帧。
    ///
    /// `fin = true` 表示正常关闭（FIN），`false` 表示重置（RST）。
    /// 服务端拒绝打开流时用 `fin = false`，客户端据此立即关闭本地连接，
    /// 不需要新增帧类型（保持协议兼容性）。
    pub fn close(stream_id: u16, fin: bool) -> Self {
        let flags = if fin {
            Flags::empty().with(Flags::FIN)
        } else {
            Flags::empty()
        };
        OwnedFrame::new(FrameType::Close, flags, stream_id, 0, Vec::new())
    }

    /// 是否是正常关闭（带 FIN）。
    pub fn is_fin(&self) -> bool {
        self.flags.has(Flags::FIN)
    }

    /// 借出为 [`Frame`]（便于复用编码逻辑）。
    pub fn as_frame(&self) -> Frame<'_> {
        Frame::new(
            self.frame_type,
            self.flags,
            self.stream_id,
            self.pkt_seq,
            &self.payload,
        )
    }

    /// 编码到 `out`。
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        self.as_frame().encode(out)
    }

    /// 从缓冲区解析一个帧，并把 payload 拷贝出来。
    ///
    /// 返回 `(帧, 消耗字节数)`；缓冲区不足时返回 `FrameError::Truncated`，
    /// 调用方应保留数据等待更多字节。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FrameError> {
        let (f, used) = Frame::decode(buf)?;
        Ok((
            OwnedFrame {
                frame_type: f.frame_type,
                flags: f.flags,
                stream_id: f.stream_id,
                pkt_seq: f.pkt_seq,
                payload: f.payload.to_vec(),
            },
            used,
        ))
    }

    /// 编码后的总长度。
    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN + self.payload.len()
    }
}

/// 帧解析迭代器：从一段记录层明文中连续取出所有完整帧。
///
/// 为什么需要它：一个记录层明文可以串联多个帧（流水线化），
/// 也可能尾部残留半个帧（跨记录边界），必须能区分「解析完」与「数据不足」。
pub struct FrameIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameIter<'a> {
    /// 在一段字节上建立迭代器。
    pub fn new(buf: &'a [u8]) -> Self {
        FrameIter { buf, pos: 0 }
    }

    /// 已消费的字节数（迭代结束后即为「完整帧占用长度」）。
    pub fn consumed(&self) -> usize {
        self.pos
    }

    /// 剩余未消费字节（尾部半包）。
    pub fn remainder(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Result<Frame<'a>, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        match Frame::decode(&self.buf[self.pos..]) {
            Ok((frame, used)) => {
                self.pos += used;
                Some(Ok(frame))
            }
            Err(FrameError::Truncated) => {
                // 数据不足：正常结束迭代，但**不推进 pos**。
                // 这样 consumed() 反映的是「完整帧占用长度」，
                // 调用方可直接用 remainder() 取出尾部半包并保留等待后续字节。
                None
            }
            Err(e) => {
                // 协议错误：消费掉整个缓冲区，避免无限循环
                self.pos = self.buf.len();
                Some(Err(e))
            }
        }
    }
}

/// 根据链路 MTU 计算内层单帧 payload 的最大可用长度。
///
/// # 开销明细（合计 79 字节）
///
/// | 层 | 字节 |
/// |----|------|
/// | IPv4 头 | 20 |
/// | TCP 头 | 20 |
/// | TLS 记录头 | 5 |
/// | masked_seq | 8 |
/// | AEAD tag | 16 |
/// | 内层帧头 | 10 |
///
/// 例：MTU 1500 → 1500 - 79 = 1421，再留 21 字节安全余量 → 1400。
///
/// # 为什么必须留余量
///
/// FakeTCP 不做 IP 分片重组（置 DF 位），一旦超过链路 MTU 会被中间设备丢弃，
/// 且没有任何反馈信号，表现为「大包神秘丢失、小包正常」，极其难排查。
pub fn max_payload_for_mtu(mtu: usize) -> usize {
    /// 固定开销：IP20 + TCP20 + TLS头5 + masked_seq8 + tag16 + 帧头10
    const OVERHEAD: usize = 79;
    /// 安全余量：应对 IPv4 选项、PPPoE(8B)、VLAN(4B) 等额外封装
    const SAFETY_MARGIN: usize = 21;

    mtu.saturating_sub(OVERHEAD + SAFETY_MARGIN)
}

/// 帧编解码错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// 数据不足，需要等待更多字节（非错误，是字节流的正常状态）。
    #[error("数据不足，需要更多字节")]
    Truncated,
    /// 未知帧类型。
    #[error("未知帧类型: 0x{0:02X}")]
    UnknownFrameType(u8),
    /// 未定义的标志位被置位。
    #[error("使用了未定义的标志位: 0x{0:02X}")]
    UndefinedFlagBits(u8),
    /// payload 超长。
    #[error("payload 超长: {0} 字节")]
    PayloadTooLarge(usize),
    /// 域名过长。
    #[error("域名过长: {0} 字节（上限 255）")]
    DomainTooLong(usize),
    /// 未知地址类型。
    #[error("未知地址类型: 0x{0:02X}")]
    UnknownAtyp(u8),
    /// 域名不是合法 UTF-8。
    #[error("域名不是合法 UTF-8")]
    InvalidDomainEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证帧头长度常量与实际编码长度一致，防止文档/代码漂移。
    #[test]
    fn 帧头长度与理论值一致() {
        let f = Frame::new(FrameType::Data, Flags::empty(), 1, 0, b"");
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        assert_eq!(out.len(), FRAME_HEADER_LEN);
    }

    /// 完整编码→解码往返，验证字节序与字段对齐。
    #[test]
    fn 编解码往返一致() {
        let payload = b"hello flowtcp";
        let f = Frame::new(
            FrameType::Data,
            Flags::empty().with(Flags::RELIABLE).with(Flags::FIN),
            0x1234,
            0xDEADBEEF,
            payload,
        );
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();

        let (decoded, used) = Frame::decode(&out).unwrap();
        assert_eq!(used, out.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id, 0x1234);
        assert_eq!(decoded.pkt_seq, 0xDEADBEEF);
        assert_eq!(decoded.payload, payload);
        assert!(decoded.flags.has(Flags::RELIABLE));
        assert!(decoded.flags.has(Flags::FIN));
        assert!(!decoded.flags.has(Flags::LAST));
    }

    /// 大端序验证：stream_id 与 pkt_seq 必须按网络字节序写在线路上。
    #[test]
    fn 字节序为大端() {
        let f = Frame::new(FrameType::Ping, Flags::empty(), 0x0102, 0x03040506, b"");
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        assert_eq!(&out[2..4], &[0x01, 0x02]);
        assert_eq!(&out[4..8], &[0x03, 0x04, 0x05, 0x06]);
    }

    /// 半包必须返回 Truncated，而不是错误或 panic。
    #[test]
    fn 半包返回截断错误() {
        let f = Frame::new(FrameType::Data, Flags::empty(), 1, 0, b"abcdef");
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();

        // 帧头都没收全
        assert_eq!(Frame::decode(&out[..5]).unwrap_err(), FrameError::Truncated);
        // 帧头收全但 payload 不足
        assert_eq!(
            Frame::decode(&out[..FRAME_HEADER_LEN + 2]).unwrap_err(),
            FrameError::Truncated
        );
    }

    /// 多帧串联必须能逐个取出，尾部半包要能被精确识别。
    #[test]
    fn 多帧串联与半包共存() {
        let mut buf = Vec::new();
        Frame::new(FrameType::Data, Flags::empty(), 1, 0, b"aaa")
            .encode(&mut buf)
            .unwrap();
        Frame::new(FrameType::Data, Flags::empty(), 2, 1, b"bbbb")
            .encode(&mut buf)
            .unwrap();
        let complete_len = buf.len();
        // 再追加半个帧
        Frame::new(FrameType::Close, Flags::empty(), 1, 2, b"")
            .encode(&mut buf)
            .unwrap();
        buf.truncate(buf.len() - 2);

        let mut iter = FrameIter::new(&buf);
        let f1 = iter.next().unwrap().unwrap();
        let f2 = iter.next().unwrap().unwrap();
        assert_eq!(f1.stream_id, 1);
        assert_eq!(f1.payload, b"aaa");
        assert_eq!(f2.stream_id, 2);
        assert_eq!(f2.payload, b"bbbb");
        // 第三个是半包，迭代应正常结束
        assert!(iter.next().is_none());
        assert_eq!(iter.consumed(), complete_len);
    }

    /// 未定义标志位必须被拒绝：防止对端用未定义位传隐藏信息。
    #[test]
    fn 拒绝未定义标志位() {
        assert!(Flags::new(0xE0).is_err());
        assert!(Flags::new(0x1F).is_ok());
    }

    /// 超长 payload 必须在编码阶段被拦截。
    #[test]
    fn 拒绝超长payload() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let f = Frame::new(FrameType::Data, Flags::empty(), 1, 0, &big);
        let mut out = Vec::new();
        assert!(matches!(
            f.encode(&mut out).unwrap_err(),
            FrameError::PayloadTooLarge(_)
        ));
    }

    /// 恶意超长 length 字段必须被拦截（内存放大攻击防护）。
    #[test]
    fn 拒绝恶意超长长度字段() {
        let mut buf = vec![0u8; FRAME_HEADER_LEN];
        buf[0] = 0x03; // Data
                       // 写入 65535 的 length
        buf[8] = 0xFF;
        buf[9] = 0xFF;
        assert!(matches!(
            Frame::decode(&buf).unwrap_err(),
            FrameError::PayloadTooLarge(_)
        ));
    }

    #[test]
    fn 地址编码往返_ipv4() {
        let addr = Address::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8080));
        let mut out = Vec::new();
        let n = addr.encode(&mut out).unwrap();
        assert_eq!(n, 7);
        let (decoded, used) = Address::decode(&out).unwrap();
        assert_eq!(used, 7);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn 地址编码往返_ipv6() {
        let addr = Address::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 443, 0, 0));
        let mut out = Vec::new();
        let n = addr.encode(&mut out).unwrap();
        assert_eq!(n, 19);
        let (decoded, used) = Address::decode(&out).unwrap();
        assert_eq!(used, 19);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn 地址编码往返_域名() {
        let addr = Address::Domain("example.com".to_string(), 53);
        let mut out = Vec::new();
        let n = addr.encode(&mut out).unwrap();
        assert_eq!(n, addr.encoded_len());
        assert_eq!(n, 2 + 11 + 2);
        let (decoded, used) = Address::decode(&out).unwrap();
        assert_eq!(used, n);
        assert_eq!(decoded, addr);
        // 域名无法直接转为 SocketAddr，必须由服务端解析
        assert!(decoded.as_socket_addr().is_none());
    }

    #[test]
    fn 拒绝超长域名() {
        let addr = Address::Domain("a".repeat(256), 80);
        let mut out = Vec::new();
        assert!(matches!(
            addr.encode(&mut out).unwrap_err(),
            FrameError::DomainTooLong(_)
        ));
    }

    /// MTU 预算是硬约束：验证 1500 MTU 下 payload 上限为 1400。
    #[test]
    fn mtu预算() {
        assert_eq!(max_payload_for_mtu(1500), 1400);
        // IPv6 最小 MTU 1280 场景
        assert_eq!(max_payload_for_mtu(1280), 1180);
        // 极小 MTU 不能下溢 panic
        assert_eq!(max_payload_for_mtu(50), 0);
    }

    /// 端到端验证：MTU 限制内的最大帧必须能完整编码且不超预算。
    #[test]
    fn 最大帧不超过mtu预算() {
        let max = max_payload_for_mtu(1500);
        let payload = vec![0xABu8; max];
        let f = Frame::new(FrameType::Data, Flags::empty(), 1, 0, &payload);
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        // 帧总长 + 各层开销必须 <= MTU
        assert!(out.len() + 79 <= 1500);
        assert_eq!(out.len(), max + FRAME_HEADER_LEN);
    }

    /// UDP 场景：HAS_ADDR 标志与地址前缀组合必须能正确解析。
    #[test]
    fn udp帧带地址前缀() {
        let addr = Address::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let mut payload = Vec::new();
        addr.encode(&mut payload).unwrap();
        payload.extend_from_slice(b"dns-query");

        let f = Frame::new(
            FrameType::Data,
            Flags::empty().with(Flags::HAS_ADDR),
            5,
            10,
            &payload,
        );
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();

        let (decoded, _) = Frame::decode(&out).unwrap();
        assert!(decoded.flags.has(Flags::HAS_ADDR));
        let (daddr, used) = Address::decode(decoded.payload).unwrap();
        assert_eq!(daddr, addr);
        assert_eq!(&decoded.payload[used..], b"dns-query");
    }
}
