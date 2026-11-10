//! CLI 子命令解析与分发
//!
//! 选项解析的细节见 [`crate::args`]（含"为什么不引入 clap"的说明）。

use std::fmt;

use crate::args::Args;

/// CLI 错误。
#[derive(Debug)]
pub enum CliError {
    /// 未知子命令。
    UnknownCommand(String),
    /// 参数缺失或非法。
    BadArgs(String),
    /// 协议错误。
    Proto(String),
    /// 自检失败。
    SelfTest(String),
    /// 指纹检测失败。
    Fingerprint(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownCommand(c) => write!(f, "未知子命令: {c}"),
            CliError::BadArgs(m) => write!(f, "参数错误: {m}"),
            CliError::Proto(m) => write!(f, "协议错误: {m}"),
            CliError::SelfTest(m) => write!(f, "自检失败: {m}"),
            CliError::Fingerprint(m) => write!(f, "指纹检测失败: {m}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<flowtcp_proto::FrameError> for CliError {
    fn from(e: flowtcp_proto::FrameError) -> Self {
        CliError::Proto(e.to_string())
    }
}

impl From<flowtcp_proto::RecordError> for CliError {
    fn from(e: flowtcp_proto::RecordError) -> Self {
        CliError::Proto(e.to_string())
    }
}

impl From<flowtcp_proto::KeyDeriveError> for CliError {
    fn from(e: flowtcp_proto::KeyDeriveError) -> Self {
        CliError::Proto(e.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for CliError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        CliError::SelfTest(e.to_string())
    }
}

/// 帮助文本。
fn help() -> String {
    "\
FlowTCP —— UDP 特性 + TLS 1.3 伪装的代理传输协议

用法:
  flowtcp <子命令> [选项]

子命令:
  server            启动服务端（偷网站模式 / 自有证书模式）
  client            启动客户端（SOCKS5 / HTTP / HTTPS 三种本地入口）
  selftest          运行协议栈自检（无需网络、无需 root）
  fingerprint       检测 TLS 指纹是否像 Chrome（需联网）
  info              显示版本与协议参数
  help              显示本帮助

查看子命令的完整选项:
  flowtcp server --help
  flowtcp client --help

快速开始:
  # 服务端（偷网站模式：零域名、零证书）
  flowtcp server --listen 0.0.0.0:443 --password 'my-secret' \\
      --target www.microsoft.com:443

  # 客户端（只开 SOCKS5）
  flowtcp client --remote 1.2.3.4:443 --password 'my-secret' \\
      --sni www.microsoft.com --socks5 127.0.0.1:1080

  # 自检
  flowtcp selftest
"
    .to_string()
}

/// 版本与协议参数信息。
fn info() -> String {
    format!(
        "\
FlowTCP v{ver}

协议参数:
  协议版本       0x{pv:02X}
  exporter 标签  {label}
  记录头格式     0x17 0x03 0x03 | length(2) | masked_seq(8) | ciphertext+tag(16)
  内层帧头       {fh} 字节
  MTU 1500 时    payload 上限 {mp} 字节
  AEAD           AES-128-GCM / ChaCha20-Poly1305
  认证魔数       {magic}

平台支持:
  服务端         Linux amd64 / arm64
  客户端         Linux / Windows(WinDivert) / Android(root)
",
        ver = env!("CARGO_PKG_VERSION"),
        pv = flowtcp_proto::PROTOCOL_VERSION,
        label = flowtcp_proto::EXPORTER_LABEL,
        fh = flowtcp_proto::FRAME_HEADER_LEN,
        mp = flowtcp_proto::max_payload_for_mtu(1500),
        magic = String::from_utf8_lossy(flowtcp_proto::AUTH_MAGIC),
    )
}

/// 入口：解析参数并分发。
///
/// 结构：`flowtcp <子命令> [选项...]`
///
/// 子命令之后的参数全部交给 [`Args::parse`]，因此新增选项不需要改这里。
pub async fn run() -> Result<(), CliError> {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // 没有参数 / 顶层 -h → 显示总帮助
    if argv.is_empty() || argv[0] == "-h" || argv[0] == "--help" {
        println!("{}", help());
        return Ok(());
    }

    let cmd = argv[0].as_str();
    let rest = &argv[1..];

    // 子命令级别的帮助优先处理：`flowtcp server --help`
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        let text = match cmd {
            "server" => crate::cmd_server::help().to_string(),
            "client" => crate::cmd_client::help().to_string(),
            _ => help(),
        };
        println!("{text}");
        return Ok(());
    }

    let args = Args::parse(rest).map_err(CliError::BadArgs)?;
    let verbose = args.has_flag("verbose") || args.has_flag("v");

    match cmd {
        "selftest" => crate::selftest(verbose).map_err(CliError::from),
        "fingerprint" => {
            let profile = if args.has_flag("plain") || args.has_flag("p") {
                flowtcp_tls::FingerprintProfile::Plain
            } else {
                flowtcp_tls::FingerprintProfile::Chrome
            };
            let endpoint = args.get("endpoint").unwrap_or("tls.peet.ws");
            let report = crate::fpcheck::check(Some(endpoint), profile)
                .await
                .map_err(|e| CliError::Fingerprint(e.to_string()))?;
            println!("{report}");
            Ok(())
        }
        "info" => {
            println!("{}", info());
            Ok(())
        }
        "server" => crate::cmd_server::run(&args)
            .await
            .map_err(CliError::BadArgs),
        "client" => crate::cmd_client::run(&args)
            .await
            .map_err(CliError::BadArgs),
        "help" => {
            println!("{}", help());
            Ok(())
        }
        other => Err(CliError::UnknownCommand(other.to_string())),
    }
}
