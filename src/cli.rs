//! 命令行参数定义。
//!
//! 所有网络行为都可以用参数覆盖配置文件；命令行优先级高于配置文件。

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "pinned-client",
    author,
    version,
    about = "对抗 TLS 中间人的证书指纹探针",
    long_about = "首次运行采用 TOFU（首次使用即信任）记录目标站点的 SPKI 指纹，\
                  之后每次连接都校验；指纹不一致即判定链路被中间人劫持。"
)]
pub struct Args {
    /// 目标域名（首次运行只给 -d 即可，会自动记录指纹）
    #[arg(short, long)]
    pub domain: Option<String>,

    /// 目标地址 IP 或 IP:端口（默认端口 443）
    #[arg(short, long)]
    pub ip: Option<String>,

    /// 期望的 SPKI 指纹（Base64 编码的 SHA-256）；留空表示 TOFU
    #[arg(short, long)]
    pub pin: Option<String>,

    /// 友军暗号，作为 X-Probe-Token 请求头发送
    #[arg(short, long)]
    pub token: Option<String>,

    /// HTTP 代理（仅用于 DoH 解析），例如 http://127.0.0.1:10808
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,

    /// 自定义 DoH 地址，例如 https://dns.alidns.com/resolve
    #[arg(long, value_name = "URL")]
    pub doh: Option<String>,

    /// 配置文件路径（默认 ./pinned-config.json，其次 /etc/pinned-client/）
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// 输出单行 JSON（便于监控脚本解析）
    #[arg(long)]
    pub json: bool,

    /// 单次连接超时（秒）
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub timeout: u64,

    /// 传输层失败时的重试次数（0~5）
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(0..=5))]
    pub retries: u32,

    /// 只连 --ip 指定的地址，不做 DoH 降级
    #[arg(long)]
    pub no_fallback: bool,

    /// 指纹不匹配时把新指纹写回配置（仅在确认是正常换证时使用）
    #[arg(long)]
    pub accept_new_pin: bool,

    /// 证书剩余天数低于阈值时以退出码 5 结束
    #[arg(long)]
    pub fail_on_expiry: bool,

    /// 只校验配置与指纹格式，不发起网络请求
    #[arg(long)]
    pub check: bool,

    /// 跳过反调试检查（开发用）
    #[arg(long, hide = true)]
    pub dev: bool,
}
