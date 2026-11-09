//! 结果模型与输出。
//!
//! 同一个 [`Report`] 既用于人类可读输出，也用于 `--json`；退出码由结果推导，
//! 这样监控脚本既可以直接读 JSON，也可以只看退出码。

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::cli::Args;
use crate::probe::ProbeOutcome;
use crate::tls::CertInfo;

/// 正常（含首次 TOFU 固定）。
pub const EXIT_OK: u8 = 0;
/// 检测到中间人。
pub const EXIT_MITM: u8 = 2;
/// 所有候选地址都不可达。
pub const EXIT_UNREACHABLE: u8 = 3;
/// 用法或配置错误。
pub const EXIT_USAGE: u8 = 4;
/// 证书即将过期 / 已过期（仅 `--fail-on-expiry`）。
pub const EXIT_EXPIRY: u8 = 5;

/// 证书剩余天数低于该值时给出警告。
const EXPIRY_WARN_DAYS: i64 = 7;

/// 一次探测的完整结果。
#[derive(Debug, Serialize)]
pub struct Report {
    /// `secure` / `tofu` / `mitm` / `unreachable`
    pub status: &'static str,
    pub domain: String,
    pub ip: Option<String>,
    /// 本次观测到的指纹。
    pub pin: Option<String>,
    /// 期望指纹（MITM 时用于对比）。
    pub expected_pin: Option<String>,
    /// 实际指纹（MITM 时用于对比）。
    pub actual_pin: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// 证书剩余天数（负数表示已过期）。
    pub expires_in_days: Option<i64>,
    pub http_status: Option<u16>,
    /// 友军暗号是否被服务端接受；未提供暗号时为 `None`。
    pub token_ok: Option<bool>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    /// 尝试过的候选地址（不可达时用于排查）。
    pub tried: Vec<String>,
}

impl Report {
    /// 输出结果：`--json` 时只打印一行 JSON，否则打印人类可读文本。
    pub fn emit(&self, args: &Args) {
        if args.json {
            match serde_json::to_string(self) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("[-] 序列化结果失败: {e}"),
            }
            return;
        }

        match self.status {
            "secure" => self.print_secure(false),
            "tofu" => self.print_secure(true),
            "mitm" => self.print_mitm(),
            _ => self.print_unreachable(),
        }

        for warning in &self.warnings {
            println!("[!] {warning}");
        }
    }

    /// 退出码：`0` 正常 / `2` MITM / `3` 不可达 / `5` 证书将过期。
    pub fn exit_code(&self, args: &Args) -> u8 {
        match self.status {
            "mitm" => EXIT_MITM,
            "unreachable" => EXIT_UNREACHABLE,
            _ => {
                let expiring = self
                    .expires_in_days
                    .is_some_and(|days| days < EXPIRY_WARN_DAYS);
                if args.fail_on_expiry && expiring {
                    EXIT_EXPIRY
                } else {
                    EXIT_OK
                }
            }
        }
    }

    fn print_secure(&self, first_run: bool) {
        println!(
            "[+] 目标: {}（{}）",
            self.domain,
            self.ip.as_deref().unwrap_or("-")
        );
        if let Some(status) = self.http_status {
            println!("[+] TLS 握手成功，HTTP {status}");
        }
        if first_run {
            println!("[+] 首次运行：已记录证书指纹（TOFU 基线）");
        } else {
            println!("[+] 指纹匹配，链路正常");
        }
        if let Some(pin) = &self.pin {
            println!("[+] 指纹: {pin}");
        }
        if let Some(issuer) = &self.issuer {
            println!("[+] 证书签发者: {issuer}");
        }
        if let Some(subject) = &self.subject {
            println!("[+] 证书主题: {subject}");
        }
        if let Some(days) = self.expires_in_days {
            println!("[+] 证书剩余有效期: {days} 天");
        }
        match self.token_ok {
            Some(true) => println!("[+] 友军暗号有效，服务端已放行"),
            Some(false) => println!("[!] 暗号未被接受：服务端返回的不是 authorized 响应"),
            None => {}
        }
    }

    fn print_mitm(&self) {
        println!("🚨 检测到中间人：证书指纹不匹配！");
        println!(
            "  目标: {}（{}）",
            self.domain,
            self.ip.as_deref().unwrap_or("-")
        );
        if let Some(expected) = &self.expected_pin {
            println!("  期望指纹: {expected}");
        }
        if let Some(actual) = &self.actual_pin {
            println!("  实际指纹: {actual}");
        }
        if let Some(issuer) = &self.issuer {
            println!("  实际签发者: {issuer}");
        }
        if let Some(subject) = &self.subject {
            println!("  实际主体: {subject}");
        }
        println!("  提示: 若确认是服务端正常换证，用 --accept-new-pin 更新指纹");
    }

    fn print_unreachable(&self) {
        println!("[-] 所有候选地址均不可达");
        if !self.tried.is_empty() {
            println!("  已尝试: {}", self.tried.join(", "));
        }
        for error in &self.errors {
            println!("  最后错误: {error}");
        }
    }
}

/// 由探测结果构造报告。
pub fn from_outcome(
    domain: &str,
    target: SocketAddr,
    outcome: &ProbeOutcome,
    expected_pin: &str,
) -> Report {
    let ip = Some(target.to_string());
    match outcome {
        ProbeOutcome::Secure {
            cert,
            status,
            token_ok,
        } => secure_report("secure", domain, ip, cert, *status, *token_ok),
        ProbeOutcome::Tofu {
            cert,
            status,
            token_ok,
        } => secure_report("tofu", domain, ip, cert, *status, *token_ok),
        ProbeOutcome::Mitm {
            expected,
            actual,
            cert,
        } => Report {
            status: "mitm",
            domain: domain.to_string(),
            ip,
            pin: cert.as_ref().map(|cert| cert.pin_b64.clone()),
            expected_pin: Some(expected.clone()),
            actual_pin: Some(actual.clone()),
            issuer: cert.as_ref().map(|cert| cert.issuer.clone()),
            subject: cert.as_ref().map(|cert| cert.subject.clone()),
            expires_in_days: cert.as_ref().map(|cert| days_until(cert.not_after)),
            http_status: None,
            token_ok: None,
            warnings: Vec::new(),
            errors: Vec::new(),
            tried: Vec::new(),
        },
        ProbeOutcome::Failed { error } => Report {
            status: "unreachable",
            domain: domain.to_string(),
            ip,
            pin: None,
            expected_pin: if expected_pin.is_empty() {
                None
            } else {
                Some(expected_pin.to_string())
            },
            actual_pin: None,
            issuer: None,
            subject: None,
            expires_in_days: None,
            http_status: None,
            token_ok: None,
            warnings: Vec::new(),
            errors: vec![error.clone()],
            tried: Vec::new(),
        },
    }
}

/// 构造"不可达"报告（所有候选地址都失败时使用）。
pub fn unreachable(domain: &str, tried: Vec<String>, last_error: String) -> Report {
    Report {
        status: "unreachable",
        domain: domain.to_string(),
        ip: None,
        pin: None,
        expected_pin: None,
        actual_pin: None,
        issuer: None,
        subject: None,
        expires_in_days: None,
        http_status: None,
        token_ok: None,
        warnings: Vec::new(),
        errors: if last_error.is_empty() {
            Vec::new()
        } else {
            vec![last_error]
        },
        tried,
    }
}

/// 打印一条不影响 stdout（JSON 模式）的备注。
pub fn note(message: &str) {
    eprintln!("[*] {message}");
}

fn secure_report(
    status: &'static str,
    domain: &str,
    ip: Option<String>,
    cert: &CertInfo,
    http_status: u16,
    token_ok: Option<bool>,
) -> Report {
    let days = days_until(cert.not_after);
    let mut warnings = Vec::new();
    if days < 0 {
        let overdue = -days;
        warnings.push(format!(
            "证书已过期 {overdue} 天（not_after={}）",
            cert.not_after
        ));
    } else if days < EXPIRY_WARN_DAYS {
        warnings.push(format!("证书仅剩 {days} 天到期，请尽快续期"));
    }

    Report {
        status,
        domain: domain.to_string(),
        ip,
        pin: Some(cert.pin_b64.clone()),
        expected_pin: None,
        actual_pin: None,
        issuer: Some(cert.issuer.clone()),
        subject: Some(cert.subject.clone()),
        expires_in_days: Some(days),
        http_status: Some(http_status),
        token_ok,
        warnings,
        errors: Vec::new(),
        tried: Vec::new(),
    }
}

/// 证书到期时间距离现在还有多少天（负数表示已过期）。
fn days_until(timestamp: u64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    (timestamp as i64 - now as i64) / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;

    fn args() -> Args {
        use clap::Parser;
        Args::parse_from(["pinned-client", "-d", "example.com"])
    }

    fn report(status: &'static str, days: Option<i64>) -> Report {
        Report {
            status,
            domain: "example.com".to_string(),
            ip: None,
            pin: None,
            expected_pin: None,
            actual_pin: None,
            issuer: None,
            subject: None,
            expires_in_days: days,
            http_status: None,
            token_ok: None,
            warnings: Vec::new(),
            errors: Vec::new(),
            tried: Vec::new(),
        }
    }

    /// 正常与 TOFU 都返回 0；MITM 与不可达各有独立退出码。
    #[test]
    fn maps_status_to_exit_code() {
        let args = args();
        assert_eq!(report("secure", Some(90)).exit_code(&args), EXIT_OK);
        assert_eq!(report("tofu", Some(90)).exit_code(&args), EXIT_OK);
        assert_eq!(report("mitm", None).exit_code(&args), EXIT_MITM);
        assert_eq!(
            report("unreachable", None).exit_code(&args),
            EXIT_UNREACHABLE
        );
    }

    /// 只有显式开启 --fail-on-expiry 才会因证书将过期返回 5。
    #[test]
    fn expiry_exit_code_is_opt_in() {
        use clap::Parser;
        let strict = Args::parse_from(["pinned-client", "-d", "example.com", "--fail-on-expiry"]);
        assert_eq!(report("secure", Some(3)).exit_code(&strict), EXIT_EXPIRY);
        assert_eq!(report("secure", Some(30)).exit_code(&strict), EXIT_OK);
        assert_eq!(report("secure", Some(3)).exit_code(&args()), EXIT_OK);
    }

    /// 剩余天数计算：未来为正、过去为负。
    #[test]
    fn computes_days_until() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(days_until(now + 86_400 * 10) >= 9);
        assert!(days_until(now.saturating_sub(86_400 * 2)) <= -2);
    }
}
