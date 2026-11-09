//! 对抗 TLS 中间人的证书指纹探针。
//!
//! 工作方式：首次运行采用 TOFU（首次使用即信任）记录目标站点的 SPKI 指纹，
//! 之后每次连接都校验指纹；指纹变化即判定链路被中间人劫持。
//!
//! 模块划分：
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `cli` | 命令行参数 |
//! | `config` | `pinned-config.json` 的查找、读写与校验 |
//! | `tls` | 自定义证书校验器（SPKI 固定）、HTTP 客户端构建 |
//! | `dns` | DoH / 系统 DNS 解析 |
//! | `probe` | 单次探测流程与结果模型 |
//! | `report` | 人类可读与 JSON 输出、退出码 |
//! | `antidebug` | Windows 反调试（可选） |
//!
//! 退出码：`0` 正常 / `2` 检测到 MITM / `3` 全部候选不可达 /
//! `4` 用法或配置错误 / `5` 证书过期（仅 `--fail-on-expiry`）。

mod antidebug;
mod cli;
mod config;
mod dns;
mod probe;
mod report;
mod tls;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use crate::cli::Args;
use crate::config::PinnedConfig;
use crate::probe::{ProbeOutcome, ProbePlan};

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // rustls 0.23 要求显式安装加密后端；重复安装会报错，忽略即可。
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 反调试只在 Windows 上生效，其余平台该函数恒返回 false。
    // 这里不加 cfg，避免非 Windows 构建把它判成 dead_code（clippy -D warnings 会挂）。
    if !args.dev && antidebug::is_being_debugged() {
        // 被调试时静默退出，避免内存里的暗号与配置被直接 dump。
        std::process::exit(0);
    }

    match run(args).await {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("[-] {message}");
            ExitCode::from(report::EXIT_USAGE)
        }
    }
}

/// 主流程：准备配置 → 选定候选地址 → 探测 → 输出。
async fn run(args: Args) -> Result<u8, String> {
    let config_path = PinnedConfig::resolve_path(args.config.clone());
    let stored = PinnedConfig::load(&config_path)?;

    if args.check {
        return check(&args, stored.as_ref(), &config_path);
    }

    let domain = args
        .domain
        .clone()
        .or_else(|| stored.as_ref().map(|config| config.domain.clone()))
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| {
            format!(
                "缺少目标域名：用 -d <域名> 指定，或在 {} 中配置 domain",
                config_path.display()
            )
        })?;

    let pin = args
        .pin
        .clone()
        .or_else(|| stored.as_ref().map(|config| config.pin.clone()))
        .unwrap_or_default();
    // 提前校验指纹格式，避免连上之后才因为 Base64 非法而报错。
    let _ = PinnedConfig::decode_pin(&pin)?;

    let token = args
        .token
        .clone()
        .or_else(|| stored.as_ref().and_then(|config| config.token.clone()));
    let proxy = args
        .proxy
        .clone()
        .or_else(|| stored.as_ref().and_then(|config| config.proxy.clone()));
    let pinned_ip = args
        .ip
        .clone()
        .or_else(|| stored.as_ref().and_then(|config| config.ip.clone()));

    let timeout = Duration::from_secs(args.timeout);
    let mut tried: Vec<String> = Vec::new();
    let mut last_error = String::new();
    let mut outcome: Option<(ProbeOutcome, SocketAddr)> = None;

    // 第一阶段：强绑 IP（配置里固定过的地址优先）。
    if let Some(raw_ip) = pinned_ip.as_deref() {
        let target = parse_target(raw_ip)?;
        tried.push(target.to_string());
        let result = probe::probe(&ProbePlan {
            domain: domain.clone(),
            target,
            pin: pin.clone(),
            token: token.clone(),
            timeout,
            retries: args.retries,
        })
        .await;

        if !matches!(result, ProbeOutcome::Failed { .. }) {
            outcome = Some((result, target));
        } else if let ProbeOutcome::Failed { error } = &result {
            last_error = error.clone();
        }
    }

    // 第二阶段：DNS 降级（--no-fallback 或已命中时跳过）。
    if outcome.is_none() && !args.no_fallback {
        let candidates = dns::resolve(&domain, proxy.as_deref(), args.doh.as_deref()).await;
        for target in candidates {
            if tried.iter().any(|entry| entry == &target.to_string()) {
                continue;
            }
            tried.push(target.to_string());
            let result = probe::probe(&ProbePlan {
                domain: domain.clone(),
                target,
                pin: pin.clone(),
                token: token.clone(),
                timeout,
                retries: args.retries,
            })
            .await;

            if matches!(result, ProbeOutcome::Failed { .. }) {
                if let ProbeOutcome::Failed { error } = &result {
                    last_error = error.clone();
                }
                continue;
            }
            outcome = Some((result, target));
            break;
        }
    }

    let (outcome, target) = match outcome {
        Some(pair) => pair,
        None => {
            let report = report::unreachable(&domain, tried, last_error);
            report.emit(&args);
            return Ok(report::EXIT_UNREACHABLE);
        }
    };

    let report = report::from_outcome(&domain, target, &outcome, &pin);
    report.emit(&args);

    // 首次运行（没有固定指纹）时把观测到的指纹落盘，形成 TOFU 基线。
    if matches!(outcome, ProbeOutcome::Tofu { .. }) {
        if let Some(cert) = outcome.cert() {
            let config = PinnedConfig {
                domain: domain.clone(),
                ip: Some(target.to_string()),
                pin: cert.pin_b64.clone(),
                expiry: Some(cert.not_after),
                token: token.clone(),
                proxy: proxy.clone(),
            };
            match config.save(&config_path) {
                Ok(()) => report::note(&format!("已把本次指纹写入 {}", config_path.display())),
                Err(e) => report::note(&format!("指纹保存失败（{e}），请手动写入配置")),
            }
        }
    }

    // 指纹不匹配：只有显式 --accept-new-pin 才更新配置（正常换证场景）。
    if matches!(outcome, ProbeOutcome::Mitm { .. }) && args.accept_new_pin {
        if let Some(cert) = outcome.cert() {
            let config = PinnedConfig {
                domain: domain.clone(),
                ip: Some(target.to_string()),
                pin: cert.pin_b64.clone(),
                expiry: Some(cert.not_after),
                token: token.clone(),
                proxy: proxy.clone(),
            };
            config.save(&config_path)?;
            report::note(&format!(
                "已按 --accept-new-pin 更新指纹（{}）",
                config_path.display()
            ));
            return Ok(report::EXIT_OK);
        }
    }

    Ok(report.exit_code(&args))
}

/// `--check`：只校验配置与指纹格式，不发起网络请求。
fn check(args: &Args, stored: Option<&PinnedConfig>, path: &std::path::Path) -> Result<u8, String> {
    println!("[*] 配置文件: {}", path.display());

    let config = match stored {
        Some(config) => config.clone(),
        None => {
            println!("[!] 配置文件不存在（首次运行会自动创建）");
            PinnedConfig {
                domain: args.domain.clone().unwrap_or_default(),
                pin: args.pin.clone().unwrap_or_default(),
                ..PinnedConfig::default()
            }
        }
    };

    if config.domain.is_empty() {
        return Err("配置缺少 domain（用 -d 指定或写进配置文件）".to_string());
    }
    println!("[+] 目标域名: {}", config.domain);

    if config.pin.is_empty() {
        println!("[!] 尚未固定指纹：下次运行会以 TOFU 方式记录");
    } else {
        let pin = PinnedConfig::decode_pin(&config.pin)?;
        println!("[+] 指纹格式有效（SHA-256 / {} 字节）", pin.len());
    }

    if let Some(ip) = &config.ip {
        let target = parse_target(ip)?;
        println!("[+] 固定地址: {target}");
    }
    if let Some(proxy) = &config.proxy {
        println!("[*] DoH 代理: {proxy}");
    }
    println!("[+] 配置校验通过");
    Ok(report::EXIT_OK)
}

/// 解析 `IP` 或 `IP:端口`（默认 443）。
fn parse_target(value: &str) -> Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 443));
    }
    Err(format!(
        "无效的地址 {value}，应为 1.2.3.4 或 1.2.3.4:443（IPv6 用 [::1]:443）"
    ))
}
