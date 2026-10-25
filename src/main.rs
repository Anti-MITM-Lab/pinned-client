use base64::Engine;
use clap::Parser;
use futures_util::StreamExt;
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

// ==================== 1. 配置文件结构 ====================
#[derive(Serialize, Deserialize, Debug, Clone)]
struct PinnedConfig {
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    pin: String,
    #[serde(default)]
    expiry: Option<u64>,
    // 新增：客户端专属暗号
    #[serde(default)]
    token: Option<String>,
}

const CONFIG_PATH: &str = "pinned-config.json";

#[derive(Parser, Debug)]
#[command(author, version, about = "终极防 MITM 探针", long_about = None)]
struct Args {
    #[arg(short, long)]
    domain: Option<String>,
    #[arg(short, long)]
    ip: Option<String>,
    #[arg(short, long)]
    pin: Option<String>,
    // 新增：命令行支持传入 token
    #[arg(short, long)]
    token: Option<String>,
    #[arg(long, hide = true)]
    dev: bool,
}

// ==================== 2. 反调试逻辑 ====================
#[cfg(target_os = "windows")]
fn is_being_debugged() -> bool {
    use windows::core::BOOL;
    use windows::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, IsDebuggerPresent,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    let basic_check = unsafe { IsDebuggerPresent() };
    if basic_check.as_bool() {
        return true;
    }

    let mut remote_debugger = BOOL(0);
    let call_ok =
        unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote_debugger) }.is_ok();

    if call_ok {
        remote_debugger.as_bool()
    } else {
        false
    }
}

#[cfg(not(target_os = "windows"))]
fn is_being_debugged() -> bool {
    false
}

// ==================== 3. 证书校验器 ====================
#[derive(Debug)]
struct PinnedVerifier {
    expected_hash: Vec<u8>,
    expected_b64: String,
    captured_data: Mutex<Option<(String, u64)>>,
}

impl PinnedVerifier {
    fn new(b64_hash: &str) -> Self {
        let expected_hash = base64::engine::general_purpose::STANDARD
            .decode(b64_hash)
            .unwrap_or_else(|_| Vec::new());
        Self {
            expected_hash,
            expected_b64: b64_hash.to_string(),
            captured_data: Mutex::new(None),
        }
    }

    fn extract_cert_info(cert_der: &[u8]) -> Result<(Vec<u8>, u64), Error> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| Error::General(format!("X509 parse error: {e}")))?;

        println!("[!] 捕获到证书 Issuer: {}", cert.issuer);

        let spki_der = cert.tbs_certificate.subject_pki.raw.to_vec();
        let not_after = cert.tbs_certificate.validity.not_after;
        let expiry_ts = not_after.timestamp() as u64;

        Ok((spki_der, expiry_ts))
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (spki_der, expiry_ts) = Self::extract_cert_info(end_entity.as_ref())?;

        let mut hasher = Sha256::new();
        hasher.update(&spki_der);
        let actual_hash = hasher.finalize();
        let actual_b64 = base64::engine::general_purpose::STANDARD.encode(actual_hash);

        if let Ok(mut lock) = self.captured_data.lock() {
            *lock = Some((actual_b64.clone(), expiry_ts));
        }

        if self.expected_hash.is_empty() || actual_hash.as_slice() == self.expected_hash.as_slice()
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "\n=========================================\n\
                 🚨 警告：检测到中间人攻击 (MITM)！\n\
                 预期指纹: {}\n\
                 实际指纹: {}\n\
                 =========================================",
                self.expected_b64, actual_b64
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ==================== 4. 配置文件读写 ====================
fn load_config() -> Option<PinnedConfig> {
    fs::read_to_string(CONFIG_PATH)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
}

fn resolve_dns_ip(domain: &str) -> Vec<String> {
    let target = format!("{}:443", domain);
    match target.to_socket_addrs() {
        Ok(addrs) => addrs.map(|addr| addr.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn save_config(cfg: &PinnedConfig) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        if fs::write(CONFIG_PATH, json).is_ok() {
            println!("[+] 已自动保存配置文件: {}", CONFIG_PATH);
        }
    }
}

fn check_expiry(expiry_ts: u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    if expiry_ts < now {
        println!("🚨 [严重警告] 证书已过期！请立即更新服务器证书。");
    } else {
        let diff = expiry_ts - now;
        let days = diff / 86400;
        if days < 7 {
            println!(
                "⚠️  [注意] 证书仅剩 {} 天到期 (到期时间: {})",
                days,
                format_ts(expiry_ts)
            );
        } else {
            println!("[+] 证书有效期剩余 {} 天", days);
        }
    }
}

fn format_ts(ts: u64) -> String {
    let dt = UNIX_EPOCH + Duration::from_secs(ts);
    match dt.duration_since(UNIX_EPOCH) {
        Ok(d) => format!("Unix {}", d.as_secs()),
        Err(_) => "Unknown".to_string(),
    }
}

fn build_client_with_verifier(
    domain: &str,
    ip: Option<&str>,
    pin_str: &str,
) -> Result<(Client, Arc<PinnedVerifier>), Box<dyn std::error::Error>> {
    let verifier = Arc::new(PinnedVerifier::new(pin_str));
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    let mut client_builder = Client::builder()
        .use_preconfigured_tls(tls_config)
        .tls_built_in_root_certs(false)
        .no_proxy();

    if let Some(ip_str) = ip {
        let target_addr: SocketAddr = ip_str
            .parse()
            .map_err(|_| "无效的 IP 格式，请使用 IP:端口 的格式")?;
        client_builder = client_builder.resolve(domain, target_addr);
    }

    let client = client_builder.build()?;
    Ok((client, verifier))
}

// ==================== 5. 响应处理 ====================
async fn process_response(
    resp: Result<reqwest::Response, reqwest::Error>,
    captured: Option<(String, u64)>,
    domain: &str,
    ip: &str,
    is_first_run: bool,
    token: Option<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    match resp {
        Ok(response) => {
            let status = response.status();

            let mut preview = Vec::new();
            let mut stream = response.bytes_stream();

            while preview.len() < 64 {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let needed = 64 - preview.len();
                        let to_take = std::cmp::min(chunk.len(), needed);
                        preview.extend_from_slice(&chunk[..to_take]);
                    }
                    Some(Err(_)) => break,
                    None => break,
                }
            }

            println!(
                "[+] 探测成功！Status: {}, 已拉取诱饵数据 (前 {} 字节: {:?})",
                status,
                preview.len(),
                String::from_utf8_lossy(&preview)
            );

            if let Some((actual_pin, expiry_ts)) = captured {
                check_expiry(expiry_ts);
                if is_first_run {
                    let cfg = PinnedConfig {
                        domain: domain.to_string(),
                        ip: Some(ip.to_string()),
                        pin: actual_pin,
                        expiry: Some(expiry_ts),
                        token: token.clone(), // 保存暗号到配置文件
                    };
                    save_config(&cfg);
                } else {
                    println!("[+] 指纹校验通过，网络环境安全。");
                }
            }
            Ok(true)
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Certificate pin mismatch") {
                println!("[-] 连接失败: {}", e);
                return Ok(true);
            }
            Ok(false)
        }
    }
}

// ==================== 6. 主函数 ====================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    #[cfg(target_os = "windows")]
    if !args.dev && is_being_debugged() {
        std::process::exit(0);
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install failed!!!");

    let config = load_config();

    let domain = args
        .domain
        .clone()
        .or_else(|| config.as_ref().map(|c| c.domain.clone()))
        .expect("缺少目标域名，请通过 -d 提供或配置 pinned-config.json");

    let current_ip = args
        .ip
        .clone()
        .or_else(|| config.as_ref().and_then(|c| c.ip.clone()));

    // 解析 Token：命令行 > 配置文件 > 空
    let token = args
        .token
        .clone()
        .or_else(|| config.as_ref().and_then(|c| c.token.clone()));

    let (pin_str, is_first_run) = if let Some(cmd_pin) = &args.pin {
        (cmd_pin.clone(), false)
    } else if let Some(cfg) = &config {
        (cfg.pin.clone(), false)
    } else {
        (String::new(), true)
    };

    let url = format!("https://{}/", domain);

    // ==================== 第一阶段：强绑 IP ====================
    if let Some(ip_str) = &current_ip {
        println!("[*] 探测目标: {} -> {}", domain, ip_str);
        let (client, verifier) = build_client_with_verifier(&domain, Some(ip_str), &pin_str)?;

        let mut req = client.get(&url);
        // 核心修改：如果有 token，就带上自定义 Header
        if let Some(t) = &token {
            req = req.header("X-Probe-Token", t);
        }

        let resp = req.send().await;

        let captured = {
            match verifier.captured_data.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => None,
            }
        };

        if process_response(resp, captured, &domain, ip_str, is_first_run, token.clone()).await? {
            return Ok(());
        }
        println!("[!] 强绑 IP 连接失败, 正在尝试 DNS 降级解析...");
    }

    // ==================== 第二阶段：DNS 降级 ====================
    println!("[*] 尝试通过 DNS 解析 {} 的新 IP...", domain);
    let new_ips = resolve_dns_ip(&domain);

    if new_ips.is_empty() {
        println!("[-] DNS 解析失败，无法降级。");
        return Ok(());
    }

    println!("[+] DNS 解析成功，获得 {} 个候选 IP", new_ips.len());

    for ip_candidate in new_ips {
        println!("[*] 正在尝试: {} -> {}", domain, ip_candidate);

        let (client, verifier) =
            match build_client_with_verifier(&domain, Some(&ip_candidate), &pin_str) {
                Ok(res) => res,
                Err(e) => {
                    println!("[-] 构建客户端失败: {}", e);
                    continue;
                }
            };

        let mut req = client.get(&url);
        if let Some(t) = &token {
            req = req.header("X-Probe-Token", t);
        }

        let resp = req.send().await;

        let captured = {
            match verifier.captured_data.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => None,
            }
        };

        if process_response(
            resp,
            captured,
            &domain,
            &ip_candidate,
            is_first_run,
            token.clone(),
        )
        .await?
        {
            return Ok(());
        }
    }

    println!("[-] 所有候选 IP 均连接失败。");
    Ok(())
}
