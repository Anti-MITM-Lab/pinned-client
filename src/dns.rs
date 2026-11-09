//! DNS 解析：优先 DoH，失败降级到系统 DNS。
//!
//! 用 DoH 的目的不是隐私，而是绕开本地可能被污染的 DNS——DNS 劫持常常是
//! 中间人的第一步。带 `--proxy` 时走 Cloudflare，否则走阿里 DNS（国内直连可用）。

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use reqwest::{Client, Proxy};
use serde_json::Value;

/// 探测目标固定用 443。
const DEFAULT_PORT: u16 = 443;
/// DoH 请求超时。
const DOH_TIMEOUT: Duration = Duration::from_secs(6);

const CLOUDFLARE_DOH: &str = "https://cloudflare-dns.com/dns-query?ct=application/dns-json";
const ALIDNS_DOH: &str = "https://dns.alidns.com/resolve";

/// 解析域名，返回去重后的候选地址（保持返回顺序）。
pub async fn resolve(domain: &str, proxy: Option<&str>, doh: Option<&str>) -> Vec<SocketAddr> {
    match resolve_via_doh(domain, proxy, doh).await {
        Ok(addresses) if !addresses.is_empty() => addresses,
        Ok(_) => {
            eprintln!("[!] DoH 未返回 A/AAAA 记录，降级到系统 DNS");
            resolve_system(domain)
        }
        Err(e) => {
            eprintln!("[!] DoH 解析失败（{e}），降级到系统 DNS");
            resolve_system(domain)
        }
    }
}

/// 通过 DoH 解析；失败返回可读错误。
async fn resolve_via_doh(
    domain: &str,
    proxy: Option<&str>,
    custom: Option<&str>,
) -> Result<Vec<SocketAddr>, String> {
    // 自定义地址优先；否则按"是否有代理"选择端点。
    let (url, bind_host, bind_ip) = match custom {
        Some(base) => (append_query(base, domain), None, None),
        None => match proxy {
            Some(_) => (
                append_query(CLOUDFLARE_DOH, domain),
                Some("cloudflare-dns.com"),
                Some("1.1.1.1:443"),
            ),
            None => (
                append_query(ALIDNS_DOH, domain),
                Some("dns.alidns.com"),
                Some("223.5.5.5:443"),
            ),
        },
    };

    let mut builder = Client::builder().timeout(DOH_TIMEOUT);
    if let Some(proxy_url) = proxy {
        let proxy = Proxy::all(proxy_url).map_err(|e| format!("代理地址无效: {e}"))?;
        builder = builder.proxy(proxy);
    }
    if let (Some(host), Some(address)) = (bind_host, bind_ip) {
        let address: SocketAddr = address
            .parse()
            .map_err(|e| format!("内置 DoH 地址无效: {e}"))?;
        builder = builder.resolve(host, address);
    }

    let client = builder
        .build()
        .map_err(|e| format!("构建 DoH 客户端失败: {e}"))?;
    let answer: Value = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DoH 请求失败: {e}"))?
        .json()
        .await
        .map_err(|e| format!("DoH 响应不是合法 JSON: {e}"))?;

    Ok(parse_doh_answers(&answer))
}

/// 给 DoH 地址补上 `name`/`type` 参数。
fn append_query(base: &str, domain: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}name={domain}&type=A")
}

/// 从 DoH JSON 响应里提取 A/AAAA 记录（纯函数，便于测试）。
pub fn parse_doh_answers(value: &Value) -> Vec<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = Vec::new();
    let Some(answers) = value["Answer"].as_array() else {
        return addresses;
    };

    for answer in answers {
        let record_type = answer["type"].as_u64().unwrap_or(0);
        if record_type != 1 && record_type != 28 {
            continue;
        }
        let Some(data) = answer["data"].as_str() else {
            continue;
        };
        if let Ok(ip) = data.parse::<IpAddr>() {
            let address = SocketAddr::new(ip, DEFAULT_PORT);
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    addresses
}

/// 系统 DNS 兜底。
fn resolve_system(domain: &str) -> Vec<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = Vec::new();
    if let Ok(resolved) = (domain, DEFAULT_PORT).to_socket_addrs() {
        for address in resolved {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 只取 A/AAAA，忽略 CNAME；重复地址去重。
    #[test]
    fn parses_a_and_aaaa_records() {
        let value = json!({
            "Answer": [
                {"type": 5, "data": "example.com."},
                {"type": 1, "data": "93.184.216.34"},
                {"type": 1, "data": "93.184.216.34"},
                {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"}
            ]
        });
        let addresses = parse_doh_answers(&value);
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].to_string(), "93.184.216.34:443");
        assert!(addresses[1].is_ipv6());
    }

    /// 没有 Answer 字段时返回空列表，不 panic。
    #[test]
    fn handles_missing_answers() {
        assert!(parse_doh_answers(&json!({"Status": 3})).is_empty());
        assert!(parse_doh_answers(&json!({"Answer": []})).is_empty());
    }

    /// 自定义 DoH 地址要正确拼接查询参数。
    #[test]
    fn appends_query_correctly() {
        assert_eq!(
            append_query("https://dns.example/resolve", "a.com"),
            "https://dns.example/resolve?name=a.com&type=A"
        );
        assert_eq!(
            append_query("https://dns.example/q?ct=json", "a.com"),
            "https://dns.example/q?ct=json&name=a.com&type=A"
        );
    }
}
