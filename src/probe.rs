//! 单次探测：连上目标、抓证书、比对指纹、读一小段响应。
//!
//! 判定不依赖错误字符串：校验器把 `mismatch()` 记下来，无论请求成功还是失败，
//! 只要出现过指纹不一致就返回 [`ProbeOutcome::Mitm`]。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;

use crate::tls::{self, CertInfo, PinnedVerifier};

/// 响应正文最多读多少字节用于判断暗号是否被接受。
const PREVIEW_BYTES: usize = 4096;
/// 友军放行时服务端返回的标记。
const AUTHORIZED_MARKER: &[u8] = b"\"status\":\"authorized\"";

/// 一次探测的输入。
pub struct ProbePlan {
    pub domain: String,
    pub target: SocketAddr,
    /// 期望指纹（Base64）；空串表示 TOFU。
    pub pin: String,
    pub token: Option<String>,
    pub timeout: Duration,
    pub retries: u32,
}

/// 一次探测的结果。
#[derive(Debug)]
pub enum ProbeOutcome {
    /// 指纹匹配，链路正常。
    Secure {
        cert: CertInfo,
        status: u16,
        token_ok: Option<bool>,
    },
    /// 首次运行：以本次观测到的指纹作为基线（TOFU）。
    Tofu {
        cert: CertInfo,
        status: u16,
        token_ok: Option<bool>,
    },
    /// 指纹不匹配：判定链路被中间人劫持。
    Mitm {
        expected: String,
        actual: String,
        cert: Option<CertInfo>,
    },
    /// 传输层失败（连接、TLS 握手、读响应等）。
    Failed { error: String },
}

impl ProbeOutcome {
    /// 取出证书信息（如果有）。
    pub fn cert(&self) -> Option<&CertInfo> {
        match self {
            ProbeOutcome::Secure { cert, .. } | ProbeOutcome::Tofu { cert, .. } => Some(cert),
            ProbeOutcome::Mitm { cert, .. } => cert.as_ref(),
            ProbeOutcome::Failed { .. } => None,
        }
    }
}

/// 执行一次探测（内部按 `retries` 重试传输层错误）。
pub async fn probe(plan: &ProbePlan) -> ProbeOutcome {
    let verifier = match PinnedVerifier::new(&plan.pin) {
        Ok(verifier) => Arc::new(verifier),
        Err(error) => return ProbeOutcome::Failed { error },
    };
    let url = format!("https://{}/", plan.domain);
    let mut last_error = String::new();

    for attempt in 0..=plan.retries {
        let client = match tls::build_client(
            &plan.domain,
            plan.target,
            Arc::clone(&verifier),
            plan.timeout,
        ) {
            Ok(client) => client,
            Err(error) => return ProbeOutcome::Failed { error },
        };

        let mut request = client.get(&url).timeout(plan.timeout);
        if let Some(token) = &plan.token {
            request = request.header("X-Probe-Token", token);
        }

        match request.send().await {
            Ok(response) => {
                // 指纹不一致时 reqwest 一般会报错；但即便拿到响应也要先检查，
                // 避免某些 TLS 实现继续把数据交给上层。
                if let Some((expected, actual)) = verifier.mismatch() {
                    return ProbeOutcome::Mitm {
                        expected,
                        actual,
                        cert: verifier.captured(),
                    };
                }

                let status = response.status().as_u16();
                let preview = read_preview(response).await;
                let token_ok = plan.token.as_ref().map(|_| {
                    preview
                        .windows(AUTHORIZED_MARKER.len())
                        .any(|window| window == AUTHORIZED_MARKER)
                });

                return match verifier.captured() {
                    Some(cert) if plan.pin.trim().is_empty() => ProbeOutcome::Tofu {
                        cert,
                        status,
                        token_ok,
                    },
                    Some(cert) => ProbeOutcome::Secure {
                        cert,
                        status,
                        token_ok,
                    },
                    None => ProbeOutcome::Failed {
                        error: "请求成功但没有拿到服务端证书".to_string(),
                    },
                };
            }
            Err(error) => {
                if let Some((expected, actual)) = verifier.mismatch() {
                    return ProbeOutcome::Mitm {
                        expected,
                        actual,
                        cert: verifier.captured(),
                    };
                }
                last_error = describe_error(&error);
                if attempt < plan.retries {
                    let backoff = 300 * (u64::from(attempt) + 1);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    ProbeOutcome::Failed { error: last_error }
}

/// 读一小段正文，用于判断暗号是否被服务端接受。
async fn read_preview(response: reqwest::Response) -> Vec<u8> {
    let mut preview = Vec::with_capacity(PREVIEW_BYTES);
    let mut stream = response.bytes_stream();
    while preview.len() < PREVIEW_BYTES {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let take = (PREVIEW_BYTES - preview.len()).min(chunk.len());
                preview.extend_from_slice(&chunk[..take]);
            }
            _ => break,
        }
    }
    preview
}

/// 把 reqwest 错误转成一句人话。
fn describe_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "连接或 TLS 握手超时".to_string()
    } else if error.is_connect() {
        format!("无法建立连接: {error}")
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有服务端返回了友军 JSON 才判定暗号有效。
    #[test]
    fn detects_authorized_marker() {
        let body = br#"{"status":"authorized","probe":"mitm-test-server"}"#;
        assert!(body
            .windows(AUTHORIZED_MARKER.len())
            .any(|window| window == AUTHORIZED_MARKER));

        let poison = b"<!DOCTYPE html><html>...";
        assert!(!poison
            .windows(AUTHORIZED_MARKER.len())
            .any(|window| window == AUTHORIZED_MARKER));
    }

    /// 标记跨两个数据块时也应能识别（用拼接后的正文模拟）。
    #[test]
    fn detects_marker_across_chunks() {
        let mut body = Vec::new();
        body.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
        body.extend_from_slice(br#"{"status":"auth"#);
        body.extend_from_slice(br#"orized"}"#);
        assert!(body
            .windows(AUTHORIZED_MARKER.len())
            .any(|window| window == AUTHORIZED_MARKER));
    }
}
