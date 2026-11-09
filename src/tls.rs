//! TLS 层：SPKI 指纹校验器与 HTTP 客户端构建。
//!
//! 这里不信任任何系统根证书，而是直接比对服务端证书公钥（SPKI）的 SHA-256。
//! 好处是换证书链、换 CA 都不影响判定，只有私钥变了才会不匹配；这正好是
//! 中间人要拦你的流量时必须付出的代价。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// 抓到的服务端证书信息，用于输出与 TOFU 落盘。
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Base64(SHA-256(SPKI))，与配置文件里的 `pin` 同格式。
    pub pin_b64: String,
    /// 签发者 DN，例如 `CN=Let's Encrypt R3`。
    pub issuer: String,
    /// 主体 DN。
    pub subject: String,
    /// 到期时间（Unix 秒）。
    pub not_after: u64,
}

/// 自定义证书校验器：只认 SPKI 指纹。
pub struct PinnedVerifier {
    expected: Vec<u8>,
    expected_b64: String,
    provider: Arc<CryptoProvider>,
    captured: Mutex<Option<CertInfo>>,
    mismatch: Mutex<Option<(String, String)>>,
}

impl std::fmt::Debug for PinnedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedVerifier")
            .field("expected", &self.expected_b64)
            .finish_non_exhaustive()
    }
}

impl PinnedVerifier {
    /// 创建校验器；`pin_b64` 为空表示 TOFU（只记录不校验）。
    pub fn new(pin_b64: &str) -> Result<Self, String> {
        let expected = crate::config::PinnedConfig::decode_pin(pin_b64)?;
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| "rustls 加密后端未初始化".to_string())?;
        Ok(Self {
            expected,
            expected_b64: pin_b64.trim().to_string(),
            provider,
            captured: Mutex::new(None),
            mismatch: Mutex::new(None),
        })
    }

    /// 供构建 TLS 配置时复用同一个加密后端。
    pub fn provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }

    /// 握手过程中抓到的（最近一次）证书信息。
    pub fn captured(&self) -> Option<CertInfo> {
        self.captured.lock().ok().and_then(|guard| guard.clone())
    }

    /// 若发生过指纹不匹配，返回（期望, 实际）。
    pub fn mismatch(&self) -> Option<(String, String)> {
        self.mismatch.lock().ok().and_then(|guard| guard.clone())
    }

    /// 解析 DER 证书并计算 SPKI 指纹。
    fn parse_cert(cert_der: &[u8]) -> Result<CertInfo, Error> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| Error::General(format!("X509 解析失败: {e}")))?;

        let spki = cert.tbs_certificate.subject_pki.raw;
        let digest = Sha256::digest(spki);
        let pin_b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        Ok(CertInfo {
            pin_b64,
            issuer: cert.issuer().to_string(),
            subject: cert.subject().to_string(),
            not_after: cert.tbs_certificate.validity.not_after.timestamp() as u64,
        })
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
        let info = Self::parse_cert(end_entity.as_ref())?;
        let actual = info.pin_b64.clone();

        // 不管校验结果如何都记录，方便调用方在读不到响应时也能给出诊断信息。
        if let Ok(mut guard) = self.captured.lock() {
            *guard = Some(info);
        }

        if self.expected.is_empty() {
            // TOFU：第一次见到的指纹就是基线。
            return Ok(ServerCertVerified::assertion());
        }

        if actual == self.expected_b64 {
            return Ok(ServerCertVerified::assertion());
        }

        if let Ok(mut guard) = self.mismatch.lock() {
            *guard = Some((self.expected_b64.clone(), actual.clone()));
        }
        // 这里的错误文案不会被用户直接看到（reqwest 会包一层），
        // 真正的判定走 `mismatch()`，避免依赖字符串匹配。
        Err(Error::General(format!(
            "certificate pin mismatch: expected {}, got {actual}",
            self.expected_b64
        )))
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构建只连指定地址的探测客户端。
///
/// * `no_proxy`：绕过系统代理，保证直连目标（中间人正是要躲开的东西）；
/// * `https_only` + 不跟随重定向：避免被 302 带去别的域名，用错指纹误判；
/// * `resolve`：把域名强绑到候选地址，TLS 仍然用域名做 SNI/Host。
pub fn build_client(
    domain: &str,
    target: SocketAddr,
    verifier: Arc<PinnedVerifier>,
    timeout: Duration,
) -> Result<Client, String> {
    let tls_config = rustls::ClientConfig::builder_with_provider(verifier.provider().clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("构建 TLS 配置失败: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Client::builder()
        .use_preconfigured_tls(tls_config)
        .tls_built_in_root_certs(false)
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(concat!("pinned-client/", env!("CARGO_PKG_VERSION")))
        .resolve(domain, target)
        .build()
        .map_err(|e| format!("构建 HTTP 客户端失败: {e}"))
}
