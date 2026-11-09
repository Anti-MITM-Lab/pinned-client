//! `pinned-config.json` 的查找、读写与校验。
//!
//! 查找顺序（先命中先用）：
//!
//! 1. `--config` 显式指定；
//! 2. 环境变量 `PINNED_CLIENT_CONFIG`；
//! 3. 当前目录的 `pinned-config.json`；
//! 4. `/etc/pinned-client/pinned-config.json`（安装脚本的默认位置）；
//! 5. 都找不到时回到当前目录（首次运行会创建）。

use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};

/// 默认配置文件名。
pub const CONFIG_FILE: &str = "pinned-config.json";
/// 系统级配置路径（安装脚本使用）。
pub const SYSTEM_CONFIG: &str = "/etc/pinned-client/pinned-config.json";
/// 指定配置路径的环境变量。
pub const ENV_CONFIG: &str = "PINNED_CLIENT_CONFIG";
/// SPKI 指纹长度：SHA-256 输出 32 字节。
const PIN_BYTES: usize = 32;

/// 持久化配置。
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PinnedConfig {
    /// 目标域名（也是 TLS SNI / Host）。
    pub domain: String,
    /// 固定连接的目标地址（可选；不填则每次走 DoH 解析）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Base64 编码的 SPKI SHA-256；空字符串表示尚未固定（TOFU）。
    #[serde(default)]
    pub pin: String,
    /// 证书到期时间（Unix 秒），仅用于提醒。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// 友军暗号（可选）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// DoH 解析使用的代理（可选）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

impl PinnedConfig {
    /// 按约定顺序挑选配置文件路径。
    pub fn resolve_path(explicit: Option<PathBuf>) -> PathBuf {
        if let Some(path) = explicit {
            return path;
        }
        if let Ok(from_env) = std::env::var(ENV_CONFIG) {
            if !from_env.trim().is_empty() {
                return PathBuf::from(from_env);
            }
        }

        let local = PathBuf::from(CONFIG_FILE);
        if local.exists() {
            return local;
        }
        let system = PathBuf::from(SYSTEM_CONFIG);
        if system.exists() {
            return system;
        }
        local
    }

    /// 读取配置；文件不存在返回 `Ok(None)`，内容损坏返回错误。
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("读取 {} 失败: {e}", path.display())),
        };
        let config: Self = serde_json::from_str(&text)
            .map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
        Ok(Some(config))
    }

    /// 写回配置（自动创建父目录，权限收紧到 0600）。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("创建目录 {} 失败: {e}", parent.display()))?;
            }
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("序列化配置失败: {e}"))?;
        std::fs::write(path, format!("{json}\n"))
            .map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;

        // 配置里可能有暗号，尽量收紧权限（Windows 上 chmod 无意义，忽略失败）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// 解码并校验指纹：空串表示未固定；否则必须是 32 字节的 Base64。
    pub fn decode_pin(pin: &str) -> Result<Vec<u8>, String> {
        let pin = pin.trim();
        if pin.is_empty() {
            return Ok(Vec::new());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(pin)
            .map_err(|e| format!("指纹不是合法的 Base64: {e}"))?;
        if bytes.len() != PIN_BYTES {
            return Err(format!(
                "指纹长度应为 {PIN_BYTES} 字节（SHA-256），实际 {} 字节",
                bytes.len()
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 字节随机值的 Base64 应当被接受，空串表示 TOFU。
    #[test]
    fn accepts_valid_pins() {
        let valid = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(PinnedConfig::decode_pin(&valid).unwrap().len(), 32);
        assert!(PinnedConfig::decode_pin("").unwrap().is_empty());
    }

    /// 非 Base64、长度不对的指纹都必须被拒绝。
    #[test]
    fn rejects_bad_pins() {
        assert!(PinnedConfig::decode_pin("not-base64!!").is_err());
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(PinnedConfig::decode_pin(&short).is_err());
    }

    /// 旧版配置文件必须仍然能解析（字段缺省）。
    #[test]
    fn parses_legacy_config() {
        let json = r#"{"domain":"example.com","ip":"1.2.3.4:443","pin":"AAA="}"#;
        let config: PinnedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.domain, "example.com");
        assert_eq!(config.ip.as_deref(), Some("1.2.3.4:443"));
        assert!(config.token.is_none());
    }
}
