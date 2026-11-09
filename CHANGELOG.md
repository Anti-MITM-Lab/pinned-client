# 更新日志

本项目所有值得注意的变更都记录在这里。格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

> **发版规则**：修改 `Cargo.toml` 的版本号时，必须同时在本文件新增对应的
> `## [x.y.z]` 段落。Release 工作流会用它生成 GitHub Release 的说明；
> 缺少该段落会导致发版直接失败。行为变化（尤其退出码、配置字段）请写清楚。

## [Unreleased]

## [0.8.0] - 2026-11-09

### 变更

- 依赖升级到当前最新版本（`cargo update` 刷新整份 Cargo.lock）：
  - `reqwest` 0.12 → 0.13.5：TLS feature 由 `rustls-tls` 改为 `rustls`；
    `tls_built_in_root_certs()` 在 0.13 中已移除（本来也无意义——我们传入的是
    完全自定义的 TLS 配置），相应调用一并删除。
  - `sha2` 0.10 → 0.11.1
  - `x509-parser` 0.16 → 0.18.1
  - `base64` 0.22 → 0.23.1
  - `rustls` 0.23 → 0.23.46、`tokio` 1 → 1.54.1、`windows` 0.62 → 0.62.2
- 无行为变化：配置文件字段、命令行参数、退出码全部保持不变，可直接覆盖升级。

### 验证

- 指纹定义仍为 `Base64(SHA-256(SPKI))`：用 openssl 独立计算同一张证书的指纹，
  与客户端输出的 `pin` 完全一致，确保升级后既有指纹基线继续有效。
- 11 个单元测试 + 12 项端到端冒烟（TOFU / secure / 暗号有效与无效 /
  篡改指纹退出码 2 / `--accept-new-pin` / 不可达退出码 3 / `--check`）全部通过。

## [0.7.0] - 2026-11-09

### 新增

- `--json`：向 stdout 输出单行 JSON（`status` / `pin` / `issuer` / `http_status` /
  `token_ok` / `expires_in_days` / `warnings` 等），便于监控与告警系统解析。
- `--check`：只校验配置、指纹格式与地址，不发起任何网络请求；适合装完先自检。
- `--config <path>` + 环境变量 `PINNED_CLIENT_CONFIG`，并支持默认查找
  `/etc/pinned-client/pinned-config.json`。
- `--timeout` / `--retries`：连接超时与传输层重试，避免探测卡死。
- `--doh <url>`：自定义 DoH 解析地址；`--no-fallback`：只连固定地址，不做 DNS 降级。
- `--accept-new-pin`：确认是服务端正常换证后，把新指纹写回配置（默认只告警）。
- `--fail-on-expiry`：证书剩余不足 7 天时以退出码 5 结束。
- 暗号有效性判定：读取响应前 4 KiB，检查服务端是否返回
  `{"status":"authorized"}`，结果写入 `token_ok`。
- 证书信息展示：签发者、主体、剩余有效期；MITM 时输出实际签发者可快速定位劫持方。
- Linux 安装脚本 `install.sh`：下载 musl 静态二进制、校验 SHA-256、写入初始配置并自检。
- GitHub Actions：`CI`（Linux 格式/Clippy/测试 + Windows 构建）与 `Release`
  （按版本号打 tag、发布 Linux x86_64/aarch64 与 Windows 二进制、用 CHANGELOG 生成说明）。

### 修复

- **MITM 被静默忽略（严重）**：指纹不匹配时 `process_response` 返回 `Ok(true)`，
  进程退出码仍是 `0`；且原实现用字符串包含 `"Certificate pin mismatch"` 判断，
  与实际错误文案不符，该分支永远不会命中。现在由校验器记录 `mismatch`，
  无论请求成功与否都判定，并以退出码 `2` 结束。
- IPv6 解析结果被拼成 `::1:443` 这类非法地址；改为直接构造 `SocketAddr`。
- 请求没有超时，目标不响应时会一直挂着；现在有 `--timeout` 与连接超时。
- 缺少域名/配置时返回 `Ok(())`（退出码 0），脚本无法区分「没探测」和「探测正常」；
  现在统一以退出码 `4` 表示用法或配置错误。
- 跟随重定向可能被带到其他域名，从而用错指纹产生误报；现在禁用重定向。
- `windows` 依赖未做平台隔离，Linux 构建也会拉入该 crate；改为
  `[target.'cfg(windows)'.dependencies]`。
- TOFU 写配置时未创建父目录、未限制权限；现在自动建目录并设为 `0600`。

### 变更

- `src/main.rs` 拆分为 `cli` / `config` / `tls` / `dns` / `probe` / `report` /
  `antidebug` 七个模块，补齐模块级注释，统一 `cargo fmt` 与 Clippy 干净。
- 输出统一由 `report::Report` 生成，人类可读与 JSON 走同一份数据。
- 探测客户端强制直连（`no_proxy`）且只允许 HTTPS，代理参数只用于 DoH 解析。
- 版本号升至 0.7.0。
