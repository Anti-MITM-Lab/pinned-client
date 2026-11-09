# pinned-client

对抗 TLS 中间人（MITM）的证书指纹探针。

- 首次运行用 **TOFU**（首次使用即信任）记录目标站点证书公钥（SPKI）的 SHA-256 指纹；
- 之后每次连接都只比对指纹，**不信任系统根证书**——换证书链、换 CA 都不影响判定，
  只有私钥变了才会不匹配，而这正是中间人必须付出的代价；
- 指纹不一致时以**退出码 2** 结束，并打印期望/实际指纹与实际签发者。

> 只应用于你自己拥有或已获授权的目标。

## 安装（Linux）

```bash
curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/pinned-client/main/install.sh \
  | sudo bash -s -- -d your.domain
```

脚本会安装到 `/usr/local/bin/pinned-client`，并写一份
`/etc/pinned-client/pinned-config.json`（指纹留空，等待首次运行固定）。

国内网络可加 `--mirror https://ghproxy.net/`。其他参数见 `install.sh --help`。

从源码构建：

```bash
cargo build --release
# 静态二进制
cargo build --release --target x86_64-unknown-linux-musl
```

## 快速开始

```bash
# 1. 首次运行：联网记录指纹（之后再改配置就要小心了）
pinned-client -d example.com
# [+] 首次运行：已记录证书指纹（TOFU 基线）

# 2. 日常检查：只做比对
pinned-client
# [+] 指纹匹配，链路正常

# 3. 带友军暗号，验证服务端确实放行
pinned-client -d example.com -t <暗号>
# [+] 友军暗号有效，服务端已放行

# 4. 给监控用
pinned-client --json
# {"status":"secure","domain":"example.com",...}
```

### 退出码

| 码 | 含义 |
|----|------|
| `0` | 正常（指纹匹配，或首次 TOFU 固定成功） |
| `2` | **检测到 MITM**（指纹不匹配） |
| `3` | 所有候选地址都不可达 |
| `4` | 用法或配置错误（缺域名、指纹非法等） |
| `5` | 证书剩余不足 7 天（仅 `--fail-on-expiry`） |

监控里最简单的用法就是：`pinned-client --json >/dev/null || alert`，退出码非 0 即异常。

## 工作原理

1. 解析目标地址：优先用配置/`--ip` 固定的地址，否则用 DoH（有代理走 Cloudflare，
   否则走阿里 DNS），失败再降级系统 DNS；
2. 用 rustls 建连，`resolve` 把域名强绑到候选 IP，SNI/Host 仍然是域名；
3. 自定义 `ServerCertVerifier` 解析证书，计算 `SHA-256(SPKI)` 并与配置比对；
4. 读一小段响应判断暗号是否被接受（服务端返回 `{"status":"authorized"}`）；
5. 输出结果并给出退出码；首次运行把指纹写回配置。

指纹是**公钥**的哈希，不是整张证书，所以续期换证书链不会误报——只有公钥变了才报。

## 配置

默认查找顺序：`--config` → 环境变量 `PINNED_CLIENT_CONFIG` → `./pinned-config.json`
→ `/etc/pinned-client/pinned-config.json`。

```json
{
  "domain": "example.com",
  "ip": "93.184.216.34:443",
  "pin": "F0KotjQ6ANwwX5/TNvxGT7tHmPlFHwdlgNItfhFPJ9g=",
  "expiry": 1797477178,
  "token": "你的暗号",
  "proxy": "http://127.0.0.1:10808"
}
```

| 字段 | 说明 |
|------|------|
| `domain` | 目标域名（SNI / Host），必填 |
| `ip` | 固定连接地址，可选；不填则每次 DoH 解析 |
| `pin` | Base64 的 `SHA-256(SPKI)`；空字符串表示尚未固定（TOFU） |
| `expiry` | 证书到期时间，仅用于提示 |
| `token` | 友军暗号，作为 `X-Probe-Token` 发送 |
| `proxy` | DoH 解析使用的代理（探测本身始终直连） |

## 常用参数

| 参数 | 说明 |
|------|------|
| `-d, --domain` | 目标域名 |
| `-i, --ip` | 固定地址（`1.2.3.4` 或 `1.2.3.4:443`） |
| `-p, --pin` | 临时指定指纹（覆盖配置，不写回） |
| `-t, --token` | 友军暗号 |
| `-x, --proxy` | DoH 代理 |
| `--json` | 输出单行 JSON |
| `--timeout` / `--retries` | 超时秒数 / 重试次数 |
| `--no-fallback` | 不做 DoH 降级 |
| `--accept-new-pin` | 确认换证后更新指纹 |
| `--fail-on-expiry` | 证书将过期时退出码 5 |
| `--check` | 只校验配置，不联网 |

## 输出示例

人类可读：

```
[+] 目标: example.com（93.184.216.34:443）
[+] TLS 握手成功，HTTP 200
[+] 指纹匹配，链路正常
[+] 证书签发者: CN=R11, O=Let's Encrypt
[+] 证书剩余有效期: 62 天
[+] 友军暗号有效，服务端已放行
```

检测到 MITM：

```
🚨 检测到中间人：证书指纹不匹配！
  目标: example.com（93.184.216.34:443）
  期望指纹: F0KotjQ6ANwwX5/TNvxGT7tHmPlFHwdlgNItfhFPJ9g=
  实际指纹: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  实际签发者: CN=Evil Proxy CA, O=Some Corp
  提示: 若确认是服务端正常换证，用 --accept-new-pin 更新指纹
```

JSON：

```json
{"status":"mitm","domain":"example.com","ip":"93.184.216.34:443","pin":"AAAA...","expected_pin":"F0Ko...","actual_pin":"AAAA...","issuer":"CN=Evil Proxy CA","subject":"CN=example.com","expires_in_days":12,"http_status":null,"token_ok":null,"warnings":[],"errors":[],"tried":[]}
```

## 代码结构

```
src/
├── main.rs       命令行编排、退出码
├── cli.rs        参数定义（clap）
├── config.rs     配置文件查找、读写、指纹校验
├── tls.rs        SPKI 校验器、HTTP 客户端
├── dns.rs        DoH / 系统 DNS
├── probe.rs      单次探测与结果模型
├── report.rs     文本 / JSON 输出
└── antidebug.rs  Windows 反调试
.github/workflows/
├── ci.yml        格式 / Clippy / 测试 + Windows 构建
└── release.yml   按版本号打 tag、多平台发布
```

## 发布流程

1. 改 `Cargo.toml` 的 `version`；
2. **在 [CHANGELOG.md](CHANGELOG.md) 新增同名 `## [x.y.z]` 段落**（缺了会发版失败）；
3. 推送到 `main`，工作流自动构建 Linux（x86_64/aarch64 musl）与 Windows 二进制、
   创建 `vX.Y.Z` 标签，并把 CHANGELOG 段落作为 Release 说明发布。

## 已知限制

- **TOFU 的信任窗口**：首次运行如果已经被劫持，固定下来的就是伪造指纹。常见做法是
  在一台可信网络里先跑一次，再把配置文件分发出去。
- 指纹绑定的是公钥：服务器正常换证（换私钥）也会告警，需要人工用 `--accept-new-pin` 确认。
- 反调试只覆盖 Windows 且只挡随手调试，不是强对抗；真正的安全边界仍是"私钥不在本地"。
- `--proxy` 只影响 DoH 解析，探测连接始终直连——这是有意为之，否则代理本身就是中间人。
