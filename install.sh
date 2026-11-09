#!/usr/bin/env bash
# pinned-client 安装脚本（Linux）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/pinned-client/main/install.sh | sudo bash -s -- -d example.com
#   sudo bash install.sh --domain example.com --token <暗号>
#   sudo bash install.sh --uninstall
#
# 说明：
#   * 二进制装到 /usr/local/bin/pinned-client，配置默认 /etc/pinned-client/pinned-config.json
#   * 客户端没有常驻服务：装好后手动跑一次完成 TOFU 指纹固定（会联网）
#   * 下载地址可用 --mirror 指定 GitHub 加速前缀
#
# 只应用于你自己拥有或已获授权的目标。

set -euo pipefail

REPO="${PINNED_CLIENT_REPO:-Anti-MITM-Lab/pinned-client}"
BIN_NAME="pinned-client"
PREFIX="/usr/local"
CONFIG_DIR="/etc/pinned-client"
CONFIG_PATH=""

VERSION="latest"
DOMAIN=""
TOKEN=""
PROXY=""
MIRROR=""
LOCAL_BINARY=""

WRITE_CONFIG=0
UNINSTALL=0
PURGE=0
DRY_RUN=0

if [ -t 1 ] && [ -t 2 ]; then
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_RESET=""
fi

log()  { printf '%s[+]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[-]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
pinned-client 安装脚本

用法：
  sudo bash install.sh [选项]

选项：
  -d, --domain <域名>   写入初始配置（指纹留空，首次运行联网固定）
      --token <暗号>    友军暗号，写入配置
  -x, --proxy <URL>     DoH 代理，写入配置
      --config <路径>   配置文件路径，默认 /etc/pinned-client/pinned-config.json
      --version <ver>   安装指定版本（如 0.7.0），默认 latest
      --prefix <dir>    安装前缀，默认 /usr/local
      --mirror <url>    GitHub 下载加速前缀，如 https://ghproxy.net/
      --binary <path>   使用本地已编译好的二进制（离线安装）
      --uninstall       卸载二进制
      --purge           与 --uninstall 一起用：同时删除配置目录
      --dry-run         只打印动作
  -h, --help            显示帮助

安装后（首次运行会记录指纹，需要联网）：
  sudo pinned-client --config /etc/pinned-client/pinned-config.json
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d|--domain)   DOMAIN="${2:?--domain 需要一个值}"; WRITE_CONFIG=1; shift 2 ;;
            --domain=*)    DOMAIN="${1#*=}"; WRITE_CONFIG=1; shift ;;
            --token)       TOKEN="${2:?--token 需要一个值}"; shift 2 ;;
            --token=*)     TOKEN="${1#*=}"; shift ;;
            -x|--proxy)    PROXY="${2:?--proxy 需要一个值}"; shift 2 ;;
            --proxy=*)     PROXY="${1#*=}"; shift ;;
            --config)      CONFIG_PATH="${2:?--config 需要一个值}"; shift 2 ;;
            --config=*)    CONFIG_PATH="${1#*=}"; shift ;;
            --version)     VERSION="${2:?--version 需要一个值}"; shift 2 ;;
            --version=*)   VERSION="${1#*=}"; shift ;;
            --prefix)      PREFIX="${2:?--prefix 需要一个值}"; shift 2 ;;
            --prefix=*)    PREFIX="${1#*=}"; shift ;;
            --mirror)      MIRROR="${2:?--mirror 需要一个值}"; shift 2 ;;
            --mirror=*)    MIRROR="${1#*=}"; shift ;;
            --binary)      LOCAL_BINARY="${2:?--binary 需要一个值}"; shift 2 ;;
            --binary=*)    LOCAL_BINARY="${1#*=}"; shift ;;
            --uninstall)   UNINSTALL=1; shift ;;
            --purge)       PURGE=1; shift ;;
            --dry-run)     DRY_RUN=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             die "未知参数: $1（用 --help 查看用法）" ;;
        esac
    done
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "需要 root 权限，请用 sudo 运行"
}

fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "需要 curl 或 wget"
    fi
}

fetch_stdout() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 "$1"
    else
        wget -qO- "$1"
    fi
}

detect_target() {
    case "$(uname -m)" in
        x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
        *) die "暂不支持该架构: $(uname -m)（可自行编译后用 --binary 安装）" ;;
    esac
}

resolve_tag() {
    if [ "$VERSION" = "latest" ]; then
        log "查询最新版本……" >&2
        local json tag
        json="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" \
            || die "查询最新版本失败；请用 --version 指定版本"
        tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1 || true)"
        [ -n "$tag" ] || die "无法解析最新版本，请用 --version 指定"
        TAG="$tag"
    else
        case "$VERSION" in
            v*) TAG="$VERSION" ;;
            *)  TAG="v$VERSION" ;;
        esac
    fi
}

install_binary() {
    local tmpdir
    mkdir -p "$PREFIX/bin"

    if [ -n "$LOCAL_BINARY" ]; then
        [ -f "$LOCAL_BINARY" ] || die "本地二进制不存在: $LOCAL_BINARY"
        log "使用本地二进制: $LOCAL_BINARY"
        run install -m 0755 "$LOCAL_BINARY" "$PREFIX/bin/${BIN_NAME}"
        return 0
    fi

    local asset="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
    local url="${MIRROR}https://github.com/${REPO}/releases/download/${TAG}/${asset}"
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" EXIT

    log "下载 ${asset}"
    if [ -z "$MIRROR" ]; then
        log "提示：下载慢可 Ctrl-C 后加 --mirror https://ghproxy.net/ 重试"
    fi
    fetch "$url" "$tmpdir/$asset"

    if fetch "$url.sha256" "$tmpdir/$asset.sha256" 2>/dev/null; then
        if command -v sha256sum >/dev/null 2>&1; then
            log "校验 SHA-256"
            ( cd "$tmpdir" && sha256sum -c "$asset.sha256" ) || die "校验失败，下载内容可能被篡改"
        else
            warn "缺少 sha256sum，跳过校验"
        fi
    else
        warn "未找到校验文件，跳过校验"
    fi

    tar -xzf "$tmpdir/$asset" -C "$tmpdir" || die "解压失败: $asset"
    [ -f "$tmpdir/$BIN_NAME" ] || die "压缩包内未找到 $BIN_NAME"
    run install -m 0755 "$tmpdir/$BIN_NAME" "$PREFIX/bin/${BIN_NAME}"
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] $*"
    else
        "$@"
    fi
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

write_config() {
    [ "$WRITE_CONFIG" -eq 1 ] || return 0
    [ -n "$DOMAIN" ] || die "写入配置需要 --domain"

    local dir
    dir="$(dirname "$CONFIG_PATH")"
    run install -d -m 0755 "$dir"

    log "写入配置: ${CONFIG_PATH}（domain=${DOMAIN}，指纹留空待首次固定）"
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi

    local token_field='null' proxy_field='null'
    [ -n "$TOKEN" ] && token_field="\"$(json_escape "$TOKEN")\""
    [ -n "$PROXY" ] && proxy_field="\"$(json_escape "$PROXY")\""

    cat > "$CONFIG_PATH" <<EOF
{
  "domain": "$(json_escape "$DOMAIN")",
  "pin": "",
  "token": ${token_field},
  "proxy": ${proxy_field}
}
EOF
    chmod 0600 "$CONFIG_PATH"
}

check_config() {
    [ "$WRITE_CONFIG" -eq 1 ] || return 0
    [ "$DRY_RUN" -eq 1 ] && return 0
    if "$PREFIX/bin/${BIN_NAME}" --check --config "$CONFIG_PATH" >/dev/null 2>&1; then
        log "配置自检通过"
    else
        warn "配置自检失败，请手动执行: ${PREFIX}/bin/${BIN_NAME} --check --config ${CONFIG_PATH}"
    fi
}

do_uninstall() {
    log "开始卸载 ${BIN_NAME}"
    run rm -f "$PREFIX/bin/${BIN_NAME}"
    if [ "$PURGE" -eq 1 ]; then
        warn "删除配置目录 ${CONFIG_DIR}"
        run rm -rf "$CONFIG_DIR"
    else
        log "已保留配置目录 ${CONFIG_DIR}（彻底删除加 --purge）"
    fi
    log "卸载完成"
}

print_summary() {
    cat <<EOF

${C_BOLD}安装完成${C_RESET}
  版本     ${TAG}
  二进制   ${PREFIX}/bin/${BIN_NAME}
  配置     ${CONFIG_PATH}

首次运行（联网固定指纹，之后每次只做比对）：
  sudo ${PREFIX}/bin/${BIN_NAME} --config ${CONFIG_PATH}

日常检查：
  ${PREFIX}/bin/${BIN_NAME} --config ${CONFIG_PATH} --json     # 退出码 0 正常 / 2 检测到 MITM
  ${PREFIX}/bin/${BIN_NAME} --config ${CONFIG_PATH} --check    # 只校验配置

提示：
  * 如需用非 root 用户运行，请先 chown 该用户 ${CONFIG_PATH}
  * 指纹变化且确认是服务端正常换证时，用 --accept-new-pin 更新
  * 更新日志：https://github.com/${REPO}/releases
EOF
}

main() {
    parse_args "$@"
    require_root
    MIRROR="${MIRROR%/}"
    [ -z "$MIRROR" ] || MIRROR="${MIRROR}/"

    [ -z "$CONFIG_PATH" ] && CONFIG_PATH="${CONFIG_DIR}/pinned-config.json"

    if [ "$UNINSTALL" -eq 1 ]; then
        do_uninstall
        exit 0
    fi

    case "$(uname -s)" in
        Linux) : ;;
        *) warn "当前系统不是 Linux（$(uname -s)），可能无法运行" ;;
    esac

    detect_target
    if [ -n "$LOCAL_BINARY" ]; then
        TAG="${VERSION}"
        case "$TAG" in latest|v*) : ;; *) TAG="v${TAG}" ;; esac
    else
        resolve_tag
    fi
    log "目标平台 ${TARGET}，版本 ${TAG}"

    install_binary
    write_config
    check_config
    print_summary
}

main "$@"
