#!/usr/bin/env bash
# 生产模式：构建前端与 release 后端，然后前台运行单个二进制（默认 127.0.0.1:8787）。
#
# 用法：
#   scripts/start.sh                        # 构建并启动
#   SKIP_BUILD=1 scripts/start.sh           # 跳过构建，直接启动已有二进制
#   QUARK_TOKEN=xxx scripts/start.sh        # 其余配置走环境变量或追加参数
#
# 前端资源会编译进二进制，启动后直接访问 http://127.0.0.1:8787 。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"
BIN="$ROOT_DIR/target/release/quark-server"

log() { printf '[start] %s\n' "$*"; }
die() { printf '[start] 错误: %s\n' "$*" >&2; exit 1; }

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || die "未找到 cargo，请先安装 Rust 工具链（https://rustup.rs）"
command -v npm >/dev/null 2>&1 || die "未找到 npm，请先安装 Node.js 18+"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  if [ ! -d "$WEB_DIR/node_modules" ]; then
    log "安装前端依赖..."
    if [ -f "$WEB_DIR/package-lock.json" ]; then
      npm --prefix "$WEB_DIR" ci
    else
      npm --prefix "$WEB_DIR" install
    fi
  fi

  log "构建前端..."
  npm --prefix "$WEB_DIR" run build

  log "构建后端（web/dist 会被嵌入二进制）..."
  cargo build --release -p quark-server
fi

[ -x "$BIN" ] || die "未找到 $BIN，请去掉 SKIP_BUILD=1 重新构建"

log "启动 $BIN"
exec "$BIN" \
  --listen "${QUARK_LISTEN:-127.0.0.1:8787}" \
  --data-dir "${QUARK_DATA_DIR:-$ROOT_DIR/data}" \
  --download-root "${QUARK_DOWNLOAD_ROOT:-$ROOT_DIR/downloads}" \
  "$@"
