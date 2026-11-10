#!/usr/bin/env bash
# 开发模式：同时拉起后端（cargo run，127.0.0.1:8787）和前端（Vite，127.0.0.1:5173）。
#
# 用法：
#   scripts/dev.sh                      # 额外参数会原样传给 quark-server
#   QUARK_TOKEN=xxx scripts/dev.sh      # 环境变量会透传给后端
#   WEB_PORT=5174 scripts/dev.sh        # 换前端端口（vite 仍代理到 8787）
#
# 访问 http://127.0.0.1:5173 。前端改动热更新；后端改动需重启本脚本（Ctrl-C 结束）。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"
LOG_DIR="$ROOT_DIR/.dev-logs"
BACKEND_ADDR="127.0.0.1:8787"
FRONTEND_PORT="${WEB_PORT:-5173}"
DATA_DIR="${QUARK_DATA_DIR:-$ROOT_DIR/data}"
DOWNLOAD_ROOT="${QUARK_DOWNLOAD_ROOT:-$ROOT_DIR/downloads}"

log() { printf '[dev] %s\n' "$*"; }
die() { printf '[dev] 错误: %s\n' "$*" >&2; exit 1; }

# --- 依赖检查 ---------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || die "未找到 cargo，请先安装 Rust 工具链（https://rustup.rs）"
command -v npm >/dev/null 2>&1 || die "未找到 npm，请先安装 Node.js 18+"

mkdir -p "$LOG_DIR" "$DATA_DIR" "$DOWNLOAD_ROOT"

# 前端依赖：缺 node_modules 时自动安装
if [ ! -d "$WEB_DIR/node_modules" ]; then
  log "未检测到 web/node_modules，开始安装前端依赖..."
  if [ -f "$WEB_DIR/package-lock.json" ]; then
    npm --prefix "$WEB_DIR" ci
  else
    npm --prefix "$WEB_DIR" install
  fi
fi

# --- 进程管理 ---------------------------------------------------------------
PIDS=()
SHUTTING_DOWN=0

cleanup() {
  trap - EXIT INT TERM
  SHUTTING_DOWN=1
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -TERM -"$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -KILL -"$pid" 2>/dev/null || true
  done
  log "前后端进程已停止"
}
trap cleanup EXIT INT TERM

# 每行加前缀输出，同时落一份到 .dev-logs/
prefix() {
  local tag="$1" file="$2"
  stdbuf -oL -eL sed -u "s/^/[$tag] /" | stdbuf -oL -eL tee -a "$file"
}

# --- 后端 -------------------------------------------------------------------
backend_cmd=(cargo run -p quark-server -- \
  --listen "$BACKEND_ADDR" \
  --data-dir "$DATA_DIR" \
  --download-root "$DOWNLOAD_ROOT")
backend_cmd+=("$@")

log "启动后端：${backend_cmd[*]}"
(
  cd "$ROOT_DIR"
  exec setsid "${backend_cmd[@]}"
) > >(prefix "后端" "$LOG_DIR/backend.log") 2>&1 &
PIDS+=("$!")

# --- 前端 -------------------------------------------------------------------
log "启动前端：vite dev --port $FRONTEND_PORT"
(
  cd "$WEB_DIR"
  exec setsid npm run dev -- --port "$FRONTEND_PORT" --strictPort
) > >(prefix "前端" "$LOG_DIR/frontend.log") 2>&1 &
PIDS+=("$!")

# --- 等待后端就绪（首次编译可能较慢） ---------------------------------------
if command -v curl >/dev/null 2>&1; then
  log "等待后端就绪（首次编译最长约 3 分钟）..."
  for _ in $(seq 1 180); do
    if curl -fsS "http://$BACKEND_ADDR/api/health" >/dev/null 2>&1; then
      log "后端已就绪"
      break
    fi
    sleep 1
  done
fi

cat <<EOF

  前端（开发入口）: http://127.0.0.1:${FRONTEND_PORT}
  后端（API）     : http://${BACKEND_ADDR}
  数据目录        : ${DATA_DIR}
  下载目录        : ${DOWNLOAD_ROOT}
  日志            : ${LOG_DIR}/backend.log ${LOG_DIR}/frontend.log

  按 Ctrl-C 同时停止前后端。

EOF

# 任一进程退出即整体退出
if ! wait -n ${PIDS[@]+"${PIDS[@]}"}; then
  [ "$SHUTTING_DOWN" = "1" ] || log "有进程异常退出，正在停止其余进程"
fi
