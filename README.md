# Quark Drive Server

把夸克网盘内容下载到无界面 Linux 服务器的轻量应用。单个 Rust 二进制同时提供 HTTP API 和浏览器 UI，适合通过 SSH 端口转发或 VS Code Remote 访问。

从 [agnes-agent](https://github.com/Gongcai/agnes-agent) 中抽离夸克 Provider 而来，本仓库只保留夸克网盘相关能力。

## 功能

- Cookie 粘贴登录、二维码登录、官方授权码/授权页登录
- 浏览目录、搜索文件、查看配额
- 单文件下载、文件夹递归下载
- 任务排队、进度展示、取消、失败重试
- 断点续传：重启服务或网络中断后从 `.part` 文件继续
- 加密凭证库：ChaCha20-Poly1305 + 本地 `master.key`（0600）或 `QUARK_VAULT_KEY`
- 默认仅监听 `127.0.0.1`；非回环地址强制要求 Bearer Token
- 前端资源编译进二进制，部署时只需要一个可执行文件

## 重要限制

夸克官方 Open API **不支持目录浏览**，只支持搜索、下载等能力。

因此：

- **Cookie 登录**：支持浏览、搜索、单文件下载、文件夹下载。
- **二维码登录**：本质上也是获取 Cookie，能力同上。
- **官方授权**：支持搜索和单文件下载；如需浏览目录或下载整个文件夹，请在账户卡片里补充一次 Cookie，服务端会把官方凭证和 Cookie 合并保存。

## 架构

```text
.
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── quark-core/             # 从 agnes-agent 抽离的夸克 Provider（无 Tauri 依赖）
│   │   └── src/
│   │       ├── domain.rs
│   │       ├── ports.rs
│   │       ├── quark_drive.rs             # Cookie / 二维码 / 浏览 / 下载
│   │       └── quark_drive_official.rs    # 官方 API + 凭证合并
│   └── quark-server/           # axum 服务 + SQLite + 下载引擎
│       ├── build.rs            # 确保 rust-embed 有 web/dist
│       └── src/
│           ├── main.rs
│           ├── api.rs          # HTTP JSON API、SSE、Token 中间件
│           ├── db.rs           # 账户、下载任务
│           ├── download.rs     # 断点续传、文件夹递归、路径安全
│           ├── vault.rs        # 加密凭证库
│           ├── config.rs
│           ├── error.rs
│           ├── state.rs
│           └── web.rs          # 嵌入前端
├── web/                        # React + Vite + TypeScript（纯 CSS）
├── scripts/
│   ├── dev.sh                  # 开发模式：同时拉起后端与前端热更新
│   └── start.sh                # 生产模式：构建并运行单个二进制
├── deploy/
│   ├── quark-drive.service
│   └── Dockerfile
├── LICENSE
└── NOTICE
```

## 快速开始

### 1. 构建

```bash
# 前端
cd web
npm install
npm run build
cd ..

# 后端（会把 web/dist 嵌入二进制）
cargo build --release -p quark-server
```

依赖：

- Rust 1.80+（本仓库在 1.99 上验证）
- Node.js 18+
- Linux 需要 `ca-certificates`，否则访问夸克 HTTPS 会失败

### 2. 启动

```bash
./target/release/quark-server \
  --listen 127.0.0.1:8787 \
  --data-dir ./data \
  --download-root ./downloads
```

浏览器打开 <http://127.0.0.1:8787>。

如果服务器只能通过 SSH 访问：

```bash
ssh -N -L 8787:127.0.0.1:8787 user@server
```

然后在本地打开 <http://127.0.0.1:8787>。VS Code Remote SSH 也可以直接转发 8787 端口。

### 3. 登录

- **二维码**：点击「扫码登录」，用夸克 App 扫码。二维码链接会渲染成图片，不依赖第三方二维码服务。
- **Cookie**：浏览器登录 `pan.quark.cn`，从开发者工具复制请求头 Cookie。至少需要 `__kps`、`__uid`。
- **官方授权**：点击「官方授权」，在打开的夸克页面确认；也可以粘贴授权码。之后如需浏览目录，点账户上的「补充 Cookie」。

## 配置

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--listen` | `QUARK_LISTEN` | `127.0.0.1:8787` | 监听地址 |
| `--data-dir` | `QUARK_DATA_DIR` | `./data` | SQLite 与凭证密钥目录 |
| `--download-root` | `QUARK_DOWNLOAD_ROOT` | `./downloads` | 下载根目录 |
| `--token` | `QUARK_TOKEN` | 空 | API 访问令牌 |
| `--allow-insecure` | `QUARK_ALLOW_INSECURE` | `false` | 允许无令牌监听非回环地址 |
| `--concurrency` | `QUARK_CONCURRENCY` | `1` | 下载并发数（1–8） |
| - | `QUARK_VAULT_KEY` | 空 | 覆盖 `master.key`；64 位 hex 或任意口令（SHA-256 派生） |

示例：

```bash
QUARK_TOKEN='change-me' ./target/release/quark-server \
  --listen 0.0.0.0:8787 \
  --data-dir /var/lib/quark-drive \
  --download-root /srv/quark-downloads \
  --concurrency 2
```

设置令牌后：

- API 请求需要 `Authorization: Bearer <token>`；
- 浏览器 UI 右上角「设置访问令牌」保存到 `localStorage`；
- SSE 进度流使用 `?token=<token>`。

## 下载行为

- 单文件写入确定性的 `.文件名.part`，完成后 `fsync` 并原子重命名。
- 重启后 `running` 任务自动回到 `queued`，按 `.part` 大小发起 Range 请求继续下载。
- 文件夹递归限制：最多 64 层、10,000 个文件。
- 目录或文件名中的 `/`、`\`、控制字符会替换为 `_`；重名时自动追加 ` (1)` 等后缀。
- API 只接受相对 `relative_dir`；服务端拼接下载根目录并 `canonicalize` 校验，拒绝 `..`、绝对路径和符号链接逃逸。
- 所有文件都下载到 `--download-root`，不执行任何安装脚本或任意命令。

## HTTP API

```text
GET    /api/health
GET    /api/config

GET    /api/accounts
POST   /api/accounts                        # { cookie | official_code, display_name? }
DELETE /api/accounts/:id
POST   /api/accounts/:id/credential         # { cookie | official_code }
POST   /api/accounts/challenges             # { method: "qr" | "official" }
GET    /api/accounts/challenges/:id

GET    /api/accounts/:id/quota
GET    /api/accounts/:id/files?parent_id=&page_token=&page_size=
GET    /api/accounts/:id/search?q=&page_token=&page_size=

POST   /api/accounts/:id/downloads          # { file_id | folder_id, relative_dir? }
GET    /api/downloads
GET    /api/downloads/:id
POST   /api/downloads/:id/cancel
POST   /api/downloads/:id/retry
DELETE /api/downloads/:id
GET    /api/downloads/events                # SSE，事件名 downloads
```

错误响应统一为：

```json
{ "error": { "code": "authentication", "message": "..." } }
```

## 安全说明

- 凭证不以明文落盘：SQLite 只保存密文，密钥在 `data/master.key`，首次启动生成，权限 0600。
- **请备份 `data/master.key`**；丢失后已保存的 Cookie/官方凭证无法解密，需要重新登录。
- API 响应与日志不会返回 Cookie 或官方 token。
- 默认仅回环监听；公网部署请使用反向代理 + TLS + 强令牌。
- 建议通过 SSH 隧道访问，而不是直接把端口暴露到公网。
- 共享服务器上请限制 `data/` 与 `downloads/` 的 UNIX 权限。

## 开发

一键拉起前后端（前端热更新，`/api` 代理到后端 8787）：

```bash
scripts/dev.sh
```

- 访问 <http://127.0.0.1:5173>；`Ctrl-C` 同时停止前后端。
- 首次运行会自动 `npm ci`，日志按行加前缀输出，同时写入 `.dev-logs/`。
- 后端首次编译较慢，脚本会轮询 `/api/health` 等待就绪。
- `QUARK_TOKEN`、`QUARK_DATA_DIR`、`QUARK_DOWNLOAD_ROOT` 等环境变量照常生效；额外参数会透传给 `quark-server`。
- 前端改动即时生效；后端改动需要重启脚本。

生产模式（构建前端 + release 二进制，前端资源内嵌，只需 8787 一个端口）：

```bash
scripts/start.sh            # 构建并启动
SKIP_BUILD=1 scripts/start.sh   # 跳过构建，直接启动已有二进制
```

手动分步启动：

```bash
# 终端 1：后端
cargo run -p quark-server -- \
  --listen 127.0.0.1:8787 \
  --data-dir ./data \
  --download-root ./downloads

# 终端 2：前端热更新（/api 代理到 8787）
cd web
npm install
npm run dev
```

测试：

```bash
cargo test --workspace
cd web && npm run build
```

前端构建产物会被 `rust-embed` 嵌入；`build.rs` 在 `web/dist` 缺失时写入占位页，保证后端可以先编译。

## systemd

```bash
sudo install -m 0755 target/release/quark-server /usr/local/bin/quark-server
sudo useradd --system --home /var/lib/quark-drive --shell /usr/sbin/nologin quark
sudo install -d -o quark -g quark -m 0700 /var/lib/quark-drive
sudo install -d -o quark -g quark /srv/quark-downloads
sudo install -m 0644 deploy/quark-drive.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now quark-drive
```

服务文件默认监听 `127.0.0.1:8787`，通过 SSH 隧道访问。

## Docker

```bash
docker build -f deploy/Dockerfile -t quark-drive-server .
docker run --rm -p 127.0.0.1:8787:8787 \
  -e QUARK_TOKEN=change-me \
  -v quark-data:/data \
  -v /srv/quark-downloads:/downloads \
  quark-drive-server
```

## 已知限制

- 夸克接口可能随官方策略变化，登录或下载失败时请先升级 Provider。
- 官方授权不提供目录浏览，需要额外 Cookie。
- 暂不支持上传、分享转存、媒体播放、TUI。
- 下载任务不做磁盘空间预检，请自行监控 `download-root` 所在分区。
- 大型文件夹会先枚举全部文件再顺序下载；重新运行会跳过已存在且大小一致的文件。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
