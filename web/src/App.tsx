import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import QRCode from "qrcode";
import {
  ApiError,
  api,
  downloadEventsUrl,
  getToken,
  setToken,
} from "./api";
import type {
  Account,
  Challenge,
  DownloadRow,
  DownloadStatus,
  FileItem,
  Quota,
  ServerConfig,
} from "./api";

type ModalState =
  | { type: "cookie"; accountId?: string }
  | { type: "official"; accountId?: string }
  | { type: "qr" }
  | { type: "token" }
  | null;

interface PathEntry {
  id: string | null;
  name: string;
}

const ROOT: PathEntry = { id: null, name: "我的网盘" };

function messageOf(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

function isUnauthorized(value: unknown): boolean {
  return value instanceof ApiError && value.code === "unauthorized";
}

function isChallengeExpired(value: unknown): boolean {
  return (
    value instanceof ApiError &&
    (value.code === "challenge_expired" || value.status === 410)
  );
}

export default function App() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [activeId, setActiveIdState] = useState<string | null>(() =>
    localStorage.getItem("quark.active_account"),
  );
  const [quotas, setQuotas] = useState<Record<string, Quota>>({});
  const [path, setPath] = useState<PathEntry[]>([ROOT]);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [nextToken, setNextToken] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [listing, setListing] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [downloads, setDownloads] = useState<DownloadRow[]>([]);

  const [modal, setModal] = useState<ModalState>(null);
  const [challenge, setChallenge] = useState<{
    kind: "qr" | "official";
    data: Challenge;
  } | null>(null);
  const [qrImage, setQrImage] = useState("");
  const [challengeStatus, setChallengeStatus] = useState("");
  const [challengeError, setChallengeError] = useState("");
  const [cookieText, setCookieText] = useState("");
  const [officialCode, setOfficialCode] = useState("");
  const [tokenInput, setTokenInput] = useState(getToken());

  const [needsToken, setNeedsToken] = useState(false);
  const [tokenRevision, setTokenRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const activeAccount = useMemo(
    () => accounts.find((account) => account.id === activeId) ?? null,
    [accounts, activeId],
  );
  const selectedItems = useMemo(
    () => files.filter((file) => selected.has(file.id)),
    [files, selected],
  );
  const pathKey = path.map((entry) => entry.id ?? "root").join("/");

  function setActiveId(id: string | null) {
    setActiveIdState(id);
    if (id) {
      localStorage.setItem("quark.active_account", id);
    } else {
      localStorage.removeItem("quark.active_account");
    }
  }

  function handleError(value: unknown) {
    if (isUnauthorized(value)) {
      setNeedsToken(true);
      return;
    }
    setError(messageOf(value));
  }

  async function refreshAccounts() {
    try {
      const list = await api.listAccounts();
      setAccounts(list);
      setActiveIdState((current) => {
        if (current && list.some((account) => account.id === current)) {
          return current;
        }
        return list[0]?.id ?? null;
      });
    } catch (value) {
      handleError(value);
    }
  }

  async function refreshDownloads() {
    try {
      setDownloads(await api.listDownloads());
    } catch (value) {
      handleError(value);
    }
  }

  async function refreshAll() {
    setError("");
    await Promise.all([refreshAccounts(), refreshDownloads()]);
  }

  useEffect(() => {
    api.getConfig().then(setConfig).catch(handleError);
    void refreshAccounts();
    void refreshDownloads();
    const onUnauthorized = () => setNeedsToken(true);
    window.addEventListener("quark:unauthorized", onUnauthorized);
    return () => window.removeEventListener("quark:unauthorized", onUnauthorized);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setPath([ROOT]);
    setSearchQuery("");
    setSearchInput("");
    setSelected(new Set());
    if (!activeId) {
      setFiles([]);
      return;
    }
    api
      .quota(activeId)
      .then((quota) => setQuotas((current) => ({ ...current, [activeId]: quota })))
      .catch(() => undefined);
  }, [activeId, accounts.length]);

  useEffect(() => {
    if (!activeId) {
      setFiles([]);
      setNextToken(null);
      return;
    }
    let cancelled = false;
    setListing(true);
    setError("");
    const parentId = path[path.length - 1]?.id ?? null;
    const request = searchQuery
      ? api.search(activeId, searchQuery)
      : api.listFiles(activeId, parentId);
    request
      .then((page) => {
        if (cancelled) return;
        setFiles(page.items);
        setNextToken(page.next_page_token);
      })
      .catch((value) => {
        if (cancelled) return;
        setFiles([]);
        setNextToken(null);
        handleError(value);
      })
      .finally(() => {
        if (!cancelled) setListing(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId, pathKey, searchQuery]);

  useEffect(() => {
    const source = new EventSource(downloadEventsUrl());
    const listener = (event: MessageEvent) => {
      try {
        setDownloads(JSON.parse(event.data) as DownloadRow[]);
      } catch {
        // Ignore malformed events; polling below still recovers.
      }
    };
    source.addEventListener("downloads", listener as EventListener);
    const poll = window.setInterval(() => void refreshDownloads(), 4_000);
    return () => {
      source.close();
      window.clearInterval(poll);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tokenRevision]);

  useEffect(() => {
    const url = challenge?.kind === "qr" ? challenge.data.payload.qr_url : undefined;
    if (!url) {
      setQrImage("");
      return;
    }
    QRCode.toDataURL(url, {
      width: 280,
      margin: 1,
      color: { dark: "#0b0f14", light: "#ffffff" },
    })
      .then(setQrImage)
      .catch(() => setQrImage(""));
  }, [challenge]);

  useEffect(() => {
    if (!challenge) return;
    const activeChallenge = challenge;
    let stopped = false;
    let timer: number | undefined;
    let inFlight = false;

    function schedule(delay: number) {
      if (!stopped) timer = window.setTimeout(tick, delay);
    }

    async function refreshQrCode() {
      setChallengeError("");
      setChallengeStatus("二维码已过期，正在重新获取…");
      try {
        const data = await api.beginChallenge("qr");
        if (stopped) return;
        setChallenge({ kind: "qr", data });
        setChallengeStatus("等待扫码确认中…");
      } catch (value) {
        if (stopped) return;
        setChallengeStatus("");
        setChallengeError(`重新获取二维码失败：${messageOf(value)}`);
        schedule(3_000);
      }
    }

    async function tick() {
      if (stopped || inFlight) return;
      inFlight = true;
      try {
        const result = await api.pollChallenge(activeChallenge.data.challenge_id);
        if (stopped) return;
        if (result.status === "authorized") {
          setChallenge(null);
          setChallengeStatus("");
          setChallengeError("");
          setModal(null);
          setNotice("登录成功，账户已保存");
          await refreshAccounts();
          await refreshDownloads();
          return;
        }
        setChallengeError("");
        setChallengeStatus(
          activeChallenge.kind === "qr" ? "等待扫码确认中…" : "等待浏览器确认中…",
        );
        schedule(1_500);
      } catch (value) {
        if (stopped) return;
        if (isUnauthorized(value)) {
          setNeedsToken(true);
          setModal({ type: "token" });
          return;
        }
        if (activeChallenge.kind === "qr" && isChallengeExpired(value)) {
          await refreshQrCode();
          return;
        }
        if (activeChallenge.kind === "official" && isChallengeExpired(value)) {
          setChallengeStatus("");
          setChallengeError("授权已过期，请重新发起官方授权");
          return;
        }
        // Keep polling after transient failures instead of silently stopping.
        setChallengeError(messageOf(value));
        schedule(3_000);
      } finally {
        inFlight = false;
      }
    }

    schedule(1_200);
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [challenge]);

  function openFolder(item: FileItem) {
    setSearchQuery("");
    setSearchInput("");
    setSelected(new Set());
    setPath((current) => [...current, { id: item.id, name: item.name }]);
  }

  function goTo(index: number) {
    setSearchQuery("");
    setSearchInput("");
    setSelected(new Set());
    setPath((current) => current.slice(0, index + 1));
  }

  function toggle(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (selected.size === files.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(files.map((file) => file.id)));
    }
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault();
    setSelected(new Set());
    setPath([ROOT]);
    setSearchQuery(searchInput.trim());
  }

  async function loadMore() {
    if (!activeId || !nextToken) return;
    try {
      const parentId = path[path.length - 1]?.id ?? null;
      const page = searchQuery
        ? await api.search(activeId, searchQuery, nextToken)
        : await api.listFiles(activeId, parentId, nextToken);
      setFiles((current) => [...current, ...page.items]);
      setNextToken(page.next_page_token);
    } catch (value) {
      handleError(value);
    }
  }

  async function startDownloads() {
    if (!activeId || selectedItems.length === 0) return;
    setBusy(true);
    setError("");
    const relative = path
      .slice(1)
      .map((entry) => entry.name)
      .join("/");
    let created = 0;
    for (const item of selectedItems) {
      try {
        await api.createDownload(
          activeId,
          item.kind === "folder"
            ? { folder_id: item.id, relative_dir: relative }
            : { file_id: item.id, relative_dir: relative },
        );
        created += 1;
      } catch (value) {
        handleError(value);
      }
    }
    setSelected(new Set());
    setBusy(false);
    if (created > 0) {
      setNotice(`已创建 ${created} 个下载任务`);
      await refreshDownloads();
    }
  }

  async function removeAccount(account: Account) {
    if (!window.confirm(`确定删除账户「${account.display_name}」及其下载记录吗？`)) {
      return;
    }
    try {
      await api.deleteAccount(account.id);
      if (activeId === account.id) setActiveId(null);
      setNotice("账户已删除");
      await refreshAll();
    } catch (value) {
      handleError(value);
    }
  }

  async function startQrLogin() {
    setError("");
    setChallengeError("");
    setChallengeStatus("正在获取二维码…");
    setChallenge(null);
    setModal({ type: "qr" });
    setQrImage("");
    try {
      const data = await api.beginChallenge("qr");
      setChallenge({ kind: "qr", data });
      setChallengeStatus("等待扫码确认中…");
    } catch (value) {
      if (isUnauthorized(value)) {
        setNeedsToken(true);
        setModal({ type: "token" });
        return;
      }
      setChallengeStatus("");
      setChallengeError(`获取二维码失败：${messageOf(value)}`);
    }
  }

  async function startOfficialLogin() {
    setError("");
    setChallengeError("");
    setChallengeStatus("");
    setChallenge(null);
    setModal({ type: "official" });
    setOfficialCode("");
    try {
      const data = await api.beginChallenge("official");
      setChallenge({ kind: "official", data });
      setChallengeStatus("等待浏览器确认中…");
      if (data.payload.authorize_url) {
        window.open(data.payload.authorize_url, "_blank", "noopener,noreferrer");
      }
    } catch (value) {
      if (isUnauthorized(value)) {
        setNeedsToken(true);
        setModal({ type: "token" });
        return;
      }
      setChallengeStatus("");
      setChallengeError(`发起官方授权失败：${messageOf(value)}`);
    }
  }

  async function submitCookie(event: FormEvent) {
    event.preventDefault();
    if (!cookieText.trim()) return;
    setBusy(true);
    setError("");
    try {
      if (modal?.type === "cookie" && modal.accountId) {
        await api.supplement(modal.accountId, { cookie: cookieText.trim() });
        setNotice("Cookie 已补充");
      } else {
        await api.createAccount({ cookie: cookieText.trim() });
        setNotice("账户已登录");
      }
      setCookieText("");
      setModal(null);
      await refreshAll();
    } catch (value) {
      handleError(value);
    } finally {
      setBusy(false);
    }
  }

  async function submitOfficialCode(event: FormEvent) {
    event.preventDefault();
    if (!officialCode.trim()) return;
    setBusy(true);
    setError("");
    try {
      if (modal?.type === "official" && modal.accountId) {
        await api.supplement(modal.accountId, { official_code: officialCode.trim() });
        setNotice("官方授权已补充");
      } else {
        await api.createAccount({ official_code: officialCode.trim() });
        setNotice("账户已登录");
      }
      setOfficialCode("");
      setChallenge(null);
      setModal(null);
      await refreshAll();
    } catch (value) {
      handleError(value);
    } finally {
      setBusy(false);
    }
  }

  function saveToken(event: FormEvent) {
    event.preventDefault();
    setToken(tokenInput);
    setNeedsToken(false);
    setModal(null);
    setTokenRevision((value) => value + 1);
    setNotice(tokenInput.trim() ? "访问令牌已保存" : "已清除访问令牌");
    window.setTimeout(() => void refreshAll(), 50);
  }

  function closeModal() {
    setModal(null);
    setChallenge(null);
    setChallengeStatus("");
    setChallengeError("");
    setCookieText("");
    setOfficialCode("");
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">Q</div>
          <div>
            <h1>Quark Drive</h1>
            <p>无头服务器下载器</p>
          </div>
        </div>

        <div className="sidebar-section-title">
          <span>账户</span>
          <button className="link-button" onClick={() => void refreshAccounts()}>
            刷新
          </button>
        </div>

        <div className="account-list">
          {accounts.length === 0 && (
            <p className="muted small">还没有账户，先添加一个夸克网盘账户。</p>
          )}
          {accounts.map((account) => {
            const quota = quotas[account.id];
            const percent =
              quota?.used_bytes != null && quota?.total_bytes
                ? Math.min(100, (quota.used_bytes / quota.total_bytes) * 100)
                : null;
            return (
              <div
                key={account.id}
                className={`account-card ${account.id === activeId ? "active" : ""}`}
                onClick={() => setActiveId(account.id)}
                role="button"
                tabIndex={0}
              >
                <div className="account-name">{account.display_name}</div>
                <div className="badges">
                  {account.credentials.official && <span className="badge">官方授权</span>}
                  {account.credentials.cookie && <span className="badge">Cookie</span>}
                  {!account.credentials.cookie && (
                    <span className="badge warn">仅搜索/下载</span>
                  )}
                </div>
                {quota && quota.total_bytes != null && (
                  <div className="quota">
                    <div className="quota-bar">
                      <div style={{ width: `${percent ?? 0}%` }} />
                    </div>
                    <span className="muted tiny">
                      {formatBytes(quota.used_bytes)} / {formatBytes(quota.total_bytes)}
                    </span>
                  </div>
                )}
                <div className="account-actions" onClick={(event) => event.stopPropagation()}>
                  {!account.credentials.cookie && (
                    <button
                      className="link-button"
                      onClick={() => setModal({ type: "cookie", accountId: account.id })}
                    >
                      补充 Cookie
                    </button>
                  )}
                  <button className="link-button danger" onClick={() => void removeAccount(account)}>
                    删除
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="add-account">
          <button className="btn primary block" onClick={() => setModal({ type: "cookie" })}>
            添加账户
          </button>
          <div className="add-account-row">
            <button className="btn" onClick={() => void startQrLogin()}>
              扫码登录
            </button>
            <button className="btn" onClick={() => void startOfficialLogin()}>
              官方授权
            </button>
          </div>
        </div>

        <div className="sidebar-footer">
          {config && (
            <>
              <div title={config.download_root}>
                下载目录：<span className="mono">{config.download_root}</span>
              </div>
              <div>
                并发：{config.concurrency} · 监听：{config.listen}
              </div>
            </>
          )}
          <button className="link-button" onClick={() => setModal({ type: "token" })}>
            设置访问令牌
          </button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h2>{activeAccount ? activeAccount.display_name : "文件浏览"}</h2>
            <p className="muted small">
              {activeAccount?.credentials.cookie
                ? "支持目录浏览、搜索和文件夹下载"
                : "当前账户仅支持搜索与单文件下载"}
            </p>
          </div>
          <form className="search" onSubmit={submitSearch}>
            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              placeholder="搜索网盘文件"
              disabled={!activeId}
            />
            <button className="btn" type="submit" disabled={!activeId}>
              搜索
            </button>
            {searchQuery && (
              <button
                className="btn ghost"
                type="button"
                onClick={() => {
                  setSearchQuery("");
                  setSearchInput("");
                }}
              >
                清除
              </button>
            )}
          </form>
        </header>

        {needsToken && (
          <div className="banner warn-banner">
            需要访问令牌。
            <button className="link-button" onClick={() => setModal({ type: "token" })}>
              立即设置
            </button>
          </div>
        )}
        {error && (
          <div className="banner error-banner">
            {error}
            <button className="link-button" onClick={() => setError("")}>
              关闭
            </button>
          </div>
        )}
        {notice && (
          <div className="banner notice-banner">
            {notice}
            <button className="link-button" onClick={() => setNotice("")}>
              关闭
            </button>
          </div>
        )}

        <section className="panel browser">
          <div className="breadcrumb">
            {searchQuery ? (
              <span>
                搜索 <strong>{searchQuery}</strong> 的结果
              </span>
            ) : (
              path.map((entry, index) => (
                <span key={`${entry.id ?? "root"}-${index}`}>
                  {index > 0 && <span className="crumb-sep">/</span>}
                  <button className="crumb" onClick={() => goTo(index)}>
                    {entry.name}
                  </button>
                </span>
              ))
            )}
          </div>

          <div className="toolbar">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={files.length > 0 && selected.size === files.length}
                onChange={toggleAll}
                disabled={files.length === 0}
              />
              全选
            </label>
            <span className="muted small">已选 {selected.size} 项</span>
            <button
              className="btn primary"
              onClick={() => void startDownloads()}
              disabled={busy || selected.size === 0}
            >
              下载所选
            </button>
            <button className="btn ghost" onClick={() => void refreshAll()}>
              刷新
            </button>
          </div>

          <div className="file-list">
            {listing && <div className="empty">正在加载…</div>}
            {!listing && files.length === 0 && (
              <div className="empty">
                {activeId ? "这个位置没有文件" : "请先添加并选择一个账户"}
              </div>
            )}
            {!listing &&
              files.map((item) => (
                <div className="file-row" key={item.id}>
                  <input
                    type="checkbox"
                    checked={selected.has(item.id)}
                    onChange={() => toggle(item.id)}
                  />
                  <span className={`file-icon ${item.kind}`}>
                    {item.kind === "folder" ? "📁" : "📄"}
                  </span>
                  <div className="file-name">
                    {item.kind === "folder" ? (
                      <button className="file-link" onClick={() => openFolder(item)}>
                        {item.name}
                      </button>
                    ) : (
                      <span>{item.name}</span>
                    )}
                  </div>
                  <span className="muted size">{item.kind === "folder" ? "—" : formatBytes(item.size)}</span>
                  <span className="muted modified">{formatDate(item.modified_at)}</span>
                </div>
              ))}
            {!listing && nextToken && (
              <button className="btn ghost block" onClick={() => void loadMore()}>
                加载更多
              </button>
            )}
          </div>
        </section>

        <section className="panel downloads">
          <div className="panel-heading">
            <h3>下载任务</h3>
            <button className="link-button" onClick={() => void refreshDownloads()}>
              刷新
            </button>
          </div>
          {downloads.length === 0 && <div className="empty">暂无下载任务</div>}
          {downloads.map((download) => (
            <DownloadItem
              key={download.id}
              download={download}
              onCancel={async () => {
                try {
                  await api.cancelDownload(download.id);
                  await refreshDownloads();
                } catch (value) {
                  handleError(value);
                }
              }}
              onRetry={async () => {
                try {
                  await api.retryDownload(download.id);
                  await refreshDownloads();
                } catch (value) {
                  handleError(value);
                }
              }}
              onDelete={async () => {
                try {
                  await api.deleteDownload(download.id);
                  await refreshDownloads();
                } catch (value) {
                  handleError(value);
                }
              }}
            />
          ))}
        </section>
      </main>

      {modal && (
        <div className="modal-backdrop" onClick={closeModal}>
          <div className="modal" onClick={(event) => event.stopPropagation()}>
            {modal.type === "cookie" && (
              <>
                <h3>{modal.accountId ? "补充 Cookie" : "Cookie 登录"}</h3>
                <p className="muted small">
                  在浏览器登录 pan.quark.cn 后，从开发者工具复制任意请求的完整 Cookie
                  （通常是 __pus、__kp、__kps、__puus、__uid 等字段），可直接粘贴整行
                  “Cookie: …”或多行 name=value。官方授权账户补充 Cookie 后才能浏览目录。
                </p>
                {error && <p className="form-error">{error}</p>}
                <form onSubmit={submitCookie}>
                  <textarea
                    value={cookieText}
                    onChange={(event) => setCookieText(event.target.value)}
                    placeholder="__kps=...; __uid=...; __puus=..."
                    rows={6}
                  />
                  <div className="modal-actions">
                    <button className="btn ghost" type="button" onClick={closeModal}>
                      取消
                    </button>
                    <button className="btn primary" type="submit" disabled={busy || !cookieText.trim()}>
                      保存
                    </button>
                  </div>
                </form>
              </>
            )}

            {modal.type === "official" && (
              <>
                <h3>官方授权</h3>
                <p className="muted small">
                  已在新标签页打开夸克授权页面（如果被浏览器拦截，请点击下方按钮）。
                  官方授权只支持搜索与下载；浏览目录仍需补充 Cookie。
                </p>
                {challenge?.kind === "official" && challenge.data.payload.authorize_url && (
                  <p>
                    <a
                      className="btn"
                      href={challenge.data.payload.authorize_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      打开授权页面
                    </a>
                  </p>
                )}
                <p className="muted small">
                  {challengeStatus || "授权已完成"}
                </p>
                {challengeError && <p className="form-error">{challengeError}</p>}
                {error && <p className="form-error">{error}</p>}
                <form onSubmit={submitOfficialCode}>
                  <label className="field-label">或粘贴官方授权码</label>
                  <input
                    value={officialCode}
                    onChange={(event) => setOfficialCode(event.target.value)}
                    placeholder="agent_auth_code"
                  />
                  <div className="modal-actions">
                    <button className="btn ghost" type="button" onClick={closeModal}>
                      取消
                    </button>
                    <button className="btn primary" type="submit" disabled={busy || !officialCode.trim()}>
                      提交授权码
                    </button>
                  </div>
                </form>
              </>
            )}

            {modal.type === "qr" && (
              <>
                <h3>扫码登录夸克网盘</h3>
                <p className="muted small">用夸克 App 扫描二维码，登录后会自动保存 Cookie。</p>
                <div className="qr-box">
                  {qrImage ? (
                    <img src={qrImage} alt="夸克登录二维码" />
                  ) : (
                    <div className="empty">
                      {challengeError ? "二维码获取失败" : "正在获取二维码…"}
                    </div>
                  )}
                </div>
                <p className="muted small">{challengeStatus || "正在获取二维码…"}</p>
                {challengeError && <p className="form-error">{challengeError}</p>}
                <div className="modal-actions">
                  <button className="btn ghost" type="button" onClick={closeModal}>
                    取消
                  </button>
                  <button className="btn" type="button" onClick={() => void startQrLogin()}>
                    刷新二维码
                  </button>
                </div>
              </>
            )}

            {modal.type === "token" && (
              <>
                <h3>访问令牌</h3>
                <p className="muted small">
                  如果服务端启动时设置了 --token，请在这里填写。令牌只保存在本机浏览器。
                </p>
                <form onSubmit={saveToken}>
                  <input
                    type="password"
                    value={tokenInput}
                    onChange={(event) => setTokenInput(event.target.value)}
                    placeholder="Bearer token"
                  />
                  <div className="modal-actions">
                    <button className="btn ghost" type="button" onClick={closeModal}>
                      取消
                    </button>
                    <button className="btn primary" type="submit">
                      保存
                    </button>
                  </div>
                </form>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function DownloadItem({
  download,
  onCancel,
  onRetry,
  onDelete,
}: {
  download: DownloadRow;
  onCancel: () => Promise<void>;
  onRetry: () => Promise<void>;
  onDelete: () => Promise<void>;
}) {
  const percent =
    download.total_bytes && download.total_bytes > 0
      ? Math.min(100, (download.downloaded_bytes / download.total_bytes) * 100)
      : null;
  const active = download.status === "running" || download.status === "queued";

  return (
    <div className="download-row">
      <div className="download-head">
        <div>
          <strong>{download.display_name}</strong>
          <span className="muted small">
            {download.kind === "folder" ? " 文件夹" : " 文件"}
          </span>
        </div>
        <span className={`status ${download.status}`}>{statusLabel(download.status)}</span>
      </div>
      <div className={`progress ${percent == null && active ? "indeterminate" : ""}`}>
        <div style={{ width: percent == null ? "100%" : `${percent}%` }} />
      </div>
      <div className="download-meta">
        <span>
          {formatBytes(download.downloaded_bytes)}
          {download.total_bytes ? ` / ${formatBytes(download.total_bytes)}` : ""}
        </span>
        {download.kind === "folder" && download.total_items != null && (
          <span>
            {download.completed_items} / {download.total_items} 个文件
          </span>
        )}
        <span className="mono muted">{download.relative_dir || "/"}</span>
      </div>
      {download.current_file && (
        <div className="current-file">正在下载：{download.current_file}</div>
      )}
      {download.error && <div className="error-text">{download.error}</div>}
      <div className="download-actions">
        {active && (
          <button className="link-button" onClick={() => void onCancel()}>
            取消
          </button>
        )}
        {(download.status === "failed" || download.status === "cancelled") && (
          <button className="link-button" onClick={() => void onRetry()}>
            重试
          </button>
        )}
        {!active && (
          <button className="link-button danger" onClick={() => void onDelete()}>
            删除记录
          </button>
        )}
      </div>
    </div>
  );
}

function statusLabel(status: DownloadStatus): string {
  switch (status) {
    case "queued":
      return "排队中";
    case "running":
      return "下载中";
    case "completed":
      return "已完成";
    case "failed":
      return "失败";
    case "cancelled":
      return "已取消";
    case "paused":
      return "已暂停";
  }
}

function formatBytes(value: number | null | undefined): string {
  if (value == null) return "未知";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}

function formatDate(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
