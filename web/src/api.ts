const TOKEN_KEY = "quark.access_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  if (token.trim()) {
    localStorage.setItem(TOKEN_KEY, token.trim());
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) {
    headers.set("authorization", `Bearer ${token}`);
  }
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    window.dispatchEvent(new Event("quark:unauthorized"));
  }
  if (!response.ok) {
    let message = `请求失败 (${response.status})`;
    let code = "http_error";
    try {
      const body = (await response.json()) as { error?: { message?: string; code?: string } };
      message = body.error?.message ?? message;
      code = body.error?.code ?? code;
    } catch {
      // Ignore non-JSON error bodies.
    }
    throw new ApiError(response.status, code, message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export interface Account {
  id: string;
  provider_id: string;
  display_name: string;
  account_subject: string | null;
  config: Record<string, unknown>;
  credentials: { official: boolean; cookie: boolean };
  capabilities: {
    browse: boolean;
    search: boolean;
    download: boolean;
    folder_download: boolean;
  };
  created_at: string;
  updated_at: string;
}

export interface ServerConfig {
  version: string;
  listen: string;
  data_dir: string;
  download_root: string;
  concurrency: number;
  auth_required: boolean;
}

export interface FileItem {
  id: string;
  parent_id: string | null;
  name: string;
  kind: "file" | "folder" | "shortcut";
  media_type: string | null;
  size: number | null;
  modified_at: string | null;
  revision: string | null;
  downloadable: boolean;
}

export interface FilePage {
  items: FileItem[];
  next_page_token: string | null;
}

export interface Quota {
  used_bytes: number | null;
  total_bytes: number | null;
  trashed_bytes: number | null;
  checked_at: string;
}

export interface Challenge {
  challenge_id: string;
  provider_id: string;
  kind: string;
  payload: { qr_url?: string; authorize_url?: string; page_code?: string };
  expires_at: string | null;
}

export type DownloadStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "paused";

export interface DownloadRow {
  id: string;
  account_id: string;
  kind: "file" | "folder";
  remote_id: string;
  display_name: string;
  relative_dir: string;
  status: DownloadStatus;
  total_bytes: number | null;
  downloaded_bytes: number;
  completed_items: number;
  total_items: number | null;
  current_file: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export const api = {
  getConfig: () => request<ServerConfig>("/api/config"),

  listAccounts: async () =>
    (await request<{ accounts: Account[] }>("/api/accounts")).accounts,

  createAccount: async (body: {
    cookie?: string;
    official_code?: string;
    display_name?: string;
  }) =>
    (
      await request<{ account: Account }>("/api/accounts", {
        method: "POST",
        body: JSON.stringify(body),
      })
    ).account,

  deleteAccount: (id: string) =>
    request<void>(`/api/accounts/${encodeURIComponent(id)}`, { method: "DELETE" }),

  beginChallenge: (method: "qr" | "official") =>
    request<Challenge>("/api/accounts/challenges", {
      method: "POST",
      body: JSON.stringify({ method }),
    }),

  pollChallenge: (id: string) =>
    request<{ status: "pending" | "authorized"; account?: Account }>(
      `/api/accounts/challenges/${encodeURIComponent(id)}`,
    ),

  supplement: (id: string, body: { cookie?: string; official_code?: string }) =>
    request<{ account: Account }>(
      `/api/accounts/${encodeURIComponent(id)}/credential`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  quota: (id: string) => request<Quota>(`/api/accounts/${encodeURIComponent(id)}/quota`),

  listFiles: (id: string, parentId: string | null, pageToken?: string | null) => {
    const params = new URLSearchParams();
    if (parentId) params.set("parent_id", parentId);
    if (pageToken) params.set("page_token", pageToken);
    params.set("page_size", "100");
    return request<FilePage>(
      `/api/accounts/${encodeURIComponent(id)}/files?${params.toString()}`,
    );
  },

  search: (id: string, query: string, pageToken?: string | null) => {
    const params = new URLSearchParams({ q: query, page_size: "100" });
    if (pageToken) params.set("page_token", pageToken);
    return request<FilePage>(
      `/api/accounts/${encodeURIComponent(id)}/search?${params.toString()}`,
    );
  },

  createDownload: (
    id: string,
    body: { file_id?: string; folder_id?: string; relative_dir?: string },
  ) =>
    request<{ download: DownloadRow }>(
      `/api/accounts/${encodeURIComponent(id)}/downloads`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  listDownloads: async () =>
    (await request<{ downloads: DownloadRow[] }>("/api/downloads")).downloads,

  cancelDownload: (id: string) =>
    request<{ download: DownloadRow }>(
      `/api/downloads/${encodeURIComponent(id)}/cancel`,
      { method: "POST" },
    ),

  retryDownload: (id: string) =>
    request<{ download: DownloadRow }>(
      `/api/downloads/${encodeURIComponent(id)}/retry`,
      { method: "POST" },
    ),

  deleteDownload: (id: string) =>
    request<void>(`/api/downloads/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

export function downloadEventsUrl(): string {
  const token = getToken();
  return token
    ? `/api/downloads/events?token=${encodeURIComponent(token)}`
    : "/api/downloads/events";
}
