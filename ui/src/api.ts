// Thin client for the caddyforge API (docs/API.md).
// Every mutation carries X-Caddyforge: 1 — the server's CSRF gate.

export class ApiError extends Error {
  status: number;
  code: string;
  details: string[];
  constructor(status: number, message: string, code = "", details: string[] = []) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type Listener = () => void;
const unauthListeners = new Set<Listener>();

/** Called whenever a request comes back 401, so the shell can show the login. */
export function onUnauthenticated(fn: Listener): () => void {
  unauthListeners.add(fn);
  return () => unauthListeners.delete(fn);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-Caddyforge"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(0, "Server nicht erreichbar: " + (e as Error).message, "network");
  }
  const text = await resp.text();
  let data: any = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (resp.status === 401 && path !== "/api/login") {
    unauthListeners.forEach((fn) => fn());
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, data?.error || resp.statusText, data?.code || "", data?.details || []);
  }
  // Some handlers report a failure with 200 and an error body (plugins/check).
  if (data && typeof data === "object" && "error" in data && "code" in data && Object.keys(data).length <= 3) {
    throw new ApiError(resp.status, data.error, data.code, data.details || []);
  }
  return data as T;
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b ?? {}),
  put: <T>(p: string, b?: unknown) => request<T>("PUT", p, b ?? {}),
  del: <T>(p: string) => request<T>("DELETE", p),
};

export function errMsg(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

// ---------- Types ----------

export interface VersionInfo {
  name: string;
  version: string;
  commit?: string;
  api: number;
  setup: boolean;
  serverTime: string;
}

export interface EnvVar {
  name: string;
  label: string;
  help?: string;
  required: boolean;
  secret: boolean;
  positional?: boolean;
  opt?: string;
}

export interface PluginState {
  id: string;
  module: string;
  name: string;
  category: string;
  subcat?: string;
  registers?: string;
  env?: EnvVar[];
  docs?: string;
  standard: boolean;
  deprecated?: boolean;
  license?: string;
  licenseRisk?: string;
  conflicts?: string[];
  requires?: string[];
  note?: string;
  detected: boolean;
  active: boolean;
  credentialState?: Record<string, "set" | "missing" | "optional">;
  complete: boolean;
}

export interface PluginsResponse {
  variant: string;
  binarySource: string;
  plugins: PluginState[];
  categories: string[];
  caddyVersion: string;
}

export interface ModuleCheck {
  module: string;
  cleanPath: string;
  version?: string;
  exists: boolean;
  inCatalog: boolean;
  providerSuffix?: string;
  hint?: string;
  warning?: string;
}

export interface CfEvent {
  id: string;
  ts: string;
  kind: string;
  step: string;
  ok: boolean;
  error?: string;
  summary?: string;
  vars?: string[];
  meta?: Record<string, unknown>;
}

export interface PortState {
  Port: number;
  Free: boolean;
  UsedBy: string;
  Own: boolean;
  Listener: boolean;
}

export interface Certificate {
  sans: string[];
  issuer: string;
  notBefore: string;
  notAfter: string;
  expiresInDays: number;
}

export interface StatusResponse {
  installed: boolean;
  caddyVersion?: string;
  variant?: string;
  adminUrl?: string;
  adminReachable: boolean;
  adminError?: string;
  serviceState?: string;
  serviceActive: boolean;
  mainPid?: string;
  listening: boolean;
  ui: { bind: string; port: number; tls: boolean; selfSigned: boolean; authConfigured: boolean; sessions: number };
  host: {
    distro?: string;
    distroVersion?: string;
    init: string;
    virt?: string;
    unprivilegedLxc: boolean;
    canBindLowPorts: boolean;
    hostname?: string;
  };
  ports: PortState[] | null;
  enabledPlugins: PluginState[] | null;
  certificates?: Certificate[];
  lastEvent?: CfEvent;
  updatedAt?: string;
  warnings?: string[];
}

export type BuildStatus = "queued" | "preparing" | "building" | "verifying" | "succeeded" | "failed" | "cancelled";

export interface Build {
  id: string;
  status: BuildStatus;
  stage?: string;
  caddyVersion: string;
  plugins: string[] | null;
  modules: string[] | null;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  durationSec?: number;
  error?: string;
  size?: number;
  sha256?: string;
  detectedModules?: string[] | null;
  active: boolean;
  activatedAt?: string;
}

export interface BuildsResponse {
  builds: Build[] | null;
  activeId?: string;
  runningId?: string;
  previousAvailable?: boolean;
}

export interface Toolchain {
  go: { installed: boolean; version?: string };
  xcaddy: { installed: boolean; version?: string };
  cacheBytes?: number;
  busy: boolean;
  runningId?: string;
}

export interface Versions {
  latest: string;
  installed: string;
  recent: string[] | null;
}

export type SiteMode = "proxy" | "redirect" | "static" | "raw";
export type SiteTLS = "auto" | "internal" | "dns" | "off";

export interface Site {
  id: string;
  domains: string[];
  mode: SiteMode;
  upstreams: string[];
  upstreamTls: boolean;
  upstreamInsecure: boolean;
  lbPolicy: string;
  healthUri: string;
  tls: SiteTLS;
  dnsProvider: string;
  compress: boolean;
  redirectTo: string;
  root: string;
  extra: string;
  raw: string;
  enabled: boolean;
  updatedAt?: string;
}

export interface SitesResponse {
  sites: Site[] | null;
  importOk: boolean;
  sitesDir: string;
  dnsProviders: { id: string; name: string; ready: boolean }[] | null;
}

export interface Session {
  id: string;
  created: string;
  expires: string;
  userAgent?: string;
  remote?: string;
}

export function emptySite(): Site {
  return {
    id: "",
    domains: [],
    mode: "proxy",
    upstreams: [],
    upstreamTls: false,
    upstreamInsecure: false,
    lbPolicy: "",
    healthUri: "",
    tls: "auto",
    dnsProvider: "",
    compress: true,
    redirectTo: "",
    root: "",
    extra: "",
    raw: "",
    enabled: true,
  };
}

// ---------- Formatting helpers ----------

export function fmtBytes(n?: number): string {
  if (!n) return "–";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

export function fmtTime(s?: string): string {
  if (!s) return "–";
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return "–";
  return d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "medium" });
}

export function fmtDuration(sec?: number): string {
  if (sec === undefined || sec === null) return "–";
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return m > 0 ? `${m} min ${s} s` : `${s} s`;
}
