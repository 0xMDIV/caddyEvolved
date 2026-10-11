// Thin client for the caddyEvolved API (docs/API.md).
// Every mutation carries X-CaddyEvolved: 1 — the server's CSRF gate.

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

/** Window event fired after a build activation or rollback. */
export const BINARY_CHANGED = "cf:binary-changed";

type Listener = () => void;
const unauthListeners = new Set<Listener>();

/** Called whenever a request comes back 401, so the shell can show the login. */
export function onUnauthenticated(fn: Listener): () => void {
  unauthListeners.add(fn);
  return () => unauthListeners.delete(fn);
}

async function request<T>(method: string, path: string, body?: unknown, raw?: { data: BodyInit; headers?: Record<string, string> }): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...(raw?.headers ?? {}) };
  if (method !== "GET") headers["X-CaddyEvolved"] = "1";
  if (body !== undefined && !raw) headers["Content-Type"] = "application/json";
  if (raw) headers["Content-Type"] = "application/octet-stream";
  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: raw ? raw.data : body === undefined ? undefined : JSON.stringify(body),
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
  // A swapped caddy binary changes which plugin pages exist.
  if (method === "POST" && /^\/api\/builds\/(rollback|[^/]+\/activate)$/.test(path)) {
    window.dispatchEvent(new Event(BINARY_CHANGED));
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
  /** POSTs a file as the raw request body. */
  upload: <T>(p: string, data: BodyInit, headers?: Record<string, string>) => request<T>("POST", p, undefined, { data, headers }),
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
  recommended?: boolean;
  license?: string;
  licenseRisk?: string;
  conflicts?: string[];
  requires?: string[];
  note?: string;
  ui?: { page: string; label: string; icon?: string };
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
  accessList?: string;
  waf?: SiteWaf;
  defender?: SiteDefender;
  rateLimit?: SiteRateLimit;
  enabled: boolean;
  updatedAt?: string;
}

export interface SiteWaf {
  enabled: boolean;
  mode: "block" | "detect";
}
export interface SiteDefender {
  enabled: boolean;
  responder: "block" | "tarpit" | "garbage" | "drop";
  ranges: string[];
}
export interface SiteRateLimit {
  enabled: boolean;
  events: number;
  window: string;
}

export const DEFENDER_RANGES = ["openai", "aws", "gcloud", "azurepubliccloud", "deepseek", "githubcopilot", "cloudflare", "vpn", "private", "all"];

export const defaultWaf = (): SiteWaf => ({ enabled: true, mode: "block" });
export const defaultDefender = (): SiteDefender => ({ enabled: true, responder: "block", ranges: ["openai", "deepseek", "githubcopilot"] });
export const defaultRateLimit = (): SiteRateLimit => ({ enabled: true, events: 100, window: "1m" });

export interface AccessList {
  id: string;
  name: string;
  allow: string[] | null;
  deny: string[] | null;
  allowCountries: string[] | null;
  denyCountries: string[] | null;
  geoDb: string;
  users: { username: string; hasPassword: boolean }[] | null;
  usedBy: string[] | null;
  needsGeo: boolean;
  updatedAt?: string;
}

export interface AccessListsResponse {
  accessLists: AccessList[] | null;
  geoAvailable: boolean;
}

export interface CertInfo {
  name: string;
  domains: string[] | null;
  issuer: string;
  issuerKey: string;
  source: "letsencrypt" | "zerossl" | "internal" | "other";
  staging: boolean;
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  hoursLeft: number;
  serial: string;
  keyType: string;
  sites: string[] | null;
}

export interface PendingCert {
  site: string;
  domain: string;
  tls: SiteTLS;
  dnsProvider?: string;
  cloudflare: boolean;
  error?: string;
  hint: string;
}

export interface CertificatesResponse {
  certificates: CertInfo[] | null;
  storage: string;
  internalCA: boolean;
  pending: PendingCert[] | null;
}

export interface NavItem {
  page: string;
  label: string;
  icon?: string;
  pluginId: string;
  plugin: string;
}

export function fmtExpiry(c: { daysLeft: number; hoursLeft: number }): string {
  if (c.hoursLeft < 0) return "abgelaufen";
  if (c.daysLeft < 2) return `noch ${c.hoursLeft} h`;
  return `noch ${c.daysLeft} Tage`;
}

/** Badge colour for a certificate's remaining lifetime. Internal certs live 12 h by design. */
export function expiryKind(c: CertInfo): "ok" | "warn" | "err" {
  if (c.hoursLeft < 0) return "err";
  if (c.source === "internal") return "ok";
  if (c.daysLeft < 7) return "err";
  if (c.daysLeft < 21) return "warn";
  return "ok";
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
    accessList: "",
    enabled: true,
  };
}

/** Download a binary response (with the session cookie) as a file. */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const resp = await fetch(path, { credentials: "same-origin" });
  if (!resp.ok) {
    let msg = resp.statusText;
    try {
      msg = (await resp.json()).error || msg;
    } catch {
      /* not JSON */
    }
    throw new ApiError(resp.status, msg);
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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

// ---------- Analytics / Audit ----------

export type AnalyticsRange = "15m" | "1h" | "6h" | "24h" | "7d" | "30d";

export interface AnalyticsPoint {
  t: string;
  requests: number;
  s2xx: number;
  s3xx: number;
  s4xx: number;
  s5xx: number;
  blocked: number;
  bytes: number;
  bytesIn?: number;
  durSum: number;
  durMax: number;
  lat?: number[] | null;
  avgMs: number;
  p95Ms: number;
}

export interface TopEntry {
  key: string;
  count: number;
}

export interface AnalyticsReport {
  from: string;
  to: string;
  step: "1m" | "1h";
  series: AnalyticsPoint[] | null;
  totals: AnalyticsPoint;
  hosts: TopEntry[] | null;
  traffic?: { host: string; requests: number; bytesOut: number; bytesIn: number }[] | null;
  top: Record<string, TopEntry[] | null> | null;
}

export interface AnalyticsResponse {
  range: AnalyticsRange;
  accessLog: string;
  report: AnalyticsReport;
}

export interface RecentRequest {
  ts: string;
  host: string;
  method: string;
  uri: string;
  status: number;
  size: number;
  durationMs: number;
  ip: string;
  agent?: string;
}

export interface AuditEntry extends CfEvent {
  meta?: { method?: string; path?: string; status?: number; remote?: string; actor?: string; ms?: number } & Record<string, unknown>;
}

export function fmtNum(n?: number): string {
  if (n === undefined || n === null) return "–";
  return n.toLocaleString("de-DE");
}

export function fmtMs(ms?: number): string {
  if (!ms) return "–";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

// ---------- API tokens & MCP ----------

export type TokenScope = "read" | "write";

export interface ApiTokenInfo {
  id: string;
  name: string;
  scope: TokenScope;
  prefix: string;
  created: string;
  lastUsed?: string;
  expires?: string;
}

export interface TokenCreated {
  token: string;
  info: ApiTokenInfo;
}

export interface McpToolInfo {
  name: string;
  description: string;
  readOnly: boolean;
}

export interface McpInfo {
  endpoint: string;
  tools: McpToolInfo[] | null;
  uiCertAvailable: boolean;
}

/** Endpoint guess when /api/mcp/info is unavailable. */
export function defaultMcpEndpoint(): string {
  return `${window.location.origin}/mcp`;
}

export interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  dev: boolean;
  notesUrl: string;
  checkedAt: string;
}
export interface UpdateResponse {
  update: UpdateInfo;
  error: string;
  /** Running in the Docker image: updates come as a new image. */
  container?: boolean;
}

export interface BackupEntry {
  name: string;
  size: number;
  createdAt: string;
  kind: "auto" | "manual" | "pre-restore";
  encrypted: boolean;
}
export interface BackupSettings {
  daily: boolean;
  keep: number;
  certs: boolean;
}
export interface BackupManifest {
  format: number;
  version: string;
  createdAt: string;
  host: string;
  sites: number;
  files: number;
  bytes: number;
  secrets: boolean;
  certs: boolean;
  encrypted: boolean;
  reason?: string;
}
export interface BackupsResponse {
  backups: BackupEntry[];
  settings: BackupSettings;
  dir: string;
  lastAuto: string;
}
