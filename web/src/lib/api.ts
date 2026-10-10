// Typed client for /api/v1 (see api/openapi.json).

export type HealthStatus = "healthy" | "degraded" | "down" | "unknown" | "disabled";
export type Component = { name: string; status: HealthStatus; detail?: string; observed_at: string };
export type Health = { status: HealthStatus; components: Component[]; observed_at: string };

export type Version = {
  version: string; commit: string; build_date: string; api_version: string; go_version: string;
  os: string; arch: string; channel: string; schema_version: number;
};

export type JobState =
  | "Queued" | "Validating" | "ImpactAnalyzed" | "Staging" | "Preflight" | "Applying" | "Verifying"
  | "Succeeded" | "Blocked" | "Failed" | "Compensating" | "RolledBack" | "RecoveryRequired" | "Cancelled";

export type Job = {
  id: string; kind: string; state: JobState; actor_id?: string; lock_set: string[]; attempts: number;
  revision: number; created_at: string; updated_at: string; started_at?: string; finished_at?: string;
};

export type Page<T> = { items: T[]; next_cursor: string | null };

export type Stage = "mfa_enroll" | "pending_mfa" | "active";
export type Session = { user: { id: string; username: string; locale: string }; stage: Stage; permissions: string[]; step_up_until?: string };

export type SetupStep = { id: string; status: "complete" | "pending" | "planned"; phase?: number };
export type PreflightCheck = { id: string; status: "pass" | "warn" | "fail" | "info"; detail: string };
export type SetupStatus = {
  initialized: boolean; owner_ready: boolean; local_bootstrap: boolean; preflight_recorded?: boolean; steps: SetupStep[];
  preflight?: { hostname: string; os: string; arch: string; checks: PreflightCheck[]; nginx_state: string };
};

export type Grant = { role_id: string; role_name?: string; scope_kind: "global" | "website" | "route" | "domain"; scope_id: string };
export type User = {
  id: string; username: string; display_name: string; status: "active" | "disabled"; locale: "en" | "fa";
  mfa_enabled: boolean; last_login_at?: string; revision: number; created_at: string; updated_at: string; grants: Grant[];
};
export type Role = { id: string; name: string; builtin: boolean; description: string; permissions: string[]; revision: number };
export type Permission = { id: string; step_up: boolean };
export type APIToken = { id: string; name: string; prefix: string; scopes: string[]; expires_at?: string; last_used_at?: string; revoked_at?: string; created_at: string };
export type AuditEvent = {
  seq: number; id: string; at: string; actor_kind: string; actor_id: string; action: string; target_kind: string;
  target_id: string; result: "success" | "failure" | "denied"; request_id: string; context: Record<string, unknown>;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId?: string,
    public retryable = false,
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)ngm_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]!) : "";
}

// Registered by the StepUp provider: prompts for a TOTP code and resolves true
// once the server accepted it.
let stepUpHandler: (() => Promise<boolean>) | null = null;
export function setStepUpHandler(h: (() => Promise<boolean>) | null) {
  stepUpHandler = h;
}

// Notified when the server says the session is gone or needs MFA.
let authListener: ((code: string) => void) | null = null;
export function setAuthListener(h: ((code: string) => void) | null) {
  authListener = h;
}

type Opts = { method?: string; body?: unknown; headers?: Record<string, string>; retried?: boolean; raw?: Blob | ArrayBuffer; contentType?: string };

import { apiUrl } from "./base";

async function request<T>(path: string, o: Opts = {}): Promise<T> {
  const method = o.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", ...(o.headers ?? {}) };
  if (o.body !== undefined) headers["Content-Type"] = "application/json";
  if (o.raw !== undefined) headers["Content-Type"] = o.contentType ?? "application/octet-stream";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  let res: Response;
  try {
    res = await fetch(apiUrl(path), { method, credentials: "same-origin", headers, body: o.raw !== undefined ? o.raw : o.body !== undefined ? JSON.stringify(o.body) : undefined });
  } catch {
    throw new ApiError(0, "network", "network unreachable", undefined, true);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    /* non-JSON */
  }
  if (!res.ok && !(path.endsWith("/system/health") && res.status === 503)) {
    const e = (body as { error?: { code?: string; message?: string; request_id?: string; retryable?: boolean; details?: Record<string, unknown> } })?.error;
    const err = new ApiError(res.status, e?.code ?? "http_" + res.status, e?.message ?? res.statusText, e?.request_id, e?.retryable ?? false, e?.details);
    if (err.code === "step_up_required" && !o.retried && stepUpHandler) {
      if (await stepUpHandler()) return request<T>(path, { ...o, retried: true });
    }
    if ((res.status === 401) && authListener && !path.startsWith("/api/v1/auth/")) authListener(err.code);
    throw err;
  }
  return body as T;
}

// downloadFile fetches a non-JSON attachment and saves it, honouring the
// step-up flow (a 403 step_up_required prompts for 2FA then retries once).
export async function downloadFile(path: string, filename: string, retried = false): Promise<void> {
  const res = await fetch(apiUrl(path), { credentials: "same-origin", headers: { Accept: "application/x-pem-file" } });
  if (!res.ok) {
    let code = "http_" + res.status, message = res.statusText;
    try { const j = await res.clone().json(); code = j?.error?.code ?? code; message = j?.error?.message ?? message; } catch { /* non-JSON */ }
    if (code === "step_up_required" && !retried && stepUpHandler) {
      if (await stepUpHandler()) return downloadFile(path, filename, true);
    }
    throw new ApiError(res.status, code, message);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}

const q = (p: Record<string, string | number | null | undefined>) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  const str = s.toString();
  return str ? "?" + str : "";
};
const etag = (rev: number) => ({ "If-Match": `"r${rev}"` });

export const api = {
  health: () => request<Health>("/api/v1/system/health"),
  version: () => request<Version>("/api/v1/system/version"),
  jobs: (p: { limit?: number; cursor?: string | null } = {}) => request<Page<Job>>("/api/v1/jobs" + q(p)),

  setupStatus: () => request<SetupStatus>("/api/v1/setup/status"),
  setupOwner: (b: { bootstrap_token: string; username: string; display_name: string; password: string; locale: string }) =>
    request<{ stage: Stage }>("/api/v1/setup/owner", { method: "POST", body: b }),

  session: () => request<Session>("/api/v1/auth/session"),
  login: (username: string, password: string) => request<{ stage: Stage }>("/api/v1/auth/login", { method: "POST", body: { username, password } }),
  logout: () => request<void>("/api/v1/auth/logout", { method: "POST" }),
  mfaEnroll: () => request<{ secret: string; otpauth_uri: string }>("/api/v1/auth/mfa/enroll", { method: "POST" }),
  mfaConfirm: (code: string) => request<{ stage: Stage }>("/api/v1/auth/mfa/confirm", { method: "POST", body: { code } }),
  mfaVerify: (code: string) => request<{ stage: Stage }>("/api/v1/auth/mfa/verify", { method: "POST", body: { code } }),
  stepUp: (code: string) => request<{ step_up_until: string }>("/api/v1/auth/step-up", { method: "POST", body: { code } }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/v1/auth/password", { method: "POST", body: { current_password, new_password } }),

  users: () => request<{ items: User[] }>("/api/v1/users"),
  createUser: (b: { username: string; display_name: string; password: string; locale: string; grants: Grant[] }) =>
    request<User>("/api/v1/users", { method: "POST", body: b }),
  updateUser: (u: User, b: Partial<Pick<User, "display_name" | "status" | "locale">> & { grants?: Grant[] }) =>
    request<User>(`/api/v1/users/${u.id}`, { method: "PATCH", body: b, headers: etag(u.revision) }),
  deleteUser: (u: User) => request<void>(`/api/v1/users/${u.id}`, { method: "DELETE", headers: etag(u.revision) }),
  resetUserMFA: (u: User) => request<void>(`/api/v1/users/${u.id}/mfa-reset`, { method: "POST" }),

  permissions: () => request<{ items: Permission[] }>("/api/v1/permissions"),
  roles: () => request<{ items: Role[] }>("/api/v1/roles"),
  createRole: (b: { name: string; description: string; permissions: string[] }) => request<Role>("/api/v1/roles", { method: "POST", body: b }),
  updateRole: (r: Role, b: { name: string; description: string; permissions: string[] }) =>
    request<Role>(`/api/v1/roles/${r.id}`, { method: "PUT", body: b, headers: etag(r.revision) }),
  deleteRole: (r: Role) => request<void>(`/api/v1/roles/${r.id}`, { method: "DELETE", headers: etag(r.revision) }),

  tokens: () => request<{ items: APIToken[] }>("/api/v1/tokens"),
  createToken: (b: { name: string; scopes: string[]; expires_in_days: number }) => request<APIToken & { token: string }>("/api/v1/tokens", { method: "POST", body: b }),
  revokeToken: (id: string) => request<void>(`/api/v1/tokens/${id}`, { method: "DELETE" }),

  audit: (p: { limit?: number; cursor?: string | null; action?: string; result?: string } = {}) =>
    request<Page<AuditEvent>>("/api/v1/audit" + q(p)),
  auditVerify: () => request<{ events: number; ok: boolean; broken_at_seq?: number; reason?: string }>("/api/v1/audit/verify"),
};

// ─── Gateway (Phase 3) ─────────────────────────────────────────────────────

export type ListenerKind = "http" | "https" | "stream" | "stream_tls_front";
export type Listener = { id: string; name: string; kind: ListenerKind; address: string; port: number; family: string; enabled: boolean; options: { http2?: boolean; udp?: boolean }; revision: number };
export type Transport = "http" | "https" | "tcp";
export type Endpoint = {
  id: string; name: string; host: string; port: number; transport: Transport; tls_verify: boolean; tls_server_name?: string; weight: number;
  priority: number; connect_timeout_ms: number; read_timeout_ms: number; write_timeout_ms: number; disabled: boolean; revision: number;
};
export type PoolMember = { endpoint_id: string; weight: number; backup: boolean };
export type Pool = { id: string; name: string; strategy: "round_robin" | "least_conn" | "hash" | "failover"; members: PoolMember[]; revision: number };
export type MatchField = "sni" | "alpn" | "host" | "path_prefix" | "path_exact";
export type Match = { field: MatchField; operator: "exact" | "wildcard" | "prefix"; value: string };
export type Protocol = "http" | "tcp" | "tls_passthrough" | "tls_terminate_http";
export type DestKind = "pool" | "endpoint" | "redirect" | "reject" | "website";
export type RouteOptions = { websocket?: boolean; preserve_host?: boolean; connect_timeout_ms?: number; read_timeout_ms?: number; send_timeout_ms?: number; client_max_body_mb?: number; redirect_url?: string; redirect_code?: number; stream_timeout_ms?: number; backend_proxy_protocol?: boolean };
export type Route = {
  id: string; name: string; listener_id: string; protocol: Protocol; priority: number; destination_kind: DestKind; destination_id?: string;
  is_fallback: boolean; certificate_id?: string; matches: Match[]; options: RouteOptions; enabled: boolean; revision: number;
};
export type RouteInput = Omit<Route, "id" | "revision">;
export type Certificate = { id: string; name: string; source: string; sans: string[]; issuer: string; not_before: string; not_after: string; fingerprint_sha256: string; status: string; has_key: boolean; revision: number; acme?: { directory: string; identifiers: string[]; last_attempt?: string; last_error?: string; renewals: number } };
export type Issue = { severity: "error" | "warning"; code: string; message: string; ref?: string };
export type Validation = { valid: boolean; issues: Issue[]; capabilities: Record<string, unknown>; preview?: { files: Record<string, string>; listens: string[] }; preview_error?: string };
export type SimInput = { model?: "desired" | "active"; listener_id?: string; address?: string; port?: number; sni?: string; alpn?: string[]; host?: string; path?: string; ech?: boolean };
export type SimStep = { stage: string; decision: string; reason: string };
export type SimResult = { matched: boolean; listener_id?: string; route_id?: string; route_name?: string; outcome: string; destination?: string; fallback: boolean; trace: SimStep[]; uncertainty: string[] };
export type FileDiff = { file: string; change: string; lines_added: number; lines_removed: number };
export type Generation = {
  id: string; number: number; status: "staged" | "active" | "superseded" | "failed" | "rolled_back"; job_id?: string; created_at: string; activated_at?: string;
  summary: { model_hash?: string; listens?: string[]; diff?: FileDiff[]; warnings?: Issue[] };
};
export type JobStep = { id: string; seq: number; name: string; from_state?: string; to_state?: string; class: string; status: string; evidence: unknown; started_at: string; finished_at?: string };
export type JobDetail = Job & { result?: unknown; error?: { code?: string; message?: string; details?: unknown } };

const crud = <T extends { id: string; revision: number }, I>(base: string) => ({
  list: () => request<{ items: T[] }>(base),
  create: (b: I) => request<T>(base, { method: "POST", body: b }),
  update: (x: T, b: I) => request<T>(`${base}/${x.id}`, { method: "PUT", body: b, headers: etag(x.revision) }),
  remove: (x: T) => request<void>(`${base}/${x.id}`, { method: "DELETE", headers: etag(x.revision) }),
});

export const gw = {
  listeners: crud<Listener, Omit<Listener, "id" | "revision" | "family">>("/api/v1/listeners"),
  endpoints: crud<Endpoint, Omit<Endpoint, "id" | "revision">>("/api/v1/backends"),
  pools: crud<Pool, Omit<Pool, "id" | "revision">>("/api/v1/pools"),
  routes: crud<Route, RouteInput>("/api/v1/routes"),
  certificates: {
    list: () => request<{ items: Certificate[] }>("/api/v1/certificates"),
    import: (b: { name: string; cert_pem: string; key_pem: string }) => request<Certificate>("/api/v1/certificates", { method: "POST", body: b }),
    selfSigned: (b: { name: string; hosts: string[]; days: number }) => request<Certificate>("/api/v1/certificates/self-signed", { method: "POST", body: b }),
    remove: (c: Certificate) => request<void>(`/api/v1/certificates/${c.id}`, { method: "DELETE", headers: etag(c.revision) }),
  },
  validate: (preview = false) => request<Validation>("/api/v1/gateway/validation" + (preview ? "?preview=1" : "")),
  simulate: (b: SimInput) => request<{ result: SimResult; model_valid: boolean }>("/api/v1/gateway/simulate", { method: "POST", body: b }),
  deployments: () => request<{ items: Generation[] }>("/api/v1/deployments"),
  apply: (b: { disable_distro_default_site?: boolean; force?: boolean; note?: string }, key: string) =>
    request<{ job_id: string; status: string }>("/api/v1/deployments", { method: "POST", body: b, headers: { "Idempotency-Key": key } }),
  rollback: (generation_id: string, key: string) =>
    request<{ job_id: string; status: string }>("/api/v1/deployments/rollback", { method: "POST", body: { generation_id }, headers: { "Idempotency-Key": key } }),
  job: (id: string) => request<JobDetail>(`/api/v1/jobs/${id}`),
  jobSteps: (id: string) => request<{ items: JobStep[] }>(`/api/v1/jobs/${id}/steps`),
};

// ─── Operations (Phase 4) ──────────────────────────────────────────────────

export type EndpointHealth = { endpoint_id: string; status: "healthy" | "down" | "degraded" | "unknown" | "disabled"; latency_ms: number; detail: string; observed_at: string; stale: boolean };
export type FWRule = { id: string; key: string; action: "allow" | "deny" | "limit"; proto: "tcp" | "udp"; port: number; source: string; active_state: "present" | "absent" | "unknown"; revision: number; updated_at: string };
export type FWObserved = { installed: boolean; active: boolean; defaults: string; owned: Record<string, string>; foreign: string[]; ssh_ports: number[]; ssh_peers: string[]; ssh_open: boolean };
export type BackupManifest = { created: string; hostname: string; ngm_version: string; schema_version: number; counts: Record<string, number>; files: unknown[] };
export type Backup = { id: string; file_name: string; size_bytes: number; sha256: string; status: string; trigger: string; created_by?: string; created_at: string; manifest: BackupManifest };
export type BackupSchedule = { enabled: boolean; interval_hours: number; retain: number };
export type RecoveryAction = { code: string; command?: string };
export type Incident = {
  id: string; job_id?: string; job_kind?: string; job_state?: string; status: "open" | "in_progress" | "resolved"; summary: string; evidence: unknown;
  opened_at: string; resolved_at?: string; resolved_by?: string; revision: number; actions: RecoveryAction[];
};
type Accepted = { job_id: string; status: string; replayed: boolean };

export const ops = {
  backendHealth: () => request<{ items: EndpointHealth[] }>("/api/v1/monitoring/backends"),
  firewall: {
    get: () => request<{ rules: FWRule[]; observed: FWObserved | null; observed_at?: string }>("/api/v1/firewall"),
    create: (b: { key: string; action: string; proto: string; port: number; source: string }) => request<FWRule>("/api/v1/firewall/rules", { method: "POST", body: b }),
    fromListeners: () => request<{ created: string[] }>("/api/v1/firewall/rules/from-listeners", { method: "POST" }),
    remove: (r: FWRule) => request<void>(`/api/v1/firewall/rules/${r.id}`, { method: "DELETE", headers: etag(r.revision) }),
    apply: (enable: boolean, key: string) => request<Accepted>("/api/v1/firewall/apply", { method: "POST", body: { enable }, headers: { "Idempotency-Key": key } }),
    confirm: (job_id: string) => request<{ confirmed: boolean }>("/api/v1/firewall/confirm", { method: "POST", body: { job_id } }),
  },
  backups: {
    list: () => request<{ items: Backup[] }>("/api/v1/backups"),
    settings: () => request<{ passphrase_configured: boolean; schedule: BackupSchedule; storage_warning: string }>("/api/v1/backups/settings"),
    setPassphrase: (passphrase: string) => request<{ warning: string }>("/api/v1/backups/passphrase", { method: "POST", body: { passphrase } }),
    setSchedule: (s: BackupSchedule) => request<BackupSchedule>("/api/v1/backups/schedule", { method: "PUT", body: s }),
    create: (key: string) => request<Accepted>("/api/v1/backups", { method: "POST", headers: { "Idempotency-Key": key } }),
    verify: (id: string) => request<{ ok: boolean; manifest: BackupManifest }>(`/api/v1/backups/${id}/verify`, { method: "POST" }),
    remove: (id: string) => request<void>(`/api/v1/backups/${id}`, { method: "DELETE" }),
    downloadUrl: (id: string) => apiUrl(`/api/v1/backups/${id}/download`),
  },
  recovery: {
    list: (open = false) => request<{ items: Incident[] }>("/api/v1/recovery/incidents" + (open ? "?status=open" : "")),
    get: (id: string) => request<{ incident: Incident; job?: JobDetail; steps?: JobStep[]; drift?: { serving: string; recorded: string; observed_at: string } | null; drift_error?: string }>(`/api/v1/recovery/incidents/${id}`),
    drift: () => request<{ drift: { serving: string; recorded: string; observed_at: string } | null; evidence: boolean; detail?: string }>("/api/v1/recovery/drift"),
    reconcileDrift: (mode: "adopt" | "restore") => request<Accepted>("/api/v1/recovery/reconcile", { method: "POST", body: { mode } }),
    reconcile: (id: string, mode: "adopt" | "restore") => request<Accepted>(`/api/v1/recovery/incidents/${id}/reconcile`, { method: "POST", body: { mode } }),
    resolve: (id: string, outcome: "rolled_back" | "failed" | "succeeded", note: string) =>
      request<Incident>(`/api/v1/recovery/incidents/${id}/resolve`, { method: "POST", body: { outcome, note } }),
  },
};

// ─── Domains, DNS, ACME, websites (Phase 5) ────────────────────────────────

export type DnsType = "A" | "AAAA" | "CNAME" | "CAA" | "NS" | "TXT";
export type Expectation = { id: string; name: string; type: DnsType; value: string; ttl?: number };
export type DnsObservation = { name: string; type: string; source: "authoritative" | "resolver"; server: string; values: string[]; ttl?: number; rcode: string; error?: string; observed_at: string };
export type DnsCompare = { name: string; type: string; value: string; status: "match" | "mismatch" | "missing" | "propagating" | "unknown"; detail: string };
export type Domain = {
  id: string; fqdn: string; purpose: "general" | "management" | "website" | "route"; notes: string; dns_provider: string; provider_zone_id?: string; revision: number;
  created_at: string; updated_at: string; dns_status: "ok" | "attention" | "unknown"; checked_at?: string;
  expectations: Expectation[]; observations: DnsObservation[]; comparison: DnsCompare[];
};
export type DomainUse = { kind: string; id?: string; name: string; what: string };
export type CfChange = { action: "create" | "update" | "conflict" | "unchanged"; desired: { name: string; type: string; value: string; ttl: number }; current?: { id: string; content: string; comment?: string }; reason?: string };
export type CfPlan = { zone_id: string; zone_name: string; changes: CfChange[]; external_records_untouched: number; hash: string };

export type L10n = Record<string, string>;
export type SiteItem = { title?: L10n; text?: L10n; image?: string; href?: string };
export type SiteBlock = { type: string; heading?: L10n; text?: L10n; label?: L10n; href?: string; image?: string; items?: SiteItem[] };
export type SitePage = { slug: string; kind?: string; title: L10n; description?: L10n; date?: string; blocks: SiteBlock[]; hidden?: boolean };
export type SiteContent = { site: { title: L10n; tagline?: L10n; footer?: L10n; base_url?: string; accent?: string }; pages: SitePage[] };
export type Website = {
  id: string; name: string; kind: "template" | "static_zip"; template?: string; default_locale: string; locales: string[]; active_version_id?: string;
  draft_revision: number; revision: number; created_at: string; updated_at: string; content?: SiteContent; has_upload: boolean;
};
export type SiteVersion = { id: string; number: number; status: "built" | "published" | "superseded" | "failed"; content_hash: string; size_bytes: number; created_at: string; published_at?: string };
export type SiteMedia = { name: string; mime: string; size_bytes: number; sha256: string; created_at: string };

export const web = {
  domains: {
    list: () => request<{ items: Domain[] }>("/api/v1/domains"),
    get: (id: string) => request<{ domain: Domain; usage: DomainUse[] }>(`/api/v1/domains/${id}`),
    create: (b: { fqdn: string; purpose: string; notes: string }) => request<Domain>("/api/v1/domains", { method: "POST", body: b }),
    remove: (d: Domain) => request<void>(`/api/v1/domains/${d.id}`, { method: "DELETE", headers: etag(d.revision) }),
    addExpectation: (id: string, b: { name: string; type: DnsType; value: string; ttl?: number }) => request<Domain>(`/api/v1/domains/${id}/expectations`, { method: "POST", body: b }),
    removeExpectation: (id: string, eid: string) => request<void>(`/api/v1/domains/${id}/expectations/${eid}`, { method: "DELETE" }),
    check: (id: string) => request<{ requested: boolean }>(`/api/v1/domains/${id}/check`, { method: "POST" }),
    cfPreview: (id: string, key: string) => request<Accepted>(`/api/v1/domains/${id}/cloudflare/preview`, { method: "POST", headers: { "Idempotency-Key": key } }),
    cfApply: (id: string, plan_hash: string, adopt: string[], key: string) =>
      request<Accepted>(`/api/v1/domains/${id}/cloudflare/apply`, { method: "POST", body: { plan_hash, adopt }, headers: { "Idempotency-Key": key } }),
  },
  cloudflare: {
    get: () => request<{ configured: boolean; required_permissions: string; note: string }>("/api/v1/integrations/cloudflare"),
    set: (token: string) => request<{ configured: boolean }>("/api/v1/integrations/cloudflare", { method: "PUT", body: { token } }),
    remove: () => request<void>("/api/v1/integrations/cloudflare", { method: "DELETE" }),
  },
  acme: (b: { name: string; identifiers: string[]; directory: string; email: string }, key: string) =>
    request<Accepted>("/api/v1/certificates/acme", { method: "POST", body: b, headers: { "Idempotency-Key": key } }),
  renew: (id: string, key: string) => request<Accepted>(`/api/v1/certificates/${id}/renew`, { method: "POST", headers: { "Idempotency-Key": key } }),
  sites: {
    templates: () => request<{ templates: string[]; locales: Record<string, string> }>("/api/v1/websites/templates"),
    list: () => request<{ items: Website[] }>("/api/v1/websites"),
    get: (id: string) => request<{ website: Website; errors: string[]; warnings: string[]; routes: string[] }>(`/api/v1/websites/${id}`),
    create: (b: { name: string; kind: string; template?: string; default_locale: string; locales: string[] }) => request<Website>("/api/v1/websites", { method: "POST", body: b }),
    update: (w: Website, b: { name: string; default_locale: string; locales: string[] }) => request<Website>(`/api/v1/websites/${w.id}`, { method: "PATCH", body: b, headers: etag(w.revision) }),
    remove: (id: string, key: string) => request<Accepted>(`/api/v1/websites/${id}`, { method: "DELETE", headers: { "Idempotency-Key": key } }),
    saveContent: (id: string, draftRevision: number, c: SiteContent) =>
      request<{ website: Website; errors: string[]; warnings: string[] }>(`/api/v1/websites/${id}/content`, {
        method: "PUT", raw: new Blob([JSON.stringify(c)]), contentType: "application/json", headers: { "X-Draft-Revision": String(draftRevision) },
      }),
    media: (id: string) => request<{ items: SiteMedia[] }>(`/api/v1/websites/${id}/media`),
    mediaUrl: (id: string, name: string) => apiUrl(`/api/v1/websites/${id}/media/${encodeURIComponent(name)}`),
    addMedia: (id: string, f: File) => request<SiteMedia>(`/api/v1/websites/${id}/media?name=${encodeURIComponent(f.name)}`, { method: "POST", raw: f, contentType: f.type || "application/octet-stream" }),
    removeMedia: (id: string, name: string) => request<void>(`/api/v1/websites/${id}/media/${encodeURIComponent(name)}`, { method: "DELETE" }),
    upload: (id: string, f: File) => request<{ bytes: number }>(`/api/v1/websites/${id}/upload`, { method: "POST", raw: f, contentType: "application/zip" }),
    build: (id: string, key: string) => request<Accepted>(`/api/v1/websites/${id}/build`, { method: "POST", headers: { "Idempotency-Key": key } }),
    versions: (id: string) => request<{ items: SiteVersion[] }>(`/api/v1/websites/${id}/versions`),
    publish: (id: string, version_id: string, key: string) => request<Accepted>(`/api/v1/websites/${id}/publish`, { method: "POST", body: { version_id }, headers: { "Idempotency-Key": key } }),
    previewLink: (id: string, vid: string) => request<{ url: string; expires_at: string }>(`/api/v1/websites/${id}/versions/${vid}/preview`, { method: "POST" }),
  },
};

// ─── Operations & UX (Phase 6) ─────────────────────────────────────────────

export type AlertItem = { id: string; rule: string; subject: string; severity: "info" | "warning" | "critical"; state: "firing" | "acknowledged" | "resolved"; message: string; first_at: string; last_at: string; resolved_at?: string; acknowledged_by?: string };
export type SysMetrics = { cpu_pct: number; load1: number; mem_used: number; mem_total: number; disk_used: number; disk_total: number; cpus: number; at: string };
export type MetricPoint = { ts: number; cpu_pct: number; load1: number; mem_used: number; mem_total: number; disk_used: number; disk_total: number };
export type LogEntry = { id: number; ts: number; category: string; severity: string; source: string; host?: string; route?: string; status?: number; method?: string; path?: string; ip?: string; duration_s?: number; message: string };
export type NotifyTarget = { id: string; name: string; kind: "telegram" | "webhook"; chat_id?: string; url?: string; min_severity: string; enabled: boolean; has_secret: boolean; revision: number };
export type Delivery = { id: string; target_id: string; alert_id?: string; event: string; status: string; attempts: number; last_error?: string; created_at: string; sent_at?: string };
export type PerfValue = { name: string; context: string; unit: string; min: number; max: number; default: number; override?: number; effective: number; note?: string };
export type PerfView = { recommended: string; profile: string; selected?: string; values: PerfValue[]; internal: { monitor_concurrency: number; log_batch: number }; reason: string };
export type TopoNode = { id: string; kind: string; label: string; status?: string; attrs?: Record<string, string> };
export type TopoEdge = { from: string; to: string; type: string; traffic: boolean };
export type LogQuery = { category?: string; q?: string; status?: string; host?: string; route?: string; severity?: string; before?: string; limit?: number };

export const opsx = {
  alerts: (open = false) => request<{ items: AlertItem[] }>("/api/v1/alerts" + (open ? "?state=open" : "")),
  ack: (id: string) => request<void>(`/api/v1/alerts/${id}/ack`, { method: "POST" }),
  system: (hours = 24) => request<{ current: SysMetrics | null; observed_at?: string; stale?: boolean; history: MetricPoint[] }>(`/api/v1/monitoring/system?hours=${hours}`),
  logs: (p: LogQuery) => request<{ items: LogEntry[]; next_before: string | null }>("/api/v1/logs" + q(p)),
  logStatus: () => request<{ status: { paused: boolean; reason?: string; sources: { path: string; lag_bytes: number; error?: string }[] } | null; observed_at?: string; retention_days: Record<string, number> }>("/api/v1/logs/status"),
  logExportUrl: (p: LogQuery, format: string) => apiUrl("/api/v1/logs/export" + q({ ...p, format, limit: 10000 })),
  logTailUrl: (p: LogQuery) => apiUrl("/api/v1/logs/tail" + q(p)),
  targets: () => request<{ items: NotifyTarget[] }>("/api/v1/notifications/targets"),
  createTarget: (b: { name: string; kind: string; chat_id?: string; url?: string; secret?: string; min_severity: string; enabled: boolean }) => request<NotifyTarget>("/api/v1/notifications/targets", { method: "POST", body: b }),
  setTarget: (id: string, enabled: boolean) => request<NotifyTarget>(`/api/v1/notifications/targets/${id}`, { method: "PATCH", body: { enabled } }),
  deleteTarget: (id: string) => request<void>(`/api/v1/notifications/targets/${id}`, { method: "DELETE" }),
  testTarget: (id: string) => request<{ delivery_id: string }>(`/api/v1/notifications/targets/${id}/test`, { method: "POST" }),
  deliveries: () => request<{ items: Delivery[] }>("/api/v1/notifications/deliveries"),
  perf: () => request<{ view: PerfView; profiles: string[]; not_managed: Record<string, string>; note: string }>("/api/v1/performance"),
  savePerf: (b: { profile: string; overrides: Record<string, number> }) => request<{ view: PerfView }>("/api/v1/performance", { method: "PUT", body: b }),
  topology: (view: "desired" | "active") => request<{ nodes: TopoNode[]; edges: TopoEdge[]; truncated: boolean }>(`/api/v1/topology?view=${view}`),
  impact: (node: string, view: string) => request<{ node: string; affected: TopoNode[]; critical: string[] }>(`/api/v1/topology/impact?node=${encodeURIComponent(node)}&view=${view}`),
};

export type UpdateInfo = {
  version: string; channel: string;
  releases: { version: string; signed: boolean; current: boolean }[];
  last_update: { from: string; to: string; phase: string; error?: string; started_at: string; finished_at?: string } | null;
  commands: Record<string, string>;
};
export const lifecycleApi = { updates: () => request<UpdateInfo>("/api/v1/system/updates") };

export type FallbackSetting = { fallback: { website_id: string; certificate_id: string }; enabled: boolean; note: string };
export const fallbackApi = {
  get: () => request<FallbackSetting>("/api/v1/gateway/fallback"),
  put: (b: { website_id: string; certificate_id: string }) => request<FallbackSetting>("/api/v1/gateway/fallback", { method: "PUT", body: b }),
};
