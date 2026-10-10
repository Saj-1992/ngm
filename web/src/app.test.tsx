import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { I18nProvider, type Locale } from "./i18n/i18n";
import { en, fa } from "./i18n/messages";
import { SessionProvider } from "./lib/session";
import { ThemeProvider } from "./lib/theme";

const health = {
  status: "unknown",
  observed_at: "2026-10-08T00:00:00Z",
  components: [
    { name: "api", status: "healthy", observed_at: "2026-10-08T00:00:00Z" },
    { name: "nginx", status: "unknown", detail: "no runtime observation available", observed_at: "2026-10-08T00:00:00Z" },
  ],
};
const version = { version: "0.1.0-dev", commit: "x", build_date: "", api_version: "v1", go_version: "go1.26", os: "linux", arch: "amd64", channel: "development", schema_version: 1 };

function mockFetch(overrides: Record<string, { status: number; body: unknown }> = {}) {
  const routes: Record<string, { status: number; body: unknown }> = {
    "/api/v1/system/health": { status: 200, body: health },
    "/api/v1/system/version": { status: 200, body: version },
    "/api/v1/jobs": { status: 200, body: { items: [], next_cursor: null } },
    "/api/v1/setup/status": { status: 200, body: { initialized: true, owner_ready: true, local_bootstrap: true, steps: [] } },
    "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read", "users.read"] } },
    ...overrides,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const path = input.split("?")[0]!;
      const r = routes[path] ?? { status: 404, body: { error: { code: "not_found", message: "nf", request_id: "r", retryable: false } } };
      return new Response(JSON.stringify(r.body), { status: r.status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

function renderAt(path: string, locale: Locale = "en") {
  return render(
    <ThemeProvider>
      <I18nProvider initial={locale}>
        <MemoryRouter initialEntries={[path]}>
          <SessionProvider>
            <App />
          </SessionProvider>
        </MemoryRouter>
      </I18nProvider>
    </ThemeProvider>,
  );
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
});
afterEach(() => vi.unstubAllGlobals());

describe("i18n catalogs", () => {
  it("fa has every en key with a non-empty translation", () => {
    for (const k of Object.keys(en) as (keyof typeof en)[]) {
      expect(fa[k], k).toBeTruthy();
    }
  });
  it("placeholders match between locales", () => {
    const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(",");
    for (const k of Object.keys(en) as (keyof typeof en)[]) expect(ph(fa[k]), k).toBe(ph(en[k]));
  });
});

describe("dashboard", () => {
  it("renders real health data and never shows unknown as healthy", async () => {
    mockFetch();
    renderAt("/");
    await waitFor(() => expect(screen.getByText("nginx")).toBeInTheDocument());
    expect(screen.getAllByText("Unknown").length).toBeGreaterThanOrEqual(2); // nginx + overall
    expect(screen.getAllByText("v1")).toHaveLength(2); // API version + schema version
    expect(screen.getByText("No jobs have run yet.")).toBeInTheDocument();
  });

  it("switches to RTL for Persian", async () => {
    mockFetch({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "fa" }, stage: "active", permissions: ["system.read", "jobs.read"] } } });
    renderAt("/", "fa");
    await waitFor(() => expect(document.documentElement.dir).toBe("rtl"));
    expect(document.documentElement.lang).toBe("fa");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("داشبورد");
  });

  it("shows sign-in required on 401 instead of fake data", async () => {
    const unauth = { status: 401, body: { error: { code: "unauthenticated", message: "authentication required", request_id: "abc", retryable: false } } };
    mockFetch({ "/api/v1/system/version": unauth, "/api/v1/jobs": unauth });
    renderAt("/");
    await waitFor(() => expect(screen.getAllByText("Sign-in required").length).toBeGreaterThanOrEqual(2));
  });
});

describe("phase 6 pages", () => {
  it("renders help and opens the command palette with Ctrl+K", async () => {
    mockFetch();
    renderAt("/system/help");
    expect(await screen.findByText("Safe Apply")).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(await screen.findByPlaceholderText("Go to…")).toBeInTheDocument();
  });
  it("shows the performance table with bounded overrides", async () => {
    mockFetch({ "/api/v1/performance": { status: 200, body: { profiles: ["low", "balanced", "high"], not_managed: { worker_processes: "nginx.conf" }, note: "n",
      view: { recommended: "balanced", reason: "2 cpus", internal: { monitor_concurrency: 8, log_batch: 500 }, values: [{ name: "keepalive_timeout", unit: "s", min: 1, max: 300, default: 65, effective: 65 }] } } } });
    renderAt("/system/performance");
    expect(await screen.findByText("keepalive_timeout")).toBeInTheDocument();
    expect(screen.getByText("worker_processes")).toBeInTheDocument();
  });
});

const unauth = { status: 401, body: { error: { code: "unauthenticated", message: "authentication required", request_id: "r", retryable: false } } };

describe("auth routing", () => {
  it("shows the setup wizard before the owner exists", async () => {
    mockFetch({
      "/api/v1/setup/status": { status: 200, body: { initialized: false, owner_ready: false, local_bootstrap: true, steps: [{ id: "preflight", status: "pending" }, { id: "owner", status: "pending" }, { id: "certificate", status: "planned", phase: 5 }] } },
      "/api/v1/auth/session": unauth,
    });
    renderAt("/");
    expect(await screen.findByText("First-run setup")).toBeInTheDocument();
    expect(screen.getByLabelText("Bootstrap token")).toBeInTheDocument();
    expect(screen.getByText("Phase 5")).toBeInTheDocument();
  });
  it("shows sign-in when there is no session", async () => {
    mockFetch({ "/api/v1/auth/session": unauth });
    renderAt("/system/users");
    expect(await screen.findByRole("heading", { name: "Sign in to NGM" })).toBeInTheDocument();
  });
  it("asks for a TOTP code in the pending_mfa stage", async () => {
    mockFetch({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "pending_mfa", permissions: [] } } });
    renderAt("/");
    expect(await screen.findByText("Two-factor verification")).toBeInTheDocument();
  });
  it("hides navigation entries the user lacks permission for", async () => {
    mockFetch({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U2", username: "viewer", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read"] } } });
    renderAt("/");
    await screen.findByText("nginx");
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Audit log" })).toBeNull();
    expect(screen.getAllByRole("link", { name: "Settings" }).length).toBeGreaterThan(0);
  });
});

describe("recovery routing", () => {
  it("after an MFA reset, an initialized gateway shows sign-in, not the setup wizard", async () => {
    mockFetch({
      "/api/v1/setup/status": { status: 200, body: { initialized: true, owner_ready: false, local_bootstrap: true, steps: [] } },
      "/api/v1/auth/session": unauth,
    });
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Sign in to NGM" })).toBeInTheDocument();
    expect(screen.queryByText("First-run setup")).toBeNull();
  });
  it("enrolment after reset uses the standalone screen", async () => {
    mockFetch({
      "/api/v1/setup/status": { status: 200, body: { initialized: true, owner_ready: false, local_bootstrap: true, steps: [] } },
      "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "mfa_enroll", permissions: [] } },
      "/api/v1/auth/mfa/enroll": { status: 200, body: { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/NGM:owner?secret=JBSWY3DPEHPK3PXP" } },
    });
    renderAt("/");
    expect(await screen.findByText("Set up two-factor authentication")).toBeInTheDocument();
    expect(screen.queryByText("First-run setup")).toBeNull();
  });
});

describe("gateway pages", () => {
  const L = { id: "L1", name: "web", kind: "http", address: "0.0.0.0", port: 80, family: "ipv4", enabled: true, options: {}, revision: 1 };
  const R = { id: "R1", name: "site", listener_id: "L1", protocol: "http", priority: 100, destination_kind: "endpoint", destination_id: "E1", is_fallback: false,
    matches: [{ field: "host", operator: "exact", value: "a.example.com" }], options: { websocket: true }, enabled: true, revision: 1 };
  const E = { id: "E1", name: "app", host: "127.0.0.1", port: 8080, transport: "http", tls_verify: true, weight: 1, priority: 0, connect_timeout_ms: 5000, read_timeout_ms: 60000, write_timeout_ms: 60000, disabled: false, revision: 1 };
  const gwRoutes = {
    "/api/v1/listeners": { status: 200, body: { items: [L] } },
    "/api/v1/routes": { status: 200, body: { items: [R] } },
    "/api/v1/backends": { status: 200, body: { items: [E] } },
    "/api/v1/pools": { status: 200, body: { items: [] } },
    "/api/v1/certificates": { status: 200, body: { items: [] } },
    "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read", "gateway.read", "gateway.write", "deploy.apply", "certificates.read"] } },
  };
  it("routes page lists routes with protocol, matches and destination", async () => {
    mockFetch(gwRoutes);
    renderAt("/gateway/routes");
    expect(await screen.findByText("site")).toBeInTheDocument();
    expect(screen.getByText("a.example.com")).toBeInTheDocument();
    expect(screen.getByText("WS")).toBeInTheDocument();
    expect(screen.getByText(/saved as desired state/)).toBeInTheDocument();
  });
  it("simulation lab shows outcome, trace and limits", async () => {
    mockFetch({ ...gwRoutes, "/api/v1/gateway/simulate": { status: 200, body: { model_valid: true, result: { matched: true, outcome: "proxy_http", route_name: "site", destination: "endpoint app", fallback: false,
      trace: [{ stage: "listener", decision: "web", reason: "HTTP listener" }], uncertainty: ["Simulation reflects the compiled configuration model"] } } } });
    renderAt("/gateway/simulation");
    const btn = await screen.findByRole("button", { name: "Simulate" });
    await waitFor(() => expect(btn).not.toBeDisabled());
    btn.click();
    expect(await screen.findByText("Proxied (HTTP)")).toBeInTheDocument();
    expect(screen.getByText(/compiled configuration model/)).toBeInTheDocument();
  });
  it("deployments page shows validation state and disables apply when invalid", async () => {
    mockFetch({ ...gwRoutes, "/api/v1/gateway/validation": { status: 200, body: { valid: false, issues: [{ severity: "error", code: "route_conflict", message: "routes collide" }], capabilities: {} } },
      "/api/v1/deployments": { status: 200, body: { items: [] } } });
    renderAt("/ops/deployments");
    expect(await screen.findByText("routes collide")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Apply/ })).toBeDisabled();
  });
});

describe("operations pages", () => {
  const sess = (perms: string[]) => ({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read", ...perms] } } });
  it("firewall shows observed UFW state, foreign rules and owned rule state", async () => {
    mockFetch({ ...sess(["firewall.read", "firewall.write"]), "/api/v1/firewall": { status: 200, body: {
      rules: [{ id: "F1", key: "web", action: "allow", proto: "tcp", port: 80, source: "any", active_state: "absent", revision: 1, updated_at: "2026-10-08T00:00:00Z" }],
      observed: { installed: true, active: false, defaults: "deny (incoming), allow (outgoing)", owned: {}, foreign: ["ufw allow 8443/tcp"], ssh_ports: [22], ssh_peers: [], ssh_open: false },
      observed_at: "2026-10-08T00:00:00Z" } } });
    renderAt("/ops/firewall");
    expect(await screen.findByText("ngm:web")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.getByText("Not applied")).toBeInTheDocument();
    expect(screen.getByText("ufw allow 8443/tcp")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply to UFW" })).toBeEnabled();
  });
  it("firewall without evidence never claims a state", async () => {
    mockFetch({ ...sess(["firewall.read"]), "/api/v1/firewall": { status: 200, body: { rules: [], observed: null } } });
    renderAt("/ops/firewall");
    expect(await screen.findByText(/No observation yet/)).toBeInTheDocument();
    expect(screen.queryByText("Active")).toBeNull();
    expect(screen.queryByRole("button", { name: "Apply to UFW" })).toBeNull(); // read-only user
  });
  it("backups page warns about local-only storage and requires a passphrase first", async () => {
    mockFetch({ ...sess(["backups.read", "backups.create", "settings.write"]),
      "/api/v1/backups": { status: 200, body: { items: [] } },
      "/api/v1/backups/settings": { status: 200, body: { passphrase_configured: false, schedule: { enabled: false, interval_hours: 24, retain: 7 }, storage_warning: "x" } } });
    renderAt("/ops/backups");
    expect(await screen.findByText(/stored only on this server/)).toBeInTheDocument();
    expect(await screen.findByText(/Set a recovery passphrase/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create backup/ })).toBeDisabled();
  });
  it("backups list offers download and shows archive metadata", async () => {
    mockFetch({ ...sess(["backups.read", "backups.create"]),
      "/api/v1/backups": { status: 200, body: { items: [{ id: "B1", file_name: "ngm-h-20261008T000000Z-manual.ngmbak", size_bytes: 20480, sha256: "aa", status: "complete", trigger: "manual", created_at: "2026-10-08T00:00:00Z",
        manifest: { created: "2026-10-08T00:00:00Z", hostname: "h", ngm_version: "0.4.0-dev", schema_version: 3, counts: {}, files: [] } }] } },
      "/api/v1/backups/settings": { status: 200, body: { passphrase_configured: true, schedule: { enabled: true, interval_hours: 24, retain: 7 }, storage_warning: "x" } } });
    renderAt("/ops/backups");
    expect(await screen.findByText("ngm-h-20261008T000000Z-manual.ngmbak")).toBeInTheDocument();
    expect(screen.getByText(/schema v3/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Download/ })).toHaveAttribute("href", "/api/v1/backups/B1/download");
    expect(screen.getByRole("button", { name: /Create backup/ })).toBeEnabled();
  });
  it("recovery center lists open incidents and says changes are blocked", async () => {
    mockFetch({ ...sess(["recovery.read"]), "/api/v1/recovery/incidents": { status: 200, body: { items: [{ id: "I1", job_id: "J1", job_kind: "deploy.gateway", job_state: "RecoveryRequired", status: "open",
      summary: "reload outcome unknown", evidence: {}, opened_at: "2026-10-08T00:00:00Z", revision: 1, actions: [{ code: "nginx_test", command: "sudo nginx -t" }] }] } } });
    renderAt("/ops/recovery");
    expect(await screen.findByText("reload outcome unknown")).toBeInTheDocument();
    expect(screen.getByText(/1 open incident/)).toBeInTheDocument();
  });
  it("recovery detail with drift offers reconcile instead of manual resolve", async () => {
    const I = { id: "I1", job_id: "J1", job_kind: "deploy.gateway", job_state: "RecoveryRequired", status: "open", summary: "helper response: EOF", evidence: {}, opened_at: "2026-10-08T00:00:00Z", revision: 1, actions: [{ code: "nginx_test", command: "sudo nginx -t" }] };
    mockFetch({ ...sess(["recovery.read", "recovery.write"]), "/api/v1/recovery/incidents": { status: 200, body: { items: [I] } },
      "/api/v1/recovery/incidents/I1": { status: 200, body: { incident: I, steps: [], drift: { serving: "GEN2", recorded: "GEN1", observed_at: "2026-10-08T00:00:00Z" } } } });
    renderAt("/ops/recovery");
    (await screen.findByText("helper response: EOF")).closest("button")!.click();
    expect(await screen.findByText("GEN2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Keep what is serving" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolve" })).toBeNull();
  });
  it("backends page shows health from monitoring evidence", async () => {
    const E = { id: "E1", name: "app", host: "127.0.0.1", port: 8080, transport: "http", tls_verify: true, weight: 1, priority: 0, connect_timeout_ms: 5000, read_timeout_ms: 60000, write_timeout_ms: 60000, disabled: false, revision: 1 };
    mockFetch({ ...sess(["gateway.read", "monitoring.read"]), "/api/v1/backends": { status: 200, body: { items: [E] } }, "/api/v1/pools": { status: 200, body: { items: [] } },
      "/api/v1/monitoring/backends": { status: 200, body: { items: [{ endpoint_id: "E1", status: "down", latency_ms: 0, detail: "connection refused", observed_at: "2026-10-08T00:00:00Z", stale: false }] } } });
    renderAt("/gateway/backends");
    expect(await screen.findByText("Down")).toBeInTheDocument();
    expect(screen.getByText("connection refused")).toBeInTheDocument();
  });
});

describe("domains and websites (phase 5)", () => {
  const sess = (perms: string[]) => ({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read", ...perms] } } });
  const D = { id: "D1", fqdn: "example.com", purpose: "website", notes: "", dns_provider: "manual", revision: 1, created_at: "2026-10-08T00:00:00Z", updated_at: "2026-10-08T00:00:00Z",
    dns_status: "attention", checked_at: "2026-10-08T00:00:00Z", expectations: [], observations: [],
    comparison: [{ name: "example.com", type: "A", value: "203.0.113.7", status: "propagating", detail: "the resolver still answers 203.0.113.9 (cached up to 120 s more)" }] };
  it("domains list shows evidence status, never claiming OK without it", async () => {
    mockFetch({ ...sess(["domains.read", "domains.write"]), "/api/v1/domains": { status: 200, body: { items: [D, { ...D, id: "D2", fqdn: "new.example.org", dns_status: "unknown", checked_at: undefined, comparison: [] }] } } });
    renderAt("/web/domains");
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("Not checked yet")).toBeInTheDocument();
  });
  it("DNS overview explains propagation with TTL", async () => {
    mockFetch({ ...sess(["domains.read"]), "/api/v1/domains": { status: 200, body: { items: [D] } },
      "/api/v1/integrations/cloudflare": { status: 200, body: { configured: false, required_permissions: "Zone:Read and DNS:Edit", note: "n" } } });
    renderAt("/web/dns");
    expect(await screen.findByText("Propagating")).toBeInTheDocument();
    expect(screen.getByText(/cached up to 120 s/)).toBeInTheDocument();
    expect(screen.getByText("Not configured")).toBeInTheDocument();
  });
  it("websites list and the website destination in the route builder", async () => {
    const W = { id: "W1", name: "Shop", kind: "template", template: "landing", default_locale: "fa", locales: ["fa", "en"], active_version_id: "V1", draft_revision: 1, revision: 1, created_at: "x", updated_at: "x", has_upload: false };
    mockFetch({ ...sess(["websites.read", "websites.write"]), "/api/v1/websites": { status: 200, body: { items: [W] } }, "/api/v1/websites/templates": { status: 200, body: { templates: ["landing"], locales: { fa: "rtl", en: "ltr" } } } });
    renderAt("/web/websites");
    expect(await screen.findByText("Shop")).toBeInTheDocument();
    expect(screen.getByText("Landing page")).toBeInTheDocument();
    expect(screen.getByText("Published")).toBeInTheDocument();
  });
  it("SSL page offers Let's Encrypt and shows ACME state", async () => {
    mockFetch({ ...sess(["certificates.read", "certificates.write"]), "/api/v1/certificates": { status: 200, body: { items: [{ id: "C1", name: "site", source: "acme", sans: ["example.com"], issuer: "(STAGING) X",
      not_before: "2026-10-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z", fingerprint_sha256: "ab".repeat(32), status: "valid", has_key: true, revision: 1,
      acme: { directory: "letsencrypt-staging", identifiers: ["example.com"], renewals: 1 } }] } } });
    renderAt("/web/ssl");
    expect(await screen.findByRole("button", { name: /Let's Encrypt/ }, { timeout: 4000 })).toBeInTheDocument();
    expect(await screen.findByText(/renewed 1 time/, {}, { timeout: 4000 })).toBeInTheDocument();
  });
});

describe("cloudflare zones page", () => {
  const sess = (perms: string[]) => ({ "/api/v1/auth/session": { status: 200, body: { user: { id: "U1", username: "owner", locale: "en" }, stage: "active", permissions: ["system.read", "jobs.read", ...perms] } } });
  it("says Cloudflare is not connected instead of faking a list", async () => {
    mockFetch({ ...sess(["domains.read"]), "/api/v1/integrations/cloudflare": { status: 200, body: { configured: false, required_permissions: "", note: "" } }, "/api/v1/domains": { status: 200, body: { items: [] } } });
    renderAt("/web/cloudflare");
    expect(await screen.findByText("Cloudflare is not connected")).toBeInTheDocument();
  });
  it("lists discovered zones, shows records and the proxy warning for a registered zone", async () => {
    const D = { id: "D1", fqdn: "example.com", purpose: "general", notes: "", dns_provider: "cloudflare", revision: 1, created_at: "2026-10-08T00:00:00Z", updated_at: "2026-10-08T00:00:00Z", dns_status: "ok", expectations: [], observations: [], comparison: [] };
    mockFetch({
      ...sess(["domains.read", "domains.write"]),
      "/api/v1/integrations/cloudflare": { status: 200, body: { configured: true, required_permissions: "", note: "" } },
      "/api/v1/domains": { status: 200, body: { items: [D] } },
      "/api/v1/integrations/cloudflare/discover": { status: 202, body: { job_id: "J1", status: "queued", replayed: false } },
      "/api/v1/jobs/J1": { status: 200, body: { id: "J1", kind: "dns.cloudflare.discover", state: "Succeeded", result: { zones: [{ id: "Z1", name: "example.com" }, { id: "Z2", name: "another.test" }], records: [{ id: "R1", type: "A", name: "www.example.com", content: "203.0.113.5", ttl: 1, proxied: false, comment: "managed-by:ngm" }], zone_id: "Z1" } } },
    });
    renderAt("/web/cloudflare");
    const zoneBtn = await screen.findByRole("button", { name: /example\.com/ });
    expect(screen.getByText("another.test")).toBeInTheDocument();
    fireEvent.click(zoneBtn);
    expect(await screen.findByText("New subdomain")).toBeInTheDocument();
    expect(screen.getByText(/Off by default\. A proxied record only carries standard HTTP\(S\) ports/)).toBeInTheDocument();
    expect(await screen.findByText("203.0.113.5")).toBeInTheDocument();
    expect(screen.getAllByText("NGM").length).toBeGreaterThan(0);
  });
});
