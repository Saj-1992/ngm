// Publishes the NGM Control Center on the owner's server and keeps the apex a
// decoy site on every other port/path. Re-runnable (also used to repair state
// at the end of a full E2E run).
//
//   Panel:  https://<domain>:9443/<secret>/   (TLS terminated, proxied to 127.0.0.1:9999)
//   Apex:   <domain> on :80, :443 and :9443 (outside the secret path) → fallback website
//
// The panel lives on its own listener (port 9443) with protected resources, so
// the gateway E2E (which works on :80/:443) never takes the panel down.
// Credentials and the secret path are written to .local/ (git-ignored), never printed.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const H = require("../e2e/harness.cjs");
const { check, sh, api, val } = H;
const DOMAIN = val("domain");
const PORT = 9443;
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const job = async (r) => { if (!r.body.job_id) throw new Error(r.status + " " + JSON.stringify(r.body).slice(0, 300)); return H.waitJob(r.body.job_id, 600000); };
const local = (f) => path.join(__dirname, "../../.local/" + f);

function secretPath() {
  const f = local("panel-path.txt");
  try { const p = fs.readFileSync(f, "utf8").trim(); if (/^\/[a-z0-9]{8,}$/.test(p)) return p; } catch {}
  const p = "/" + crypto.randomBytes(9).toString("hex");
  fs.writeFileSync(f, p, { mode: 0o600 });
  return p;
}

H.start(async () => {
  check("auth", await H.login(), "signed in");
  await H.stepUp();
  const SECRET = secretPath();

  // 1. set-origin (port + secret path) BEFORE anything validates the panel route.
  let o = await sh(`/usr/local/bin/ngm admin set-origin https://${DOMAIN}:${PORT} ${SECRET} 2>&1 | tail -1; sleep 3`);
  check("origin", o.out.includes("management origin set"), o.out.trim());
  check("auth2", await H.login(), "signed in after restart");

  // 2. Production certificate (Let's Encrypt) for the apex; reused if valid.
  let certs = (await api("GET", "/api/v1/certificates")).body.items;
  let cert = certs.find((c) => c.name === "panel-prod" && c.status !== "expired" && !/STAGING|Fake/i.test(c.issuer));
  if (!cert) {
    const j = await job(await api("POST", "/api/v1/certificates/acme", { name: "panel-prod", identifiers: [DOMAIN], directory: "letsencrypt" }, key("acme-prod-")));
    cert = (await api("GET", "/api/v1/certificates")).body.items.find((c) => c.name === "panel-prod");
    check("certificate", j.state === "Succeeded" && !!cert, `ACME → ${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 200) : ""}`);
  } else check("certificate", true, "production certificate reused");
  check("certificate-trusted", cert && !/STAGING|Fake/i.test(cert.issuer), "issuer: " + (cert && cert.issuer));

  // 3. Decoy website (published) and the global fallback (unknown host/SNI/IP on any port).
  const sites = (await api("GET", "/api/v1/websites")).body.items;
  // The decoy is the owner's chosen branded site (see scripts/ops/seed_sites.cjs); main-site is the older default.
  let site = sites.find((w) => w.name === "villa-advisory") || sites.find((w) => w.name === "main-site");
  if (!site) site = (await api("POST", "/api/v1/websites", { name: "villa-advisory", kind: "template", template: "corporate", default_locale: "fa", locales: ["fa", "en"] })).body;
  if (!site.active_version_id) {
    const b = await job(await api("POST", `/api/v1/websites/${site.id}/build`, undefined, key("b-")));
    await job(await api("POST", `/api/v1/websites/${site.id}/publish`, { version_id: b.result.version.id }, key("p-")));
  }
  let r = await api("PUT", "/api/v1/gateway/fallback", { website_id: site.id, certificate_id: cert.id });
  check("fallback", r.status === 200 && r.body.enabled, "global fallback = "+site.name+" + production cert");

  // 4. Listeners: keep :80 (ACME + fallback), :443 (fallback/passthrough), add :9443 (panel).
  const listeners = (await api("GET", "/api/v1/listeners")).body.items;
  const ensureL = async (name, kind, port) => listeners.find((l) => l.name === name) || (await api("POST", "/api/v1/listeners", { name, kind, address: "0.0.0.0", port })).body;
  await ensureL("web", "http", 80);
  await ensureL("front443", "stream_tls_front", 443);
  const panelL = await ensureL("panel443", "stream_tls_front", PORT);

  // 5. Backend → local API, and the panel route (SNI=apex, path=/<secret>/ → API).
  let ep = (await api("GET", "/api/v1/backends")).body.items.find((b) => b.name === "ngm-panel");
  if (!ep) ep = (await api("POST", "/api/v1/backends", { name: "ngm-panel", host: "127.0.0.1", port: 9999, transport: "http" })).body;
  const routes = (await api("GET", "/api/v1/routes")).body.items;
  // Remove any apex content route so :80/:443 fall through to the fallback.
  const apexNames = new Set(["site", "api", "wild", "site6", "extra", "panel"]);
  for (const rt of routes)
    if (rt.name !== "ngm-panel-public" && (apexNames.has(rt.name) || (rt.matches || []).some((m) => (m.field === "host" || m.field === "sni") && m.value === DOMAIN)))
      await api("DELETE", "/api/v1/routes/" + rt.id, undefined, { "If-Match": `"r${rt.revision}"` });
  const want = { name: "ngm-panel-public", listener_id: panelL.id, protocol: "tls_terminate_http", destination_kind: "endpoint", destination_id: ep.id, certificate_id: cert.id, matches: [{ field: "sni", operator: "exact", value: DOMAIN }, { field: "path_prefix", operator: "prefix", value: SECRET + "/" }] };
  let rt = routes.find((x) => x.name === "ngm-panel-public");
  if (!rt) {
    const c = await api("POST", "/api/v1/routes", want);
    check("panel-route", c.status === 201, "route " + c.status + " " + (c.status !== 201 ? JSON.stringify(c.body).slice(0, 300) : ""));
  } else {
    const cur = (await api("GET", "/api/v1/routes/" + rt.id)).body;
    const upd = { ...cur, ...want }; delete upd.id; delete upd.revision;
    const u = await api("PUT", "/api/v1/routes/" + rt.id, upd, { "If-Match": `"r${cur.revision}"` });
    check("panel-route", u.status === 200, "route repaired → " + u.status + " " + (u.status !== 200 ? JSON.stringify(u.body).slice(0, 300) : ""));
  }
  const d = await job(await api("POST", "/api/v1/deployments", {}, key("deploy-")));
  check("deploy", d.state === "Succeeded" || (d.error && d.error.code === "no_changes"), "deploy " + d.state + (d.error ? " " + JSON.stringify(d.error).slice(0, 150) : ""));

  // 6. Personal owner account (separate from the test "owner").
  const users = (await api("GET", "/api/v1/users")).body.items;
  if (!users.find((u) => u.username === "sajjad")) {
    const role = (await api("GET", "/api/v1/roles")).body.items.find((x) => /^owner$/i.test(x.name));
    const pw = crypto.randomBytes(15).toString("base64url");
    const u = await api("POST", "/api/v1/users", { username: "sajjad", display_name: "Sajjad", password: pw, locale: "fa", grants: [{ role_id: role.id, scope_kind: "global", scope_id: "" }] });
    if (u.status === 201) fs.writeFileSync(local("panel-credentials.txt"), `URL: https://${DOMAIN}:${PORT}${SECRET}/\nusername: sajjad\npassword: ${pw}\n(role: ${role.name}; set up 2FA on first sign-in, then change the password)\n`, { mode: 0o600 });
    check("account", u.status === 201, `account sajjad → ${u.status}`);
  } else check("account", true, "account sajjad exists");

  // 7. Verify from the server: panel at the secret path, decoy everywhere else.
  const c = (a) => sh(`curl -s -o /dev/null -w '%{http_code}' -m 8 ${a}`);
  o = await c(`--resolve ${DOMAIN}:${PORT}:127.0.0.1 https://${DOMAIN}:${PORT}${SECRET}/`);
  check("panel-up", o.out.trim() === "200", `panel https://${DOMAIN}:${PORT}${SECRET}/ → ${o.out.trim()}`);
  o = await c(`--resolve ${DOMAIN}:${PORT}:127.0.0.1 https://${DOMAIN}:${PORT}${SECRET}/api/v1/system/health`);
  check("panel-api", o.out.trim() === "200", `panel API → ${o.out.trim()}`);
  const titles = await sh(`for u in "https://${DOMAIN}:${PORT}/" "https://${DOMAIN}/" "http://${DOMAIN}/"; do curl -sk -m 8 --resolve ${DOMAIN}:${PORT}:127.0.0.1 --resolve ${DOMAIN}:443:127.0.0.1 --resolve ${DOMAIN}:80:127.0.0.1 "$u" | grep -o '<title>[^<]*' | head -1; done`);
  check("apex-decoy", !/Control Center/.test(titles.out) && (titles.out.match(/<title>/g) || []).length >= 1,
    `apex titles (9443/,443/,80/): ${titles.out.replace(/\n/g, " | ")}`);
  // Panel verified from the owner's network over real DNS+TLS.
  o = await c(`https://${DOMAIN}:${PORT}${SECRET}/api/v1/system/health; echo " verify=$(curl -s -o /dev/null -w '%{ssl_verify_result}' -m 8 https://${DOMAIN}:${PORT}${SECRET}/)"`);
  check("public-https", o.out.startsWith("200") && o.out.includes("verify=0"), "public panel → " + o.out.trim());
});
