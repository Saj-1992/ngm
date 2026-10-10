// Phase 8 security sweep over EVERY operation in api/openapi.json against the live VM:
// unauthenticated access, CSRF/Origin enforcement for cookie sessions, and the RBAC
// matrix with a narrowly scoped API token. Requests that should be refused carry
// dummy IDs, so a wrongly accepted request cannot hit real data.
const http = require("http");
const H = require("./harness.cjs");
const { check, api } = H;
const spec = require("../../api/openapi.json");
const ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

function raw(method, path, headers = {}, body) {
  return new Promise((resolve, reject) => {
    if (body) headers = { ...headers, "Content-Length": Buffer.byteLength(body) };
    const req = http.request({ host: "127.0.0.1", port: 19998, method, path, headers: { Accept: "application/json", ...headers } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
const ops = [];
for (const [p, o] of Object.entries(spec.paths))
  for (const [m, op] of Object.entries(o))
    ops.push({ method: m.toUpperCase(), tmpl: p, path: p.replace(/\{[^}]+\}/g, (x) => (x === "{path}" || x === "{token}" ? "x" : ULID)), perm: op["x-ngm-permission"] || "NONE" });

H.start(async () => {
  // 1. Unauthenticated.
  const leaks = [], publicOps = [];
  for (const o of ops) {
    const st = await raw(o.method, o.path, o.method === "GET" ? {} : { "Content-Type": "application/json" }, o.method === "GET" ? undefined : "{}");
    if (o.perm === "NONE") publicOps.push(`${o.method} ${o.tmpl}→${st}`);
    else if (st !== 401 && st !== 403) leaks.push(`${o.method} ${o.tmpl}→${st}`);
  }
  check("sec-unauthenticated", leaks.length === 0, `${ops.length} operations; protected ones all 401/403; leaks: ${leaks.join(", ") || "none"}; public: ${publicOps.join(", ")}`);

  // 2. Cookie session without CSRF token / with a foreign Origin.
  const noCsrf = [], badOrigin = [];
  const muts = ops.filter((o) => o.method !== "GET" && o.perm !== "NONE" && !o.tmpl.startsWith("/api/v1/auth/"));
  for (const o of muts) {
    const a = await api(o.method, o.path, {}, { "X-CSRF-Token": "wrong" });
    if (a.status !== 403) noCsrf.push(`${o.method} ${o.tmpl}→${a.status}`);
    const b = await api(o.method, o.path, {}, { Origin: "https://evil.example" });
    if (b.status !== 403) badOrigin.push(`${o.method} ${o.tmpl}→${b.status}`);
  }
  check("sec-csrf", noCsrf.length === 0, `${muts.length} mutations with a wrong CSRF token → all 403; exceptions: ${noCsrf.join(", ") || "none"}`);
  check("sec-origin", badOrigin.length === 0, `${muts.length} mutations with a foreign Origin → all 403; exceptions: ${badOrigin.join(", ") || "none"}`);

  // 3. RBAC: token scoped to gateway.read only.
  await H.stepUp();
  const t = await api("POST", "/api/v1/tokens", { name: "p8-rbac-" + Date.now(), scopes: ["gateway.read"], expires_in_days: 1 });
  const tok = t.body.token || t.body.secret;
  check("sec-token-create", t.status === 201 && !!tok, "scoped token created: " + t.status);
  const over = [], under = [];
  for (const o of ops) {
    if (o.perm === "NONE" || o.perm.startsWith("@") || o.tmpl.includes("/preview/")) continue;
    const st = await raw(o.method, o.path, { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, o.method === "GET" ? undefined : "{}");
    if (o.perm !== "gateway.read" && st !== 403) over.push(`${o.method} ${o.tmpl}(${o.perm})→${st}`);
    if (o.perm === "gateway.read" && (st === 401 || st === 403)) under.push(`${o.method} ${o.tmpl}→${st}`);
  }
  check("sec-rbac-token", over.length === 0 && under.length === 0, `denied outside scope: ${over.length ? over.join(", ") : "all"}; allowed in scope: ${under.length ? "BROKEN " + under.join(", ") : "all gateway.read routes"}`);
  if (t.body.id) await api("DELETE", "/api/v1/tokens/" + t.body.id);
  const after = await raw("GET", "/api/v1/routes", { Authorization: "Bearer " + tok });
  check("sec-token-revoke", after === 401, "revoked token → " + after);
});
