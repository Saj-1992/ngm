// Removes test leftovers from the VM through the API (owner-authorised cleanup).
// Keeps: the published Control Center (listeners web/front443/panel443, route ngm-panel-public,
// backend ngm-panel, certificate panel-prod), the four branded websites, the owner accounts and the
// newest backups. Dry run by default:  node scripts/ops/cleanup_vm.cjs [--apply]
const H = require("../e2e/harness.cjs");
const { check, api, waitJob } = H;
const APPLY = process.argv.includes("--apply");
const KEEP_BACKUPS = 5;
const KEEP = {
  routes: new Set(["ngm-panel-public"]),
  backends: new Set(["ngm-panel"]),
  listeners: new Set(["web", "front443", "panel443"]),
  certificates: new Set(["panel-prod"]),
  websites: new Set(["villa-advisory", "sarv-journal", "atelier-dena", "hamrah-app"]),
  users: new Set(["owner", "sajjad"]),
};
const key = (p) => ({ "Idempotency-Key": p + Date.now() + Math.random().toString(36).slice(2, 6) });
const items = async (path) => (await api("GET", path)).body.items || [];

async function del(label, path, it) {
  if (!APPLY) return console.log("  would delete", label, it.name || it.id);
  const h = it.revision != null ? { "If-Match": `"r${it.revision}"`, ...key("d-") } : key("d-");
  const r = await api("DELETE", path + "/" + it.id, undefined, h);
  const ok = r.status < 300 || r.status === 404;
  if (r.body && r.body.job_id) await waitJob(r.body.job_id, 120000);
  if (!ok) console.log("  FAILED", label, it.name || it.id, r.status, JSON.stringify(r.body).slice(0, 160));
  return ok;
}

H.start(async () => {
  check("auth", await H.login(), "signed in");
  await H.stepUp();
  // Order matters: routes → pools → backends → listeners → certificates.
  for (const [what, path] of [["routes", "/api/v1/routes"], ["pools", "/api/v1/pools"], ["backends", "/api/v1/backends"], ["listeners", "/api/v1/listeners"], ["certificates", "/api/v1/certificates"]]) {
    const gone = (await items(path)).filter((x) => !(KEEP[what] || new Set()).has(x.name));
    console.log(what + ":", gone.length);
    for (const it of gone) await del(what, path, it);
  }
  const sites = (await items("/api/v1/websites")).filter((x) => !KEEP.websites.has(x.name));
  console.log("websites:", sites.length);
  for (const it of sites) await del("website", "/api/v1/websites", it);
  const toks = (await items("/api/v1/tokens")).filter((x) => /^(e2e-|p8-)/.test(x.name));
  console.log("tokens:", toks.length);
  for (const it of toks) await del("token", "/api/v1/tokens", it);
  const users = (await items("/api/v1/users")).filter((x) => !KEEP.users.has(x.username));
  console.log("users:", users.map((u) => u.username).join(","));
  for (const it of users) await del("user", "/api/v1/users", it);
  const backups = (await items("/api/v1/backups")).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  const old = backups.slice(KEEP_BACKUPS);
  console.log(`backups: keeping ${Math.min(KEEP_BACKUPS, backups.length)} newest, removing ${old.length}`);
  for (const it of old) await del("backup", "/api/v1/backups", it);
  check("done", true, APPLY ? "cleanup applied" : "dry run only (use --apply)");
});
