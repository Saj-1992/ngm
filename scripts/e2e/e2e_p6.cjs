// Phase 6 E2E against the real VM (dev host): node scripts/e2e/e2e_p6.cjs logs
const H = require("./harness.cjs");
const { check, sleep, sh, api, val } = H;
const DOMAIN = val("domain");
const ONLY = (process.argv[2] || "logs").split(",");

async function waitLogs(params, pred, ms = 40000) {
  const end = Date.now() + ms;
  let r;
  while (Date.now() < end) {
    r = await api("GET", "/api/v1/logs?" + params);
    if (r.status === 200 && pred(r.body.items || [])) return r.body.items;
    await sleep(2000);
  }
  return (r && r.body && r.body.items) || [];
}

async function logTests() {
  const st0 = await sh("systemctl is-active ngm-log-indexer; ls -l /var/log/ngm/nginx/ | tail -n +2 | awk '{print $1, $3, $4, $9}'");
  check("logs-indexer", st0.out.startsWith("active"), st0.out.replace(/\n/g, " | "));
  // Real traffic with a marker and a secret-looking query string.
  const marker = "e2e-" + Date.now().toString(36);
  await sh(`for i in 1 2 3; do curl -s -o /dev/null -H 'Host: ${DOMAIN}' 'http://127.0.0.1/${marker}?token=SECRET-QUERY-123'; done; curl -s -o /dev/null -H 'Host: nope.invalid' http://127.0.0.1/${marker}-closed`);
  const items = await waitLogs("category=http&q=" + marker, (it) => it.length >= 3);
  const routes = (await api("GET", "/api/v1/routes")).body.items;
  const site = routes.find((r) => r.name === "site");
  const e = items.find((x) => x.host === DOMAIN && x.path === "/" + marker) || {};
  const closed = items.find((x) => x.host === "nope.invalid") || {};
  check("logs-http-indexed", items.length >= 3 && e.host === DOMAIN && e.route === (site && site.id) && e.status > 0,
    `${items.length} entries; host ${e.host}; route ${e.route} (= route "site": ${site && e.route === site.id}); status ${e.status}; ${e.duration_s}s; unknown host → ${closed.status} without route`);
  const raw = await sh(`grep -c 'SECRET-QUERY-123' /var/log/ngm/nginx/access.jsonl || true`);
  const leaked = JSON.stringify(items).includes("SECRET-QUERY");
  check("logs-no-query-strings", raw.out.trim() === "0" && !leaked, `query string in source file: ${raw.out.trim()}, in index/API: ${leaked}`);
  // Filters + full text + status classes.
  const s5 = await api("GET", "/api/v1/logs?category=http&status=4xx&limit=5");
  check("logs-filters", s5.status === 200 && s5.body.items.every((x) => x.status >= 400 && x.status < 500), `4xx filter → ${s5.body.items.length} rows`);
  // Error log + app logs + security (audit failures) categories.
  await sh(`curl -s -o /dev/null -H 'Host: ${DOMAIN}' http://127.0.0.1/api/v1/forced-error-${marker}`);
  await api("POST", "/api/v1/auth/login", { username: "owner", password: "wrong-" + marker }).catch(() => {});
  const sec = await waitLogs("category=security&q=login", (it) => it.length > 0, 30000);
  const app = await waitLogs("category=api", (it) => it.length > 0, 20000);
  check("logs-categories", sec.length > 0 && app.length > 0, `security ${sec.length} (e.g. ${sec[0] && sec[0].message}); api ${app.length}`);
  // Pipeline status.
  const ps = await api("GET", "/api/v1/logs/status");
  const lag = ((ps.body.status && ps.body.status.sources) || []).map((s) => s.lag_bytes);
  check("logs-status", ps.status === 200 && ps.body.status && !ps.body.status.paused && lag.every((x) => x < 1 << 20), "lag bytes per source " + JSON.stringify(lag));
  // Rotation by logrotate (real) loses nothing: lines written right before and after.
  await sh(`for i in 1 2 3 4 5; do curl -s -o /dev/null -H 'Host: ${DOMAIN}' http://127.0.0.1/${marker}-before; done`);
  const rot = await sh("logrotate -f /etc/logrotate.d/ngm; ls /var/log/ngm/nginx/");
  await sh(`for i in 1 2 3 4 5; do curl -s -o /dev/null -H 'Host: ${DOMAIN}' http://127.0.0.1/${marker}-after; done`);
  const before = await waitLogs("category=http&q=" + marker + "-before", (it) => it.length >= 5);
  const after = await waitLogs("category=http&q=" + marker + "-after", (it) => it.length >= 5);
  check("logs-rotation-no-loss", before.length === 5 && after.length === 5 && /access\.jsonl\.1/.test(rot.out), `before ${before.length}/5, after ${after.length}/5; files: ${rot.out.replace(/\n/g, " ")}`);
  // Export (CSV) and permission check.
  const ex = await api("GET", "/api/v1/logs/export?format=csv&q=" + marker, undefined, {}, true);
  check("logs-export", ex.status === 200 && ex.buf.toString().split("\n")[0].startsWith("time,category"), `csv ${ex.buf.length} bytes`);
  // Rebuild from source files (index is derived data).
  const rb = await sh("/opt/ngm/current/ngm logs reindex 2>&1 | tail -2");
  const re = await waitLogs("category=http&q=" + marker + "-after", (it) => it.length >= 5, 60000);
  check("logs-reindex", re.length === 5, rb.out.replace(/\n/g, " | ") + `; ${re.length} entries after rebuild`);
}

H.start(async () => {
  if (ONLY.includes("logs")) await logTests();
});
