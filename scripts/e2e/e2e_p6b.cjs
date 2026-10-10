// Phase 6 E2E (monitoring, alerts, notifications, performance, topology) against the real VM.
const H = require("./harness.cjs");
const { check, sleep, sh, api } = H;
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
async function job(r) {
  if (!r.body.job_id) throw new Error("no job: " + r.status + " " + JSON.stringify(r.body));
  return H.waitJob(r.body.job_id);
}

H.start(async () => {
  // Metrics: real /proc sample from ngm-monitor, fresh, with history.
  const m = (await api("GET", "/api/v1/monitoring/system?hours=1")).body;
  check("mon-metrics", m.current && !m.stale && m.current.mem_total > 0 && m.current.cpus > 0 && m.history.length > 0,
    `cpu ${m.current && m.current.cpu_pct.toFixed(1)}% of ${m.current && m.current.cpus}; mem ${m.current && (m.current.mem_used / 2 ** 30).toFixed(2)}/${m.current && (m.current.mem_total / 2 ** 30).toFixed(2)} GiB; ${m.history.length} points; stale=${m.stale}`);

  // Backend-down alert: add an endpoint on a closed local port to a fresh pool, wait for monitor + evaluation.
  const tag = "e2e-alert-" + Date.now().toString(36);
  let r = await api("POST", "/api/v1/backends", { name: tag, host: "127.0.0.1", port: 9, transport: "http", weight: 1, health: { interval_s: 5 } });
  check("alert-setup", r.status === 201, "endpoint on a closed port: " + r.status + " " + (r.status !== 201 ? JSON.stringify(r.body).slice(0, 200) : ""));
  const poolId = r.body.id, poolRev = r.body.revision;
  let al;
  for (let i = 0; i < 30; i++) {
    al = (await api("GET", "/api/v1/alerts?state=open")).body.items.find((a) => a.rule === "backend_down" && a.subject === tag);
    if (al) break;
    await sleep(5000);
  }
  check("alert-backend-down", !!al, al ? `${al.severity} "${al.message}" (${al.state})` : "no alert within 150s");
  const all = (await api("GET", "/api/v1/alerts?state=open")).body.items;
  const keys = all.map((a) => a.rule + "|" + a.subject);
  check("alert-dedup", new Set(keys).size === keys.length, `${keys.length} open alerts, ${new Set(keys).size} unique rule+subject`);
  if (al) {
    r = await api("POST", `/api/v1/alerts/${al.id}/ack`);
    const a2 = (await api("GET", "/api/v1/alerts")).body.items.find((a) => a.id === al.id);
    check("alert-ack", r.status < 300 && a2 && a2.state === "acknowledged", `ack ${r.status} → ${a2 && a2.state}`);
  }
  const del = await api("DELETE", "/api/v1/backends/" + poolId, undefined, { "If-Match": '"r' + poolRev + '"' });
  if (del.status >= 300) console.log("delete endpoint:", del.status, JSON.stringify(del.body));
  let gone = false;
  for (let i = 0; i < 30 && al; i++) {
    const a3 = (await api("GET", "/api/v1/alerts")).body.items.find((a) => a.id === al.id);
    if (a3 && a3.state === "resolved") { gone = true; break; }
    await sleep(5000);
  }
  check("alert-resolve", gone, "alert auto-resolves once the condition disappears: " + gone);

  // Notifications: SSRF guard and https-only.
  const bad = [];
  for (const url of ["https://127.0.0.1/x", "https://10.0.0.5/x", "http://example.com/x", "https://[::1]/x", "https://169.254.169.254/latest"]) {
    r = await api("POST", "/api/v1/notifications/targets", { name: "bad", kind: "webhook", url, min_severity: "info", enabled: true });
    if (r.status < 300) { bad.push(url); await api("DELETE", "/api/v1/notifications/targets/" + r.body.id); }
  }
  check("notify-ssrf-guard", bad.length === 0, bad.length ? "accepted: " + bad.join(", ") : "loopback, private, link-local, metadata, plain http all rejected");
  // Retry path: Telegram target with an invalid token → real API call fails → recorded, retried, secret never echoed.
  r = await api("POST", "/api/v1/notifications/targets", { name: tag, kind: "telegram", chat_id: "1", secret: "123456789:INVALID-" + tag + "-padpadpadpadpad", min_severity: "warning", enabled: true });
  const tid = r.body.id;
  check("notify-target", r.status === 201 && !JSON.stringify(r.body).includes("INVALID-"), `created ${r.status}; has_secret=${r.body.has_secret}; secret echoed=${JSON.stringify(r.body).includes("INVALID-")}`);
  r = await api("POST", `/api/v1/notifications/targets/${tid}/test`);
  let d;
  for (let i = 0; i < 20; i++) {
    d = (await api("GET", "/api/v1/notifications/deliveries")).body.items.find((x) => x.id === r.body.delivery_id);
    if (d && d.attempts > 0) break;
    await sleep(3000);
  }
  const vault = await sh("grep -c 'INVALID-" + tag + "' /var/lib/ngm/ngm.db || true");
  check("notify-retry", d && d.attempts >= 1 && d.status !== "sent" && !String(d.last_error).includes("INVALID-"),
    d ? `status ${d.status}; attempts ${d.attempts}; error "${String(d.last_error).slice(0, 80)}"; plaintext in DB: ${vault.out.trim()}` : "no delivery");
  await api("DELETE", "/api/v1/notifications/targets/" + tid);

  // Performance: override → deploy → rendered + nginx -t; then revert.
  r = await api("PUT", "/api/v1/performance", { profile: "high", overrides: { keepalive_timeout: 71 } });
  const eff = r.body.view && r.body.view.values.find((v) => v.name === "keepalive_timeout");
  r = await api("PUT", "/api/v1/performance", { profile: "high", overrides: { keepalive_timeout: 100000 } });
  check("perf-bounds", r.status === 400 || r.status === 422, "out-of-range override → " + r.status);
  let j = await job(await api("POST", "/api/v1/deployments", {}, key("p1")));
  const conf = await sh("grep -rh 'keepalive_timeout' /etc/nginx/ngm/current/ | sort | uniq -c; nginx -t 2>&1 | tail -1");
  check("perf-apply", eff && eff.effective === 71 && j.state === "Succeeded" && conf.out.includes("keepalive_timeout 71s") && conf.out.includes("successful"),
    `effective ${eff && eff.effective}; deploy ${j.state}; ${conf.out.replace(/\n/g, " | ")}`);
  await api("PUT", "/api/v1/performance", { profile: "", overrides: {} });
  j = await job(await api("POST", "/api/v1/deployments", {}, key("p2")));
  const conf2 = await sh("grep -rh 'keepalive_timeout 71s' /etc/nginx/ngm/current/ | wc -l");
  check("perf-revert", j.state === "Succeeded" && conf2.out.trim() === "0", `revert deploy ${j.state}; remaining overrides ${conf2.out.trim()}`);

  // Topology: desired + active graphs and impact of removing a pool.
  const tg = (await api("GET", "/api/v1/topology?view=desired")).body;
  const ta = (await api("GET", "/api/v1/topology?view=active")).body;
  check("topo-graph", tg.nodes.length > 0 && tg.edges.length > 0 && ta.nodes.length > 0,
    `desired ${tg.nodes.length} nodes/${tg.edges.length} edges; active ${ta.nodes.length}/${ta.edges.length}; kinds ${[...new Set(tg.nodes.map((n) => n.kind))].join(",")}`);
  const pool = tg.nodes.find((n) => n.kind === "pool" && tg.edges.some((e) => e.to === n.id && e.traffic));
  if (pool) {
    const im = (await api("GET", `/api/v1/topology/impact?node=${encodeURIComponent(pool.id)}&view=desired`)).body;
    check("topo-impact", im.affected.length > 0, `removing pool ${pool.label}: ${im.affected.length} affected, critical: ${im.critical.join("; ").slice(0, 160)}`);
  }
});
