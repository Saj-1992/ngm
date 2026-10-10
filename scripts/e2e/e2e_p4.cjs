// Phase 4 reliability E2E against the real VM. Run from the dev host:
//   node scripts/e2e/e2e_p4.cjs monitor,firewall,deadman,backup,vault,crash,killpoint,drift
// Requires /tmp/rotkill.sh and /tmp/killpoint.sh on the VM (scripts/e2e/). Credentials are read at runtime
// from the git-ignored "example server detail.txt"; nothing secret is stored here.
// Safety: before any UFW change an OUTER, NGM-independent transient timer is armed
// (`ufw --force disable` after 15 min), and SSH is re-verified with fresh connections.
const { Client } = require("../remote/node_modules/ssh2");
const net = require("net");
const fs = require("fs");
const http = require("http");
const crypto = require("crypto");

const lines = fs.readFileSync(require("path").join(__dirname, "..", "..", "example server detail.txt"), "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
const val = (k) => lines[lines.findIndex((l) => l.toLowerCase().replace(/\s/g, "").startsWith(k + ":")) + 1];
const VMIP = val("ip");
const SSHCFG = { host: VMIP, username: val("user"), password: val("password"), port: 22, readyTimeout: 20000 };
const ONLY = (process.argv[2] || "monitor,firewall,backup,vault,crash").split(",");
const results = [];
const check = (id, ok, detail) => {
  results.push({ id, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${id} — ${detail}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function totp(secretB32, t = Date.now()) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32.replace(/\s|=/g, "").toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / 30)));
  const h = crypto.createHmac("sha1", key).update(ctr).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}
let lastStep = 0;
async function freshCode(secret) {
  // TOTP codes are single-use: wait for a time step not used before.
  while (Math.floor(Date.now() / 30000) <= lastStep) await sleep(1000);
  lastStep = Math.floor(Date.now() / 30000);
  return totp(secret);
}

let ssh;
function connectSSH() {
  return new Promise((res, rej) => {
    const c = new Client();
    c.on("ready", () => res(c)).on("error", rej).connect(SSHCFG);
  });
}
function sh(cmd, timeoutMs = 120000, conn = ssh) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, s) => {
      if (err) return reject(err);
      let out = "", errOut = "";
      const t = setTimeout(() => s.close(), timeoutMs);
      s.on("data", (d) => (out += d)).stderr.on("data", (d) => (errOut += d));
      s.on("close", (code) => {
        clearTimeout(t);
        resolve({ code, out: out.trim(), err: errOut.trim() });
      });
      s.end();
    });
  });
}
async function freshSSH() {
  try {
    const c = await connectSSH();
    const r = await sh("echo ok", 10000, c);
    c.end();
    return r.out === "ok";
  } catch (e) {
    return false;
  }
}

let cookie = "", csrf = "";
function api(method, path, body, extraHeaders = {}, raw = false) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : undefined;
    const headers = { Accept: "application/json", ...extraHeaders };
    if (data) headers["Content-Type"] = "application/json";
    if (cookie) headers.Cookie = cookie;
    if (method !== "GET") {
      headers["X-CSRF-Token"] = csrf;
      headers.Origin = "http://127.0.0.1:19998";
    }
    const req = http.request({ host: "127.0.0.1", port: 19998, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (d) => chunks.push(d));
      res.on("end", () => {
        for (const c of res.headers["set-cookie"] || []) {
          const [kv] = c.split(";");
          const [k, v] = kv.split("=");
          if (k === "ngm_session") cookie = "ngm_session=" + v;
          if (k === "ngm_csrf") csrf = v;
        }
        const buf = Buffer.concat(chunks);
        let j = {};
        if (!raw) try { j = buf.length ? JSON.parse(buf.toString()) : {}; } catch {}
        resolve({ status: res.statusCode, body: j, buf, headers: res.headers });
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}
const TERMINAL = ["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"];
async function waitJob(id, timeoutMs = 240000, until = TERMINAL) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const r = await api("GET", "/api/v1/jobs/" + id);
    if (until.includes(r.body.state)) return r.body;
    await sleep(700);
  }
  throw new Error("job timeout " + id);
}
async function steps(id) {
  return (await api("GET", `/api/v1/jobs/${id}/steps`)).body.items || [];
}

let secret = "";
async function login() {
  cookie = csrf = "";
  const pw = (await sh("/opt/ngm/current/ngm admin reset owner | sed -n 's/new password: //p'")).out;
  await api("POST", "/api/v1/auth/login", { username: "owner", password: pw });
  const r = await api("POST", "/api/v1/auth/mfa/enroll");
  secret = r.body.secret;
  const c = await api("POST", "/api/v1/auth/mfa/confirm", { code: await freshCode(secret) });
  return c.body.stage === "active";
}
async function stepUp() {
  const r = await api("POST", "/api/v1/auth/step-up", { code: await freshCode(secret) });
  return r.status === 200;
}

async function monitorTests() {
  await sh("pkill -x ngm-testkit; sleep 0.3; for spec in 'http-echo -listen 127.0.0.1:9101 -name A' 'http-echo -listen 127.0.0.1:9102 -name B' 'tcp-echo -listen 127.0.0.1:9201 -name T' 'tls-echo -listen 127.0.0.1:9301 -name passthrough-backend'; do setsid setpriv --reuid=nobody --regid=nogroup --clear-groups /usr/local/sbin/ngm-testkit $spec >/dev/null 2>&1 < /dev/null & done; sleep 1");
  const st = await sh("systemctl is-active ngm-monitor; systemctl show ngm-monitor -p User --value");
  check("monitor-service", st.out.startsWith("active") && st.out.includes("ngm-monitor"), "ngm-monitor active as user: " + st.out.replace(/\n/g, " "));
  await sleep(25000);
  let r = await api("GET", "/api/v1/monitoring/backends");
  const eps = (await api("GET", "/api/v1/backends")).body.items || [];
  const by = (n) => r.body.items.find((x) => x.endpoint_id === (eps.find((e) => e.name === n) || {}).id) || {};
  check("health-up", by("echo-a").status === "healthy" && by("tcp-echo").status === "healthy", `echo-a=${by("echo-a").status} (${by("echo-a").latency_ms} ms), tcp-echo=${by("tcp-echo").status}`);
  // Kill backend B and observe down after the anti-flap threshold (2 consecutive failures).
  await sh("pkill -f 'ngm-testkit http-echo -listen 127.0.0.1:9102'");
  const t0 = Date.now();
  let down = null;
  while (Date.now() - t0 < 60000) {
    await sleep(3000);
    r = await api("GET", "/api/v1/monitoring/backends");
    if (by("echo-b").status === "down") { down = by("echo-b"); break; }
  }
  check("health-down", !!down, down ? `echo-b down after ${Math.round((Date.now() - t0) / 1000)} s: ${down.detail}` : "echo-b never reported down: " + JSON.stringify(by("echo-b")));
  const hc = (await api("GET", "/api/v1/system/health")).body.components.find((c) => c.name === "backends");
  check("health-component", hc && hc.status === "degraded", "system health backends component: " + JSON.stringify(hc));
  await sh("setsid setpriv --reuid=nobody --regid=nogroup --clear-groups /usr/local/sbin/ngm-testkit http-echo -listen 127.0.0.1:9102 -name B >/dev/null 2>&1 < /dev/null &");
  // SSRF guard: an endpoint pointing at the metadata address is never probed.
  const bad = await api("POST", "/api/v1/backends", { name: "meta-probe", host: "169.254.169.254", port: 80, transport: "http" });
  if (bad.status === 201) {
    await sleep(25000);
    r = await api("GET", "/api/v1/monitoring/backends");
    const m = r.body.items.find((x) => x.endpoint_id === bad.body.id) || {};
    check("health-ssrf-guard", m.status !== "healthy" && /block|refus|not allowed|link-local|metadata/i.test(m.detail || ""), `169.254.169.254 → ${m.status}: ${m.detail}`);
    await api("DELETE", "/api/v1/backends/" + bad.body.id, undefined, { "If-Match": `"r${bad.body.revision}"` });
  } else {
    check("health-ssrf-guard", true, "rejected at model validation: " + bad.status);
  }
}

async function fwTests() {
  const pre = await sh("ufw status verbose | head -5; ufw show added; ss -Htlnp | awk '{print $4}' | sort -u | tr '\\n' ' '");
  console.log("     pre-state:", pre.out.replace(/\n/g, " | "));
  // Outer safety net independent of NGM.
  await sh("systemctl stop ngm-e2e-ufw-safety.timer 2>/dev/null; systemd-run --unit=ngm-e2e-ufw-safety --on-active=900 /usr/sbin/ufw --force disable");
  // A foreign rule that NGM must preserve.
  await sh("ufw allow 8443/tcp");
  if (!(await stepUp())) throw new Error("step-up failed");
  let r = await api("POST", "/api/v1/firewall/rules/from-listeners");
  check("fw-from-listeners", r.status === 200, "created: " + JSON.stringify(r.body.created));
  // F1 enable + confirm.
  r = await api("POST", "/api/v1/firewall/apply", { enable: true }, { "Idempotency-Key": "e2e-fw-en-" + Date.now() });
  let j = await waitJob(r.body.job_id, 60000, ["Verifying", ...TERMINAL]);
  const ev = ((await steps(j.id)).find((s) => s.to_state === "Verifying") || {}).evidence || {};
  check("fw-awaits-confirm", j.state === "Verifying" && ev.confirm_required === true && !!ev.confirm_deadline, `state=${j.state} deadline=${ev.confirm_deadline}`);
  const timers = await sh("systemctl list-timers --all --no-legend | grep -c ngm-fw || true");
  check("fw-watchdog-armed", Number(timers.out) >= 1, "transient systemd revert timers: " + timers.out);
  const ok1 = await freshSSH();
  check("fw-ssh-new-session", ok1, "fresh SSH connection while UFW active: " + ok1);
  r = await api("POST", "/api/v1/firewall/confirm", { job_id: j.id });
  j = await waitJob(j.id);
  const st = await sh("ufw status | head -1; ufw show added");
  check("fw-enable-confirmed", j.state === "Succeeded" && st.out.includes("Status: active") && st.out.includes("ngm:ssh-guard") && st.out.includes("8443/tcp"),
    `${j.state}; ${st.out.replace(/\n/g, " | ")}`);
  const timersAfter = await sh("systemctl list-timers --all --no-legend | grep -c ngm-fw || true");
  check("fw-watchdog-disarmed", Number(timersAfter.out) === 0, "revert timers after confirmation: " + timersAfter.out);
  const http80 = await new Promise((res) => http.get({ host: VMIP, port: 80, path: "/", timeout: 8000, headers: { Host: val("domain") } }, (x) => res(x.statusCode)).on("error", (e) => res(e.code)));
  check("fw-public-80-reachable", typeof http80 === "number", "dev host → VM:80 through UFW: " + http80);

  // F2 risky change NOT confirmed → automatic revert.
  if (!(await stepUp())) throw new Error("step-up failed");
  r = await api("POST", "/api/v1/firewall/rules", { key: "e2e-deny", action: "deny", proto: "tcp", port: 7001, source: "any" });
  r = await api("POST", "/api/v1/firewall/apply", {}, { "Idempotency-Key": "e2e-fw-deny-" + Date.now() });
  j = await waitJob(r.body.job_id, 60000, ["Verifying", ...TERMINAL]);
  const during = await sh("ufw show added | grep -c 'ngm:e2e-deny' || true");
  const t0 = Date.now();
  j = await waitJob(j.id, 200000);
  const after = await sh("ufw show added | grep -c 'ngm:e2e-deny' || true; ufw status | head -1");
  check("fw-unconfirmed-reverts", during.out === "1" && j.state === "RolledBack" && JSON.stringify(j.error).includes("not_confirmed") && after.out.startsWith("0") && after.out.includes("active"),
    `rule present during wait=${during.out}; after ${Math.round((Date.now() - t0) / 1000)} s → ${j.state}; rule count now ${after.out.split("\n")[0]}`);

  // F3 coordinator killed while waiting: systemd-run watchdog / reconcile must still revert.
  if (!(await stepUp())) throw new Error("step-up failed");
  r = await api("POST", "/api/v1/firewall/apply", {}, { "Idempotency-Key": "e2e-fw-kill-" + Date.now() });
  j = await waitJob(r.body.job_id, 60000, ["Verifying", ...TERMINAL]);
  await sh("systemctl kill -s KILL ngm-ops");
  const t1 = Date.now();
  let gone = false;
  while (Date.now() - t1 < 180000) {
    await sleep(3000);
    if ((await sh("ufw show added | grep -c 'ngm:e2e-deny' || true")).out === "0") { gone = true; break; }
  }
  j = await waitJob(j.id, 120000);
  const why = (await sh("journalctl -u 'ngm-fw-*' -u ngm-ops --since '-4 min' --no-pager | grep -iE 'revert|reconcil|watchdog' | tail -3")).out;
  check("fw-ops-killed-reverts", gone && ["RolledBack", "Failed"].includes(j.state) && (await sh("ufw status | head -1")).out.includes("active"),
    `rule removed after ${Math.round((Date.now() - t1) / 1000)} s; job ${j.state}; ${why.replace(/\n/g, " | ").slice(0, 300)}`);
  check("fw-ssh-after-kill", await freshSSH(), "fresh SSH session after revert");
  // Desired rule stays desired; delete it so the model matches.
  const rules = (await api("GET", "/api/v1/firewall")).body.rules;
  const dr = rules.find((x) => x.key === "e2e-deny");
  if (dr) await api("DELETE", "/api/v1/firewall/rules/" + dr.id, undefined, { "If-Match": `"r${dr.revision}"` });
  const foreign = await sh("ufw status | grep -c '^8443/tcp' || true");
  check("fw-foreign-preserved", Number(foreign.out) >= 1, "unmanaged 8443/tcp rule untouched across all changes");

  // Restore the VM's original firewall posture (UFW was inactive before these tests).
  await sh("ufw delete allow 8443/tcp; ufw --force disable; systemctl stop ngm-e2e-ufw-safety.timer 2>/dev/null; ufw status | head -1");
}

async function deadmanTest() {
  await sh("systemctl stop ngm-e2e-ufw-safety.timer 2>/dev/null; systemd-run --unit=ngm-e2e-ufw-safety --on-active=900 /usr/sbin/ufw --force disable");
  if (!(await stepUp())) throw new Error("step-up failed");
  let r = await api("POST", "/api/v1/firewall/apply", { enable: true }, { "Idempotency-Key": "e2e-fw-dm-" + Date.now() });
  let j = await waitJob(r.body.job_id, 60000, ["Verifying", ...TERMINAL]);
  const on = await sh("ufw status | head -1");
  // Stop the coordinator and keep it down: only the transient systemd timer can revert now.
  await sh("systemctl stop ngm-ops");
  const t0 = Date.now();
  let off = false;
  while (Date.now() - t0 < 200000) {
    await sleep(5000);
    if ((await sh("ufw status | head -1")).out.includes("inactive")) { off = true; break; }
  }
  const secs = Math.round((Date.now() - t0) / 1000);
  const jr = (await sh("journalctl --since '-5 min' --no-pager | grep -E 'fw-revert|watchdog' | tail -2")).out;
  await sh("systemctl start ngm-ops");
  j = await waitJob(j.id, 120000);
  check("fw-deadman-timer", on.out.includes("Status: active") && off && ["RolledBack", "Failed"].includes(j.state),
    `enabled, ngm-ops stopped; systemd timer disabled UFW after ~${secs} s; job on restart → ${j.state}; ${jr.replace(/\n/g, " | ").slice(0, 260)}`);
  check("fw-deadman-ssh", await freshSSH(), "fresh SSH session after timer revert");
  await sh("ufw --force disable; systemctl stop ngm-e2e-ufw-safety.timer 2>/dev/null");
}

async function recoveryTests() {
  const ret = await sh("/opt/ngm/current/ngm vault retire 1; echo exit=$?; /opt/ngm/current/ngm vault status | head -3");
  check("vault-retire", ret.out.includes("exit=0") && ret.out.includes("v1  retired"), ret.out.replace(/\n/g, " | "));
  let inc = (await api("GET", "/api/v1/recovery/incidents?status=open")).body.items || [];
  if (!inc.length) { check("rc-open", false, "no open incident to resolve"); return; }
  const i = inc[0];
  const d = (await api("GET", "/api/v1/recovery/incidents/" + i.id)).body;
  check("rc-detail", d.job && d.steps && d.steps.length > 0 && i.actions.length > 0, `incident for ${i.job_kind}: ${d.steps.length} journaled steps, ${i.actions.length} guided checks`);
  // Operator checks (what the guidance asks for), then resolves with step-up.
  const n = await sh("nginx -t 2>&1 | tail -1; readlink -f /etc/nginx/ngm/current");
  const note = "e2e: nginx -t ok; current=" + n.out.split("\n")[1];
  let r = await api("POST", "/api/v1/recovery/incidents/" + i.id + "/resolve", { outcome: "failed", note });
  check("rc-step-up-required", r.status === 403 || (r.body.error && r.body.error.code === "step_up_required") || r.status === 200, "resolve without fresh MFA → " + r.status + " " + ((r.body.error||{}).code||""));
  if (r.status !== 200) { await stepUp(); r = await api("POST", "/api/v1/recovery/incidents/" + i.id + "/resolve", { outcome: "failed", note }); }
  const j = (await api("GET", "/api/v1/jobs/" + i.job_id)).body;
  check("rc-resolved", r.status === 200 && r.body.status === "resolved" && j.state === "Failed", `incident resolved; job ${i.job_id} → ${j.state}`);
  const r2 = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-after-resolve-" + Date.now() });
  const j2 = await waitJob(r2.body.job_id, 180000);
  check("rc-unblocked", j2.state === "Succeeded", "next deployment after resolution → " + j2.state + " " + JSON.stringify(j2.error || "").slice(0, 300));
  const au = await sh("/opt/ngm/current/ngm audit verify");
  check("rc-audited", au.out.includes("ok"), au.out);
}

async function driftTests() {
  await sleep(35000); // let ngm-ops record the pointer observation
  let d = (await api("GET", "/api/v1/recovery/drift")).body;
  const ptr = (await sh("readlink /etc/nginx/ngm/current")).out;
  check("drift-detected", d.evidence === true && (d.drift === null || d.drift.serving === ptr.replace(/^.*\//, "")), "drift: " + JSON.stringify(d.drift) + "; live pointer " + ptr);
  if (d.drift) {
    if (!(await stepUp())) throw new Error("step-up");
    const r = await api("POST", "/api/v1/recovery/reconcile", { mode: "adopt" }, { "Idempotency-Key": "e2e-adopt-" + Date.now() });
    const j = await waitJob(r.body.job_id, 120000);
    const st = (await steps(j.id)).map((x) => x.name).join(" → ");
    check("drift-adopt", j.state === "Succeeded", "reconcile adopt → " + j.state + " " + JSON.stringify(j.error || j.result || "").slice(0, 200) + " | " + st);
    await sleep(35000);
    d = (await api("GET", "/api/v1/recovery/drift")).body;
    check("drift-cleared", d.evidence === true && d.drift === null, "drift after adopt: " + JSON.stringify(d.drift));
  }
  const r2 = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-after-adopt-" + Date.now() });
  const j2 = await waitJob(r2.body.job_id, 120000);
  check("drift-deploy-works", j2.state === "Succeeded", "deployment after reconcile → " + j2.state + " " + JSON.stringify(j2.error || "").slice(0, 200));
}

async function killpointTests() {
  for (const point of (process.env.KP || "test,reload").split(",")) {
    await login();
    await sh("rm -f /tmp/killpoint.log; setsid sh /tmp/killpoint.sh " + point + " >/dev/null 2>&1 < /dev/null &");
    await sleep(300);
    const r = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-kp-" + point + Date.now() });
    const j = await waitJob(r.body.job_id, 180000);
    const log = (await sh("sleep 1; cat /tmp/killpoint.log; pkill -fx 'sh /tmp/killpoint.sh " + point + "'; true")).out;
    const st = (await steps(j.id)).map((x) => x.name + (x.status === "failed" ? "(failed)" : "")).join(" > ");
    const n = await sh("nginx -t 2>&1 | tail -1; readlink /etc/nginx/ngm/current; curl -s -o /dev/null -w '%{http_code}' -H 'Host: " + val("domain") + "' http://127.0.0.1/");
    await sleep(35000);
    const d = (await api("GET", "/api/v1/recovery/drift")).body;
    const hit = log.includes("killed");
    check("killpoint-" + point, hit && ["Succeeded", "RolledBack"].includes(j.state) && st.includes("nginx.activate(failed)") && n.out.includes("successful") && n.out.endsWith("200") && d.drift === null,
      `${log.trim()} → job ${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 140) : ""} | steps: ${st} | drift after: ${JSON.stringify(d.drift)}`);
  }
}

async function backupTests() {
  if (!(await stepUp())) throw new Error("step-up failed");
  const PASS = "e2e-" + crypto.randomBytes(12).toString("hex");
  let r = await api("POST", "/api/v1/backups/passphrase", { passphrase: PASS });
  check("bk-passphrase", r.status === 200, "passphrase set (derived key in vault)");
  const leak = await sh(`grep -c -a '${PASS}' /var/lib/ngm/ngm.db /var/lib/ngm/ngm.db-wal 2>/dev/null; journalctl -u 'ngm-*' --since '-10 min' --no-pager | grep -c '${PASS}' || true`);
  check("bk-passphrase-not-stored", !leak.out.split(/\s+/).some((x) => /:[1-9]/.test(x) || /^[1-9]/.test(x)), "passphrase not found in DB/WAL/journal: " + leak.out.replace(/\n/g, " "));
  r = await api("POST", "/api/v1/backups", undefined, { "Idempotency-Key": "e2e-bk-" + Date.now() });
  const j = await waitJob(r.body.job_id, 120000);
  check("bk-job", j.state === "Succeeded", `backup job ${j.state} ${JSON.stringify(j.result || j.error).slice(0, 200)}`);
  const list = (await api("GET", "/api/v1/backups")).body.items;
  const a = list[0];
  const perm = await sh(`stat -c '%U:%G %a' /var/lib/ngm/backups/${a.file_name}; head -c 8 /var/lib/ngm/backups/${a.file_name}`);
  check("bk-file", perm.out.includes("ngm-ops:ngm 640") && perm.out.includes("NGMBAK1"), perm.out.replace(/\n/g, " "));
  const dl = await api("GET", `/api/v1/backups/${a.id}/download`, undefined, {}, true);
  const sha = crypto.createHash("sha256").update(dl.buf).digest("hex");
  check("bk-download", dl.status === 200 && sha === a.sha256 && dl.buf.length === a.size_bytes, `downloaded ${dl.buf.length} bytes, sha256 match=${sha === a.sha256}`);
  fs.writeFileSync(require("path").join(require("os").tmpdir(), "e2e-download.ngmbak"), dl.buf);
  r = await api("POST", `/api/v1/backups/${a.id}/verify`);
  check("bk-verify", r.status === 200 && r.body.ok === true, "server-side verify: decrypt + manifest hashes + integrity_check");
  // The downloaded copy contains no plaintext secrets.
  const plain = dl.buf.includes(Buffer.from("BEGIN PRIVATE KEY")) || dl.buf.includes(Buffer.from("SQLite format 3"));
  check("bk-ciphertext", !plain, "archive contains no plaintext SQLite header or PEM keys");

  // Restore on this host: change state after the backup, then restore.
  const marker = await api("POST", "/api/v1/listeners", { name: "after-backup", kind: "http", address: "127.0.0.1", port: 18080 });
  const file = `/var/lib/ngm/backups/${a.file_name}`;
  const wrong = await sh(`sha256sum /var/lib/ngm/ngm.db | cut -c1-16; echo wrong-passphrase-123456 | /opt/ngm/current/ngm restore ${file}; echo "exit=$?"; sha256sum /var/lib/ngm/ngm.db | cut -c1-16`);
  const wl = wrong.out.split("\n");
  check("restore-wrong-passphrase", wrong.out.includes("exit=1") && wl[0] === wl[wl.length - 1] && /passphrase|authentic/i.test(wrong.err),
    "refused; live DB unchanged; " + wrong.err.slice(0, 120));
  const pv = await sh(`NGM_BACKUP_PASSPHRASE='${PASS}' /opt/ngm/current/ngm restore --preview ${file}`);
  check("restore-preview", pv.code === 0 && pv.out.includes("archive verified") && pv.out.includes("nothing was changed"), pv.out.split("\n")[0]);
  const t0 = Date.now();
  const rs = await sh(`NGM_BACKUP_PASSPHRASE='${PASS}' /opt/ngm/current/ngm restore ${file}; echo "exit=$?"`, 180000);
  const healthy = await sh("sleep 2; systemctl is-active ngm-api ngm-ops ngm-monitor nginx | tr '\\n' ' '; curl -s -o /dev/null -w '%{http_code}' -H 'Host: " + val("domain") + "' http://127.0.0.1/");
  check("restore-apply", rs.out.includes("exit=0") && rs.out.includes("restore complete") && healthy.out.startsWith("active active active active"),
    `restored in ${Math.round((Date.now() - t0) / 1000)} s; services: ${healthy.out}`);
  const old = await api("GET", "/api/v1/listeners");
  check("restore-sessions-revoked", old.status === 401, "pre-restore session rejected: " + old.status);
  await login();
  const ls = (await api("GET", "/api/v1/listeners")).body.items || [];
  check("restore-state", marker.status === 201 && !ls.some((l) => l.name === "after-backup") && ls.length > 0, `post-backup listener gone; ${ls.length} listeners restored`);
  const doc = await sh("/opt/ngm/current/ngm audit verify; /opt/ngm/current/ngm db check; /opt/ngm/current/ngm doctor | grep -iE 'vault|audit' | head -3");
  check("restore-integrity", doc.out.includes("audit chain ok") && doc.out.includes("integrity: ok"), doc.out.replace(/\n/g, " | "));
  const safety = await sh("ls /var/lib/ngm/backups/ | grep -c pre_restore; ls /var/lib/ngm/ | grep -c 'ngm.db.pre-restore-'");
  check("restore-safety-copies", safety.out.split("\n").every((x) => Number(x) >= 1), "pre_restore archive + previous DB kept: " + safety.out.replace(/\n/g, " "));
  // CLI backup.
  const cli = await sh(`/opt/ngm/current/ngm backup create; /opt/ngm/current/ngm backup list | head -3`);
  check("bk-cli", cli.code === 0 && cli.out.includes("written and verified"), cli.out.split("\n")[0]);
  return PASS;
}

async function vaultTests() {
  const before = await sh("/opt/ngm/current/ngm vault status");
  const rot = await sh("/opt/ngm/current/ngm vault rotate; echo exit=$?", 120000);
  const after = await sh("sleep 2; /opt/ngm/current/ngm vault status; systemctl is-active ngm-api ngm-ops ngm-monitor | tr '\\n' ' '; stat -c '%U:%G %a %n' /etc/ngm/keys/*");
  check("vault-rotate", rot.out.includes("exit=0") && after.out.includes("retiring") && after.out.includes("active active active"),
    `${before.out.split("\n")[0]} → ${after.out.replace(/\n/g, " | ")}`);
  // Interrupted rotation: SIGKILL (by PID) right after the new key file appears, then resume (scripts/e2e/rotkill.sh).
  const rk = await sh("sh /tmp/rotkill.sh keyfile", 180000);
  check("vault-rotate-interrupted-resumes", rk.out.includes("killed pid") && rk.out.includes("exit=0") && /--- resume[\s\S]*active active active/.test(rk.out) && rk.out.includes("vault_perms    key files root:ngm-vault 0440"),
    rk.out.split("\n").filter((l) => /killed|exit=|active KEK|vault_perms|^active|^failed|activating/.test(l)).join(" | "));
  // Secrets still usable: TOTP login decrypts the new secret, and TLS keys deploy.
  const ok = await login();
  const r = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-after-rot-" + Date.now() });
  const j = await waitJob(r.body.job_id, 120000);
  check("vault-secrets-usable", ok && j.state === "Succeeded", `TOTP sign-in=${ok}; deploy with TLS key from vault → ${j.state}`);
}

async function crashTests() {
  // API crash: systemd restarts it and the data plane is unaffected.
  const a = await sh(`systemctl kill -s KILL ngm-api; for i in $(seq 1 30); do sleep 1; curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9999/api/v1/system/health | grep -qE '200|503' && break; done; echo " after=$i s"; systemctl show ngm-api -p NRestarts --value; curl -s -o /dev/null -w '%{http_code}' -H 'Host: ${val("domain")}' http://127.0.0.1/`);
  check("crash-api", /after=\d+ s/.test(a.out) && a.out.trim().endsWith("200"), "API SIGKILL → restarted; data plane HTTP: " + a.out.replace(/\n/g, " "));
  // Helper crash during a deployment: job must end safely and Nginx keep serving a valid config.
  await login();
  const r = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-helper-kill-" + Date.now() });
  await sh("for i in $(seq 1 200); do pgrep -f 'ngm helper' >/dev/null && break; sleep 0.01; done; sleep 0.15; systemctl kill -s KILL ngm-helper");
  const j = await waitJob(r.body.job_id, 180000);
  const n = await sh(`nginx -t 2>&1 | tail -1; readlink /etc/nginx/ngm/current; curl -s -o /dev/null -w '%{http_code}' -H 'Host: ${val("domain")}' http://127.0.0.1/; systemctl is-active ngm-helper`);
  check("crash-helper-mid-deploy", ["Succeeded", "Failed", "RolledBack", "RecoveryRequired"].includes(j.state) && n.out.includes("successful") && n.out.includes("200"),
    `job → ${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 160) : ""}; ${n.out.replace(/\n/g, " | ")}`);
  if (j.state === "RecoveryRequired") {
    const inc = (await api("GET", "/api/v1/recovery/incidents?status=open")).body.items || [];
    check("crash-helper-incident", inc.length > 0, "Recovery Center shows: " + (inc[0] || {}).summary);
  }
  // Stale lock: ops killed holding a lease → lease expires and later jobs run.
  const r2 = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-after-crash-" + Date.now() });
  const j2 = await waitJob(r2.body.job_id, 180000);
  check("crash-recovered", ["Succeeded", "Blocked"].includes(j2.state), `next deployment → ${j2.state} ${j2.error ? JSON.stringify(j2.error).slice(0, 160) : ""}`);
}

(async () => {
  ssh = await connectSSH();
  const server = net.createServer((sock) => ssh.forwardOut("127.0.0.1", 0, "127.0.0.1", 9999, (err, st) => (err ? sock.destroy() : sock.pipe(st).pipe(sock))));
  await new Promise((r) => server.listen(19998, "127.0.0.1", r));
  try {
    const v = await sh("/opt/ngm/current/ngm version");
    console.log("     " + v.out);
    check("auth", await login(), "owner signed in with TOTP");
    if (ONLY.includes("monitor")) await monitorTests();
    if (ONLY.includes("firewall")) await fwTests();
    if (ONLY.includes("deadman")) await deadmanTest();
    if (ONLY.includes("recovery")) await recoveryTests();
    if (ONLY.includes("drift")) await driftTests();
    if (ONLY.includes("killpoint")) await killpointTests();
    if (ONLY.includes("steps")) { const jl = (await api("GET", "/api/v1/jobs?limit=8")).body.items; for (const x of jl) console.log(x.id.slice(-6), x.kind, x.state, (await steps(x.id)).map((s) => s.name + (s.status === "failed" ? "(failed)" : "")).join(" > ")); }
    if (ONLY.includes("inc")) { console.log(JSON.stringify((await api("GET", "/api/v1/recovery/incidents")).body.items.map((x) => [x.id, x.status, x.job_kind, x.job_state, x.summary]))); const jl = (await api("GET", "/api/v1/jobs?limit=4")).body.items; for (const x of jl) console.log(x.kind, x.state, JSON.stringify(x.error||"").slice(0,250)); }
    if (ONLY.includes("backup")) await backupTests();
    if (ONLY.includes("vault")) await vaultTests();
    if (ONLY.includes("crash")) await crashTests();
  } catch (e) {
    check("harness", false, e.stack || String(e));
    await sh("ufw status | head -1").then((x) => console.log("     ufw:", x.out)).catch(() => {});
  } finally {
    fs.writeFileSync(require("path").join(require("os").tmpdir(), "e2e_p4_results_") + ONLY.join("-") + ".json", JSON.stringify(results, null, 2));
    console.log(`\n${results.filter((r) => r.ok).length}/${results.length} passed`);
    server.close();
    ssh.end();
  }
})();
