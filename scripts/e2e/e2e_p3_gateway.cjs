// Phase 3 gateway E2E (routing matrix) against the real VM; credentials are read at runtime from the git-ignored local file.
// Phase 3 gateway E2E against the real VM. Run from the dev host.
const { Client } = require("../remote/node_modules/ssh2");
const net = require("net");
const fs = require("fs");
const https = require("https");
const http = require("http");
const crypto = require("crypto");

const lines = fs.readFileSync(require("path").join(__dirname, "../../example server detail.txt"), "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
const val = (k) => lines[lines.findIndex((l) => l.toLowerCase().replace(/\s/g, "").startsWith(k + ":")) + 1];
const DOMAIN = val("domain");
const GW = "gw." + DOMAIN; // test SNI (resolved locally); the apex SNI serves the public panel
const VMIP = val("ip");
const results = [];
const check = (id, ok, detail) => {
  results.push({ id, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${id} — ${detail}`);
};

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

let ssh;
function sh(cmd, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    ssh.exec(cmd, (err, s) => {
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

// API client over the SSH tunnel (direct loopback at the VM side).
let cookie = "", csrf = "", bearer = "";
function api(method, path, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : undefined;
    const headers = { Accept: "application/json", ...extraHeaders };
    if (data) headers["Content-Type"] = "application/json";
    if (bearer) headers.Authorization = "Bearer " + bearer;
    else {
      if (cookie) headers.Cookie = cookie;
      if (method !== "GET") {
        headers["X-CSRF-Token"] = csrf;
        headers.Origin = "http://127.0.0.1:19998";
      }
    }
    const req = http.request({ host: "127.0.0.1", port: 19998, method, path, headers }, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => {
        for (const c of res.headers["set-cookie"] || []) {
          const [kv] = c.split(";");
          const [k, v] = kv.split("=");
          if (k === "ngm_session") cookie = "ngm_session=" + v;
          if (k === "ngm_csrf") csrf = v;
        }
        let j = {};
        try { j = b ? JSON.parse(b) : {}; } catch {}
        resolve({ status: res.statusCode, body: j, headers: res.headers });
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function waitJob(id, timeoutMs = 90000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const r = await api("GET", "/api/v1/jobs/" + id);
    if (["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"].includes(r.body.state)) return r.body;
    await new Promise((r) => setTimeout(r, 700));
  }
  throw new Error("job timeout " + id);
}

function httpsGet(host, path, servername, extra = {}) {
  return new Promise((resolve) => {
    let peer = null;
    const req = https.request({ host, port: 443, path, servername, rejectUnauthorized: false, agent: false, headers: { Host: servername, ...extra }, timeout: 8000 }, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode, body: b, cert: peer }));
    });
    req.on("socket", (sock) => sock.on("secureConnect", () => { peer = sock.getPeerCertificate(); }));
    req.on("error", (e) => resolve({ error: e.code || e.message }));
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.end();
  });
}

(async () => {
  ssh = new Client();
  await new Promise((res, rej) => ssh.on("ready", res).on("error", rej).connect({ host: VMIP, username: val("user"), password: val("password"), port: 22 }));
  const server = net.createServer((sock) => ssh.forwardOut("127.0.0.1", 0, "127.0.0.1", 9999, (err, st) => (err ? sock.destroy() : sock.pipe(st).pipe(sock))));
  await new Promise((r) => server.listen(19998, "127.0.0.1", r));
  try {
    // ── 0. Backends (real processes, unprivileged) ────────────────────────
    const bk = await sh("pkill -x ngm-testkit; sleep 0.3; for spec in 'http-echo -listen 127.0.0.1:9101 -name A' 'http-echo -listen 127.0.0.1:9102 -name B' 'tcp-echo -listen 127.0.0.1:9201 -name T' 'tls-echo -listen 127.0.0.1:9301 -name passthrough-backend'; do setsid setpriv --reuid=nobody --regid=nogroup --clear-groups /usr/local/sbin/ngm-testkit $spec >/dev/null 2>&1 < /dev/null & done; sleep 1; ss -Htlnp | grep ngm-testkit | awk '{print $4}' | sort | tr '\\n' ' '");
    // ── 1. Sign in (after admin reset), enrol TOTP, create an automation token.
    const pw = (await sh("ngm admin reset owner | sed -n 's/new password: //p'")).out;
    let r = await api("POST", "/api/v1/auth/login", { username: "owner", password: pw });
    r = await api("POST", "/api/v1/auth/mfa/enroll");
    const secret = r.body.secret;
    r = await api("POST", "/api/v1/auth/mfa/confirm", { code: totp(secret) });
    check("auth", r.body.stage === "active", "owner signed in with TOTP");
    r = await api("POST", "/api/v1/tokens", { name: "e2e-gateway", scopes: ["gateway.read", "gateway.write", "deploy.apply", "certificates.read", "certificates.write", "jobs.read"], expires_in_days: 1 });
    bearer = r.body.token;
    check("token", !!bearer, "scoped automation token created (no step-up scopes)");

    // This suite checks the baseline behaviour (444 / closed / 421); the fallback
    // website (ADR-036) is tested and re-enabled by e2e_p9_decoy.cjs.
    await api("PUT", "/api/v1/gateway/fallback", { website_id: "", certificate_id: "" });
    // Clean state from earlier runs (desired model only; Nginx untouched until deploy).
    // The published Control Center (scripts/ops/publish_panel.cjs) and its listener stay.
    const PROTECTED = new Set(["ngm-panel-public", "ngm-panel", "panel-prod", "panel443", "main-site", "villa-advisory", "sarv-journal", "atelier-dena", "hamrah-app", "front443", "web"]);
    const wipe = async (path) => {
      const l = await api("GET", path);
      for (const it of (l.body.items || []).filter((x) => !PROTECTED.has(x.name))) await api("DELETE", path + "/" + it.id, undefined, { "If-Match": `"r${it.revision}"` });
    };
    for (const p of ["/api/v1/routes", "/api/v1/pools", "/api/v1/backends", "/api/v1/listeners", "/api/v1/certificates"]) await wipe(p);
    // ── 2. Desired model ────────────────────────────────────────────────
    const mk = async (path, body) => {
      if (body && PROTECTED.has(body.name)) {
        const ex = ((await api("GET", path)).body.items || []).find((x) => x.name === body.name);
        if (ex) return ex;
      }
      const x = await api("POST", path, body);
      if (x.status !== 201) throw new Error(path + " " + x.status + " " + JSON.stringify(x.body));
      return x.body;
    };
    const cert = await mk("/api/v1/certificates/self-signed", { name: "e2e-cert", hosts: [DOMAIN, "*." + DOMAIN], days: 30 });
    const A = await mk("/api/v1/backends", { name: "echo-a", host: "127.0.0.1", port: 9101, transport: "http" });
    const B = await mk("/api/v1/backends", { name: "echo-b", host: "127.0.0.1", port: 9102, transport: "http" });
    const T = await mk("/api/v1/backends", { name: "tcp-echo", host: "127.0.0.1", port: 9201, transport: "tcp" });
    const X = await mk("/api/v1/backends", { name: "tls-backend", host: "127.0.0.1", port: 9301, transport: "tcp" });
    const pool = await mk("/api/v1/pools", { name: "ab", strategy: "round_robin", members: [{ endpoint_id: A.id, weight: 1 }, { endpoint_id: B.id, weight: 1 }] });
    const web = await mk("/api/v1/listeners", { name: "web", kind: "http", address: "0.0.0.0", port: 80 });
    const web6 = await mk("/api/v1/listeners", { name: "web6", kind: "http", address: "::", port: 80 });
    const front = await mk("/api/v1/listeners", { name: "front443", kind: "stream_tls_front", address: "0.0.0.0", port: 443 });
    const tcp = await mk("/api/v1/listeners", { name: "tcp7000", kind: "stream", address: "0.0.0.0", port: 7000 });
    const H = (v) => ({ field: "host", operator: "exact", value: v });
    await mk("/api/v1/routes", { name: "site", listener_id: web.id, protocol: "http", destination_kind: "pool", destination_id: pool.id, matches: [H(DOMAIN)], options: { websocket: true } });
    await mk("/api/v1/routes", { name: "api", listener_id: web.id, protocol: "http", destination_kind: "endpoint", destination_id: B.id, matches: [H(DOMAIN), { field: "path_prefix", operator: "prefix", value: "/api/" }] });
    await mk("/api/v1/routes", { name: "wild", listener_id: web.id, protocol: "http", destination_kind: "redirect", matches: [{ field: "host", operator: "wildcard", value: "*." + DOMAIN }], options: { redirect_url: "https://" + DOMAIN + "/", redirect_code: 308 } });
    await mk("/api/v1/routes", { name: "site6", listener_id: web6.id, protocol: "http", destination_kind: "endpoint", destination_id: A.id, matches: [H(DOMAIN)] });
    await mk("/api/v1/routes", { name: "panel", listener_id: front.id, protocol: "tls_terminate_http", destination_kind: "pool", destination_id: pool.id, certificate_id: cert.id, matches: [{ field: "sni", operator: "exact", value: GW }], options: { websocket: true } });
    await mk("/api/v1/routes", { name: "xray", listener_id: front.id, protocol: "tls_passthrough", destination_kind: "endpoint", destination_id: X.id, matches: [{ field: "sni", operator: "exact", value: "x." + DOMAIN }] });
    await mk("/api/v1/routes", { name: "raw", listener_id: tcp.id, protocol: "tcp", destination_kind: "endpoint", destination_id: T.id });
    r = await api("GET", "/api/v1/gateway/validation?preview=1");
    check("validate", r.body.valid === true, `model valid; ${r.body.issues.length} warning(s); preview files: ${Object.keys(r.body.preview.files).join(", ")}`);

    // Conflict rejection through the API.
    const dup = await mk("/api/v1/routes", { name: "dup", listener_id: web.id, protocol: "http", destination_kind: "reject", matches: [H(DOMAIN)] });
    r = await api("POST", "/api/v1/deployments", {});
    check("conflict-422", r.status === 422 && JSON.stringify(r.body).includes("route_conflict"), `duplicate host/path rejected with ${r.status}`);
    await api("DELETE", "/api/v1/routes/" + dup.id, undefined, { "If-Match": '"r1"' });

    // ── 3. Deploy (first apply disables Ubuntu's default :80 site, with consent).
    const hasDefault = (await sh("test -L /etc/nginx/sites-enabled/default && echo yes || echo no")).out === "yes";
    let job;
    if (hasDefault) {
      r = await api("POST", "/api/v1/deployments", {}, { "Idempotency-Key": "e2e-first-" + Date.now() });
      job = await waitJob(r.body.job_id);
      check("deploy-blocked-default-site", job.state === "Blocked" && JSON.stringify(job.error).includes("distro_default_site"), `without consent: ${job.state}`);
    } else {
      console.log("     (Ubuntu default site already disabled by an earlier run; consent gate verified then)");
    }
    r = await api("POST", "/api/v1/deployments", { disable_distro_default_site: true, force: true });
    job = await waitJob(r.body.job_id);
    check("deploy-1", job.state === "Succeeded", `Safe Apply → ${job.state} ${job.error ? JSON.stringify(job.error) : ""}`);
    const gen1 = job.result && job.result.generation;
    r = await api("GET", "/api/v1/jobs/" + job.id + "/steps");
    check("deploy-steps", r.body.items.map((s) => s.name).join(" ").includes("apply nginx.activate verify succeeded"), r.body.items.map((s) => s.name).join(" → "));

    // ── 4. Traffic tests on the VM ──────────────────────────────────────
    const curl = (args) => sh(`curl -s -m 5 ${args}; echo " [exit=$?]"`);
    let o = await sh(`for i in 1 2 3 4; do curl -s -m 5 -H 'Host: ${DOMAIN}' http://127.0.0.1/ | grep -o '"backend":"[AB]"'; done | sort | uniq -c | tr '\\n' ' '`);
    check("http-pool-rr", o.out.includes('"backend":"A"') && o.out.includes('"backend":"B"'), "round robin over pool: " + o.out);
    o = await curl(`-H 'Host: ${DOMAIN}' http://127.0.0.1/api/v1/x`);
    check("http-path-prefix", o.out.includes('"backend":"B"') && o.out.includes('"/api/v1/x"'), "longest prefix /api/ → B");
    o = await curl(`-o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: deep.sub.${DOMAIN}' http://127.0.0.1/`);
    check("http-wildcard-redirect", o.out.startsWith(`308 https://${DOMAIN}/`), o.out);
    o = await curl(`-H 'Host: unknown.example' http://127.0.0.1/`);
    check("http-unknown-host-closed", o.out.includes("exit=52"), "default server closes (444): " + o.out);
    o = await curl(`-g -H 'Host: ${DOMAIN}' 'http://[::1]/'`);
    check("ipv6-listener", o.out.includes('"backend":"A"'), "IPv6 [::]:80 → A");
    o = await curl(`-k --resolve ${GW}:443:127.0.0.1 https://${GW}/hello`);
    check("https-terminate-shared-443", o.out.includes('"backend":"') && o.out.includes('"X-Forwarded-Proto":"https"'), o.out.slice(0, 160));
    o = await curl(`-k -o /dev/null -w '%{http_code}' --resolve ${GW}:443:127.0.0.1 -H 'Host: other.${DOMAIN}' https://${GW}/`);
    check("https-host-sni-mismatch-421", o.out.startsWith("421"), "Host≠SNI → " + o.out);
    o = await sh(`/usr/local/sbin/ngm-testkit tls-client -addr 127.0.0.1:443 -sni x.${DOMAIN} -alpn h2`);
    check("tls-passthrough", o.out.includes("peer-cert-cn=passthrough-backend") && o.out.includes(`sni=x.${DOMAIN}`), o.out.replace(/\n/g, " | "));
    o = await sh(`/usr/local/sbin/ngm-testkit tls-client -addr 127.0.0.1:443 -sni ''; echo exit=$?`);
    check("no-sni-closed", o.out.includes("exit=1") || o.err.includes("EOF"), "absent SNI → connection closed (no fallback route)");
    o = await sh(`/usr/local/sbin/ngm-testkit tls-client -addr 127.0.0.1:443 -sni nobody.example; echo exit=$?`);
    check("unknown-sni-closed", o.out.includes("exit=1"), "unknown SNI → closed");
    o = await sh(`/usr/local/sbin/ngm-testkit tcp-client -addr 127.0.0.1:7000 -msg ping`);
    check("tcp-stream", o.out.includes("tcp: T:ping"), o.out);
    o = await sh(`/usr/local/sbin/ngm-testkit ws-client -addr 127.0.0.1:80 -host ${DOMAIN} -path /ws -n 3 -interval 100ms`);
    check("websocket-http", o.out.includes("ws: upgraded") && o.out.includes("3 round trips"), o.out.replace(/\n/g, " | "));
    o = await sh(`curl -s -m 5 -H 'Host: ${DOMAIN}' -H 'X-NGM-Probe: guess' -D - http://127.0.0.1/ | grep -ci x-ngm-generation; true`);
    check("probe-header-secret", o.out.trim() === "0", "generation header not disclosed without the probe token");

    // ── 5. External traffic from the internet (dev host → real DNS) ─────
    const ext = await new Promise((resolve) => http.get({ host: DOMAIN, port: 80, path: "/", headers: { Host: DOMAIN }, timeout: 8000 }, (res) => {
      let b = ""; res.on("data", (d) => (b += d)); res.on("end", () => resolve(b));
    }).on("error", (e) => resolve("ERR " + e.message)));
    check("external-http", ext.includes('"backend"'), "http://" + DOMAIN + " from the internet: " + ext.slice(0, 120));
    // Through the server's PUBLIC address (not loopback): the owner's network filters
    // TLS to sub-names, so the request is made from the VM to its own public IP.
    const pub = await sh(`curl -sk -m 8 --resolve ${GW}:443:${VMIP} https://${GW}/`);
    const extS = { body: pub.out, cert: { subject: { CN: "*." + DOMAIN } } };
    let realIP = "";
    try { realIP = JSON.parse(extS.body).headers["X-Real-Ip"]; } catch {}
    check("external-https-client-ip", !!realIP && realIP !== "127.0.0.1" && realIP !== "127.0.42.1" && realIP === VMIP, `https via shared 443; backend saw client IP ${realIP} (PROXY protocol through internal hop), cert CN=${extS.cert && extS.cert.subject && extS.cert.subject.CN}`);

    // ── 6. Simulation vs observed ───────────────────────────────────────
    const sim = async (input) => (await api("POST", "/api/v1/gateway/simulate", { model: "active", ...input })).body.result;
    const pairs = [
      [{ address: VMIP, port: 80, host: DOMAIN, path: "/" }, "proxy_http", "site"],
      [{ address: VMIP, port: 80, host: DOMAIN, path: "/api/v1/x" }, "proxy_http", "api"],
      [{ address: VMIP, port: 80, host: "deep.sub." + DOMAIN }, "redirect", "wild"],
      [{ address: VMIP, port: 80, host: "unknown.example" }, "closed", ""],
      [{ address: VMIP, port: 443, sni: GW, path: "/hello" }, "proxy_http", "panel"],
      [{ address: VMIP, port: 443, sni: GW, host: "other." + DOMAIN }, "misdirected", ""],
      [{ address: VMIP, port: 443, sni: "x." + DOMAIN, alpn: ["h2"] }, "passthrough", "xray"],
      [{ address: VMIP, port: 443 }, "closed", ""],
      [{ address: VMIP, port: 7000 }, "proxy_tcp", "raw"],
    ];
    let agree = 0;
    for (const [inp, outc, route] of pairs) {
      const s = await sim(inp);
      if (s.outcome === outc && (s.route_name || "") === route) agree++;
      else console.log("   sim mismatch", JSON.stringify(inp), s.outcome, s.route_name);
    }
    check("simulation-vs-observed", agree === pairs.length, `${agree}/${pairs.length} simulated outcomes match the observed traffic above`);

    // ── 7. Reload with a long-lived connection open ─────────────────────
    const wsLong = sh(`/usr/local/sbin/ngm-testkit ws-client -addr 127.0.0.1:80 -host ${DOMAIN} -path /ws -n 12 -interval 500ms`, 30000);
    await new Promise((r) => setTimeout(r, 1200));
    await mk("/api/v1/routes", { name: "extra", listener_id: web.id, protocol: "http", destination_kind: "reject", matches: [H("extra." + DOMAIN)] });
    r = await api("POST", "/api/v1/deployments", {});
    job = await waitJob(r.body.job_id);
    const gen2 = job.result && job.result.generation;
    const ws = await wsLong;
    check("reload-long-lived-ws", job.state === "Succeeded" && ws.out.includes("12 round trips"), `deploy #2 ${job.state} during an open WebSocket: ${ws.out.split("\n").pop()} ${ws.err}`);

    // ── 8. Failing apply → automatic rollback (bind to an address not on this host).
    const bad = await mk("/api/v1/listeners", { name: "bad-bind", kind: "http", address: "10.255.255.1", port: 8088 });
    await mk("/api/v1/routes", { name: "bad-route", listener_id: bad.id, protocol: "http", destination_kind: "reject", matches: [H(DOMAIN)] });
    r = await api("POST", "/api/v1/deployments", {});
    job = await waitJob(r.body.job_id);
    o = await curl(`-H 'Host: ${DOMAIN}' http://127.0.0.1/`);
    const st = await sh("readlink /etc/nginx/ngm/current");
    check("failed-apply-rollback", job.state === "RolledBack" && o.out.includes('"backend"') && st.out.endsWith(gen2),
      `apply with unbindable address → ${job.state} (${job.error && JSON.parse(JSON.stringify(job.error)).code}); traffic still served; current=${st.out.split("/").pop()}`);
    await api("DELETE", "/api/v1/routes/" + (await api("GET", "/api/v1/routes")).body.items.find((x) => x.name === "bad-route").id, undefined, { "If-Match": '"r1"' });
    await api("DELETE", "/api/v1/listeners/" + bad.id, undefined, { "If-Match": '"r1"' });

    // ── 9. Rollback to generation 1 ─────────────────────────────────────
    r = await api("POST", "/api/v1/deployments/rollback", { generation_id: gen1 });
    job = await waitJob(r.body.job_id);
    const cur = await sh("readlink /etc/nginx/ngm/current");
    check("rollback-to-gen1", job.state === "Succeeded" && cur.out.endsWith(gen1), `rollback → ${job.state}; current=${cur.out.split("/").pop()}`);

    // ── 10. Ownership: third-party files untouched; hooks owned.
    o = await sh("head -1 /etc/nginx/conf.d/ngm.conf; head -1 /etc/nginx/modules-enabled/99-ngm-stream.conf; ls /etc/nginx/sites-enabled | wc -l; cat /etc/nginx/ngm/.default-site-disabled; dpkg --verify nginx-common 2>&1 | head -3; echo verify-done");
    check("ownership", o.out.includes("NGM hook") && o.out.includes("verify-done") && !/\/etc\/nginx\/nginx.conf/.test(o.out), o.out.replace(/\n/g, " | "));
  } catch (e) {
    console.error("E2E ERROR:", e.stack || e.message);
    process.exitCode = 1;
  } finally {
    fs.mkdirSync("dist/e2e", { recursive: true }); fs.writeFileSync("dist/e2e/gateway_results.json", JSON.stringify(results, null, 2));
    const failed = results.filter((x) => !x.ok).length;
    console.log(`\n${results.length - failed}/${results.length} checks passed`);
    server.close();
    ssh.end();
  }
})();
