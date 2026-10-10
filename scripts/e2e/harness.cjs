// Shared live-test harness for the VM (SSH tunnel to the loopback API, TOTP sign-in, job waits).
// Credentials are read at runtime from the git-ignored "example server detail.txt".
const { Client } = require("../remote/node_modules/ssh2");
const net = require("net");
const fs = require("fs");
const http = require("http");
const crypto = require("crypto");

const lines = fs.readFileSync(require("path").join(__dirname, "..", "..", "example server detail.txt"), "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
const val = (k) => lines[lines.findIndex((l) => l.toLowerCase().replace(/\s/g, "").startsWith(k + ":")) + 1];
const VMIP = val("ip");
const SSHCFG = { host: VMIP, username: val("user"), password: val("password"), port: 22, readyTimeout: 20000 };
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
function api(method, path, body, extraHeaders = {}, raw = false, rawBody) {
  return new Promise((resolve, reject) => {
    const data = rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : undefined;
    const headers = { Accept: "application/json", ...extraHeaders };
    if (data && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    if (data) headers["Content-Length"] = Buffer.byteLength(data);
    if (cookie) headers.Cookie = cookie;
    if (method !== "GET") {
      if (!("X-CSRF-Token" in extraHeaders)) headers["X-CSRF-Token"] = csrf;
      if (!("Origin" in extraHeaders)) headers.Origin = "http://127.0.0.1:19998";
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


function start(main) {
  (async () => {
    ssh = await connectSSH();
    const server = net.createServer((sock) => ssh.forwardOut("127.0.0.1", 0, "127.0.0.1", 9999, (err, st) => (err ? sock.destroy() : sock.pipe(st).pipe(sock))));
    await new Promise((r) => server.listen(19998, "127.0.0.1", r));
    try {
      console.log("     " + (await sh("/opt/ngm/current/ngm version")).out);
      check("auth", await login(), "owner signed in with TOTP");
      await main();
    } catch (e) {
      check("harness", false, e.stack || String(e));
    } finally {
      console.log(`
${results.filter((r) => r.ok).length}/${results.length} passed`);
      server.close();
      ssh.end();
    }
  })();
}
const H = { check, sleep, sh, api, waitJob, steps, login, stepUp, freshSSH, start, val, VMIP, results, TERMINAL, session: () => ({ cookie, csrf }) };
module.exports = H;
