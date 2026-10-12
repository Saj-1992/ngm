// Forwards a TCP port of this server to another host:port (Layer 4, no TLS handling) through the
// NGM API, then applies it with Safe Apply (preview, rollback on failure). Works for VMess/VLESS/
// Trojan etc. with any transport header, because the bytes are passed through untouched.
//
//   node scripts/ops/forward_tcp.cjs <listenPort> <targetHost> [targetPort] [name]
//   e.g. node scripts/ops/forward_tcp.cjs 849 78.135.77.113 849 vmess-849
const H = require("../e2e/harness.cjs");
const { check, api, waitJob } = H;
const [LISTEN, HOST, TPORT, NAME] = [Number(process.argv[2]), process.argv[3], Number(process.argv[4] || process.argv[2]), process.argv[5] || "fwd-" + process.argv[2]];
if (!LISTEN || !HOST) {
  console.error("usage: node scripts/ops/forward_tcp.cjs <listenPort> <targetHost> [targetPort] [name]");
  process.exit(2);
}
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const find = async (path, name) => ((await api("GET", path)).body.items || []).find((x) => x.name === name);

H.start(async () => {
  check("auth", await H.login(), "signed in");
  await H.stepUp();
  const be = (await find("/api/v1/backends", NAME)) || (await api("POST", "/api/v1/backends", { name: NAME, host: HOST, port: TPORT, transport: "tcp" })).body;
  check("backend", !!be.id, `backend ${NAME} → ${HOST}:${TPORT}`);
  const ls = (await find("/api/v1/listeners", NAME)) || (await api("POST", "/api/v1/listeners", { name: NAME, kind: "stream", address: "0.0.0.0", port: LISTEN })).body;
  check("listener", !!ls.id, `listener ${NAME} on 0.0.0.0:${LISTEN} (TCP)`);
  const rt = (await find("/api/v1/routes", NAME)) || (await api("POST", "/api/v1/routes", { name: NAME, listener_id: ls.id, protocol: "tcp", destination_kind: "endpoint", destination_id: be.id })).body;
  check("route", !!rt.id, `route ${NAME}: TCP :${LISTEN} → ${HOST}:${TPORT}`);
  const v = (await api("GET", "/api/v1/gateway/validation?preview=1")).body;
  check("validate", v.valid === true, `model valid; ${(v.issues || []).length} issue(s)`);
  const d = await api("POST", "/api/v1/deployments", {}, key("fwd-"));
  const j = await waitJob(d.body.job_id, 300000);
  check("apply", j.state === "Succeeded", `Safe Apply → ${j.state}${j.error ? " " + JSON.stringify(j.error).slice(0, 200) : ""}`);
  console.log(`\nDone. Use this server's address and port ${LISTEN} in your client; the VMess settings stay the same as on the target.`);
});
