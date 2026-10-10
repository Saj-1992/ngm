// Closes routing evidence gaps (O-8): HTTPS backend with proxy_ssl_verify off/on, and
// WebSocket over Nginx-terminated TLS on shared 443. Run after e2e_p3_gateway.cjs.
// Prerequisite: `ngm-testkit https-echo -listen 127.0.0.1:9401 -name S` running on the VM.
const H = require("./harness.cjs");
const { check, sh, api, val } = H;
const DOMAIN = val("domain");
const NAME = "https." + DOMAIN;
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const deploy = async (k) => { const r = await api("POST", "/api/v1/deployments", {}, key(k)); if (!r.body.job_id) throw new Error("deploy " + r.status + " " + JSON.stringify(r.body).slice(0, 400)); return H.waitJob(r.body.job_id); };

H.start(async () => {
  // Leftovers from an interrupted run.
  for (const [p, n] of [["/api/v1/routes", "https-be"], ["/api/v1/backends", "https-s"]])
    for (const it of (await api("GET", p)).body.items.filter((x) => x.name === n)) await api("DELETE", p + "/" + it.id, undefined, { "If-Match": `"r${it.revision}"` });
  const web = (await api("GET", "/api/v1/listeners")).body.items.find((l) => l.name === "web");
  let ep = await api("POST", "/api/v1/backends", { name: "https-s", host: "127.0.0.1", port: 9401, transport: "https", tls_verify: false, tls_server_name: "backend.test" });
  check("https-backend-create", ep.status === 201, "https backend (self-signed) " + ep.status);
  ep = ep.body;
  const rt = (await api("POST", "/api/v1/routes", { name: "https-be", listener_id: web.id, protocol: "http", destination_kind: "endpoint", destination_id: ep.id, matches: [{ field: "host", operator: "exact", value: NAME }] })).body;
  let j = await deploy("hb1");
  let o = await sh(`curl -s -m 5 -o /tmp/hb.out -w '%{http_code}' -H 'Host: ${NAME}' http://127.0.0.1/x; head -c 60 /tmp/hb.out; echo; grep -rh 'proxy_ssl_verify\\|proxy_ssl_name' /etc/nginx/ngm/current/ | sort -u | tr '\\n' ' '`);
  check("https-backend-verify-off", j.state === "Succeeded" && o.out.startsWith("200") && o.out.includes('"backend":"S"') && o.out.includes("proxy_ssl_verify off"), o.out.replace(/\n/g, " | "));

  // Verification on: the self-signed backend is not in the trust bundle → Nginx refuses it.
  const cur = (await api("GET", "/api/v1/backends/" + ep.id)).body;
  const up = await api("PUT", "/api/v1/backends/" + ep.id, { name: cur.name, host: cur.host, port: cur.port, transport: cur.transport, tls_server_name: cur.tls_server_name, tls_verify: true }, { "If-Match": `"r${cur.revision}"` });
  j = await deploy("hb2");
  o = await sh(`curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: ${NAME}' http://127.0.0.1/x; echo; grep -rh 'proxy_ssl_verify' /etc/nginx/ngm/current/ | sort -u | tr '\\n' ' '; grep -c 'upstream SSL certificate verify error\\|certificate verify failed' /var/log/ngm/nginx/error.log`);
  check("https-backend-verify-on", up.status === 200 && j.state === "Succeeded" && o.out.startsWith("502") && o.out.includes("proxy_ssl_verify on"), `PUT ${up.status} ${up.status !== 200 ? JSON.stringify(up.body).slice(0, 200) : ""} ; ` + o.out.replace(/\n/g, " | "));

  // WebSocket through TLS terminated by Nginx (route "panel": SNI DOMAIN on shared 443).
  o = await sh(`/usr/local/sbin/ngm-testkit ws-client -addr 127.0.0.1:443 -sni gw.${DOMAIN} -host gw.${DOMAIN} -path /ws -n 3 -interval 100ms 2>&1`);
  check("websocket-over-tls", o.out.includes("ws: upgraded") && o.out.includes("3 round trips"), o.out.replace(/\n/g, " | "));

  // Clean up.
  const r2 = (await api("GET", "/api/v1/routes/" + rt.id)).body;
  await api("DELETE", "/api/v1/routes/" + rt.id, undefined, { "If-Match": `"r${r2.revision}"` });
  const e2 = (await api("GET", "/api/v1/backends/" + ep.id)).body;
  await api("DELETE", "/api/v1/backends/" + ep.id, undefined, { "If-Match": `"r${e2.revision}"` });
  j = await deploy("hb3");
  check("cleanup", j.state === "Succeeded", "test route/backend removed, redeployed: " + j.state);
});
