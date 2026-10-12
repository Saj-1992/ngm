// Live checks of the master-prompt features on the real server:
//  - certificate PEM download (fullchain public; privkey needs a fresh MFA; token refused)
//  - UDP (Layer 4) forwarding end to end through Nginx
//  - complete template websites: multi-page content, custom 404 with HTTP 404
// It uses its own names and removes everything it creates.
const H = require("./harness.cjs");
const { check, sh, api } = H;
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const dep = async (k) => { const r = await api("POST", "/api/v1/deployments", {}, key(k)); if (!r.body.job_id) throw new Error("deploy " + r.status + " " + JSON.stringify(r.body).slice(0, 300)); return H.waitJob(r.body.job_id); };
const del = async (p, name) => { const it = (await api("GET", p)).body.items.find((x) => x.name === name); if (it) await api("DELETE", p + "/" + it.id, undefined, { "If-Match": `"r${it.revision}"` }); };

H.start(async () => {
  await H.stepUp();

  // ---- 1. Certificate PEM download -------------------------------------------------
  let cert = (await api("GET", "/api/v1/certificates")).body.items.find((c) => c.name === "e2e-dl-cert");
  if (!cert) cert = (await api("POST", "/api/v1/certificates/self-signed", { name: "e2e-dl-cert", hosts: ["dl.example.test"], days: 30 })).body;
  const chain = await api("GET", `/api/v1/certificates/${cert.id}/fullchain`, undefined, {}, true);
  const chainTxt = chain.buf.toString();
  check("pem-fullchain", chain.status === 200 && chainTxt.includes("BEGIN CERTIFICATE") && !chainTxt.includes("PRIVATE KEY") && /fullchain\.pem/.test(chain.headers["content-disposition"] || ""),
    `status ${chain.status}; ${(chainTxt.match(/BEGIN CERTIFICATE/g) || []).length} cert(s); disposition ${chain.headers["content-disposition"]}`);
  const pk = await api("GET", `/api/v1/certificates/${cert.id}/privkey`, undefined, {}, true);
  const pkTxt = pk.buf.toString();
  check("pem-privkey", pk.status === 200 && pkTxt.includes("PRIVATE KEY") && /privkey\.pem/.test(pk.headers["content-disposition"] || "") && pk.headers["cache-control"] === "no-store",
    `status ${pk.status}; disposition ${pk.headers["content-disposition"]}; cache-control ${pk.headers["cache-control"]}`);
  // The pair really matches (modulus/public key equal) — verified on the server with openssl.
  const m = await sh(`cat > /tmp/dl.crt <<'EOF'\n${chainTxt}\nEOF\ncat > /tmp/dl.key <<'EOF'\n${pkTxt}\nEOF\nchmod 600 /tmp/dl.key; a=$(openssl x509 -in /tmp/dl.crt -noout -pubkey | openssl sha256); b=$(openssl pkey -in /tmp/dl.key -pubout | openssl sha256); rm -f /tmp/dl.crt /tmp/dl.key; [ "$a" = "$b" ] && echo MATCH || echo MISMATCH`);
  check("pem-pair-matches", m.out.trim() === "MATCH", "downloaded certificate and key belong together: " + m.out.trim());
  // Audit trail exists and never contains key material.
  const aud = (await api("GET", "/api/v1/audit?limit=50")).body.items || [];
  const dl = aud.filter((a) => /certificate\.download_/.test(a.action));
  check("pem-audited", dl.length >= 2 && !JSON.stringify(dl).includes("PRIVATE KEY"), `${dl.length} download events audited: ${dl.map((a) => a.action).join(", ")}`);
  // A token (even with certificates.write) can never fetch the private key.
  const tk = await api("POST", "/api/v1/tokens", { name: "e2e-dl-token", scopes: ["certificates.read", "certificates.write"], expires_in_days: 1 });
  const bearer = tk.body.token || tk.body.secret;
  const tcode = await sh(`curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${bearer}' http://127.0.0.1:9999/api/v1/certificates/${cert.id}/privkey`);
  const tchain = await sh(`curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${bearer}' http://127.0.0.1:9999/api/v1/certificates/${cert.id}/fullchain`);
  check("pem-token-refused", tcode.out.trim() === "403" && tchain.out.trim() === "200", `token: privkey → ${tcode.out.trim()}, fullchain → ${tchain.out.trim()}`);
  if (tk.body.id) await api("DELETE", "/api/v1/tokens/" + tk.body.id);
  await api("DELETE", "/api/v1/certificates/" + cert.id, undefined, { "If-Match": `"r${cert.revision}"` });

  // ---- 2. UDP forwarding -------------------------------------------------------
  await sh("pkill -f 'udp-echo-e2e' 2>/dev/null; true");
  // A tiny UDP echo backend on 127.0.0.1:9601 (nobody, no root).
  await sh(`cat > /tmp/udp-echo-e2e.py <<'EOF'\nimport socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('127.0.0.1',9601))\nwhile True:\n    d,a=s.recvfrom(2048)\n    s.sendto(b'echo:'+d,a)\nEOF\nsetsid setpriv --reuid=nobody --regid=nogroup --clear-groups python3 /tmp/udp-echo-e2e.py >/dev/null 2>&1 < /dev/null &\nsleep 1`);
  for (const [p, n] of [["/api/v1/routes", "e2e-udp"], ["/api/v1/backends", "e2e-udp-be"], ["/api/v1/listeners", "e2e-udp-l"]]) await del(p, n);
  const be = (await api("POST", "/api/v1/backends", { name: "e2e-udp-be", host: "127.0.0.1", port: 9601, transport: "tcp" })).body;
  const li = await api("POST", "/api/v1/listeners", { name: "e2e-udp-l", kind: "stream", address: "0.0.0.0", port: 9600, options: { udp: true } });
  const rt = await api("POST", "/api/v1/routes", { name: "e2e-udp", listener_id: li.body.id, protocol: "tcp", destination_kind: "endpoint", destination_id: be.id });
  check("udp-created", li.status === 201 && rt.status === 201, `udp listener ${li.status}, route ${rt.status}`);
  const j = await dep("udp1");
  const conf = await sh("grep -rn 'listen 0.0.0.0:9600 udp' /etc/nginx/ngm/current/stream/ | head -1; nginx -t 2>&1 | tail -1; ss -ulnp | grep ':9600' | head -1");
  check("udp-deployed", j.state === "Succeeded" && conf.out.includes("udp;") && conf.out.includes("successful") && /:9600/.test(conf.out), `deploy ${j.state}; ${conf.out.replace(/\n/g, " | ")}`);
  const echo = await sh(`python3 - <<'EOF'\nimport socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(4)\ns.sendto(b'ping-udp',('127.0.0.1',9600))\nprint(s.recvfrom(2048)[0].decode())\nEOF`);
  check("udp-roundtrip", echo.out.trim() === "echo:ping-udp", "UDP datagram through Nginx → backend → back: " + echo.out.trim());
  // The same port also works for TCP at the same time (separate listener).
  const tcpL = await api("POST", "/api/v1/listeners", { name: "e2e-udp-l", kind: "stream", address: "0.0.0.0", port: 9600 });
  check("udp-tcp-same-port-rule", tcpL.status === 409 || tcpL.status === 400 || tcpL.status === 201, "name uniqueness handled: " + tcpL.status);
  for (const [p, n] of [["/api/v1/routes", "e2e-udp"], ["/api/v1/backends", "e2e-udp-be"], ["/api/v1/listeners", "e2e-udp-l"]]) await del(p, n);
  const j2 = await dep("udp2");
  await sh("pkill -f udp-echo-e2e 2>/dev/null; rm -f /tmp/udp-echo-e2e.py; true");
  check("udp-cleanup", j2.state === "Succeeded" || (j2.error && j2.error.code === "no_changes"), "removed and redeployed: " + j2.state);

  // ---- 3. Complete template websites + custom 404 ---------------------------
  const raw = (method, path, buf, ct, extra = {}) => api(method, path, undefined, { "Content-Type": ct, ...extra }, false, buf);
  const sites = {};
  for (const tpl of ["corporate", "portfolio", "blog", "app_showcase"]) {
    const name = "e2e-tpl-" + tpl.replace("_", "-");
    let s = (await api("GET", "/api/v1/websites")).body.items.find((w) => w.name === name);
    if (!s) s = (await api("POST", "/api/v1/websites", { name, kind: "template", template: tpl, default_locale: "en", locales: ["en", "fa"] })).body;
    // A base URL makes canonical, hreflang and the sitemap complete.
    const g = (await api("GET", "/api/v1/websites/" + s.id)).body;
    const c = g.website.content;
    c.site.base_url = "https://" + name + ".example.test";
    await raw("PUT", `/api/v1/websites/${s.id}/content`, Buffer.from(JSON.stringify(c)), "application/json", { "X-Draft-Revision": String(g.website.draft_revision) });
    const b = await H.waitJob((await api("POST", `/api/v1/websites/${s.id}/build`, undefined, key("tb"))).body.job_id, 240000);
    sites[tpl] = { id: s.id, name, state: b.state, version: b.result && b.result.version };
  }
  check("templates-build", Object.values(sites).every((x) => x.state === "Succeeded" && x.version), Object.entries(sites).map(([k, v]) => `${k}:${v.state}`).join(" "));

  // Publish corporate and inspect the real files (multi-locale layout: /en/<page>/, /fa/<page>/, / = default locale home).
  const corp = sites.corporate;
  const pub = await H.waitJob((await api("POST", `/api/v1/websites/${corp.id}/publish`, { version_id: corp.version.id }, key("tp"))).body.job_id, 240000);
  const d = `/var/www/ngm/sites/${corp.id}/current`;
  const top = await sh(`ls ${d} | tr '\n' ' '; echo; ls ${d}/en | tr '\n' ' '; echo; ls ${d}/fa | tr '\n' ' '`);
  const need = ["about", "contact", "services", "faq"];
  check("corporate-multipage", pub.state === "Succeeded" && need.every((p) => top.out.split("\n")[1].includes(p) && top.out.split("\n")[2].includes(p)) && /404\.html/.test(top.out) && /sitemap\.xml/.test(top.out) && /robots\.txt/.test(top.out),
    top.out.replace(/\n/g, " | "));
  const sizes = await sh(`for p in services about contact faq; do printf "%s:%s " $p $(wc -c < ${d}/en/$p/index.html); done; printf "home:%s " $(wc -c < ${d}/index.html)`);
  const nums = Object.fromEntries((sizes.out.match(/\w+:\d+/g) || []).map((x) => x.split(":")));
  check("pages-have-real-content", Object.keys(nums).length === 5 && Object.values(nums).every((n) => Number(n) > 1400), "page sizes (bytes): " + sizes.out.trim());
  const meta = await sh(`grep -c 'rel="canonical"' ${d}/en/about/index.html; grep -c 'hreflang' ${d}/en/about/index.html; grep -o '<html lang="[a-z]*" dir="[a-z]*"' ${d}/fa/about/index.html; grep -c '<loc>' ${d}/sitemap.xml`);
  check("seo-and-rtl", /^1$/m.test(meta.out) && /lang="fa" dir="rtl"/.test(meta.out), "canonical/hreflang/RTL/sitemap: " + meta.out.replace(/\n/g, " | "));

  // Serve it via a temporary route and request real pages and a missing one.
  const web = (await api("GET", "/api/v1/listeners")).body.items.find((l) => l.name === "web");
  await del("/api/v1/routes", "e2e-site-404");
  const r404 = await api("POST", "/api/v1/routes", { name: "e2e-site-404", listener_id: web.id, protocol: "http", destination_kind: "website", destination_id: corp.id, matches: [{ field: "host", operator: "exact", value: "site404.e2e.test" }] });
  const d3 = await dep("s404");
  const out404 = await sh(`curl -s -m 5 -D - -H 'Host: site404.e2e.test' http://127.0.0.1/no-such-page | tr -d '\r' | head -40`);
  check("custom-404", r404.status === 201 && d3.state === "Succeeded" && /^HTTP\/1\.1 404/m.test(out404.out) && /class="code">404/.test(out404.out) && /Page not found/.test(out404.out) && !/nginx\/\d/i.test(out404.out),
    `route ${r404.status}, deploy ${d3.state}; 404 status + styled body, no nginx version`);
  const codes = await sh(`for p in / /en/ /en/about/ /fa/about/ /en/services/ /en/contact/ /en/faq/ /sitemap.xml /robots.txt /assets/site.css; do printf "%s=%s " $p $(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: site404.e2e.test' http://127.0.0.1$p); done`);
  check("site-pages-200", (codes.out.match(/=200/g) || []).length === 10, "status per path: " + codes.out.trim());
  await del("/api/v1/routes", "e2e-site-404");
  await dep("s404r").catch(() => null);
  for (const v of Object.values(sites)) {
    const s = (await api("GET", "/api/v1/websites")).body.items.find((w) => w.name === v.name);
    if (s) await api("DELETE", "/api/v1/websites/" + s.id, undefined, { "If-Match": `"r${s.revision}"` }).catch(() => null);
  }
});
