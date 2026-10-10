// O-6 / first-run step 3: the Control Center published through Nginx on an HTTPS origin.
// Two modes:
//  - a management origin is already configured (the live published panel at
//    <origin><base-path>, set up by scripts/ops/publish_panel.cjs): test it in
//    place, change nothing;
//  - none configured (fresh install): publish on a temporary internal name,
//    test, and clean up (back to SSH-tunnel-only access).
const H = require("./harness.cjs");
const { check, sh, api, val } = H;
const DOMAIN = val("domain");
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const deploy = async (k) => { const r = await api("POST", "/api/v1/deployments", {}, key(k)); if (!r.body.job_id) throw new Error("deploy " + r.status + " " + JSON.stringify(r.body).slice(0, 300)); return H.waitJob(r.body.job_id); };

H.start(async () => {
  const PREV = (await sh("sed -n 's/.*\"public_origin\": *\"\\([^\"]*\\)\".*/\\1/p' /etc/ngm/ngm.json")).out.trim();
  const BPATH = (await sh("sed -n 's/.*\"public_path\": *\"\\([^\"]*\\)\".*/\\1/p' /etc/ngm/ngm.json")).out.trim();
  const live = PREV !== "";

  if (live) {
    // PREV e.g. https://example.test:9443 ; BPATH e.g. /6c44...
    const u = new URL(PREV);
    const host = u.hostname, port = u.port || "443";
    const base = `${PREV}${BPATH}`;
    const curl = (args) => sh(`curl -s -m 8 --resolve ${host}:${port}:127.0.0.1 ${args}`);
    check("origin-live", true, `testing the published panel in place: ${base}/`);
    let o = await curl(`-o /dev/null -w '%{http_code}' ${base}/api/v1/system/health`);
    check("origin-health-via-nginx", o.out.trim() === "200", "panel health through Nginx TLS → " + o.out.trim());
    const st = JSON.parse((await curl(`${base}/api/v1/setup/status`)).out || "{}");
    const step = (st.steps || []).find((s) => s.id === "management_origin");
    check("origin-setup-step", step && step.status === "complete" && st.local_bootstrap === false,
      `management_origin=${step && step.status}; proxied request is not local bootstrap: ${st.local_bootstrap === false}`);
    const pw = (await sh("ngm admin reset owner | sed -n 's/new password: //p'")).out.trim();
    const body = JSON.stringify({ username: "owner", password: pw }).replace(/'/g, "'\\''");
    o = await curl(`-D - -o /dev/null -H 'Content-Type: application/json' -H 'Origin: ${PREV}' -d '${body}' ${base}/api/v1/auth/login | grep -i -E '^HTTP|set-cookie' | tr -d '\\r'`);
    check("origin-login-secure-cookie", /HTTP\/\S+ 200/.test(o.out) && /ngm_session=[^;]+;.*Secure/i.test(o.out) && /HttpOnly/i.test(o.out),
      o.out.replace(/ngm_session=[^;]+/, "ngm_session=…").replace(/ngm_csrf=[^;]+/, "ngm_csrf=…").replace(/\n/g, " | "));
    o = await curl(`-o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'Origin: https://evil.example' -d '${body}' ${base}/api/v1/auth/login`);
    check("origin-foreign-rejected", o.out.trim() === "403", "login with a foreign Origin through Nginx → " + o.out.trim());
    // The secret path is required: the bare apex is the decoy site, not the API.
    o = await curl(`-o /dev/null -w '%{http_code}' ${PREV}/api/v1/system/health`);
    check("origin-path-required", o.out.trim() !== "200", "API is not reachable without the base path → " + o.out.trim());
    check("auth-again", await H.login(), "re-signed in after admin reset");
    return;
  }

  // Fresh install: publish on a temporary internal name, then clean up.
  const UI = "ui." + DOMAIN;
  const curl = (args) => sh(`curl -sk -m 8 --resolve ${UI}:443:127.0.0.1 ${args}`);
  for (const [p, n] of [["/api/v1/routes", "panel-ui"], ["/api/v1/backends", "ngm-panel-e2e"]])
    for (const it of (await api("GET", p)).body.items.filter((x) => x.name === n)) await api("DELETE", p + "/" + it.id, undefined, { "If-Match": `"r${it.revision}"` });
  let o = await sh(`ngm admin set-origin https://${UI} 2>&1 | tail -1; sleep 3`);
  check("origin-set", o.out.includes("management origin set"), o.out.trim());
  check("auth-after-restart", await H.login(), "re-signed in after the ngm-api restart");
  const front = (await api("GET", "/api/v1/listeners")).body.items.find((l) => l.kind === "stream_tls_front");
  const cert = (await api("GET", "/api/v1/certificates")).body.items.find((c) => (c.sans || []).includes("*." + DOMAIN));
  const ep = (await api("POST", "/api/v1/backends", { name: "ngm-panel-e2e", host: "127.0.0.1", port: 9999, transport: "http" })).body;
  const rt = await api("POST", "/api/v1/routes", { name: "panel-ui", listener_id: front.id, protocol: "tls_terminate_http", destination_kind: "endpoint", destination_id: ep.id, certificate_id: cert && cert.id, matches: [{ field: "sni", operator: "exact", value: UI }] });
  let j = await deploy("o1");
  check("origin-route", rt.status === 201 && j.state === "Succeeded", `route ${rt.status}; deploy ${j.state}; cert ${cert && cert.name}`);
  o = await curl(`-o /dev/null -w '%{http_code}' https://${UI}/api/v1/system/health`);
  check("origin-health-via-nginx", o.out.trim() === "200", "panel health → " + o.out.trim());
  const pw = (await sh("ngm admin reset owner | sed -n 's/new password: //p'")).out.trim();
  const body = JSON.stringify({ username: "owner", password: pw }).replace(/'/g, "'\\''");
  o = await curl(`-D - -o /dev/null -H 'Content-Type: application/json' -H 'Origin: https://${UI}' -d '${body}' https://${UI}/api/v1/auth/login | grep -i -E '^HTTP|set-cookie' | tr -d '\\r'`);
  check("origin-login-secure-cookie", /HTTP\/\S+ 200/.test(o.out) && /ngm_session=[^;]+;.*Secure/i.test(o.out) && /HttpOnly/i.test(o.out), o.out.replace(/ngm_session=[^;]+/, "ngm_session=…").replace(/\n/g, " | "));
  o = await curl(`-o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'Origin: https://evil.example' -d '${body}' https://${UI}/api/v1/auth/login`);
  check("origin-foreign-rejected", o.out.trim() === "403", "foreign Origin → " + o.out.trim());
  check("auth-again", await H.login(), "re-signed in after admin reset");
  await sh("ngm admin set-origin --clear >/dev/null 2>&1; sleep 3");
  await H.login();
  const r2 = (await api("GET", "/api/v1/routes/" + rt.body.id)).body;
  await api("DELETE", "/api/v1/routes/" + rt.body.id, undefined, { "If-Match": `"r${r2.revision}"` });
  const e2 = (await api("GET", "/api/v1/backends/" + ep.id)).body;
  await api("DELETE", "/api/v1/backends/" + ep.id, undefined, { "If-Match": `"r${e2.revision}"` });
  j = await deploy("o2");
  o = await curl(`-o /dev/null -w '%{http_code}' https://${UI}/api/v1/system/health`);
  check("origin-cleanup", j.state === "Succeeded" && o.out.trim() !== "200", `origin cleared, route removed, deploy ${j.state}; panel now → ${o.out.trim() || "no answer"}`);
});
