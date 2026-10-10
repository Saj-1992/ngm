// Phase 5 E2E against the real VM (dev host): node scripts/e2e/e2e_p5.cjs dns,acme,renew
// ACME uses Let's Encrypt STAGING only (untrusted test certificates; no production rate limits).
const H = require("./harness.cjs");
const { check, sleep, sh, api, waitJob, steps, stepUp, val, VMIP } = H;
const https = require("https");
const ONLY = (process.argv[2] || "dns,acme,renew").split(",");
const DOMAIN = val("domain");

async function domainByName(fqdn) {
  const l = (await api("GET", "/api/v1/domains")).body.items || [];
  return l.find((d) => d.fqdn === fqdn);
}

async function dnsTests() {
  let d = await domainByName(DOMAIN);
  if (!d) {
    const r = await api("POST", "/api/v1/domains", { fqdn: DOMAIN, purpose: "website", notes: "e2e" });
    check("dns-register", r.status === 201, `registered ${DOMAIN}: ${r.status}`);
    d = r.body;
  }
  const full = (await api("GET", "/api/v1/domains/" + d.id)).body.domain;
  if (!full.expectations.some((e) => e.type === "A" && e.value === VMIP)) {
    await api("POST", `/api/v1/domains/${d.id}/expectations`, { name: DOMAIN, type: "A", value: VMIP });
  }
  // A deliberately wrong expectation must be reported as a mismatch, never "ok".
  if (!full.expectations.some((e) => e.type === "TXT")) {
    await api("POST", `/api/v1/domains/${d.id}/expectations`, { name: DOMAIN, type: "TXT", value: "ngm-e2e-expected-but-absent" });
  }
  const r = await api("POST", `/api/v1/domains/${d.id}/check`);
  check("dns-check-requested", r.status === 202, "check requested; the API itself performs no lookups");
  let g;
  for (let i = 0; i < 20; i++) {
    await sleep(3000);
    g = (await api("GET", "/api/v1/domains/" + d.id)).body.domain;
    if (g.observations.length >= 4) break;
  }
  const obs = (n, t, s) => g.observations.find((o) => o.name === n && o.type === t && o.source === s) || {};
  const aAuth = obs(DOMAIN, "A", "authoritative"), aRes = obs(DOMAIN, "A", "resolver"), ns = obs(DOMAIN, "NS", "authoritative");
  check("dns-authoritative", aAuth.values && aAuth.values.includes(VMIP) && aAuth.ttl > 0 && !!aAuth.server, `authoritative A ${JSON.stringify(aAuth.values)} TTL ${aAuth.ttl} from ${aAuth.server}`);
  check("dns-resolver", aRes.values && aRes.values.includes(VMIP) && !!aRes.server, `resolver A ${JSON.stringify(aRes.values)} TTL ${aRes.ttl} via ${aRes.server}`);
  check("dns-ns-caa", (ns.values || []).length > 0 && !!obs(DOMAIN, "CAA", "authoritative").observed_at, `NS ${JSON.stringify(ns.values)}; CAA ${JSON.stringify(obs(DOMAIN, "CAA", "authoritative").values)}`);
  const cmp = (t) => g.comparison.find((c) => c.type === t) || {};
  check("dns-compare", cmp("A").status === "match" && cmp("TXT").status === "missing" && g.dns_status === "attention",
    `A → ${cmp("A").status}; absent TXT → ${cmp("TXT").status} (${cmp("TXT").detail}); domain status ${g.dns_status}`);
  const u = (await api("GET", "/api/v1/domains/" + d.id)).body.usage;
  check("dns-usage", u.some((x) => x.kind === "route"), "usage: " + u.map((x) => x.kind + ":" + x.name).join(", "));
  // Remove the deliberately wrong TXT expectation again.
  const txt = g.expectations.find((e) => e.type === "TXT");
  if (txt) await api("DELETE", `/api/v1/domains/${d.id}/expectations/${txt.id}`);
}

function peerCert(host, sni) {
  return new Promise((resolve) => {
    const req = https.request({ host, port: 443, path: "/", servername: sni, rejectUnauthorized: false, agent: false, headers: { Host: sni }, timeout: 8000 }, (res) => {
      const c = res.socket.getPeerCertificate();
      res.resume();
      resolve({ status: res.statusCode, issuer: c.issuer && c.issuer.CN, fp: c.fingerprint256, valid_to: c.valid_to });
    });
    req.on("error", (e) => resolve({ error: e.message }));
    req.end();
  });
}

async function findCert(name) {
  return ((await api("GET", "/api/v1/certificates")).body.items || []).find((c) => c.name === name);
}

async function acmeTests() {
  const name = "e2e-acme-staging";
  let cert = await findCert(name);
  if (!cert) {
    const r = await api("POST", "/api/v1/certificates/acme", { name, identifiers: [DOMAIN], directory: "letsencrypt-staging" }, { "Idempotency-Key": "e2e-acme-" + Date.now() });
    const j = await waitJob(r.body.job_id, 600000);
    const st = (await steps(j.id)).map((s) => s.name).join(" > ");
    check("acme-issue", j.state === "Succeeded", `${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 300) : ""} | ${st}`);
    cert = await findCert(name);
  }
  check("acme-stored", cert && cert.source === "acme" && /STAGING|\(STAGING\)|Fake|Staging/i.test(cert.issuer) && cert.sans.includes(DOMAIN),
    cert ? `issuer "${cert.issuer}", SANs ${cert.sans}, expires ${cert.not_after}` : "missing");
  const left = (await sh("ls -A /etc/nginx/ngm/acme 2>/dev/null | wc -l")).out;
  check("acme-challenges-cleared", left === "0", "challenge files left: " + left);
  // Attach to the shared-443 terminate route and deploy.
  const routes = (await api("GET", "/api/v1/routes")).body.items;
  const panel = routes.find((r) => r.protocol === "tls_terminate_http" && r.matches.some((m) => m.value === DOMAIN));
  if (panel && panel.certificate_id !== cert.id) {
    const upd = { ...panel, certificate_id: cert.id };
    delete upd.id; delete upd.revision;
    const r = await api("PUT", "/api/v1/routes/" + panel.id, upd, { "If-Match": `"r${panel.revision}"` });
    if (r.status !== 200) throw new Error("route update " + r.status + JSON.stringify(r.body));
  }
  const r = await api("POST", "/api/v1/deployments", {}, { "Idempotency-Key": "e2e-acme-deploy-" + Date.now() });
  const j = await waitJob(r.body.job_id, 180000);
  const pc = await peerCert(VMIP, DOMAIN);
  check("acme-served", ["Succeeded", "Blocked"].includes(j.state) && /STAGING|Staging|Fake/i.test(pc.issuer || "") && pc.fp,
    `deploy ${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 120) : ""}; served issuer "${pc.issuer}" valid_to ${pc.valid_to}`);
  return { cert, fp: pc.fp };
}

async function renewTests() {
  const cert = await findCert("e2e-acme-staging");
  if (!cert) return check("acme-renew", false, "no ACME certificate");
  const before = await peerCert(VMIP, DOMAIN);
  const r = await api("POST", `/api/v1/certificates/${cert.id}/renew`, undefined, { "Idempotency-Key": "e2e-renew-" + Date.now() });
  const j = await waitJob(r.body.job_id, 600000);
  const res = JSON.parse(JSON.stringify(j.result || {}));
  check("acme-renew", j.state === "Succeeded" && res.deploy_job, `${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 200) : ""} result ${JSON.stringify(res).slice(0, 160)}`);
  if (res.deploy_job) {
    const d = await waitJob(res.deploy_job, 180000);
    const after = await peerCert(VMIP, DOMAIN);
    const c2 = await findCert("e2e-acme-staging");
    check("acme-renew-deployed", d.state === "Succeeded" && after.fp && after.fp !== before.fp && JSON.stringify(c2.acme).includes('"renewals":'),
      `deploy ${d.state}; served fingerprint changed ${before.fp && before.fp.slice(0, 17)} → ${after.fp && after.fp.slice(0, 17)}; acme ${JSON.stringify(c2.acme)}`);
    // Rollback to the generation before renewal must re-use the old key version.
    const gens = (await api("GET", "/api/v1/deployments")).body.items;
    const prev = gens.find((g) => g.status === "superseded");
    if (prev) {
      await stepUp().catch(() => {});
      const rb = await api("POST", "/api/v1/deployments/rollback", { generation_id: prev.id }, { "Idempotency-Key": "e2e-rb-" + Date.now() });
      const rj = await waitJob(rb.body.job_id, 180000);
      const back = await peerCert(VMIP, DOMAIN);
      check("acme-rollback-old-key", rj.state === "Succeeded" && back.fp === before.fp, `rollback ${rj.state} ${rj.error ? JSON.stringify(rj.error).slice(0, 160) : ""}; served fingerprint back to ${back.fp && back.fp.slice(0, 17)}`);
      // Return to the newest configuration.
      const fwd = await api("POST", "/api/v1/deployments", { force: true }, { "Idempotency-Key": "e2e-fwd-" + Date.now() });
      await waitJob(fwd.body.job_id, 180000);
    }
  }
}

H.start(async () => {
  // The apex is the only name with public DNS, so the ACME tests attach their
  // staging certificate to the apex TLS route. When that route is the published
  // Control Center, its production certificate is put back afterwards.
  const pub = (await api("GET", "/api/v1/routes")).body.items.find((r) => r.name === "ngm-panel-public");
  try {
    if (ONLY.includes("dns")) await dnsTests();
    if (ONLY.includes("acme")) await acmeTests();
    if (ONLY.includes("renew")) await renewTests();
  } finally {
    if (pub) {
      const cur = (await api("GET", "/api/v1/routes/" + pub.id)).body;
      if (cur.certificate_id !== pub.certificate_id) {
        const upd = { ...cur, certificate_id: pub.certificate_id };
        delete upd.id; delete upd.revision;
        await api("PUT", "/api/v1/routes/" + pub.id, upd, { "If-Match": `"r${cur.revision}"` });
        const r = await api("POST", "/api/v1/deployments", {}, { "Idempotency-Key": "e2e-acme-restore-" + Date.now() });
        const j = await waitJob(r.body.job_id, 180000);
        check("panel-certificate-restored", j.state === "Succeeded", "published panel back on its production certificate: " + j.state);
      }
    }
  }
});
