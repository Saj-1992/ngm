// ADR-036 live probe: with a fallback website, scanners/crawlers hitting the server by IP,
// with unknown Host, or with unknown/missing SNI on shared 443 see an ordinary website
// (HTTP 200, valid TLS handshake, no version or NGM headers) — and real routes still work.
const H = require("./harness.cjs");
const { check, sh, api, val } = H;
const DOMAIN = val("domain");
const IP = H.VMIP;
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
const job = async (r) => { if (!r.body.job_id) throw new Error(r.status + " " + JSON.stringify(r.body).slice(0, 300)); return H.waitJob(r.body.job_id); };

H.start(async () => {
  const dep = async (k) => job(await api("POST", "/api/v1/deployments", {}, key(k)));
  // Baseline: without a fallback the default servers close/reject (the fingerprint being removed).
  await api("PUT", "/api/v1/gateway/fallback", { website_id: "", certificate_id: "" });
  await dep("d0").catch(() => null);
  let o = await sh(`curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1/ -H 'Host: scanner.invalid'; echo; curl -sk -m 5 -o /dev/null -w '%{http_code}' --resolve nope.invalid:443:127.0.0.1 https://nope.invalid/; echo; curl -sk -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1/`);
  check("baseline-fingerprint", !o.out.includes("200"), "without fallback: unknown Host / unknown SNI / no SNI → " + o.out.replace(/\n/g, " , ") + " (closed/rejected)");

  // A real-looking site: template website, built and published.
  let site = (await api("GET", "/api/v1/websites")).body.items.find((w) => w.name === "decoy-site");
  if (!site) site = (await api("POST", "/api/v1/websites", { name: "decoy-site", kind: "template", template: "corporate", default_locale: "en", locales: ["en"] })).body;
  {
    const b = await job(await api("POST", `/api/v1/websites/${site.id}/build`, undefined, key("db")));
    await job(await api("POST", `/api/v1/websites/${site.id}/publish`, { version_id: b.result.version.id }, key("dp")));
  }
  const cert = (await api("GET", "/api/v1/certificates")).body.items.find((c) => c.has_key && c.source === "acme") || (await api("GET", "/api/v1/certificates")).body.items.find((c) => c.has_key);
  let r = await api("PUT", "/api/v1/gateway/fallback", { website_id: site.id, certificate_id: "" });
  check("fallback-validation", r.status === 400, "website without certificate refused: " + r.status);
  r = await api("PUT", "/api/v1/gateway/fallback", { website_id: site.id, certificate_id: cert.id });
  let j = await dep("d1");
  check("fallback-set", r.status === 200 && r.body.enabled && j.state === "Succeeded", `fallback = ${site.name} + cert ${cert.name}; deploy ${j.state}`);
  // Regression (rc.9): a fallback certificate used by no route must still be deployed.
  let lone = (await api("GET", "/api/v1/certificates")).body.items.find((c) => c.name === "decoy-lone-cert");
  if (!lone) lone = (await api("POST", "/api/v1/certificates/self-signed", { name: "decoy-lone-cert", hosts: ["www.decoy-lone.test"], days: 30 })).body;
  await api("PUT", "/api/v1/gateway/fallback", { website_id: site.id, certificate_id: lone.id });
  const jl = await dep("dl");
  const subj = await sh("openssl s_client -connect 127.0.0.1:443 -servername nothing.invalid </dev/null 2>/dev/null | grep subject=");
  check("fallback-unused-cert", jl.state === "Succeeded" && subj.out.includes("decoy-lone"), `deploy ${jl.state}; presented ${subj.out.trim()}`);
  r = await api("PUT", "/api/v1/gateway/fallback", { website_id: site.id, certificate_id: cert.id });
  j = await dep("d1b");

  // Probes a scanner would send.
  const probes = {
    "ip-http": `curl -s -m 5 -D - -o /tmp/p1 http://${IP}/`,
    "unknown-host": `curl -s -m 5 -D - -o /tmp/p2 -H 'Host: scanner.invalid' http://127.0.0.1/`,
    "ip-https-no-sni": `curl -sk -m 5 -D - -o /tmp/p3 https://${IP}/`,
    "unknown-sni-443": `curl -sk -m 5 -D - -o /tmp/p4 --resolve scan.invalid:443:127.0.0.1 https://scan.invalid/`,
    "missing-page": `curl -s -m 5 -D - -o /dev/null -H 'Host: scanner.invalid' http://127.0.0.1/wp-login.php`,
  };
  for (const [n, cmd] of Object.entries(probes)) {
    o = await sh(cmd + " | tr -d '\\r' | grep -i -E '^HTTP|^server:|^x-ngm|^content-type'");
    const status = (o.out.match(/^HTTP\/\S+ (\d+)/m) || [])[1];
    const leaks = /x-ngm|nginx\/\d/i.test(o.out);
    const want = n === "missing-page" ? "404" : "200";
    check("decoy-" + n, status === want && !leaks, o.out.replace(/\n/g, " | "));
  }
  o = await sh("head -c 400 /tmp/p4 | tr '\\n' ' ' | sed 's/  */ /g'; echo; openssl s_client -connect 127.0.0.1:443 -servername scan.invalid </dev/null 2>/dev/null | grep -E 'subject=|Verify return' | head -2");
  check("decoy-content-and-cert", /<html/i.test(o.out) && !/http-equiv/i.test(o.out) && /subject=/.test(o.out), o.out.replace(/\n/g, " | ").slice(0, 300));
  // ACME and real routes keep working.
  o = await sh(`curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: ${DOMAIN}' http://127.0.0.1/api/x; echo; /usr/local/sbin/ngm-testkit tls-client -addr 127.0.0.1:443 -sni x.${DOMAIN} -alpn h2 2>&1 | tail -1; echo; echo probe > /var/www/ngm/acme/decoytest; curl -s -m 5 -H 'Host: scanner.invalid' http://127.0.0.1/.well-known/acme-challenge/decoytest; rm -f /var/www/ngm/acme/decoytest`);
  check("routes-unaffected", o.out.startsWith("200") && /passthrough|backend|ok/i.test(o.out) && o.out.includes("probe"), o.out.replace(/\n/g, " | "));
  // Simulator agrees; the fallback site cannot be deleted while in use.
  const sim = await api("POST", "/api/v1/gateway/simulate", { port: 80, address: IP, host: "scanner.invalid", path: "/" });
  check("simulator", JSON.stringify(sim.body).includes("fallback_site"), "simulate unknown host → " + (sim.body.result ? sim.body.result.outcome : JSON.stringify(sim.body).slice(0, 120)));
  const g = await api("GET", "/api/v1/websites/" + site.id);
  check("in-use-guard", (g.body.routes || []).some((x) => x.includes("fallback")), "website usage: " + JSON.stringify(g.body.routes));
});
