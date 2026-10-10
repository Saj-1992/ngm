// Read-only diagnosis of which routes/certificates serve the apex SNI.
const H = require("../e2e/harness.cjs");
H.start(async () => {
  const D = H.val("domain");
  const certs = (await H.api("GET", "/api/v1/certificates")).body.items;
  const cn = (id) => { const c = certs.find((x) => x.id === id); return c ? `${c.name}/${c.issuer}` : id; };
  for (const r of (await H.api("GET", "/api/v1/routes")).body.items)
    if ((r.matches || []).some((m) => (m.value || "").includes(D)) || r.is_fallback) console.log("ROUTE", r.name, r.protocol, r.enabled, JSON.stringify(r.matches), "cert=" + cn(r.certificate_id));
  console.log("FALLBACK", JSON.stringify((await H.api("GET", "/api/v1/gateway/fallback")).body.fallback));
  console.log("ACTIVE", JSON.stringify((await H.api("GET", "/api/v1/deployments/active")).body).slice(0, 200));
  console.log((await H.sh("readlink /etc/nginx/ngm/current; grep -rn "${D}" /etc/nginx/ngm/current/stream/ | head -6 | cut -c1-150")).out);
});
