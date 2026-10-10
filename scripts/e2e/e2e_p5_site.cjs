// Phase 5 website E2E against the real VM (dev host): node scripts/e2e/e2e_p5_site.cjs
const H = require("./harness.cjs");
const { check, sh, api, waitJob, val } = H;
const DOMAIN = val("domain");

// Minimal ZIP writer (stored entries) for test archives; mode sets Unix file type bits.
function zipOf(files) {
  const crcT = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (b) => {
    let c = 0xffffffff;
    for (const x of b) c = crcT[(c ^ x) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const parts = [], central = [];
  let off = 0;
  for (const [name, content, mode] of files) {
    const data = Buffer.from(content), nb = Buffer.from(name), c = crc(data);
    const h = Buffer.alloc(30);
    h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt32LE(c, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(nb.length, 26);
    parts.push(h, nb, data);
    const ce = Buffer.alloc(46);
    ce.writeUInt32LE(0x02014b50, 0); ce.writeUInt16LE(0x0314, 4); ce.writeUInt16LE(20, 6); ce.writeUInt32LE(c, 16); ce.writeUInt32LE(data.length, 20); ce.writeUInt32LE(data.length, 24);
    ce.writeUInt16LE(nb.length, 28); ce.writeUInt32LE(((mode || 0o100644) << 16) >>> 0, 38); ce.writeUInt32LE(off, 42);
    central.push(ce, nb);
    off += 30 + nb.length + data.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}

const raw = (method, path, buf, ct, extra = {}) => api(method, path, undefined, { "Content-Type": ct, ...extra }, false, buf);
const key = (p) => ({ "Idempotency-Key": p + Date.now() });
async function job(r) {
  if (!r.body.job_id) throw new Error("no job: " + r.status + " " + JSON.stringify(r.body));
  return waitJob(r.body.job_id, 300000);
}
const curl = (args) => sh(`curl -s ${args}`);

H.start(async () => {
  const name = "e2e-site-" + Date.now().toString(36);
  let r = await api("POST", "/api/v1/websites", { name, kind: "template", template: "corporate", default_locale: "fa", locales: ["fa", "en"] });
  check("site-create", r.status === 201, "template site created: " + r.status);
  const id = r.body.id;
  let g = (await api("GET", "/api/v1/websites/" + id)).body;
  const c = g.website.content;
  c.site.title = { fa: "سایت آزمایشی NGM", en: "NGM test site" };
  c.site.base_url = "http://" + DOMAIN + "/site";
  r = await raw("PUT", "/api/v1/websites/" + id + "/content", Buffer.from(JSON.stringify(c)), "application/json", { "X-Draft-Revision": String(g.website.draft_revision) });
  check("site-save", r.status === 200 && r.body.errors.length === 0, "draft saved; warnings " + (r.body.warnings || []).length);
  let j = await job(await api("POST", `/api/v1/websites/${id}/build`, undefined, key("b1")));
  const v1 = j.result && j.result.version;
  check("site-build", j.state === "Succeeded" && !!v1, `build → ${j.state} v${v1 && v1.number} ${v1 && v1.content_hash.slice(0, 12)}`);

  // Isolated preview: no cookie needed, sandbox CSP.
  const link = (await api("POST", `/api/v1/websites/${id}/versions/${v1.id}/preview`)).body.url;
  const pv = await sh(`curl -s -D /tmp/pvh -o /tmp/pv.html "http://127.0.0.1:9999${link}fa/about/"; head -1 /tmp/pvh; grep -i content-security /tmp/pvh; grep -c 'dir="rtl"' /tmp/pv.html`);
  check("site-preview-isolated", / 200/.test(pv.out) && /sandbox/.test(pv.out) && !/allow-same-origin/.test(pv.out) && pv.out.trim().endsWith("1"), pv.out.replace(/\n/g, " | ").slice(0, 240));

  // Publish v1 (no route yet → file-level verification).
  j = await job(await api("POST", `/api/v1/websites/${id}/publish`, { version_id: v1.id }, key("p1")));
  const pub = await sh(`readlink /var/www/ngm/sites/${id}/current; stat -c '%U %a' /var/www/ngm/sites/${id}/${v1.id}/index.html`);
  check("site-publish-v1", j.state === "Succeeded" && pub.out.startsWith(v1.id) && pub.out.includes("root 644"), j.state + " " + pub.out.replace(/\n/g, " | "));

  // Route DOMAIN/site/ → website (sub-path mount), deploy.
  const ls = (await api("GET", "/api/v1/listeners")).body.items;
  const web80 = ls.find((l) => l.port === 80 && l.address === "0.0.0.0");
  r = await api("POST", "/api/v1/routes", { name: "e2e-site", listener_id: web80.id, protocol: "http", destination_kind: "website", destination_id: id,
    matches: [{ field: "host", operator: "exact", value: DOMAIN }, { field: "path_prefix", operator: "prefix", value: "/site/" }] });
  const routeId = r.body.id;
  check("site-route", r.status === 201, "route " + r.status + " " + (r.body.error ? JSON.stringify(r.body.error) : ""));
  j = await job(await api("POST", "/api/v1/deployments", {}, key("d1")));
  const page = await curl(`-H 'Host: ${DOMAIN}' http://127.0.0.1/site/fa/about/`);
  const css = await curl(`-o /dev/null -w '%{http_code} %{content_type}' -H 'Host: ${DOMAIN}' http://127.0.0.1/site/assets/site.css`);
  const hdr = await curl(`-D - -o /dev/null -H 'Host: ${DOMAIN}' http://127.0.0.1/site/fa/ | grep -i -E 'x-content-type|referrer-policy'`);
  check("site-served", j.state === "Succeeded" && page.out.includes('dir="rtl"') && page.out.includes("سایت آزمایشی NGM") && page.out.includes("../../assets/site.css") && css.out.startsWith("200 text/css") && /nosniff/i.test(hdr.out),
    `deploy ${j.state}; page rtl=${page.out.includes('dir="rtl"')}; css ${css.out}; headers ${hdr.out.replace(/\r?\n/g, " ")}`);

  // v2: published with verification through Nginx, without a reload.
  g = (await api("GET", "/api/v1/websites/" + id)).body;
  g.website.content.site.title.fa = "نسخهٔ دوم";
  await raw("PUT", "/api/v1/websites/" + id + "/content", Buffer.from(JSON.stringify(g.website.content)), "application/json", { "X-Draft-Revision": String(g.website.draft_revision) });
  j = await job(await api("POST", `/api/v1/websites/${id}/build`, undefined, key("b2")));
  const v2 = j.result.version;
  const gen0 = (await sh("readlink /etc/nginx/ngm/current")).out;
  const reloads0 = (await sh("journalctl -u nginx --since '-10 min' --no-pager | grep -c Reload || true")).out;
  j = await job(await api("POST", `/api/v1/websites/${id}/publish`, { version_id: v2.id }, key("p2")));
  const checks = (j.result && j.result.checks) || [];
  const served2 = await curl(`-H 'Host: ${DOMAIN}' http://127.0.0.1/site/fa/`);
  const gen1 = (await sh("readlink /etc/nginx/ngm/current")).out;
  const reloads1 = (await sh("journalctl -u nginx --since '-10 min' --no-pager | grep -c Reload || true")).out;
  check("site-publish-v2-verified", j.state === "Succeeded" && checks.length === 1 && checks[0].ok && served2.out.includes("نسخهٔ دوم") && gen1 === gen0 && reloads1 === reloads0,
    `${j.state}; Nginx check ${JSON.stringify(checks)}; generation unchanged ${gen1 === gen0}; reloads ${reloads0}→${reloads1}`);

  // Rollback to v1.
  j = await job(await api("POST", `/api/v1/websites/${id}/publish`, { version_id: v1.id }, key("rb")));
  const back = await curl(`-H 'Host: ${DOMAIN}' http://127.0.0.1/site/fa/`);
  check("site-rollback", j.state === "Succeeded" && back.out.includes("سایت آزمایشی NGM"), "rollback " + j.state);

  // A tampered published copy is detected (re-publishing v2 verifies the copy against its build).
  await sh(`sed -i 's/<title>/<title>TAMPERED /' /var/www/ngm/sites/${id}/${v2.id}/fa/index.html`);
  j = await job(await api("POST", `/api/v1/websites/${id}/publish`, { version_id: v2.id }, key("pt")));
  const still = (await sh(`readlink /var/www/ngm/sites/${id}/current`)).out;
  check("site-tamper-detected", j.state === "RolledBack" && still === v1.id, `${j.state} ${j.error ? JSON.stringify(j.error).slice(0, 140) : ""}; still serving v1: ${still === v1.id}`);

  // Deleting a routed website is refused.
  r = await api("DELETE", "/api/v1/websites/" + id, undefined, key("del"));
  check("site-delete-guard", r.status === 409, "delete while routed → " + r.status);

  // ZIP site: malicious archive rejected at build; a valid one is published.
  r = await api("POST", "/api/v1/websites", { name: name + "-zip", kind: "static_zip", default_locale: "en", locales: ["en"] });
  const zid = r.body.id;
  const evil = zipOf([["index.html", "<h1>x</h1>"], ["shell.php", "<?php system($_GET[1]);"], ["../../etc/cron.d/x", "x"], ["link.html", "/etc/shadow", 0o120777]]);
  await raw("POST", `/api/v1/websites/${zid}/upload`, evil, "application/zip");
  j = await job(await api("POST", `/api/v1/websites/${zid}/build`, undefined, key("zb")));
  const emsg = JSON.stringify(j.error || "");
  check("zip-malicious-rejected", j.state === "Failed" && /server-side/.test(emsg) && /symbolic link/.test(emsg) && /segment/.test(emsg), j.state + " " + emsg.slice(0, 280));
  const good = zipOf([["dist/index.html", "<!doctype html><h1>zip ok</h1>"], ["dist/app.js", "console.log(1)"]]);
  await raw("POST", `/api/v1/websites/${zid}/upload`, good, "application/zip");
  j = await job(await api("POST", `/api/v1/websites/${zid}/build`, undefined, key("zg")));
  const zv = j.result && j.result.version;
  const zp = zv ? await job(await api("POST", `/api/v1/websites/${zid}/publish`, { version_id: zv.id }, key("zp"))) : null;
  const zf = await sh(`cat /var/www/ngm/sites/${zid}/current/index.html`);
  check("zip-published", j.state === "Succeeded" && zp && zp.state === "Succeeded" && zf.out.includes("zip ok"), `build ${j.state}, publish ${zp && zp.state}, top folder stripped → ${zf.out.slice(0, 40)}`);

  // Clean up: remove the test route, redeploy, delete the zip site.
  const rt = (await api("GET", "/api/v1/routes")).body.items.find((x) => x.id === routeId);
  if (rt) await api("DELETE", "/api/v1/routes/" + routeId, undefined, { "If-Match": `"r${rt.revision}"` });
  await job(await api("POST", "/api/v1/deployments", {}, key("d2")));
  j = await job(await api("DELETE", "/api/v1/websites/" + zid, undefined, key("zd")));
  const gone = (await sh(`test -e /var/www/ngm/sites/${zid} && echo present || echo gone`)).out;
  check("site-delete", j.state === "Succeeded" && gone === "gone", `zip site deleted: ${j.state}; files ${gone}`);
});
