// Creates (idempotently) the four branded starter websites on the VM, builds and publishes
// each one. The decoy/fallback (publish_panel.cjs) uses "villa-advisory".
//   node scripts/ops/seed_sites.cjs            create what is missing
//   node scripts/ops/seed_sites.cjs --refresh   also replace existing sites' content with the current starter
//   (the old draft is kept in the website's revision history; unchanged content reuses its version)
const { execFileSync } = require("child_process");
const H = require("../e2e/harness.cjs");
const { check, api, waitJob, val } = H;
const DOMAIN = val("domain");
const SITES = [
  ["villa-advisory", "corporate"],
  ["sarv-journal", "blog"],
  ["atelier-dena", "portfolio"],
  ["hamrah-app", "app_showcase"],
];
const key = (p) => ({ "Idempotency-Key": p + Date.now() + Math.random().toString(36).slice(2, 6) });
async function job(r) {
  if (!r.body.job_id) throw new Error("no job: " + r.status + " " + JSON.stringify(r.body));
  return waitJob(r.body.job_id, 300000);
}

H.start(async () => {
  check("auth", await H.login(), "signed in");
  await H.stepUp();
  for (const [name, template] of SITES) {
    let site = (await api("GET", "/api/v1/websites")).body.items.find((w) => w.name === name);
    if (!site) {
      const r = await api("POST", "/api/v1/websites", { name, kind: "template", template, default_locale: "fa", locales: ["fa", "en"] });
      check(name + "-create", r.status === 201, `${template} site created: ${r.status}`);
      site = r.body;
      const g = (await api("GET", "/api/v1/websites/" + site.id)).body.website;
      const c = g.content;
      c.site.base_url = "https://" + DOMAIN;
      const s = await api("PUT", `/api/v1/websites/${site.id}/content`, c, { "X-Draft-Revision": String(g.draft_revision) });
      check(name + "-save", s.status === 200 && s.body.errors.length === 0, "draft saved with base URL; warnings " + (s.body.warnings || []).length);
    }
    if (site.id && process.argv.includes("--refresh") && site.template === template) {
      const goBin = process.env.GO_BIN || "D:/Sajjad/tools/go/bin/go.exe";
      const c = JSON.parse(execFileSync(goBin, ["run", "./scripts/ops/starter", template], { encoding: "utf8", env: { ...process.env, GOPROXY: "https://goproxy.cn,direct", CGO_ENABLED: "0" } }));
      c.site.base_url = "https://" + DOMAIN;
      const g = (await api("GET", "/api/v1/websites/" + site.id)).body.website;
      const s = await api("PUT", `/api/v1/websites/${site.id}/content`, c, { "X-Draft-Revision": String(g.draft_revision) });
      check(name + "-refresh", s.status === 200 && s.body.errors.length === 0, "content refreshed; errors " + (s.body.errors || []).length);
      site = { ...site, active_version_id: null };
    }
    if (!site.active_version_id) {
      const b = await job(await api("POST", `/api/v1/websites/${site.id}/build`, undefined, key("b-")));
      const v = b.result && b.result.version;
      check(name + "-build", b.state === "Succeeded" && !!v, `build → ${b.state} ${v ? v.file_count + " files" : JSON.stringify(b.error || "").slice(0, 150)}`);
      const p = await job(await api("POST", `/api/v1/websites/${site.id}/publish`, { version_id: v.id }, key("p-")));
      check(name + "-publish", p.state === "Succeeded", "publish → " + p.state);
    } else check(name + "-exists", true, "already published");
  }
});
