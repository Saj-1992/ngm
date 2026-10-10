// Removes resources left behind by e2e_p6b.cjs runs (names prefixed e2e-alert-).
const H = require("./harness.cjs");
H.start(async () => {
  for (const b of (await H.api("GET", "/api/v1/backends")).body.items.filter((x) => x.name.startsWith("e2e-alert-"))) {
    const r = await H.api("DELETE", "/api/v1/backends/" + b.id, undefined, { "If-Match": `"r${b.revision}"` });
    console.log("backend", b.name, r.status);
  }
  for (const t of (await H.api("GET", "/api/v1/notifications/targets")).body.items.filter((x) => x.name.startsWith("e2e-alert-"))) {
    console.log("target", t.name, (await H.api("DELETE", "/api/v1/notifications/targets/" + t.id)).status);
  }
  const open = (await H.api("GET", "/api/v1/alerts?state=open")).body.items;
  console.log("open alerts:", open.map((a) => `${a.rule}:${a.subject}`).join(", "));
});
