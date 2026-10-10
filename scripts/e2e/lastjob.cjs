const H = require("./harness.cjs");
H.start(async () => {
  const r = await H.api("GET", "/api/v1/jobs?limit=3");
  for (const j of r.body.items.slice(0, 2)) {
    const s = await H.steps(j.id);
    console.log(j.kind, j.state, JSON.stringify(j.error || j.result || {}).slice(0, 400));
    console.log(JSON.stringify(s).slice(-900));
  }
});
