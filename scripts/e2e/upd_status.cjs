const H = require("./harness.cjs");
H.start(async () => {
  const r = await H.api("GET", "/api/v1/system/updates");
  H.check("api-update-status", r.status === 200 && r.body.version === "0.7.4-dev" && r.body.last_update && r.body.last_update.phase === "succeeded" && !r.body.state_error,
    `${r.status} ${r.body.version}; last ${r.body.last_update && r.body.last_update.from}→${r.body.last_update && r.body.last_update.to} ${r.body.last_update && r.body.last_update.phase}; signed releases ${r.body.releases.filter((x) => x.signed).length}`);
});
