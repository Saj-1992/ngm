// Enables an hourly backup schedule (O-14) so a scheduled archive can be observed.
const H = require("./harness.cjs");
H.start(async () => {
  await H.stepUp();
  const r = await H.api("PUT", "/api/v1/backups/schedule", { enabled: true, interval_hours: 1, retain: 30 });
  H.check("schedule-set", r.status < 300, `${r.status} ${JSON.stringify(r.body).slice(0, 150)} at ${new Date().toISOString()}`);
});
