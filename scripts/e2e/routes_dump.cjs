const H = require("./harness.cjs");
H.start(async () => {
  const rs = (await H.api("GET", "/api/v1/routes")).body.items;
  for (const r of rs) console.log("R", r.name, r.listener_ids || r.listener_id, JSON.stringify(r.matches), JSON.stringify(r.destination || r.pool_id));
  for (const b of (await H.api("GET", "/api/v1/backends")).body.items) console.log("B", b.name, b.host + ":" + b.port, b.transport);
  for (const l of (await H.api("GET", "/api/v1/listeners")).body.items) console.log("L", l.id, l.name, l.kind, l.port);
});
