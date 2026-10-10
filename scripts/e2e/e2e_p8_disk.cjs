// O-31 / §18.6 disk pressure: the log index filesystem runs out of space.
// A 16 MiB tmpfs is mounted over /var/lib/ngm/logindex (NGM-owned, fully
// reversible: the real index underneath is untouched and returns on unmount).
const H = require("./harness.cjs");
const { check, sh, api, val } = H;
const DOMAIN = val("domain");

H.start(async () => {
  const before = await sh("ls -l /var/lib/ngm/ngm.db | awk '{print $5}'; ls /var/lib/ngm/backups | wc -l; ls /etc/nginx/ngm/keys | wc -l");
  await sh("systemctl stop ngm-log-indexer && mount -t tmpfs -o size=16m,mode=2770,gid=$(getent group ngm | cut -d: -f3) tmpfs /var/lib/ngm/logindex && systemctl start ngm-log-indexer");
  let paused = null;
  for (let i = 0; i < 20 && !paused; i++) {
    const st = (await api("GET", "/api/v1/logs/status")).body.status;
    if (st && st.paused) paused = st;
    else await H.sleep(3000);
  }
  check("disk-guard-pauses", !!paused, paused ? `paused: "${paused.reason}", free ${(paused.free_bytes / 2 ** 20).toFixed(1)} MiB` : "indexer did not pause");
  // Traffic keeps flowing and is still written to the source logs.
  const marker = "disk-" + Date.now().toString(36);
  const sz1 = (await sh("stat -c %s /var/log/ngm/nginx/access.jsonl")).out.trim();
  await sh(`for i in $(seq 1 20); do curl -s -o /dev/null -H 'Host: ${DOMAIN}' http://127.0.0.1/${marker}; done`);
  const sz2 = (await sh("stat -c %s /var/log/ngm/nginx/access.jsonl")).out.trim();
  let al;
  for (let i = 0; i < 30 && !al; i++) {
    al = (await api("GET", "/api/v1/alerts?state=open")).body.items.find((a) => a.rule === "log_pipeline_paused");
    if (!al) await H.sleep(5000);
  }
  const after = await sh("ls -l /var/lib/ngm/ngm.db | awk '{print $5}'; ls /var/lib/ngm/backups | wc -l; ls /etc/nginx/ngm/keys | wc -l");
  const http = (await sh(`curl -s -o /dev/null -w '%{http_code}' -H 'Host: ${DOMAIN}' http://127.0.0.1/`)).out.trim();
  check("disk-guard-safe", Number(sz2) > Number(sz1) && al && http === "200" && before.out.split("\n").slice(1).join() === after.out.split("\n").slice(1).join(),
    `source log grew ${sz1}→${sz2} B; alert ${al && al.severity}: ${al && al.message}; data plane ${http}; backups/keys unchanged (${after.out.split("\n").slice(1).join("/")})`);
  // Space returns: unmount, the indexer resumes and indexes what was written meanwhile.
  await sh("systemctl stop ngm-log-indexer && umount /var/lib/ngm/logindex && systemctl start ngm-log-indexer");
  let found = 0;
  for (let i = 0; i < 30 && found < 20; i++) {
    found = ((await api("GET", "/api/v1/logs?category=http&q=" + marker)).body.items || []).length;
    if (found < 20) await H.sleep(3000);
  }
  const st = (await api("GET", "/api/v1/logs/status")).body.status;
  check("disk-guard-resumes", found >= 20 && st && !st.paused, `after unmount: ${found} entries written during the pause are indexed; paused=${st && st.paused}; mount gone: ${(await sh("mount | grep -c logindex || true")).out.trim() === "0"}`);
});
