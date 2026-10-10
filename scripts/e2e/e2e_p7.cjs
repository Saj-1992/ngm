// Phase 7 lifecycle E2E on the VM. Steps: node scripts/e2e/e2e_p7.cjs bootstrap,update,repair,nginx,uninstall,cli
// Prerequisite: signed releases uploaded to /tmp/rel-<v> (see TEST_REPORT Phase 7).
const H = require("./harness.cjs");
const { check, sh } = H;
const ONLY = (process.argv[2] || "bootstrap").split(",");
const cur = async () => (await sh("readlink /opt/ngm/current; /opt/ngm/current/ngm version | awk '{print $2}'")).out.trim().replace(/\n/g, " ");
const health = async () => (await sh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9999/api/v1/system/health")).out.trim();

async function bootstrap() {
  const before = await cur();
  // Tampered copies: every one must fail before anything changes.
  const cases = {
    "manifest-byte": "sed -i 's/\"db_schema\": 6/\"db_schema\": 7/' $D/manifest.json",
    "binary-byte": "printf x >> $D/ngm-linux-amd64",
    "foreign-signature": "openssl genpkey -algorithm ed25519 -out /tmp/evil.pem 2>/dev/null; openssl pkeyutl -sign -inkey /tmp/evil.pem -rawin -in $D/manifest.json | base64 -w0 > $D/manifest.sig",
    "missing-signature": "rm $D/manifest.sig",
  };
  for (const [name, mut] of Object.entries(cases)) {
    const r = await sh(`D=/tmp/tamper-${name}; rm -rf $D; cp -r /tmp/rel-0.7.0 $D; ${mut}; sh /tmp/rel-0.7.0/install.sh --from $D 2>&1 | tail -2; echo "rc=$?"`);
    const after = await cur();
    check("bootstrap-reject-" + name, /FAILED|nothing was installed|No such file/.test(r.out) && after === before, r.out.replace(/\n/g, " | ").slice(0, 220) + ` ; current unchanged: ${after === before}`);
  }
  const r0 = await sh("NGM_EXPECT_KEY=sha256:0000 sh /tmp/rel-0.7.0/install.sh --from /tmp/rel-0.7.0 2>&1 | tail -1");
  check("bootstrap-expect-key", r0.out.includes("FAILED") && (await cur()) === before, "wrong NGM_EXPECT_KEY → " + r0.out.trim());
  // Happy path: signed bootstrap upgrade 0.6.7 → 0.7.0.
  const r2 = await sh("sh /tmp/rel-0.7.0/install.sh --from /tmp/rel-0.7.0 2>&1 | grep -E 'signature OK|digest OK|verified|installed' | tail -5", 300000);
  const now = await cur();
  check("bootstrap-install", now.includes("0.7.0-dev") && (await health()) === "200" && r2.out.includes("signature OK"),
    r2.out.replace(/\n/g, " | ") + " ; now " + now);
  const sig = await sh("ls /opt/ngm/releases/0.7.0-dev/; /opt/ngm/current/ngm release verify --dir /opt/ngm/releases/0.7.0-dev 2>&1 | tail -1");
  check("bootstrap-manifest-kept", sig.out.includes("manifest.sig") && sig.out.includes("signed by pinned key"), sig.out.replace(/\n/g, " "));
}

async function update() {
  // Go-side check: a valid release dir but a different binary is refused by `install --release-dir`.
  const r1 = await sh("/opt/ngm/current/ngm install --release-dir /tmp/rel-0.7.1 2>&1 | tail -1");
  check("install-self-check", /does not match|signed manifest is for/.test(r1.out) && (await cur()).includes("0.7.0-dev"), r1.out.trim());
  let r = await sh("ngm update check --from /tmp/rel-0.7.1 2>&1 | head -1");
  check("update-check", r.out.includes("verified 0.7.1-dev"), r.out.trim());
  r = await sh("ngm update apply --from /tmp/rel-0.7.1 2>&1 | tail -1; ngm version | awk '{print $2}'");
  check("update-needs-approval", r.out.includes("--yes") && r.out.includes("0.7.0-dev"), r.out.replace(/\n/g, " | "));
  r = await sh("ngm update apply --from /tmp/rel-0.7.1 --yes 2>&1 | tail -4", 300000);
  const st = JSON.parse((await sh("cat /var/lib/ngm/update/state.json")).out);
  check("update-apply", (await cur()).includes("0.7.1-dev") && st.phase === "succeeded" && (await health()) === "200" && !!st.snapshot,
    r.out.replace(/\n/g, " | ").slice(0, 300) + ` ; state ${st.from}→${st.to} ${st.phase}`);
  // Broken but correctly signed release (publisher error: arm64 binary labelled amd64) → automatic rollback.
  r = await sh("ngm update apply --from /tmp/rel-0.7.2-broken --yes 2>&1 | tail -3", 300000);
  const st2 = JSON.parse((await sh("cat /var/lib/ngm/update/state.json")).out);
  check("update-auto-rollback", (await cur()).includes("0.7.1-dev") && st2.phase === "rolled_back" && (await health()) === "200",
    r.out.replace(/\n/g, " | ").slice(0, 300) + ` ; state ${st2.phase}; now ${await cur()}`);
  // Downgrade refused; explicit rollback of the successful update works.
  r = await sh("ngm update apply --from /tmp/rel-0.7.0 --yes 2>&1 | tail -1");
  check("update-downgrade-refused", r.out.includes("older"), r.out.trim());
}

async function rollback() {
  // Re-apply 0.7.1 → 0.7.1 is refused; so roll back from a fresh successful state.
  let r = await sh("ngm update apply --from /tmp/rel-0.7.3 --yes 2>&1 | tail -1", 300000);
  r = await sh("ngm update rollback 2>&1 | tail -1");
  check("rollback-needs-approval", r.out.includes("--yes"), r.out.trim());
  r = await sh("ngm update rollback --yes 2>&1 | tail -2", 300000);
  const st = JSON.parse((await sh("cat /var/lib/ngm/update/state.json")).out);
  check("update-rollback", (await cur()).includes("0.7.1-dev") && st.phase === "rolled_back" && (await health()) === "200", r.out.replace(/\n/g, " | ") + " ; now " + (await cur()));
}

async function repair() {
  await sh("chmod 0777 /var/lib/ngm; rm -f /etc/systemd/system/ngm-monitor.service; systemctl daemon-reload; systemctl stop ngm-monitor");
  const r = await sh("ngm repair 2>&1 | tail -2", 300000);
  const st = await sh("stat -c %a /var/lib/ngm; test -f /etc/systemd/system/ngm-monitor.service && echo unit-ok; systemctl is-active ngm-monitor");
  check("repair-restores", st.out.includes("2770") && st.out.includes("unit-ok") && st.out.includes("active"), r.out.replace(/\n/g, " | ") + " ; " + st.out.replace(/\n/g, " "));
  // A modified release binary is never executed by repair.
  const rel = (await sh("readlink /opt/ngm/current")).out.trim();
  await sh(`cp ${rel}/ngm /tmp/ngm.orig && cp ${rel}/ngm /tmp/ngm.bad && printf x >> /tmp/ngm.bad && mv /tmp/ngm.bad ${rel}/ngm`);
  const r2 = await sh("/tmp/ngm.orig repair 2>&1 | tail -1");
  await sh(`mv /tmp/ngm.orig ${rel}/ngm`);
  check("repair-refuses-tampered", r2.out.includes("modified after installation"), r2.out.trim());
}

async function nginx() {
  const r = await sh("ngm nginx upgrade 2>&1 | tail -4", 300000);
  check("nginx-upgrade-plan", /up to date|--yes|accepted Nginx/.test(r.out), r.out.replace(/\n/g, " | "));
  // External change detection: make the recorded baseline older than the installed package.
  await sh(`sqlite3 /var/lib/ngm/ngm.db "UPDATE settings SET value_json=json_set(value_json,'$.package_version','1.0.0-old') WHERE key='nginx.baseline'" 2>&1 || python3 -c "
import sqlite3,json;c=sqlite3.connect('/var/lib/ngm/ngm.db');v=json.loads(c.execute(\\"select value_json from settings where key='nginx.baseline'\\").fetchone()[0]);v['package_version']='1.0.0-old';c.execute(\\"update settings set value_json=? where key='nginx.baseline'\\",(json.dumps(v),));c.commit()"`);
  let al;
  for (let i = 0; i < 30 && !al; i++) {
    al = (await H.api("GET", "/api/v1/alerts?state=open")).body.items.find((a) => a.rule === "nginx_external_change");
    if (!al) await H.sleep(5000);
  }
  check("nginx-drift-alert", !!al, al ? `${al.severity}: ${al.message}` : "no alert");
  const rc = await sh("ngm nginx reconcile 2>&1 | tail -1");
  let gone = false;
  for (let i = 0; i < 30 && !gone; i++) {
    const a = (await H.api("GET", "/api/v1/alerts")).body.items.find((x) => al && x.id === al.id);
    gone = a && a.state === "resolved";
    if (!gone) await H.sleep(5000);
  }
  check("nginx-reconcile", rc.out.includes("accepted Nginx") && gone, rc.out.trim() + " ; alert resolved: " + gone);
}

async function uninstall() {
  let r = await sh("ngm uninstall --keep-data 2>&1");
  check("uninstall-plan", r.out.includes("conf.d/ngm.conf") && r.out.includes("kept (Keep Data)") && r.out.includes("--yes") && (await health()) === "200",
    r.out.split("\n").filter((l) => /warn|remove|keep/.test(l)).slice(0, 8).join(" | ").slice(0, 400));
  r = await sh("ngm uninstall --purge --yes 2>&1 | tail -1");
  check("purge-needs-typed-confirm", r.out.includes("--confirm") && (await health()) === "200", r.out.trim());
  r = await sh("ngm uninstall --purge 2>&1 | grep -E 'ufw delete|userdel|remove ' | head -40");
  check("purge-plan", r.out.includes("/var/lib/ngm") && !/ufw delete \d+ .*22\/tcp/.test(r.out), r.out.replace(/\n/g, " | ").slice(0, 400));
}

async function cli() {
  let r = await sh("ngm config test 2>&1 | tail -2");
  check("cli-config-test", r.out.includes("successful") && r.out.includes("active NGM generation"), r.out.replace(/\n/g, " | "));
  const before = (await sh("readlink /etc/nginx/ngm/current")).out.trim();
  r = await sh("ngm rollback 2>&1 | tail -2", 300000);
  const after = (await sh("readlink /etc/nginx/ngm/current")).out.trim();
  check("cli-rollback", r.out.includes("rollback succeeded") && after !== before, r.out.replace(/\n/g, " | ") + ` ; ${before.slice(-26)} → ${after.slice(-26)}`);
  // Bring the desired configuration back.
  const j = await H.api("POST", "/api/v1/deployments", {}, { "Idempotency-Key": "p7-redeploy-" + Date.now() });
  const done = await H.waitJob(j.body.job_id);
  const noChange = done.state === "Blocked" && done.error && done.error.code === "no_changes";
  check("cli-redeploy", done.state === "Succeeded" || noChange, "redeploy desired → " + done.state + (noChange ? " (no_changes: the restored generation already equals the desired model)" : ""));
}

H.start(async () => {
  for (const [k, f] of Object.entries({ bootstrap, update, rollback, repair, nginx, uninstall, cli })) if (ONLY.includes(k)) await f();
});
