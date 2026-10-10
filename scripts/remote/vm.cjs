#!/usr/bin/env node
// Dev-only: run commands / upload files on the test VM.
// Credentials come from a local, git-ignored file (default: "example server detail.txt"
// at the repo root, override with NGM_TEST_SERVER_FILE). Nothing is persisted.
//
//   node scripts/remote/vm.cjs exec '<command>'
//   node scripts/remote/vm.cjs put <local-file> <remote-path> [mode]
const { Client } = require("ssh2");
const fs = require("fs");
const path = require("path");

function creds() {
  const file = process.env.NGM_TEST_SERVER_FILE || path.join(__dirname, "..", "..", "example server detail.txt");
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const val = (k) => {
    const i = lines.findIndex((l) => l.toLowerCase().replace(/\s/g, "").startsWith(k + ":"));
    if (i < 0 || !lines[i + 1]) throw new Error(`missing "${k}" in ${file}`);
    return lines[i + 1];
  };
  return { host: val("ip"), username: val("user"), password: val("password") };
}

function connect() {
  return new Promise((resolve, reject) => {
    const c = new Client();
    c.on("ready", () => resolve(c)).on("error", reject).connect({ ...creds(), port: 22, readyTimeout: 20000, keepaliveInterval: 10000 });
  });
}

async function exec(cmd) {
  const c = await connect();
  return new Promise((resolve, reject) => {
    c.exec(cmd, (err, s) => {
      if (err) return reject(err);
      s.on("data", (d) => process.stdout.write(d));
      s.stderr.on("data", (d) => process.stderr.write(d));
      s.on("exit", (code) => {
        c.end();
        resolve(code ?? 0);
      });
      s.end();
    });
  });
}

// Streams the file through `cat` over exec; the VM's SFTP subsystem
// misbehaves with ssh2, and this needs nothing beyond a shell.
async function put(local, remote, mode) {
  if (!/^[A-Za-z0-9_./-]+$/.test(remote)) throw new Error("unsafe remote path");
  const m = mode && /^[0-7]{3,4}$/.test(mode) ? mode : "0644";
  const c = await connect();
  const cmd = `umask 077; cat > '${remote}.part' && chmod ${m} '${remote}.part' && mv -f '${remote}.part' '${remote}'`;
  return new Promise((resolve, reject) => {
    c.exec(cmd, (err, s) => {
      if (err) return reject(err);
      s.stderr.on("data", (d) => process.stderr.write(d));
      s.on("exit", (code) => {
        c.end();
        code === 0 ? resolve(0) : reject(new Error("remote write failed with exit " + code));
      });
      fs.createReadStream(local).on("error", reject).pipe(s);
    });
  });
}

(async () => {
  const [op, ...args] = process.argv.slice(2);
  let code = 2;
  if (op === "exec") code = await exec(args.join(" "));
  else if (op === "put") code = await put(args[0], args[1], args[2]);
  else console.error("usage: vm.cjs exec <cmd> | put <local> <remote> [mode]");
  process.exit(code);
})().catch((e) => {
  console.error("vm:", e.message);
  process.exit(255);
});
