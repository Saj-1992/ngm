// Publishes dist/release/<version> as a GitHub Release (token only from the GH_TOKEN environment variable).
const fs = require("fs");
const https = require("https");
const TOKEN = process.env.GH_TOKEN;
const REPO = "Saj-1992/ngm";
const VERSION = process.argv[2];
if (!TOKEN || !VERSION) { console.error("usage: GH_TOKEN=... node scripts/release_github.cjs <version>   (e.g. 0.8.1; assets from dist/release/<version>)"); process.exit(2); }
const TAG = "v" + VERSION;
const DIR = __dirname + "/../dist/release/" + VERSION + "/";
const FP = "sha256:82558c32017fd487558faea76d2cf2f3a46d34642436891aad23482711b5cc21";

function req(method, host, path, headers, body) {
  return new Promise((res, rej) => {
    const r = https.request({ method, host, path, headers: { "User-Agent": "ngm-release", Authorization: "Bearer " + TOKEN, ...headers } }, (x) => {
      const c = [];
      x.on("data", (d) => c.push(d));
      x.on("end", () => res({ status: x.statusCode, body: Buffer.concat(c) }));
    });
    r.on("error", rej);
    if (body) r.write(body);
    r.end();
  });
}

(async () => {
  const notes = `NGM ${TAG} — development channel release.

**One-line install:**
\`\`\`
curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | sudo sh
\`\`\`

The installer verifies the Ed25519 signature and SHA-256 of the binary before running. For extra assurance, pin the publisher key:
\`\`\`
NGM_EXPECT_KEY=${FP}
\`\`\`
Publisher key: \`dev-2026a\` (development channel). A production (stable) key will be published separately.

Assets: signed \`manifest.json\`/\`manifest.sig\`, \`ngm-linux-amd64\`, \`ngm-linux-arm64\`, \`install.sh\`, \`SHA256SUMS\`.`;

  // Delete an existing release for this tag (idempotent re-run).
  const existing = await req("GET", "api.github.com", `/repos/${REPO}/releases/tags/${TAG}`, {});
  if (existing.status === 200) {
    const id = JSON.parse(existing.body).id;
    await req("DELETE", "api.github.com", `/repos/${REPO}/releases/${id}`, {});
  }
  const create = await req("POST", "api.github.com", `/repos/${REPO}/releases`, { "Content-Type": "application/json" },
    JSON.stringify({ tag_name: TAG, name: "NGM " + TAG, body: notes, prerelease: /-rc./.test(VERSION), make_latest: /-rc./.test(VERSION) ? "false" : "true" }));
  if (create.status >= 300) throw new Error("create release: " + create.status + " " + create.body);
  const rel = JSON.parse(create.body);
  console.log("release created:", rel.html_url);
  const ct = { ".sh": "text/x-shellscript", ".json": "application/json", ".sig": "text/plain", "SUMS": "text/plain" };
  for (const name of ["install.sh", "manifest.json", "manifest.sig", "ngm-linux-amd64", "ngm-linux-arm64", "SHA256SUMS"]) {
    const data = fs.readFileSync(DIR + name);
    const type = name.endsWith(".sh") ? "text/x-shellscript" : name.endsWith(".json") ? "application/json" : name.startsWith("ngm-linux") ? "application/octet-stream" : "text/plain";
    const up = await req("POST", "uploads.github.com", `/repos/${REPO}/releases/${rel.id}/assets?name=${name}`, { "Content-Type": type, "Content-Length": data.length }, data);
    console.log(name, up.status === 201 ? "uploaded" : "FAILED " + up.status + " " + up.body.toString().slice(0, 120));
  }
})();
