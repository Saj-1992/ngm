# DECISIONS — architecture decision records

The closed decisions in MASTER_SPEC §20 are binding. The ADRs below refine implementation choices within that baseline.
Changes that affect P0/P1 or architecture need an owner-approved change request.

## ADR-001: Single Go binary with role modes (2026-10-08, Accepted)
`cmd/ngm` builds one static binary. systemd units start it as `ngm api`, `ngm ops`, `ngm monitor`,
`ngm log-indexer`, and `ngm helper` under separate accounts. This implements MASTER_SPEC §3 ("shared Go binary with
role-specific execution modes is acceptable").

## ADR-002: SQLite driver is modernc.org/sqlite, pure Go (2026-10-08, Accepted)
Rationale: `CGO_ENABLED=0` cross-compiles to linux/arm64 from any host, which gives reproducible builds. WAL, foreign keys,
`VACUUM INTO` (online consistent snapshot), and FTS5 are all supported. Alternative considered: mattn/go-sqlite3 (CGO), rejected
because it complicates arm64 cross builds. Risk: it is slower than CGO, which is acceptable for a control plane.

## ADR-003: HTTP routing uses stdlib net/http ServeMux with Go 1.22+ patterns (2026-10-08, Accepted)
This keeps the dependency and supply-chain surface small. Middleware is hand-written and tested.

## ADR-004: UI is Vite + React + TypeScript + Tailwind CSS + Radix primitives (shadcn/ui pattern) + Lucide (2026-10-08, Accepted)
The UI is built into `web/dist` and embedded in the binary via `embed`. `ngm-api` serves it on the loopback
listener. Nginx exposes the management origin over HTTPS (Phase 2/3). shadcn components are vendored as source (that is how shadcn works),
not pulled from an npm runtime package.

## ADR-005: Durable lock total order (2026-10-08, Accepted)
Locks are acquired in strictly ascending rank, and a job declares its full lock set up front:
1 `system-update` → 2 `backup-restore` → 3 `gateway-config` → 4 `certificate` → 5 `website-publish` → 6 `firewall`.
Each grant increments a global monotonic fencing token. Every DB commit and helper call made under a lease must present
the current token, and it is rejected if a newer token was issued for that resource. Leases expire without a heartbeat.

## ADR-006: IDs are 128-bit random with a millisecond-time prefix, Crockford base32 (ULID-shaped) (2026-10-08, Accepted)

## ADR-007: Audit tamper evidence (2026-10-08, Accepted)
Each audit row stores `prev_hash` and `hash = SHA-256(prev_hash || canonical_row)`. Verification recomputes the chain.
Per spec this is tamper-evident, not an immutable ledger.

## ADR-008: Test environment reality (2026-10-08, Accepted, constraint)
The dev host is Windows 10 with no WSL or Docker. Linux behavior (nginx, systemd, UFW, SO_PEERCRED) is tested on the owner-provided
VM (Ubuntu 24.04.5 LTS, x86_64, KVM, 2 vCPU, 3.8 GiB, 38 GB disk, fresh, UFW inactive, no Nginx). That covers only one of the four
platform cells. The Compatibility gate stays **Blocked** for 22.04 AMD64/ARM64 and 24.04 ARM64 until environments exist.

## ADR-009: Configuration file format is JSON at /etc/ngm/ngm.json (2026-10-08, Accepted)
This avoids a TOML/YAML dependency. Unknown fields are rejected (`DisallowUnknownFields`).

## Open decisions (to be resolved in their phase; owner input marked ★)
- OD-1 (Phase 5): ACME client library (`go-acme/lego` vs a minimal in-house RFC 8555 client). Default plan: lego.
- OD-2 ★ (Phase 7): Release signing key custody (offline Ed25519 key held by owner, plus a CI signing step).
- OD-3 (Phase 2): TOTP and Argon2 come from `golang.org/x/crypto`. TOTP is implemented per RFC 6238 in-house (small, testable).

## ADR-010: MFA is mandatory for every account (2026-10-08, Accepted)
A password-verified session is in stage `mfa_enroll` (no TOTP yet) or `pending_mfa`, and it has no permissions until a TOTP code is verified.
Enrolment is only possible in `mfa_enroll`, so a stolen password cannot replace an existing authenticator. Every stage change rotates the
session token (fixation defence). Recovery is host-local through `ngm admin reset USER`.

## ADR-011: First-run owner creation needs a one-time bootstrap token (2026-10-08, Accepted)
The installer stores SHA-256(token) in `settings` and prints the token once. `POST /setup/owner` also requires a direct-loopback request
(no proxy headers) and an empty users table. This closes the race in which another local account on the host could claim
the first-run window. The token is consumed on success. `ngm admin bootstrap-token` reissues it while no user exists.

## ADR-012: Built-in role refinements (2026-10-08, Accepted)
Operator has no `users.read`, `roles.read`, `audit.read` or `secrets.read`. Viewer additionally has no `tokens.read`. Custom roles can never hold
`owner.transfer` or `system.purge`. Actors can only grant permissions they hold, and cannot modify users who hold permissions they lack.

## ADR-013: Style-only CSP nonce (2026-10-08, Accepted)
Radix's scroll lock (react-remove-scroll → react-style-singleton) injects a `<style>` element, which `style-src 'self'` blocks. `index.html`
is served with a per-response nonce allowed in `style-src` only, and passed to the library through `get-nonce`. `script-src` stays `'self'`
with no nonce, hash or `unsafe-inline`.

## ADR-014: Helper socket access = filesystem group + kernel peer UID (2026-10-08, Accepted)
`/run/ngm/helper.sock` is root:ngm-helper 0660, and only `ngm-ops` is a member of ngm-helper. Each request is then authorised by SO_PEERCRED UID
against the helper policy (root and ngm-ops). Both layers were verified on the VM (EACCES for ngm-api, `forbidden` for other UIDs in the group).

## ADR-015: Include hooks without editing nginx.conf (2026-10-08, Accepted)
NGM attaches to the distribution configuration through two owned files: `/etc/nginx/conf.d/ngm.conf` (http context) and
`/etc/nginx/modules-enabled/99-ngm-stream.conf` (main context; a `stream {}` block that loads after `50-mod-stream.conf`). Both start
with an ownership marker. They are created only if absent and are never overwritten if foreign. `nginx.conf` (a dpkg conffile) is untouched,
which `dpkg --verify` confirms.

## ADR-016: In-place `nginx -t` with automatic revert (2026-10-08, Accepted)
Generations are immutable directories under `/etc/nginx/ngm/gen/<id>`, and `/etc/nginx/ngm/current` is a symlink swapped by rename(2).
Activation swaps the pointer, runs `nginx -t` against the real configuration root (the exact prospective include graph), and on failure
swaps back before any reload. Residual risk: an external `nginx -s reload` during that window (milliseconds, under the helper mutex) would
load the candidate. Accepted and documented. The alternative of a mirrored test root was rejected because it diverges from the real include graph.

## ADR-017: Shared 443 via stream front + internal hops with PROXY protocol (2026-10-08, Accepted)
The public `stream_tls_front` server always sends PROXY v1. Terminate routes go to an internal http TLS server on 127.0.42.1:<port>
(`listen … ssl proxy_protocol`, realip from 127.0.0.0/8). Passthrough backends without PROXY support go through an internal stream hop
that strips the header. Unmatched connections go to an internal reject hop. Verified: the backend sees the real internet client IP.

## ADR-018: Verification probes (2026-10-08, Accepted)
Each generation has a random probe token. Every generated server answers `X-NGM-Probe: <token>` with 204 at server level and
adds `X-NGM-Generation` only for that token. Verification needs no backend availability, and the generation is never disclosed to others.

## ADR-019: ngm-ops reads the vault (2026-10-08, Accepted; SECURITY_MODEL updated)
Deploying TLS keys requires decryption, so `ngm-ops` joins `ngm-vault`. Keys travel to the helper over the peer-authenticated
socket and are written 0600 root under `/etc/nginx/ngm/keys`. The API keeps vault access only for TOTP.

## ADR-020: Firewall changes use a dead-man watchdog plus browser confirmation (2026-10-08, Accepted)
NGM owns only UFW rules tagged `comment 'ngm:<key>'`. It never runs `ufw reset` or flushes, and rules without that tag are reported but never modified.
Before any change the helper writes a revert plan (`/var/lib/ngm/fw/revert-<job>.json`). Risky changes (enabling UFW, deletions while active, or
non-allow rules) also arm an independent `systemd-run --on-active=120s ngm fw-revert <job>` timer. The job then waits in `Verifying` until an
operator confirms from the Control Center, which proves the management path still works. Without that confirmation, the coordinator reverts.
If the coordinator itself dies, the timer reverts anyway. An `ssh-guard` allow rule for every detected sshd port is added before enabling,
and deny rules on SSH ports are blocked.

## ADR-021: Portable backup format NGMBAK1 (2026-10-08, Accepted)
The archive is a tar (manifest, `VACUUM INTO` DB snapshot, KEK files) encrypted in 64 KiB AES-256-GCM chunks. Each nonce is a 7-byte random
prefix plus a 4-byte counter plus a final flag. The AAD is SHA-256 of the cleartext header (KDF parameters and salt). The key is Argon2id
(64 MiB, t=3, p=2) of a user passphrase. These choices detect truncation, reordering, header tampering and trailing data. The passphrase is never stored. The derived key
is kept in the vault so scheduled backups can run unattended. A host compromise therefore also compromises future archives; the KEK files are
inside the archive, but only under the passphrase-derived key. Restore re-wraps every DEK to the destination host's KEK, so plaintext secrets are never materialised.

## ADR-022: Restore is a root CLI operation; the Control Center only creates, verifies and downloads (2026-10-08, Accepted)
A restore swaps the database and must stop NGM's own services, which an unprivileged API process cannot (and must not) do. `ngm restore` takes a
safety backup, stages and re-keys a copy, migrates it, verifies the vault, revokes sessions, swaps with services stopped (Nginx keeps serving),
health-checks, and restores the previous database on failure. The restored gateway model stays Desired until it is deployed (`--apply` queues that deployment).

## ADR-023: Open recovery incidents block new mutations of the same family (2026-10-08, Accepted)
When a job reaches `RecoveryRequired`, its incident blocks new `deploy.gateway` jobs, or new `firewall.apply` jobs for a firewall incident.
The block stays until an operator resolves the incident in the Recovery Center. Resolution requires `recovery.write` (step-up MFA), a stated outcome and a note,
is audited, and moves the job to the attested terminal state. Rollback jobs are not blocked, because they are the recovery path.

## ADR-024: An interrupted activation is resolved from evidence (2026-10-08, Accepted)
If `nginx.activate` returns an error without a typed result (for example the helper crashed or the socket broke), the coordinator does not guess.
It waits up to 30 s for the helper, then reads the live pointer:
- If the pointer is the new generation and verification probes pass, it promotes.
- If the pointer is the new generation but the probes fail (swapped but not reloaded), it compensates.
- If the pointer is the previous generation, it verifies that generation and ends RolledBack.
- Anything else is RecoveryRequired.
The same applies to rollback, which previously claimed "the current one stays active" without proof.

## ADR-025: Drift needs a supervised, verified reconcile; manual attestation is refused (2026-10-08, Accepted)
ngm-ops records the live generation pointer every 30 s. A gateway incident can be resolved by hand only when that evidence is fresh and matches
NGM's active record. Otherwise the operator picks `deploy.reconcile`:
- **adopt**: keep the serving generation after its probes pass.
- **restore**: switch back to the recorded generation, verify it, and compensate on failure.
The reconcile job closes the incident only on proven success. It also exists without an incident, for drift caused outside NGM.

## ADR-026: Versioned certificate keys (2026-10-08, Accepted)
Each private-key version has its own vault entry (`tls_key`, `cert:<id>`, `key-<keyID>`) and its own file, `/etc/nginx/ngm/keys/<keyID>.key`.
A generation records which key version each certificate uses (`summary.cert_keys`).
Renewal or re-import therefore never rewrites a key that an older generation still references. A rollback re-stages exactly the key it was built with, which was verified live.
Old versions are pruned only when no retained generation uses them. Legacy single keys (`key_id=''`) keep their previous paths.

## ADR-027: ACME via HTTP-01 served by NGM's own Nginx (2026-10-08, Accepted)
Only HTTP-01 is implemented: wildcards are refused, not promised.
- **Where challenges are served:** every port-80 server has `location ^~ /.well-known/acme-challenge/` aliased to `/var/www/ngm/acme`. The route path is reserved by validation, and the simulator reports it.
- **Ownership:** challenge files are written by the helper, which validates them, fences them with the `certificate` lock, and gives them explicit mode 0644 regardless of UMask=0077.
- **Before contacting the CA:** the job requires the active generation to contain the challenge location and fresh CAA evidence that allows the CA (from the Domain Registry). It then runs a self-check by fetching the challenge by name, so failed validations do not consume CA rate limits.
- **After issuance:** the result is verified (names, key match, validity) before it is stored.
- **Renewal:** runs automatically 30 days before expiry, and the renewed certificate is deployed by a Safe Apply.

## ADR-028: Public tree /var/www/ngm (2026-10-08, Accepted)
`/etc/nginx/ngm` stays root-only (0700), because it holds private keys and generations. Content that Nginx workers must read lives in a separate NGM-owned tree, `/var/www/ngm` (root, 0755):
- ACME challenges in `/acme`;
- published websites in `/sites/<site>/<version>`, with a `current` pointer per site.

## ADR-029: Website publishing by per-site pointer and verification (2026-10-08, Accepted)
**Builds.** Each build is deterministic: same content and media give the same hash, and a rebuild with identical content reuses the existing version. Builds are immutable under `/var/lib/ngm/websites/<site>/builds/<version>`.

**Publishing.** The helper copies a build into the public tree, accepting only regular files, with explicit modes. It then switches `current` with rename(2). Nginx follows the pointer per request, so publishing needs no reload.

**Verification.** Verification compares the served `index.html` with the build, through every active route that serves the site, over real HTTP/HTTPS via Nginx. When the site has no route, the check is file-level only, and the job says so. On failure the pointer is switched back. A failed first publication is removed entirely. Re-publishing an existing copy verifies it against its build, so a tampered copy is refused.

**Rollback** means publishing an older version again.

## ADR-030: Isolated website preview by signed link + CSP sandbox (2026-10-08, Accepted)
Previews are served by the API under `/api/v1/preview/<site>/<version>/<token>/…`. The token is an HMAC with a 30-minute lifetime, bound to that site and version, issued to authorised users.

Responses carry `Content-Security-Policy: sandbox …` (no `allow-same-origin`, `connect-src 'none'`). Because of the sandbox, content has an opaque origin and cannot use NGM cookies, storage or authenticated API calls, even when the link is opened directly.

A cookie-authenticated preview was rejected because SameSite=Strict cookies are not sent from sandboxed (opaque-origin) frames.

Template sites use relative links, so they work in the preview and when mounted on a sub-path.

## ADR-031: Cloudflare changes bound to a preview (2026-10-08, Accepted)
- **Where calls happen:** only ngm-ops calls Cloudflare, in jobs; the API never calls it.
- **Token:** stored in the vault and never read back.
- **Binding to the preview:** a preview produces a plan with a hash, and an apply must quote that hash. If the zone or the expectations changed in between, the apply is Blocked.
- **Which records change:** NGM only updates records it marked (`comment: managed-by:ngm`), or conflicting records the operator explicitly adopts. Created A/AAAA/CNAME records are not proxied.
- **Not transactional:** partial failures are reported, and nothing claims a rollback is possible.

## ADR-032: Signed releases with pinned Ed25519 keys (2026-10-09, Accepted)
- **Format:** each release is `manifest.json` (version, channel, key id, supported OS, schema count, API version, required modules, per-arch size and SHA-256), plus `manifest.sig` (a base64 Ed25519 signature over the exact bytes), plus `ngm-linux-{amd64,arm64}`. Unknown manifest fields are rejected.
- **Trust anchors:**
  - The binary trusts only keys embedded at build time (`internal/release/trusted/*.pub`).
  - `install.sh` trusts only the PEM keys pinned inside it. Verification uses `openssl pkeyutl -rawin` (OpenSSL 3, present on 22.04 and 24.04).
  - A key shipped next to the artifacts is never trusted.
  - `NGM_EXPECT_KEY` lets the operator enforce a fingerprint obtained out of band.
- **Key scope:** keys named `dev-*` may sign only the development channel. A stable or beta key needs a separate key ceremony, which is not done yet.
- **Verification order:** first `install.sh` checks the signature and the digest, then the binary re-verifies itself (`install --release-dir`) before any change. For updates, the currently installed binary verifies the new release.
- **Immutability:** releases are immutable except `*-dev` versions.

## ADR-033: Updates are a root CLI action with snapshot rollback (2026-10-09, Accepted)
- **Approval:** `ngm update apply --from DIR --yes` is the administrator approval. The API and UI only show status. This avoids a request path that can replace the running binary.
- **Before installing:** a `VACUUM INTO` DB snapshot, an encrypted `pre_update` backup if a passphrase is configured, and an immutable staged release.
- **Install and health:** the new binary runs its own idempotent `install`, which covers migrations, units and restart, and then must pass the health check.
- **Automatic rollback:** on failure, NGM switches the pointer back. If migrations ran, it restores the snapshot. It then re-runs the old release's install.
- **Policy:** downgrades go only through `ngm update rollback` and are refused otherwise. A release whose `db_schema` is older than the database is refused.

## ADR-034: Nginx package changes are coordinated or detected (2026-10-09, Accepted)
`ngm nginx upgrade` works in this order:
1. Checks the dpkg locks.
2. Simulates the upgrade, and refuses mixed module sets (every `libnginx-mod-*` must move with `nginx-common`).
3. Takes a backup and a copy of `/etc/nginx`.
4. Upgrades with `--force-confold`.
5. Runs `nginx -t`, restarts Nginx and records a new baseline.

NGM does not block external upgrades (for example unattended-upgrades). The monitor compares every observation with the baseline and raises `nginx_external_change`, which is critical if the stream module or ssl_preread disappeared. `ngm nginx reconcile` re-verifies and accepts the change. It refuses if the stream module is gone while stream listeners exist. Package downgrades are never offered as a configuration rollback.

## ADR-035: Uninstall touches only marker-verified NGM resources (2026-10-09, Accepted)
- **Plan first:** `ngm uninstall --keep-data|--purge` always prints a plan with dependency warnings and backup advice. `--yes` is required to execute, and `--purge` also needs `--confirm "purge <hostname>"`.
- **Nginx hooks:** removed only if their first line carries the NGM marker. Then `nginx -t` runs; if it fails, the hooks and the default site are restored and nothing else is removed. The distribution default site is restored only if NGM recorded disabling it.
- **Keep Data:** keeps `/etc/ngm`, `/var/lib/ngm`, `/var/log/ngm`, `/etc/nginx/ngm`, `/var/www/ngm` and the NGM UFW rules, so the traffic policy is unchanged.
- **Purge:** additionally deletes those directories, the `ngm:`-tagged UFW rules (highest number first) and the NGM accounts. It never deletes the only rule that allows SSH.

## ADR-036: Fallback website for unmatched traffic (2026-10-09, Accepted)
- **Context:** Crawlers, scanners and network probes (hosting-provider abuse scanners, Cloudflare, national firewalls) connect by IP or with unknown or missing Host/SNI. A closed connection (444), a TLS `unrecognized_name` alert or a reset on the shared 443 front is unusual for a normal web server. It reveals that the host routes traffic selectively and invites abuse flags.
- **Decision:** a gateway setting `gateway.fallback` = {published website, certificate with key}. When set, every request that matches no route gets the same answer:
  - the HTTP default servers (unknown Host, IP-only) serve the website, and ACME challenges keep working;
  - the TLS default servers present the fallback certificate and serve the website;
  - on `stream_tls_front`, unknown or absent SNI (incl. ECH) goes to an internal TLS-terminating server with the fallback website instead of the reject hop.
- **Precedence:** explicit fallback routes still win.
- **Other hardening:** `server_tokens off` in every NGM server. The probe header is answered only with the per-generation secret token.
- **Deployment and safety:** the setting is part of the model hash (it reaches Nginx through Safe Apply). The simulator reports `fallback_site`. The website and certificate cannot be deleted while they serve as the fallback.
- **Limits (explicit):**
  - This removes the cheap fingerprints only.
  - It does not hide traffic volume or timing, and it does not defeat active probing of a passthrough backend reached through a known SNI.
  - It does not change a provider's terms of service.
  - The fallback site should look genuine: real content, and a certificate for a real domain, not self-signed.

## ADR-037: Control Center on a secret port and path (2026-10-10, Accepted)
- **Context:** the apex domain must look like an ordinary website on every port and path. The management panel must therefore not live at a guessable URL.
- **Decision:** the panel is published at `https://<domain>:<port>/<secret-path>/` (default port 9443). Config `api.public_origin` carries the host and port, and `api.public_path` carries the secret base path (random, 18 hex characters, kept only in the local, git-ignored `.local/panel-path.txt` and in `/etc/ngm/ngm.json`).
- **Mechanism:**
  - The API strips the prefix (`withBasePath`) and injects `<base href>` into the SPA shell. The SPA derives its base (`lib/base.ts`) for fetch, SSE, downloads and the router. The same binary still answers at the root for the SSH tunnel.
  - A TLS-terminate route with SNI = host and `path_prefix = /<secret>/` may target the control API. This is the only exception to the "never expose the API" validation, and it applies only when the route matches exactly the configured host and path.
  - `base-uri` in the CSP changed from `'none'` to `'self'` (same-origin only) because of the `<base>` tag.
- **Everything else on that host answers with the fallback website** (ADR-036), including `:9443` outside the secret path. Unknown paths on a configured vhost fall through to the fallback site instead of a bare 404.
- **Limits (explicit):** a secret path is obscurity, not authentication. Authentication (password, MFA, CSRF, rate limiting) still protects every operation. The path appears in browser history and in the TLS-terminated access log.

## ADR-038: UDP is a flag on a stream listener (2026-10-10, Accepted)
- **Decision:** `options.udp` on a `stream` listener renders `listen <addr:port> udp;`. A TCP and a UDP listener may share a port. It needs no schema migration.
- **Verification:** UDP binds are labelled `udp:<addr>` in the generation's listen list. The TCP ownership check (`ss -t`) skips them, and the post-reload check probes UDP separately: one datagram on a connected socket, where ICMP port-unreachable (ECONNREFUSED) means "not bound" and a read timeout means "bound". This is verified on Linux only. Windows does not deliver that ICMP error to the program.
- **Limits:** UDP has no TLS or SNI routing. A UDP route is a plain forward.

## ADR-039: ACME DNS-01 through Cloudflare (2026-10-10, Accepted)
- **Decision:** `challenge: dns-01` makes the ACME job publish `_acme-challenge` TXT records through the Cloudflare integration, wait (bounded) until a public resolver shows them, and remove them afterwards. Wildcard names require it. The API refuses a wildcard with HTTP-01.
- **Boundaries:** the API never calls Cloudflare (ADR-031). Zone discovery is a read-only job (`dns.cloudflare.discover`). The token stays in the vault. NGM-created TXT records carry the `managed-by:ngm` marker.
- **Not interchangeable:** publicly trusted ACME certificates (Let's Encrypt) and Cloudflare Origin CA certificates are different things. Origin CA certificates are trusted only by Cloudflare's edge, not by browsers. NGM issues ACME certificates and does not manage Origin CA certificates.
- **Status:** unit-tested against a fake ACME CA and a fake Cloudflare API. **Not live-verified**: no Cloudflare token or delegated zone was available.

## ADR-040: Certificate downloads (2026-10-10, Accepted)
- `GET /certificates/{id}/fullchain` (certificate plus chain, `certificates.read`) and `GET /certificates/{id}/privkey` (`certificates.write`).
- The private key requires an interactive user (never an API token) with a fresh second factor (step-up). Every download is audited with the certificate id only, never the key. Responses are `no-store`, `nosniff` attachments.
- Keys are otherwise vault-only: they never appear in lists, logs or frontend state. The UI fetches the file as a blob and does not keep it.
