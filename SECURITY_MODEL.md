# SECURITY_MODEL

Refines MASTER_SPEC §10–§11. Status: design baseline. Controls become real only when tests in TEST_REPORT.md pass.

## Assets
Admin credentials and sessions, TOTP seeds, API tokens, vault secrets (Cloudflare and notification tokens), TLS private keys,
backup passphrase (user-held and never stored), the KEK, Active Nginx config, UFW state, SSH reachability, and hosted website content.

## Trust boundaries & principals
| Principal | Account | Can | Cannot |
|---|---|---|---|
| Browser user | — | Reach the management origin via Nginx HTTPS, then the API on loopback | Reach the API directly from outside (loopback bind) |
| `ngm-api` | `ngm-api` | Read/write SQLite, enqueue jobs, read vault ciphertext | Exec system commands, write nginx/ufw, read the KEK |
| `ngm-ops` | `ngm-ops` (groups ngm, ngm-helper, ngm-vault) | Run jobs, hold locks, render staged configs, decrypt TLS keys for deployment, call the helper | Run as root; reach the API port |
| `ngm-monitor` | `ngm-monitor` | Outbound probes via an SSRF-guarded dialer | Mutate config |
| `ngm-log-indexer` | `ngm-logs` | Read log sources (group read), write the index | Mutate anything else |
| `ngm-helper` | root (minimised caps) | Allowlisted typed ops only | Arbitrary exec, paths, env, or service names |
| Nginx | distro (`www-data` workers) | Serve/forward, read deployed certs | — |

Peer identity on the helper socket comes from `SO_PEERCRED`. Only the `ngm-ops` UID can call mutating helper ops,
and each call carries a job ID plus a fencing token that the helper checks against SQLite (read-only).

## Threats → controls
| Threat | Control | Req |
|---|---|---|
| Remote unauthenticated admin | Loopback-only API, Argon2id, TOTP, throttling, sessions | SEC-002..005 |
| CSRF | SameSite=Strict cookie, Origin/Sec-Fetch-Site check, double-submit CSRF token on unsafe methods | SEC-003 |
| XSS | Strict CSP (`default-src 'self'`, no inline script), React escaping, no `dangerouslySetInnerHTML` on user data | SEC-003 |
| IDOR / privilege | Deny-by-default RBAC on every handler, SSE subscription, and export | SEC-006 |
| SSRF via backends/health/webhooks | Resolve-then-dial guarded dialer: block link-local/metadata/private unless explicitly allowed, re-check after DNS (anti-rebinding), no redirects to blocked ranges | SEC-008 |
| Config injection | Typed model, strict validation of every token emitted to nginx, no raw directive pass-through | ROUTE-010 |
| Path traversal / symlink / TOCTOU | Helper uses `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` where available, otherwise O_NOFOLLOW walk; zip extraction normalises paths | ARCH-003, WEB-001 |
| Malicious ZIP | Size, ratio, entry-count limits, no symlinks/devices, MIME allowlist | WEB-001 |
| IPC escalation | Peercred UID check, schema validation, no generic exec, fencing | ARCH-002/003 |
| Secret leakage | Redaction in logger; secrets never returned by the API; tokens shown once | LOG-003, VAULT-003 |
| Backup tamper | AEAD over the archive and manifest, Argon2id KDF, verify before any restore step | BAK-002/003 |
| Supply chain | Pinned go.sum and package-lock, minimal deps, signed releases, pinned publisher key | LIFE-001/002 |
| Management lockout | UFW SSH-path protection, watchdog rollback, local CLI `ngm admin reset` | FW-002, LIFE-005 |

## Key lifecycle
- **KEK**: 32 random bytes per version in `/etc/ngm/keys/kek-<v>.key`, owned by root:ngm-vault, mode 0440. Only processes that need
  decryption are in the group. Rotation: stage new KEK → rewrap all DEKs (journaled) → verify → retire the old one after a grace period.
- **DEK**: per secret, AES-256-GCM, 96-bit random nonce. AAD = `secret_id|type|scope|version`.
- **Passwords**: Argon2id (m=64 MiB, t=3, p=2 initial, recalibrated per profile), with a per-user salt.
- **API tokens**: 256-bit random, shown once, stored as SHA-256 (high-entropy input, so a slow hash is not needed).
- **Backups**: user passphrase → Argon2id (calibrated, params in header) → AES-256-GCM. The archive carries its own DEKs, wrapped
  by the passphrase key, so a new host can restore without the source KEK.

## Explicit non-guarantees
Root compromise with access to the KEK and live process memory defeats at-rest encryption. Audit is tamper-evident, not immutable.
Provider firewalls are out of scope. External SSH reachability cannot be proven from local probes.

## Phase 4 additions
- **Firewall**:
  - Only typed, validated rules are applied (no free-text ufw arguments). NGM touches only rules commented `ngm:<key>`.
  - Reset and flush are never used.
  - Deny rules on detected SSH ports are refused.
  - An SSH guard is added before enabling.
  - Risky changes need an operator confirmation from the Control Center, plus an independent systemd revert timer (ADR-020).
  - `firewall.write` requires step-up MFA.
- **Monitoring**:
  - Health probes resolve once and dial the vetted IP.
  - Loopback is allowed for local backends, but link-local, metadata, NGM-internal and API-port targets are refused.
  - Probes run as the unprivileged `ngm-monitor` user.
- **Backups**:
  - Archives are encrypted end to end (ADR-021) and are `ngm-ops:ngm 0640` in a setgid `ngm` directory.
  - The passphrase is never stored or logged (verified by grepping the DB, WAL and journal). Only an Argon2id-derived key is kept in the vault, so a root compromise also exposes future archives (accepted; documented).
  - Download requires `backups.create`.
  - Restore is root-only CLI, revokes all sessions, and keeps a safety copy.
- **Vault keys**: KEK files must be `root:ngm-vault 0440`. `ngm vault rotate` re-asserts this, and `ngm doctor` checks it (`vault_perms`).
- **Recovery**:
  - Resolving incidents and running reconcile require `recovery.write` (step-up MFA), and both are audited.
  - Manual resolution is refused while the data plane disagrees with the record (ADR-025).

## Phase 5–8 additions
- **ACME and websites.**
  - HTTP-01 challenge files live in the public tree `/var/www/ngm/acme` (mode 0644, written only by the helper). `/etc/nginx/ngm` stays 0700.
  - Website previews use HMAC-signed links valid for 30 minutes, served with `Content-Security-Policy: sandbox` (opaque origin). The session cookie is neither needed nor sent.
  - ZIP uploads reject traversal, absolute paths, symlinks, devices, size/ratio bombs and disallowed types.
- **Outbound requests (SSRF).**
  - Webhook targets must be `https://`.
  - Literal loopback, private, link-local and metadata addresses and `localhost`/`.local`/`.internal` names are rejected when the target is created.
  - Every resolved address is checked again at dial time (DNS rebinding).
  - Telegram and Cloudflare calls go only to their fixed API hosts.
  - Webhook bodies are signed with HMAC-SHA256.
  - Delivery runs in ngm-ops (vault access), is rate-limited to 30 per hour per target, and never echoes secrets.
- **Logs.** Query strings and `Authorization` values are removed before indexing. The index is derived data and can be rebuilt (`ngm logs reindex`). Client IPs can be anonymized.
- **Release trust (ADR-032/033).**
  - Publisher keys are Ed25519 and pinned in the binary and in `install.sh`. Keys downloaded with artifacts are never trusted.
  - Development keys (`dev-*`) cannot sign stable or beta releases.
  - The shell installer verifies the signature (OpenSSL) and the SHA-256 before executing anything. The binary re-verifies itself before changing anything.
  - Updates are verified by the installed binary and need root plus `--yes`. They take a DB snapshot and an encrypted backup first, and roll back automatically if health fails.
  - A release binary that no longer matches its manifest is never executed by `ngm repair`.
- **Lifecycle boundaries.** `internal/lifecycle` (which runs commands) is reachable only from the root CLI. The API import graph test forbids `os/exec`. Uninstall touches only marker-verified NGM files and `ngm:`-tagged UFW rules, and never the only SSH allow rule.
- **Verified sweep (Phase 8).** All 136 API operations were tested live:
  - unauthenticated requests → 401/403;
  - cookie-session mutations with a wrong CSRF token or a foreign Origin → 403;
  - a token scoped to one permission is denied everything else;
  - a revoked token → 401.

  See TEST_REPORT Phase 8.
- **Known gaps.**
  - Only a development signing key exists (O-24).
  - Dependency vulnerability scanning could not reach vuln.go.dev or OSV from the development network. It runs in CI (`security` job) once a remote exists.
  - No third-party penetration test.

## Crawlers, scanners and what NGM can and cannot tell
NGM serves every request that matches no route with a complete fallback website, the same answer for everyone (ADR-036). It deliberately does **not** try to classify visitors. This is why:

- **User-Agent and headers are trivially spoofed.** Any client can claim to be a search engine, a Cloudflare health check or a hosting-provider monitor. Branching on them would be unreliable and would add behaviour that differs between visitors, which is itself a fingerprint. NGM does not do it.
- **Behind Cloudflare (proxied records) the TCP peer is Cloudflare.** The real client address arrives only in `CF-Connecting-IP` / `X-Forwarded-For`, and those headers are trustworthy only when the connection really comes from Cloudflare's published ranges. NGM does not read them for decisions. Cloudflare's own crawlers, health checks and the visitors it proxies all look like Cloudflare to the origin.
- **Source address is the only non-spoofable signal at the origin**, and address ranges of providers (Cloudflare, hosting monitors, search engines) change and are shared by unrelated customers. Reverse-DNS checks help for some search engines but are not available for most scanners.
- **TLS behaviour is consistent by design.** Unknown or missing SNI on the shared port, direct IP access and unknown hosts all complete a normal handshake with the same certificate and receive the same website, so a scanner cannot tell a routed host from an unrouted one by a closed connection or a TLS alert.
- **What is still observable:** a scanner that knows a real backend's SNI reaches that backend (for TLS passthrough, NGM sees only the ClientHello and cannot inspect or change the traffic). Timing, traffic volume and the open ports themselves are visible. Hosting providers judge more than a web page, and NGM cannot change their policy or detection.
- **Practical guidance:** keep realistic content on the fallback site, use a certificate for a real domain, keep the admin path secret and rate-limited, and rely on authentication (not obscurity) for protection.
