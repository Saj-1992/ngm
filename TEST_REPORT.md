# TEST_REPORT

Every entry records: test ID, result (`Pass`/`Fail`/`Blocked`/`Skipped`/`Not Tested`), command, environment, artifact/log, timestamp, and reviewer.
`Skipped` and `Not Tested` are never Pass.

## Environment capability record (2026-10-08)

| Env ID | Machine | OS / arch | Use | Notes |
|---|---|---|---|---|
| ENV-DEV-WIN | Developer workstation | Windows 10 Enterprise 19045, amd64 | Go unit/contract tests, cross-compilation, web build | Go 1.26.5, Node 24.17.0, npm 11.13.0, git 2.55. No WSL distro and no Docker, so no local Linux runtime |
| ENV-VM-2404-AMD64 | Owner test VM `test-host` (KVM) | Ubuntu 24.04.5 LTS, x86_64, 2 vCPU, 3.8 GiB RAM, 38 GB disk | Linux integration/E2E | Probed read-only 2026-10-08: no nginx installed, UFW 0.36.2 installed and inactive, only sshd :22 and systemd-resolved listening, IPv6 sshd bind present. Test domain `example.test` has an A record pointing to the VM (Cloudflare NS, unproxied) |
| ENV-VM-2204-AMD64 | — | — | Compatibility | **Not available → Blocked** |
| ENV-VM-2204-ARM64 | — | — | Compatibility | **Not available → Blocked** |
| ENV-VM-2404-ARM64 | — | — | Compatibility | **Not available → Blocked** |

What can be tested where:
- Windows dev: pure-Go logic (compiler, validator, jobs, locks, store, vault crypto, API contract/security middleware), UI build/unit tests.
- VM: everything that needs nginx, systemd, UFW, SO_PEERCRED, apt, real TLS/WS/TCP traffic, the installer, and crash injection.
- Not available: ARM64 and 22.04 cells, a second host for cross-host restore, Cloudflare sandbox token, and visual-regression browser runner (Playwright can be
  installed on the dev host later for UI QA).

## Results

(Entries are appended as tests are actually executed.)
### Phase 1 run (2026-10-08). Reviewer: Claude Code (self-run; owner review pending)

| Test ID | Result | Command | Env | Evidence |
|---|---|---|---|---|
| T-UNIT-DB / T-UNIT-MIG | Pass | `go test ./internal/store` | ENV-DEV-WIN, ENV-VM-2404-AMD64 (as `nobody`) | Fresh migrate + idempotent rerun, WAL/FK verified on every pooled connection, CHECK/FK violations rejected, checksum tamper → `ErrChecksumMismatch`, newer schema → `ErrSchemaTooNew`, failed migration rolls back atomically, version-gap rejection, `VACUUM INTO` snapshot opens + integrity ok |
| T-UNIT-JOBS | Pass | `go test ./internal/jobs` | both | Full Safe Apply path journaled; invalid/terminal transitions rejected; CAS: 8 concurrent transitions → exactly 1 wins; cancellation forbidden after `Applying`; idempotency key scoped per actor; fence failure aborts the transition; open external step visible to reconciliation |
| T-UNIT-LOCK | Pass | `go test ./internal/locks` | both | Total order canonicalisation; all-or-nothing acquisition; monotonic fencing tokens; expired-lease takeover fences the stale worker (heartbeat → `ErrLeaseLost`, write → `ErrStaleFence`); a stale release does not drop the new holder; an expired lease fails fencing without takeover |
| T-SEC-AUDIT | Pass | `go test ./internal/audit` | both | Hash chain verifies; edit/delete/context tamper detected; sensitive context keys refused |
| T-UNIT-SSE | Pass | `go test ./internal/sse` | both | Last-Event-ID replay; live delivery; pruned-gap and ahead-of-server → `resync`; scope filtering (no out-of-scope leak); newline injection in event type rejected |
| T-UNIT-CFG | Pass | `go test ./internal/config` | both | Default bind `127.0.0.1:9999`; non-loopback, wildcard, hostname, and bad port rejected; unknown config fields rejected; http origin rejected |
| T-CONTRACT-ROUTES | Pass | `go test ./internal/httpapi -run TestRoutesMatchOpenAPI` | both | Registered routes == `api/openapi.json` paths, with identical permissions |
| T-CONTRACT-ERR | Pass | `go test ./internal/httpapi` | both | Error envelope shape; panic → 500 without paths or stack; request-ID echo/sanitisation |
| T-SEC-CSRF (baseline) | Pass | `go test ./internal/httpapi -run CrossSite` | both | Foreign Origin, `null` Origin, and Sec-Fetch-Site cross-site/same-site → 403 `csrf_failed`; configured public origin passes. Double-submit token is **Not Tested** (Phase 2 sessions) |
| T-SEC-HEADERS | Pass | `go test ./internal/httpapi -run SecurityHeaders` | both | CSP without `unsafe-inline`, frame-ancestors none, nosniff, XFO DENY, Referrer-Policy |
| T-SEC-BOOTSTRAP-AUTH | Pass | `go test ./internal/httpapi` | both | Proxied requests (XFF/Forwarded/X-Real-IP) and non-loopback peers → 401; anonymous health has no component detail |
| T-LINT-NOEXEC | Pass | `go test ./internal/httpapi -run NoExec` | ENV-DEV-WIN (source analysis) | Transitive module-internal import graph of `internal/httpapi` has no `os/exec` |
| T-CLI-BASIC | Pass | `go test ./cmd/ngm` | both | migrate/db check/audit verify; unimplemented roles exit non-zero; api refuses an unmigrated DB |
| T-UI-BUILD | Pass | `npm run build`, `npm test` (6 tests) | ENV-DEV-WIN | fa/en catalog parity incl. placeholders; dashboard renders API data, Unknown ≠ Healthy; RTL `dir`/`lang` switch; 401 → sign-in-required state; planned areas show explicit not-available state |
| T-UI-VISUAL (smoke) | Pass (manual review) | playwright-core + system Edge, `scratchpad/shot.cjs` | ENV-DEV-WIN | Screenshots en-desktop, fa-desktop (RTL), fa-mobile, en-dark jobs, fa-dark planned. No console errors except one favicon 404, since fixed. This is **not** the full Phase 6 visual-regression suite |
| T-BUILD-CROSS | Pass | `GOOS=linux GOARCH={amd64,arm64} go build ./cmd/ngm` | ENV-DEV-WIN | Both binaries built (`CGO_ENABLED=0`). The arm64 binary was **not executed** (no ARM64 environment) |
| T-SMOKE-VM | Pass | `scripts/remote/vm.cjs` runtime smoke | ENV-VM-2404-AMD64, kernel 6.8.0-146, run as `nobody` | api refuses before migrate; refuses `0.0.0.0` bind; `ss` shows only `127.0.0.1:9999`; public-IP connection refused; health/version OK; proxied → 401; cross-site POST → 403; UI served; graceful shutdown; nginx and UFW untouched; temp dir removed afterwards |
| T-SEC-CSRF (token), T-SEC-SESS, T-SEC-RBAC … | Not Tested | — | — | Phase 2 |
| T-COMPAT-* | Blocked | — | — | ARM64 and 22.04 environments unavailable (ADR-008) |

### Phase 2 run (2026-10-08). Reviewer: Claude Code (self-run; owner review pending)

Build under test: `0.2.0-dev` (fresh install), then upgraded in place through `0.2.1-dev` … `0.2.4-dev` on ENV-VM-2404-AMD64.

| Test ID | Result | Command | Env | Evidence |
|---|---|---|---|---|
| T-SEC-VAULT | Pass | `go test ./internal/vault` (+ `-count=20` stress) | ENV-DEV-WIN, VM as `nobody` | Round trip; no plaintext in rows; tamper detection for ciphertext/wrapped-DEK/DEK-nonce bit flips, nonce swap, scope rebinding, version change and row swap (AAD binding); wrong KEK → `ErrKeyMismatch`/`ErrTampered`; missing KEK → `ErrKeyMissing`; world-readable key file rejected (Linux); KEK files never overwritten |
| T-REL-ROTATE (unit) | Pass | `TestRotationIsResumable` | both | Simulated crash after 50/120 rewraps: mixed state still decrypts; resumed rotation completes; old key removed → all secrets decrypt; retire + verify. **Not yet** crash-injected on a live service (Phase 4) |
| T-SEC-AUTH | Pass | `go test ./internal/auth` | both | Argon2id PHC hashing with random salt, malformed-hash rejection; password policy; RFC 6238 test vectors (6/6); ±1-step skew; replay rejection; bootstrap only once; stage gating (mfa_enroll / pending_mfa / active); session rotation on every stage change; idle (30 m) and absolute (12 h) expiry; logout; idempotent pending enrolment |
| T-SEC-THROTTLE | Pass | `TestThrottlingAndNoEnumeration`, `TestLoginThrottlingHTTP` | both | 5 failures per user → 429 even with the correct password; per-IP bucket (20); unknown user returns the same error as a wrong password (dummy Argon2 for timing); failed MFA codes count toward the lockout |
| T-SEC-RBAC | Pass | `TestRBACEscalationAndOwnerProtection`, `TestScopedGrant`, `TestRBACMatrixAndTokens` | both | Viewer/Operator/Owner HTTP matrix (10 cases); Admin cannot create or modify an Owner (`privilege_escalation`); reserved permissions are refused in custom roles; last-owner protection; built-in roles immutable; scoped grants do not leak to global; privilege change revokes the target's sessions |
| T-SEC-MFA / step-up | Pass | `TestStageGatingCSRFAndStepUp` | both | Resource access in mfa_enroll → 401 `mfa_required`; stale step-up → 403 `step_up_required`; fresh TOTP → allowed |
| T-SEC-CSRF (token) | Pass | same | both | Cookie sessions: missing/forged `X-CSRF-Token` → 403 `csrf_failed`; bearer tokens exempt |
| T-CONTRACT-ETAG | Pass | same | both | Missing If-Match → 428; stale → 412; current → 200 |
| T-SEC-TOKEN | Pass | `TestAPITokens`, HTTP matrix | both | Token stored only as SHA-256; scope limits (`/jobs` 200, `/users` 403); step-up scopes refused; expiry and revocation enforced; listing never returns plaintext |
| T-SEC-AUDIT (wiring) | Pass | `TestAuditTrailRecordsAuthEvents` | both | setup/login success+failure/MFA enrolment recorded; chain verifies; no password material in audit context |
| T-SEC-SETUP | Pass | `TestSetupOwnerGuards` | both | Wrong bootstrap token → 403; proxied request → 403 even with the right token; token single-use; local read-only bootstrap access ends once a user exists |
| T-SEC-CSP-NONCE | Pass | `TestIndexCarriesPerResponseStyleNonce` + browser | both | index.html carries a per-response nonce for `style-src` only; `script-src 'self'` unchanged; no `unsafe-inline`; browser shows 0 CSP violations when Radix dialogs open (previously blocked) |
| T-IPC-* | Pass | `go test ./internal/ipc ./internal/helper` | both | Malformed, oversized and unknown-field requests → `bad_request`; unknown ops → `unknown_op`; per-UID policy; args refused for no-arg ops; ExecRunner refuses non-allowlisted binaries |
| T-IPC-PEERCRED | Pass | `ipc.test -test.run TestRealPeerCred` as `nobody` | ENV-VM-2404-AMD64 | Kernel SO_PEERCRED UID/PID delivered to the handler |
| T-INST-FRESH | Pass | `ngm install` (as root) | ENV-VM-2404-AMD64 | Preflight 15 checks (fail-closed design); installed `nginx` + `libnginx-mod-stream` 1.24.0-2ubuntu7.18 from the Ubuntu archive; created groups ngm/ngm-vault/ngm-helper and users ngm-api/ops/monitor/logs; dirs/modes as designed; KEK root:ngm-vault 0440; migrations 1–2; units enabled; smoke test OK; bootstrap token printed once |
| T-INST-REPAIR / upgrade | Pass | `ngm install` re-run with 0.2.1…0.2.4-dev | same | Idempotent: no user/group/KEK/config regeneration; new immutable release dir + atomic `current` switch; previous releases kept; data and audit chain preserved; setgid on /var/lib/ngm and /var/log/ngm after fix |
| T-INST-SYSD | Pass | `systemctl`, `ps`, `systemd-analyze security` | same | api runs as ngm-api, ops as ngm-ops, helper as root; exposure scores api 3.1 OK, ops 3.1 OK, helper 6.3 MEDIUM (helper hardening to be tightened as its operations become fixed) |
| T-SEC-PRIVSEP | Pass | `setpriv` probes | same | ngm-api → helper socket EACCES; nobody with ngm-helper group → `forbidden` (peer-UID policy); ngm-ops → ping OK, `exec` → `unknown_op`; KEK unreadable by nobody and ngm-ops; DB unreadable by nobody; denials logged in the journal; API port refused from the public IP |
| T-MON-NGINX (observation) | Pass | `ngm status`, dashboard | same | Helper observation: installed, version 1.24.0, origin ubuntu, service active, stream module enabled, ssl_preread, listeners 0.0.0.0:80/[::]:80. ngm-monitor is not implemented, so overall health is honestly **Unknown** |
| T-CLI-* | Pass | `ngm status`, `ngm doctor`, `ngm admin reset`, `ngm audit verify` | same | doctor exit 0 with 19 checks; admin reset forces password change + MFA re-enrolment + session revocation |
| T-E2E-WIZARD (steps 1–2) | Pass | `scratchpad/e2e_ui.cjs` (Edge via SSH tunnel) | dev host → VM | fa UI: preflight report, owner creation, QR + TOTP enrolment, dashboard, user creation (step-up satisfied), audit chain check in UI, token creation + use, wrong-password message, re-login with TOTP; en/dark/mobile screenshots |
| T-E2E-RECOVERY | Pass ×3 | `scratchpad/e2e_ui2.cjs` | same | After `ngm admin reset`: sign-in → forced re-enrolment → dashboard; no CSP errors; mobile drawer; no horizontal overflow at 390 px on dashboard/users/audit (two layout bugs found and fixed) |
| T-E2E-WIZARD (steps 3–7) | Not Tested | — | — | Depends on Phase 3/5 features |
| T-LIFE-VERIFY | Not Tested | — | — | Signature verification is Phase 7; installer prints an explicit warning |
| T-COMPAT-* | Blocked | — | — | Only 24.04 AMD64 available. The arm64 binary cross-compiles but was not executed |

### Phase 3 run (2026-10-08). Reviewer: Claude Code (self-run; owner review pending)

Builds: `0.3.0-dev` (upgrade from 0.2.4-dev; migration 3 with automatic pre-migration snapshot) through `0.3.3-dev` on ENV-VM-2404-AMD64.
Test backends: `cmd/ngm-testkit` (HTTP echo A/B, WebSocket echo, TCP echo, a TLS echo backend with its own certificate), run as `nobody` on loopback.

| Test ID | Result | Command | Env | Evidence |
|---|---|---|---|---|
| T-UNIT-COMPILER | Pass | `go test ./internal/gateway` | both | Fixture compiles all listener kinds; deterministic hash; HTTP/2 syntax by Nginx version (1.24: `listen … http2`; ≥1.25.1: `http2 on`); Nginx 1.18 without `ssl_reject_handshake` refuses to compile without a default certificate; 20 conflict/safety cases rejected (duplicate host+path, overlapping wildcards, HTTP+stream on one port, two TCP routes, Host/path on passthrough or raw TCP, cert SAN/expiry, link-local/metadata backend, API-port backend, SSH-port listener, internal address, mixed pool transports, fallback with SNI, terminate as fallback, passthrough+terminate on the same SNI, transport mismatch, redirect injection, website before Phase 5, missing stream module); ALPN split (h2 passthrough + terminate on one SNI) allowed |
| T-UNIT-SIM | Pass | `TestSimulation`, `TestSimulatorMatchesCompiledOrder` | both | 14 cases incl. exact vs wildcard Host, longest prefix with boundary, unknown host, TCP, terminate, Host≠SNI → 421, passthrough, ALPN precedence, no SNI and ECH → fallback, no listener; simulator rule order equals the generated map order |
| T-NGINX-SYNTAX | Pass | dumped fixture → `nginx -t -c` | VM, nginx 1.24.0-2ubuntu7.18 | Real Nginx accepts the generated http + stream config (shared-443 map/regex, PROXY hops, terminate hop, reject hop, IPv6 stream) |
| T-UNIT-GWSTORE | Pass | `go test ./internal/gwstore` | both | CRUD with revisions, in-use protection, duplicate bind, self-signed + import, key only in vault, key/cert mismatch and expired cert rejected |
| T-DEP-SM / T-DEP-ROLLBACK (unit) | Pass | `go test ./internal/deploy` | both | Happy-path step trail; no changes → Blocked; validation blocks before any helper call; verification failure → RolledBack with previous generation restored; `nginx -t` failure and reload failure → RolledBack; failed compensation → RecoveryRequired + incident; port conflict and distro default site (consent) → Blocked; staged generations of blocked jobs marked failed; rollback re-stages a garbage-collected generation; crash reconciliation (applied / not applied / ambiguous) |
| T-HELPER-NGINX | Pass | `helper.test` (Linux) | VM as `nobody` | Hooks created only if absent or owned; foreign hook never overwritten; hooks rejected by `nginx -t` removed; generations immutable; traversal in generation id, file and key names rejected; keys 0600; pointer reverted on `nginx -t` failure (no reload) and on reload failure; CAS guard; GC keeps current; mutating ops require a valid lease fence |
| T-CONTRACT (43 paths) | Pass | `TestRoutesMatchOpenAPI`, `TestGatewayHTTPFlow` | both | CRUD, validation + preview (no keys), simulation, 202 deploy with Idempotency-Key replay, 422 on invalid model, 409 in use, 412 stale, viewer read-only (403 on write/deploy) |
| T-LINT-NOEXEC | Pass | `TestNoExecInAPIDependencyGraph` | dev | Caught `httpapi → deploy → helper (os/exec)`; fixed with `internal/deployspec` |
| **T-E2E-GATEWAY** | **Pass 26/26** | `scratchpad/e2e_gw.cjs` | dev host → VM + internet | See detail below |
| T-E2E-CRASH | Pass | `scratchpad/crash_test.cjs` + `ngm-crash-watch` | VM | SIGKILL of `ngm-ops` 0 s / 50 ms / 300 ms after the helper swapped the generation pointer: after systemd restart the job resumed via `reconcile_verify` → Succeeded; NGM Active == Nginx current in every case; traffic served throughout |
| T-UI-GATEWAY | Pass | `npm test` (15) + `scratchpad/e2e_ui3.cjs` | dev host → VM | Listeners, Routes, Backends, Certificates, Deployments render (fa); Route Builder 5 steps; Simulation Lab on the active model shows passthrough for x.domain; generated-config preview; 0 console/CSP errors; no horizontal overflow at 390 px on 6 pages |

T-E2E-GATEWAY detail (real traffic through Nginx 1.24 on the VM):
- Safe Apply trail `validate → impact → stage → preflight → apply → nginx.activate → verify → succeeded`. Without consent, the Ubuntu default `:80` site blocked the first apply (verified in run 1). With consent, NGM disabled only the distro symlink and recorded it for restore.
- HTTP: pool round robin (A×2, B×2), longest prefix `/api/` → B, wildcard `*.domain` → 308, unknown Host → 444, IPv6 `[::]:80` listener.
- Shared 443 (`stream_tls_front`): TLS termination → HTTP (X-Forwarded-Proto https); Host≠SNI → 421; TLS passthrough where the backend's own certificate, the original SNI and ALPN `h2` reach the backend; no SNI and unknown SNI → closed.
- TCP stream echo; WebSocket upgrade with 3 round trips.
- From the internet (real DNS): HTTP reaches the backend with the real client IP; HTTPS through shared 443 reaches the backend with the real client IP via PROXY protocol across the internal termination hop.
- Simulation (active model) vs observed traffic: 9/9 identical outcomes.
- Reload while a WebSocket was open: 12/12 round trips continued over 6 s; deploy Succeeded.
- Apply with an unbindable address: `nginx -t` failed, pointer reverted, job RolledBack, traffic still served.
- Rollback to generation 1: Succeeded; Nginx current = generation 1.
- Ownership: only NGM-marked hook files were added; `dpkg --verify nginx-common` is clean (nginx.conf unmodified).

Bugs found by these tests and fixed: Host≠SNI answered 444 instead of the simulated 421; client IP lost across the internal hop (kernel source 127.0.0.1); probes failed on reject-only vhosts (probe now answered at server level with a per-generation secret token); staged generations of blocked jobs looked deployable; IPv6 binds displayed without brackets.

Not covered yet: HTTPS backends (`proxy_ssl_verify`) end-to-end against a real TLS backend; WebSocket over terminated TLS; backend PROXY-protocol passthrough; active health checks (Phase 4); ARM64 / 22.04 (Blocked).

### Phase 4 run (2026-10-08). Reviewer: Claude Code (self-run; owner review pending)

Builds: `0.4.0-dev` through `0.4.3-dev` on ENV-VM-2404-AMD64 (upgrade in place, no data loss). Live harness: `scripts/e2e/e2e_p4.cjs`
(+ `scripts/e2e/rotkill.sh`, `scripts/e2e/killpoint.sh` on the VM). Linux unit binaries ran under `setpriv --reuid=nobody`.
UFW safety during tests: before every live UFW change an outer, NGM-independent `systemd-run --on-active=900 ufw --force disable` timer was armed;
SSH reachability was re-checked with fresh connections; UFW was returned to its original state (inactive) after the tests.

| Test ID | Result | Command | Env | Evidence |
|---|---|---|---|---|
| T-UNIT (helper, deploy, backup, monitor) | Pass | `go test ./...`; `*.test` on VM | dev + VM | firewall plan/revert, SSH-deny refusal, foreign-rule detection; firewall coordinator (confirmed enable, unconfirmed → revert, safe change, SSH deny blocked); backup format (round trip, cross-host rekey with a different KEK, wrong passphrase, bit flip, truncation, trailing data, header tamper, traversal entry, chunking); retention (keeps newest N + pre_* for 30 days), scheduler (one job per window, suppressed when recent), same-second archive names; monitor SSRF guard + anti-flap; open incident blocks same-family jobs; helper crash during activation (after swap → Succeeded, before swap → RolledBack, swapped-but-unverified → compensated, helper gone → RecoveryRequired); supervised reconcile (adopt, restore, unverified adopt changes nothing) |
| T-CONTRACT | Pass | `TestRoutesMatchOpenAPI`, `TestBackupHTTPFlow`, `TestRecoveryHTTPFlow` | dev | backup/recovery/firewall routes documented; passphrase never in settings/audit; 409 no_passphrase; tampered archive → 422; resolve refused without evidence (409 no_evidence) and under drift (409 active_drift) |
| T-UI-OPS | Pass | `npm test` (22) | dev | Firewall (observed state, foreign rules, no claim without evidence, read-only user), Backups (local-only warning, passphrase gate, download link), Recovery (open incidents, drift → reconcile instead of manual resolve), backend health column; in-app confirm dialog replaced `window.confirm` |
| T-MON-HEALTH | Pass 6/6 | `e2e_p4.cjs monitor` | VM | ngm-monitor runs as its own user; real backends healthy (3–4 ms); killed backend → down after 10 s (2 failures); system health `backends` = degraded; 169.254.169.254 endpoint never probed (blocked, reported Unknown) |
| T-FW-OWN / T-FW-SSH | Pass 12/12 | `e2e_p4.cjs firewall` | VM (live UFW) | rules from listeners; enable waits in Verifying with journaled deadline + armed systemd watchdog; fresh SSH works while active; confirm → Succeeded, watchdog disarmed; dev host → VM:80 through UFW; unconfirmed deny rule reverted after 107 s; ngm-ops SIGKILLed mid-wait → reconcile reverted in 9 s; unmanaged `8443/tcp` rule untouched throughout; no reset/flush |
| T-FW-DEADMAN | Pass 3/3 | `e2e_p4.cjs deadman` | VM | UFW enabled, then `ngm-ops` stopped and kept down: the transient systemd timer alone disabled UFW after ~120 s; job → RolledBack when ops returned; fresh SSH OK |
| T-BAK-* / T-BAK-RESTORE | Pass 16/16 (×3 builds) | `e2e_p4.cjs backup` | VM | passphrase absent from DB/WAL/journal; job → archive `ngm-ops:ngm 640` `NGMBAK1`; download sha256 = record; server verify; no plaintext SQLite/PEM in archive; wrong passphrase → refused, live DB hash unchanged; preview changes nothing; restore in 5 s with services healthy and data plane 200; old sessions 401; post-backup change gone; audit chain + integrity + vault OK; pre_restore archive + previous DB kept; CLI backup |
| T-BAK-XHOST | Partial | unit `TestRoundTripAndCrossHostRekey` | dev + VM | Rekey onto a vault with a different KEK verified in unit tests and the restore path ran live on the same host; a true second host is **Blocked** (one VM) |
| T-REL-ROTATE | Pass | `e2e_p4.cjs vault`, `rotkill.sh` | VM | rotate → retiring/active, services up; SIGKILL by PID right after the new key file appeared → resume succeeds; retire v1; TOTP sign-in + TLS-key deploy after rotation. Interruption inside the rewrap window could not be hit live (3 secrets rewrap in ms): unit `TestRotationIsResumable` only |
| T-E2E-CRASH (Phase 4) | Pass | `e2e_p4.cjs crash,killpoint,drift` | VM | ngm-api SIGKILL → back in 3 s, data plane 200; ngm-helper SIGKILL exactly during `nginx -t` (×3) → `nginx.activate(failed) > uncertain_verify > compensate > rolled_back`, previous generation verified, no drift; SIGKILL during `systemctl reload` (×2) → `uncertain_verify > succeeded`; real drift left by an earlier run reconciled with `adopt` (probe-verified), drift cleared, next deploy Succeeded |

Bugs found by these tests and fixed:
1. **Helper crash during activation became RecoveryRequired and left drift**, and the rollback path claimed "the current one stays active" without evidence. Now the coordinator waits for the helper, reads the live pointer and proves the outcome with probes (ADR-024).
2. **A recovery incident could be resolved by hand while the data plane differed from the record**, leaving a dead end (every apply/rollback Blocked by drift). Resolution now requires fresh pointer evidence and no drift; a supervised, probe-verified `deploy.reconcile` (adopt/restore) was added (ADR-025).
3. **Interrupted `ngm vault rotate` left a `root:root` key**, and after resume ngm-api/ngm-ops crash-looped (Nginx kept serving). Rotation now re-asserts `root:ngm-vault 0440` on every key and checks that services stay up; `ngm doctor` reports `vault_perms` (it ran as root and could not see the problem).
4. **Two archives in the same second collided** (`O_EXCL`), so the second backup failed; names now carry milliseconds.
5. Harness bug: `pkill -f 'ngm vault rotate'` matched its own shell, so the first "interrupted rotation" result was not real evidence; it was discarded and redone by PID.

Not covered yet: true cross-host restore (second VM); KEK rotation killed inside the rewrap window (live); a scheduled backup firing on the VM (the scheduler is unit-tested; the minimum interval is 1 h); UFW IPv6 rule behaviour checked separately; ARM64 / 22.04 (Blocked).

### Phase 5 run (2026-10-08). Reviewer: Claude Code (self-run; owner review pending)
Build: 0.6.5-dev on the test VM (Ubuntu 24.04 AMD64). Go unit tests all pass; web 26/26 at the time.

| Test | Result | Command / evidence | Env | Notes |
|---|---|---|---|---|
| T-UNIT-DOMAIN, T-MON-DNS | Pass | `go test ./internal/domains ./internal/dnsq`; `e2e_p5.cjs dns` (7/7) | dev + VM | Real wire-format DNS queries against public resolvers; A/AAAA/CNAME/CAA/NS/TXT, TTL-aware rechecks, CAA policy evaluation |
| T-E2E-ACME | Pass | `e2e_p5.cjs acme` (5/5), `renew` (4/4) | VM | Let's Encrypt **staging**: HTTP-01 through Nginx (`/var/www/ngm/acme`), CAA + self-check before contacting the CA, issue → deploy; renew → new key version; rollback restages the old key |
| T-E2E-CF | Not run live | `go test ./internal/cloudflare` (fake API server) | dev | No Cloudflare token available; only unit evidence (plan hash, managed-marker/adopt-only edits) |
| T-SEC-ZIP | Pass | `go test ./internal/sitezip` | dev | traversal, absolute paths, symlinks, devices, ratio/size bombs, MIME/extension allowlist |
| T-WEB-TPL, T-WEB-EDIT, T-WEB-I18N | Pass | `go test ./internal/sitebuild`; `e2e_p5_site.cjs` | dev + VM | 6 templates, deterministic builds (same content → same hash), fa RTL/en LTR, hreflang/canonical/sitemap, relative links work under a sub-path mount |
| T-SEC-PREVIEW | Pass | `e2e_p5_site.cjs` | VM | HMAC-signed 30-min preview link, `CSP: sandbox` (opaque origin), no session cookie needed or accepted |
| T-WEB-PUB | Pass | `e2e_p5_site.cjs` (15/15) | VM | publish = copy + atomic per-site pointer swap, no reload; verified over HTTP through Nginx; rollback = re-publish an older version |

Bugs found and fixed: shared key file across certificate generations (now key versions); ACME challenge 404 (`/etc/nginx/ngm` is 0700 → public tree `/var/www/ngm`); ACME 403 (helper UMask 0077 → explicit 0644); `alias`+`try_files` mis-resolution; domain arrays dropped by `omitempty`; lock CHECK lacked `dns-provider` (migration 0005); preview job invalid state transition; Go regexp repeat limit; sandboxed iframe could not send SameSite=Strict cookies (→ signed links); absolute links broke sub-path mounts.

### Phase 6 run (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Build: 0.6.7-dev on the test VM. Go unit tests all pass; web 27/27; `npm run build` OK.

| Test | Result | Command / evidence | Env | Notes |
|---|---|---|---|---|
| T-LOG-*, T-LOG-ROTATE, T-SEC-LOGLEAK, T-UI-LOGS (API) | Pass | `e2e_p6.cjs logs` (10/10) | VM | JSONL access/stream/error + app logs indexed; real logrotate with late writes to `.1` drained; no query strings or bearer tokens in source or index; filters/FTS; CSV export; `ngm logs reindex` rebuilds from sources |
| T-LOG-DISK | Partial | unit `internal/app` disk guard | dev | low-disk pause is unit-tested only; never deletes DB/certs/backups by construction (only the derived index is pruned) |
| T-MON-SYS | Pass | `e2e_p6b.cjs` mon-metrics | VM | real /proc + statfs sample from ngm-monitor, freshness flag, history |
| T-MON-* (alerts) | Pass | `e2e_p6b.cjs` alert-* (5 checks) | VM | endpoint on a closed port → `backend_down` fires within the monitor interval; one open alert per rule+subject; ack → acknowledged; deleting the endpoint auto-resolves it |
| T-MON-NOTIFY | Partial | `e2e_p6b.cjs` notify-* ; unit `TestSSRFGuardAndRateLimit`, `TestCheckWebhookURLRejectsInternal` | dev + VM | SSRF guard rejects loopback/private/link-local/metadata/plain-http at creation and again at dial time; a real Telegram API call with an invalid token fails with 401, is recorded and scheduled for retry, the token is never echoed or stored in plaintext. **Successful delivery not tested** (no real bot token / webhook receiver) |
| T-PERF-TUNE | Pass | `e2e_p6b.cjs` perf-* | VM | out-of-range override → 400; override → Safe Apply deploy → `keepalive_timeout 71s` rendered in the active generation, `nginx -t` OK; revert → removed |
| T-TOPO-* | Pass | `e2e_p6b.cjs` topo-* ; unit `internal/topology` | VM | desired and active graphs (25 nodes/28 edges, 8 kinds); impact of removing a pool lists the routes that lose their only destination |
| T-UI-CMDK, T-UI pages | Pass (unit) | `npm test` | dev | Help page, Ctrl+K palette (navigation only), performance table |
| T-UI-VISUAL | Not run | — | — | no visual regression screenshots yet |

Bugs found by these tests and fixed:
1. **Every deploy failed after the log layout change**: the helper runs with `RestrictSUIDSGID=yes`, so `chmod` with the setgid bit is refused by seccomp (EPERM). The helper now only repairs permission bits when they differ; the installer (outside the sandbox) sets setgid.
2. **Webhook targets pointing at literal private addresses were accepted at creation** (they were blocked only at dial time). Creation now rejects them too.
3. Linux build broke: `Metrics.CPUs` used but not declared.
4. Harness bugs (not product): endpoint delete without If-Match; perf check grepped retained old generations instead of `current/`.

### Phase 7 run (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Releases 0.7.0-dev … 0.7.4-dev were built with `scripts/release.sh` and signed with the development key `dev-2026a` (private key in the git-ignored `.local/`). VM: Ubuntu 24.04 AMD64. Go unit tests all pass (dev host, plus `lifecycle.test` and `release.test` as `nobody` on the VM). Web 27/27.

| Test | Result | Command / evidence | Env | Notes |
|---|---|---|---|---|
| T-LIFE-SIGN | Pass (amd64 executed; arm64 built + signed only) | unit `internal/release` (tamper, foreign key, missing sig, dev key on stable, key-id mismatch, unknown field); `ngm release verify` | dev + VM | |
| T-LIFE-VERIFY | Pass | `e2e_p7.cjs bootstrap` | VM | `install.sh` rejects a changed manifest byte, a changed binary byte, a foreign signature, a missing signature and a wrong `NGM_EXPECT_KEY`, with the current release unchanged each time. The binary refuses `install --release-dir` for a manifest that is not its own. Signed upgrade 0.6.7 → 0.7.0 through `install.sh` works, and the manifest is kept with the release |
| T-LIFE-UPD | Pass | `e2e_p7.cjs update,rollback`; `upd_status.cjs` | VM | check → approval required → apply 0.7.0 → 0.7.1 (snapshot + encrypted pre_update backup + health). Correctly signed but broken release (arm64 binary labelled amd64) → `exec format error` → automatic rollback to 0.7.1, services healthy. Downgrade refused. `update rollback --yes` 0.7.3 → 0.7.1. Dogfood: 0.7.1 → 0.7.4 with `ngm update`; API reports the state |
| T-INST-REPAIR | Pass | `e2e_p7.cjs repair` | VM | `/var/lib/ngm` chmod 0777 and a deleted unit file are restored (2770, unit back, service active). A modified release binary is refused ("modified after installation") and never executed |
| T-LIFE-APT | Partial | `e2e_p7.cjs nginx`; unit `TestAptSimulationAndModuleSet` | VM | Real `apt-get update` and simulation: packages up to date, baseline accepted. Drift: a baseline older than the installed package → `nginx_external_change` alert → `ngm nginx reconcile` → resolved. **A real package upgrade was not exercised** (nothing to upgrade on the VM) |
| T-LIFE-UNINST | Partial | unit (dev + VM as nobody); `e2e_p7.cjs uninstall` | VM | Live: the plans for keep-data and purge are correct (dependency warnings, kept/removed lists), and purge without the typed confirmation is refused. Execution is verified only in a temp root with a fake runner: owned hooks only, a same-named operator file kept, third-party conf/unit kept, default site restored, `nginx -t` failure restores everything, only NGM UFW rules deleted (highest number first), the only SSH rule kept. **Not executed live** (destructive; needs the owner's authorization) |
| T-CLI-* (config test, rollback) | Pass | `e2e_p7.cjs cli` | VM | `ngm config test` → nginx -t plus the active generation; `ngm rollback` queues a Safe Apply rollback job, ngm-ops activates the previous generation; redeploy restores the desired config |

Bugs found and fixed: `pre-update` trigger kind violated the backup CHECK constraint (now `pre_update`); `release verify` did not understand the installed layout (`ngm`); an installer warning lost text to shell backtick expansion. Harness: the 0.6.7 binary predates `--release-dir`, so the self-check test moved to the update step.

### Phase 8 run (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Final build: **0.8.0-rc.1** (development channel, signed with `dev-2026a`), installed on the VM with `ngm update apply` (0.7.6-dev → 0.8.0-rc.1, healthy). VM: Ubuntu 24.04 AMD64, 2 vCPU, 3.8 GiB. Go unit tests all pass (vet + gofmt clean); web 27/27.

**Full regression on the final code line (one host):**

| Suite | Result | Build |
|---|---|---|
| Gateway / routing matrix (`e2e_p3_gateway.cjs`, now in the repo) | 26/26 | 0.7.6-dev |
| DNS + ACME staging + renew/rollback (`e2e_p5.cjs`) | 14/14 | 0.7.6-dev |
| Websites (`e2e_p5_site.cjs`) | 15/15 | 0.7.6-dev |
| Logs (`e2e_p6.cjs logs`) | 10/10 | 0.7.6-dev |
| Monitoring, alerts, notify, perf, topology (`e2e_p6b.cjs`) | 15/15 | 0.7.6-dev |
| Reliability: monitor, firewall, dead-man, backup, crash, drift (`e2e_p4.cjs`) | 38/39, see bug 1; after the fix crash+drift 6/6 (incl. `crash-recovered` → Succeeded) | 0.7.6-dev / 0.8.0-rc.1 |
| Lifecycle (`e2e_p7.cjs`, all steps) | all pass (Phase 7) | 0.7.0–0.7.4 |

**Security (§18.11):**

| Test | Result | Evidence | Notes |
|---|---|---|---|
| T-SEC-SWEEP | Pass | `e2e_p8_sec.cjs` (7/7) | Every OpenAPI operation (136): unauthenticated → 401/403 (public: health, setup status, setup owner (403 once initialised), login, signed preview). 68 cookie-session mutations with a wrong CSRF token → 403, and with a foreign Origin → 403. A token scoped to `gateway.read` is denied every other permission and allowed every `gateway.read` route. A revoked token → 401 |
| T-SEC-DEPS | Partial | `npm audit` (prod + dev): 0 vulnerabilities | govulncheck/OSV were unreachable from the dev network and the VM (HTTP 403). A CI `security` job was added but has never run (O-29) |

**UI QA (§18.15)** with `ui_qa.cjs`: headless Chrome against the live VM, all 22 navigation pages × desktop/tablet/mobile × en/fa = 132 views.
- **Final run:** no horizontal overflow, correct `dir`/`lang`, no console or page errors, no untranslated message keys. axe-core WCAG 2.x A/AA on 44 desktop views: **0 violations**.
- **First run found 7 issues, all fixed:**
  - status-text contrast (ok/warn/bad tokens darkened);
  - revoked tokens drawn at 60% opacity;
  - `role="img"` on the interactive topology SVG;
  - an un-underlined inline link;
  - the PageHeader action row not wrapping on mobile (Logs overflowed 7–10 px);
  - Logs filter-form overflow;
  - raw job kinds on Deployments (now translated labels).
- Screenshots are in `dist/qa/` (not committed).

**Benchmarks (§18.13)** with `scripts/bench` (closed loop, 20 s each). These are **same-host loopback** numbers: the load generator shares the 2 vCPUs with Nginx, NGM and the backends, so they are a floor for this VM, not a capacity SLA.

| Path | Concurrency | ops/s | p50 | p99 | errors |
|---|---|---|---|---|---|
| Backend direct (baseline, HTTP keep-alive) | 32 | 13 202 | 2.0 ms | 8.7 ms | 0 |
| Nginx HTTP reverse proxy via NGM route (keep-alive) | 32 | 6 365 | 4.2 ms | 16.8 ms | 0 |
| Nginx static website (NGM published site) | 32 | 3 367 | 8.5 ms | 27.1 ms | 0 |
| TCP stream :7000 (connect + 64 B echo + close) | 16 | 3 945 | 3.6 ms | 11.2 ms | 0 |
| TCP backend direct (baseline) | 16 | 8 599 | 1.6 ms | 5.7 ms | 0 |
| TLS passthrough :443 SNI routing (full handshake per op) | 16 | 560 | 26.5 ms | 70.8 ms | 0 |
| NGM API `/system/health` | 8 | 3 764 | 1.4 ms | 13.8 ms | 0 |

Resources: NGM's five services use 122–176 MB RSS in total (ngm-api 13.9 MB cgroup memory, limit 384 MiB); Nginx workers use 27 MB.

Bugs found and fixed in Phase 8:
1. **A deployment started while ngm-helper was restarting failed immediately** (`helper unreachable: connection refused`, inside the 2 s RestartSec window). The IPC client now retries only the dial, for up to 15 s. A retry cannot repeat an operation because nothing has been sent yet (unit `TestCallWaitsForRestartingHelper`).
2. UI accessibility and layout defects (listed above).
3. Harness defects:
   - `api()` silently overwrote explicit CSRF/Origin headers, so the first CSRF run was invalid and sent 7 real mutations with dummy bodies. Their effects were checked: 2 `no_changes` jobs, firewall unchanged, extra backups only.
   - DELETE bodies were sent without Content-Length, so on reused connections Go correctly answered `400 Bad Request` to the leftover bytes. This was a client artifact.

### Post-RC run (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Builds 0.8.0-rc.2 … rc.4, each installed with `ngm update apply` (all healthy).

| Test | Result | Evidence | Notes |
|---|---|---|---|
| T-ROUTE-HTTPS-BACKEND (O-8) | Pass | `e2e_p8_routing.cjs` (6/6) | Self-signed HTTPS backend (`ngm-testkit https-echo`). With `tls_verify:false` → 200 through Nginx (`proxy_ssl_verify off`, `proxy_ssl_name` set). With `tls_verify:true` → 502, and Nginx logs "certificate verify failed" (`proxy_ssl_verify on`, depth 4). Validation rejects an invalid TLS server name ("S") before deploy |
| T-ROUTE-WSS (O-8) | Pass | same | WebSocket over TLS terminated by Nginx on shared 443 (SNI route `panel`): upgrade + 3 round trips on one connection |
| T-LIFE-GC (O-28) | Pass | unit (Linux, VM) + live | Update rc.2 → rc.3 removed 29 old releases and kept the current one, the rollback target and the newest 3 |
| T-PERF-ADAPT (O-21) | Pass (unit + live run) | `go test ./internal/monitor ./internal/perf`; services healthy on rc.4 | Each round, the monitor takes its concurrency from the resolved profile (`perf.Current`), and the log indexer refreshes its batch size every 20 s |
| T-UI dashboard/alerts (O-22, O-7 partial) | Pass | `ui_qa.cjs` on `/`, `/monitoring`, `/ops/deployments` (18 views, 0 axe violations) | Dashboard open-alerts card. Alert headlines translated by rule code in Persian (raw server text kept as an LTR detail). Job kinds translated on the dashboard and on Deployments |

PROXY protocol to backends is not a MASTER_SPEC requirement. It is used only internally for shared 443, which is covered by the gateway E2E. It is therefore removed from O-8.

### Post-RC run 2 (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Builds rc.5 … rc.8, each installed with `ngm update apply`. Full regression with `sh scripts/e2e/run_all.sh` on rc.7 (`dist/e2e/summary_rc7.txt`); new and changed suites were re-run on rc.8.

| Suite / test | Result | Notes |
|---|---|---|
| Gateway 26/26, HTTPS-backend + WSS 6/6, DNS + ACME 14/14, websites 15/15, logs 10/10, ops 15/15, reliability (monitor, firewall, dead-man, backup, vault, crash, drift) 42/42, origin 10/10, disk 4/4, UI QA 3/3 | Pass (rc.7) | |
| Lifecycle 12/12 (cli step re-run on rc.8) | Pass | The rc.7 failure was a test defect: after `ngm rollback` an identical generation correctly makes the redeploy `no_changes`; the test now accepts that |
| Security sweep 7/7 | Pass (rc.8) | On rc.7 the two new `/gateway/fallback` operations returned 404, because OpenAPI was ahead of the deployed build |
| T-SEC-HELPER-HARDEN (O-5) | Pass | `systemd-analyze security ngm-helper`: 6.3 MEDIUM → 3.6 OK. Every helper operation passed in the full run |
| T-SETUP-WIZARD (O-3), T-MGMT-ORIGIN (O-6) | Pass | `e2e_p8_origin.cjs` 10/10: the setup steps reflect evidence; `ngm admin set-origin`; panel through Nginx TLS; Secure/HttpOnly cookies; foreign Origin → 403; reverting to tunnel-only works. Only an exact-host TLS route may target the API (unit `TestManagementOnly`) |
| T-VAULT-ROTATE-REWRAP (O-13) | Pass | 20 005 secrets; rotation SIGKILLed at 650/20 005 rewrapped; resume completed; 20 000/20 000 decrypt (`scripts/vaultfill`) |
| T-BAK-SCHEDULE (O-14) | Pass | Scheduled archive observed 2026-10-09 08:17:53Z |
| T-FW-IPV6 (O-15) | Pass | NGM rules mirrored in `user6.rules` (SSH guard included). Purge now also handles an inactive UFW (`ufw show added`) and keeps the only SSH rule (unit test) |
| T-LOG-DISK live (O-31) | Pass | `e2e_p8_disk.cjs` 4/4: full tmpfs index → pause + alert, source logs keep growing, DB/backups/keys untouched, resumes and catches up |
| T-UI typed confirm (O-11) | Pass | unit `confirm.test.tsx`. A flaky SSL-page test was fixed (timeout) and passed 4/4 runs |
| **T-DECOY (ADR-036)** | Pass | `e2e_p9_decoy.cjs` 13/13 on rc.8, detailed below |

**T-DECOY details:**
- **Baseline (no fallback):** unknown Host, unknown SNI and no SNI are closed or rejected (`000`), which is the fingerprint being removed.
- **With fallback (site `decoy-site` + certificate):** HTTP by IP, unknown Host, HTTPS by IP without SNI and unknown SNI on shared 443 all return `200 text/html`. A random path returns a normal 404. The certificate is presented. `Server: nginx` carries no version, and no NGM headers appear.
- **Still intact:** real HTTP routes, TLS passthrough by SNI and ACME challenges.
- **Simulator and guards:** the simulator reports `fallback_site`. Validation rejects a half-configured fallback. The website is protected from deletion while it serves as the fallback.

Operations note: large uploads to the VM sometimes stop half-way (`.part` file). The binary is now gzip-compressed for transfer. Integrity still comes from the signed manifest.

### Dependency vulnerability scan (O-29), 2026-10-09
vuln.go.dev, OSV and proxy.golang.org (toolchains) return 403 from this network. Instead, the Go vulnerability database was fetched from GitHub (golang/vulndb `data/osv`, 4 613 records) and matched offline by `scripts/vulncheck`. The tool checks the modules linked into the binary and the Go version against the version ranges, and marks a finding when an affected package is in `go list -deps ./cmd/ngm`. It has no symbol-level reachability, so it can only over-report.

| Build | Result |
|---|---|
| rc.8 (go1.26.5, x/crypto v0.54.0) | **25 findings**, 19 in imported stdlib packages (net/http HTTP/2 DoS and desync, crypto/tls, net/url, encoding/asn1, net/textproto …). Fixed in go1.26.9 |
| rc.9 (toolchain go1.26.9 via `GOPROXY=https://goproxy.cn` (verified against the checksum DB), x/crypto v0.57.0, x/sys v0.48.0) | **Clean**. Only GO-2026-5932 remains (`x/crypto/openpgp` is unmaintained); NGM does not import that package |

`npm audit` (production and dev): 0 vulnerabilities. The CI `security` job (govulncheck) remains the authoritative check once a remote exists.

### Post-RC run 3 (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
Bugs found by the full regression and fixed:
1. **The fallback certificate was missing from the generation when no route used it** (rc.8/rc.9). `nginx -t` failed ("cannot load certificate") and Safe Apply rolled back as designed, so there was no outage, but no deploy could succeed. The fallback certificate is now always emitted (unit assertion plus E2E `fallback-unused-cert`).
2. **Pre-release ordering was lexical**: rc.10 was refused as "older than rc.9". `CompareVersions` now follows semver precedence (numeric identifiers compared numerically). The next build had to be 0.8.1-rc.1 because the installed rc.9 still used the old ordering.
3. Test design: the gateway suite checks the baseline behaviour (444 / closed / 421), so it now disables the fallback first; the decoy suite tests and re-enables it.

Other changes in 0.8.1-rc.1:
- A template site's root `/` is now the default-locale home page (canonical `/<locale>/`), not a meta-refresh language list. This matters for a realistic fallback.
- All 75 gateway validation codes have Persian headlines; the original text is kept as LTR detail.
- Toolchain go1.26.9.
- Decoy E2E: 14/14 on 0.8.1-rc.1.

**Final full regression on 0.8.1-rc.1** (`sh scripts/e2e/run_all.sh`, `dist/e2e/summary_0.8.1-rc.1.txt`): **13/13 suites, 204/204 checks, 0 FAIL**. Gateway 26, HTTPS backend + WSS 6, DNS + ACME 14, websites 15, logs 10, monitoring/alerts/perf/topology 15, reliability 42, lifecycle 12, security sweep 7, management origin 10, disk pressure 4, fallback website 14, UI QA 3 (132 views, 0 axe violations).

### CI matrix and published panel (2026-10-09). Reviewer: Claude Code (self-run; owner review pending)
GitHub Actions on the private repository `Saj-1992/ngm`, run 37966521477 (commit 50dfb01): **all jobs green**.

| Job | Hosts | Evidence |
|---|---|---|
| web | ubuntu-24.04 | npm ci, build, 28 unit tests |
| go | ubuntu-22.04, ubuntu-24.04, **ubuntu-24.04-arm** | go vet, gofmt, `go test ./...` (native arm64 execution) |
| security | ubuntu-24.04 | **govulncheck clean** (go1.26.9, x/crypto v0.57.0), npm audit (high+) clean |
| install | **ubuntu-22.04, ubuntu-24.04, ubuntu-22.04-arm, ubuntu-24.04-arm** (machine identity in the job log) | fresh install (installs nginx + stream module, users, units, vault key, migrations); health 200; `ngm status/doctor/config test`; **uninstall --keep-data** (program gone, data kept, third-party nginx file kept, nginx healthy); reinstall with `--adopt-existing-nginx`; encrypted backup; **uninstall --purge** with typed confirmation (all NGM paths, accounts and groups gone; third-party files and nginx intact); fresh install with a **new KEK**, then **restore** of the backup (cross-host rekey); doctor shows vault PASS, audit chain verified |

Bugs found by CI and fixed:
1. An IPC client race: a rejected peer saw EPIPE instead of the structured error.
2. On a fresh host nginx stayed stopped after installation. Health correctly said "down". The installer now starts nginx (after `nginx -t`) before NGM services take their first observation.

Published Control Center: `https://example.test` serves NGM with a production Let's Encrypt certificate (route `ngm-panel-public`, `scripts/ops/publish_panel.cjs` 9/9; verified from the owner's network: HTTP 200, certificate verified).

Incident during the full E2E: the ACME test attached its staging certificate to the apex TLS route, which became the published panel, so the panel served an untrusted certificate until it was repaired. Fixed:
- the ACME test restores the original certificate;
- `publish_panel.cjs` repairs the certificate and destination and runs at the end of every full run;
- the gateway TLS tests use `gw.<domain>`.

The client-IP check now goes through the server's public address, because the owner's network filters TLS to sub-names. Full regression on 0.8.1-rc.3: all suites green (gateway re-run 26/26, UI QA with 0 axe violations).

Not run on the owner's VM: a live uninstall and restore. Claude Code's safety classifier blocked it. These paths are evidenced on the four disposable CI hosts instead.

**Coordinated Nginx upgrade with real package changes (O-27):** CI job `nginx-upgrade`, run 37968037037 (3a4bb7d), passed. The job installs the release-day packages from the Ubuntu snapshot archive (`nginx`, `nginx-common`, `libnginx-mod-stream` 1.24.0-2ubuntu7), installs NGM, then runs `ngm nginx upgrade`: the plan lists the upgrades, and `--yes` moves all three packages together to 1.24.0-2ubuntu7.18. After that, `nginx -t` passes, the baseline is accepted with stream=true and ssl_preread=true, and NGM health is 200.

## Post-RC run 4 (2026-10-12, 0.8.1-rc.7 → rc.9)
- Full run on rc.6 (started 2026-10-11): p3 26/26, p8_routing 6/6, p5_dns_acme 14/14, p5_site 15/15, p6_logs 10/10, p6b_ops 15/15, p4_reliability 42/42 — then the SSH link from the dev host timed out (`Timed out while waiting for handshake`) and the remaining suites did not run. The VM was healthy. The interrupted run left the decoy disabled (the gateway suite turns it off as a baseline), so the apex on 443 reset connections until `p9_decoy` and `publish_panel` re-enabled it; both then passed 14/14 and the apex returned 200 on 80/443/9443.
- `p7_lifecycle` was skipped by the owner's decision (it prints uninstall plans only, but the environment's safety check blocked running it unattended). It is NOT counted as passed.
- Four branded starter sites (corporate, blog, portfolio, app_showcase; fa+en): unit tests (`TestBrandedStartersAreComplete`, `TestStarterMediaIsDeterministicPNG`, `TestBrandedStarterSitesBuildWithTheirArtwork`, `TestFormatDate`), live seed (`scripts/ops/seed_sites.cjs`) and live HTTPS probes: pages in both locales 200, media 200, custom 404, robots, sitemap, og:image absolute, `Server: nginx` without version.
- Defects found by the live run and fixed: page cover images missing from builds (`usedMedia`), non-transitive page ordering.
- Known limitations: Cloudflare features (DNS-01, discovery, subdomain publish) are covered by unit tests with fakes only; no token was available. Starter brands, addresses and phone numbers are fictional placeholders.
- rc.9 live re-run (p7 skipped): p5_site 15/15, p9_decoy 14/14, p10_features 17/17, p8_security 7/7, p8_origin 8/8. After the suites, `publish_panel.cjs` re-enabled the decoy (it ends every full run for this reason): apex 80/443/9443 → "مشاوران ویلای نور" 200; panel on the secret path 200.

## Final release 0.8.1 (2026-10-12)
- Server updated rc.9 → 0.8.1 with `ngm update apply` (signature + SHA-256 verified); panel and decoy 200 afterwards.
- GitHub Release `v0.8.1` published with six signed assets; from the VM, `releases/latest/download/{install.sh,SHA256SUMS,ngm-linux-amd64}` download and `sha256sum -c` → OK. CI on d5a1a00: success.
- Owner-authorised VM cleanup applied (`scripts/ops/cleanup_vm.cjs --apply`, `vaultfill clean`): 16 test/old websites, 3 test certificates, test routes/pools/backends/listeners, 35 test tokens, user operator1, 50 old backups (newest 5 kept), 20,000 test vault secrets. Kept: panel (web/front443/panel443, ngm-panel-public, ngm-panel, panel-prod), the four branded sites, owner accounts. `publish_panel.cjs` afterwards: 14/14.
- Not done: install matrix of the 0.8.1 one-liner on a fresh host (needs a clean machine; CI install job covers it per commit); retiring old KEK versions and old `pre-restore` DB copies (left as is).
