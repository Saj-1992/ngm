# IMPLEMENTATION_PLAN

Phases are dependency-ordered (MASTER_SPEC §17). Each phase builds vertical slices:
schema → service → authz → worker/helper → API → UI → tests → docs.

## Package map
| Path | Responsibility |
|---|---|
| `cmd/ngm` | Single binary. Roles: `api`, `ops`, `monitor`, `log-indexer`, `helper`. CLI: `status`, `doctor`, `config test`, `rollback`, `backup create`, `restore`, `admin reset`, `update`, `migrate` |
| `internal/buildinfo` | Version, commit, schema/API version |
| `internal/config` | `/etc/ngm/ngm.toml`-equivalent config (JSON), defaults, validation, canonical paths |
| `internal/store` | SQLite open (WAL, FK, busy_timeout), migrations w/ checksums, integrity check, online backup |
| `internal/ids` | Sortable random IDs (ULID-like) |
| `internal/jobs` | Persistent job journal, steps, state machine transitions, idempotency |
| `internal/locks` | Durable lease locks, total order, fencing tokens, heartbeat |
| `internal/audit` | Hash-chained audit events |
| `internal/apierr` | Standard error envelope |
| `internal/httpapi` | Router, middleware (request ID, security headers, CSRF/origin, authn/z, ETag, idempotency), handlers |
| `internal/sse` | Event log in SQLite + broker w/ replay, scope filtering, heartbeat |
| `internal/auth` | Users, Argon2id, sessions, TOTP, API tokens, throttling, RBAC |
| `internal/vault` | Envelope encryption, KEK versions, rotation journal |
| `internal/ipc` | Unix-socket typed RPC, SO_PEERCRED, schemas |
| `internal/helper` | Allowlisted privileged ops (fd-relative FS, nginx -t/reload, ufw owned rules, apt) |
| `internal/gateway` | Model (listeners/routes/matches/backends/pools), validator, precedence, compiler → nginx config, simulator |
| `internal/deploy` | Coordinator: Safe Apply state machine, staging, verify, compensation, reconciliation, drift |
| `internal/firewall` | UFW ownership ledger, SSH safety, watchdog |
| `internal/monitor` | Health probes (SSRF-safe dialer), DNS, SSL expiry, system metrics, alerts |
| `internal/dns`, `internal/acme`, `internal/certs` | Domains, Cloudflare client, ACME, cert validation |
| `internal/websites` | ZIP hardening, templates, builder, publish/rollback |
| `internal/backup` | Snapshot, portable encryption, restore |
| `internal/logs` | JSONL writers, indexer, retention |
| `internal/topology` | Graph projection, impact analyzer |
| `internal/perf` | Profiles, guarded tuning |
| `internal/update` | Signed manifests, update/rollback |
| `web/` | Control Center SPA (embedded into binary at build) |
| `api/openapi.json` | Contract |
| `deploy/` | systemd units, installer, nginx base templates |
| `scripts/remote/` | Dev helpers to run integration tests on the test VM |

## Phase 1: Foundation (current)
Deliverables:
- Repository, docs, Go module, Makefile, and CI workflow (GitHub Actions: go vet/test, cross-build, web build/test).
- Config + canonical paths. API defaults to `127.0.0.1:9999`.
- SQLite store: WAL, foreign keys, busy timeout, checksummed migrations, integrity check, online backup (`VACUUM INTO`).
- Initial schema for all §7.1 entity families, with core columns (id, created_at, updated_at, revision, scope).
- Job journal with steps, plus idempotency keys.
- Durable lock leases with fencing tokens and a total order.
- Audit hash chain.
- `/api/v1` skeleton: error envelope, request IDs, security headers, origin/CSRF guard, health/version/jobs endpoints, ETag/If-Match helpers, OpenAPI document, and a contract test that checks routes match the spec.
- SSE event table + broker with Last-Event-ID replay.
- UI shell: Vite + React + TS + Tailwind + Radix, fa/en with RTL/LTR, light/dark/system themes, primary nav, and a status page fed by real `/api/v1/system/health`.
- Static check: request handler packages must not import `os/exec`.

Exit evidence: `go build` for linux/amd64 and linux/arm64, `go test ./...`, migration tests (fresh and re-run with checksum tamper detection), contract tests, baseline security tests (headers, CSRF/origin rejection, error non-leakage), and `npm run build` + tests.

## Phase 2: Security & Installer
Covers auth (Argon2id, sessions, TOTP, throttling, step-up), RBAC, API tokens, vault, helper IPC with peercred,
systemd units and users, installer preflight (Nginx origin, apt locks, ports, disk, and SSH/UFW read-only),
the 7-step wizard, and CLI bootstrap. Evidence: authz matrix tests, IPC tests on Linux, and a fresh install on the test VM.

## Phase 3: Gateway & Routing
Covers the model, validator, precedence, compiler (http + stream + shared-443), simulator, staged generation, `nginx -t`,
reload/verify/rollback, and the Route Builder. Evidence: real E2E on the VM with HTTP, HTTPS, WS, TCP echo, passthrough,
shared 443, and no-SNI cases.

## Phase 4: Reliability
Covers lock fencing under crash, supervised recovery, UFW ownership with an SSH watchdog, health checks, backup/restore
(cross-host), and KEK rotation. Evidence: crash injection, SSH-safety scenarios, and cross-host restore (needs a second VM).

## Phase 5: Domains & Websites
Covers the DNS registry/monitoring, Cloudflare (needs a scoped token from the owner), ACME staging, templates/editor/publish,
and ZIP hardening.

## Phase 6: Operations & UX
Covers logs/indexer, SSE live tail, alerts, performance profiles/tuning, topology, full premium UI, and visual QA.

## Phase 7: Lifecycle
Covers signed artifacts (Ed25519), the verifying installer, update/rollback, APT coordination, repair, and uninstall.

## Phase 8: Integration & Release
Covers the full 4-platform matrix, security audit, benchmarks, docs, and RC classification.

## External dependencies needing the owner
| Need | Phase | Why |
|---|---|---|
| Ubuntu 22.04 AMD64, 22.04 ARM64, 24.04 ARM64 test VMs | 2–8 | Compatibility gate (§2, §18.1). Only a 24.04 AMD64 VM is available now |
| Second VM (any supported) | 4 | Cross-host restore |
| Cloudflare scoped API token (Zone.DNS edit, one zone) | 5 | DNS integration E2E |
| Release signing key custody decision | 7 | Pinned publisher key |
| Telegram bot token/chat (optional) | 6 | Notification E2E |
