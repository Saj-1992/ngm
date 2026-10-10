Partially closed (alert headlines and job kinds translated; health details, job error text and validation messages still English)
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-PLAT-001 | P0 | Ubuntu 22.04/24.04 × AMD64/ARM64 support matrix with real evidence | §2 | 8 | T-COMPAT-* | Verified — CI install + go jobs on 22.04/24.04 × amd64/arm64 (50dfb01); full E2E on the 24.04 AMD64 VM |
| NGM-PLAT-002 | P1 | Install distro Nginx OSS + libnginx-mod-stream; probe versions/modules/directives | §2 | 2 | T-INST-FRESH | Verified — CI fresh install on 4 OS/arch + VM probe (TEST_REPORT Phases 2/3, CI) |
| NGM-PLAT-003 | P0 | Pre-existing Nginx inspection; refuse unsafe adoption | §2,§16 | 2 | T-INST-FRESH (absent case) | Implemented (classification unit-tested; 'absent' on 4 CI hosts and the VM; customised path via --adopt-existing-nginx in CI reinstall) |
| NGM-PLAT-004 | P1 | Host detection: IPv4/IPv6, bind conflicts, low disk, apt locks, systemd, cgroup | §2 | 2 | T-INST-FRESH | Implemented (bind-conflict detection limited to the API port + 80/443 report) |
| NGM-PLAT-005 | P0 | Data plane independent: API/worker failure never stops Nginx | §2,§3 | 4 | T-REL-005 | Verified — crash suite: ngm-api/helper SIGKILL while Nginx keeps serving 200 (Phase 4, full runs) |
| NGM-ARCH-001 | P1 | Go modular monolith, role modes api/ops/monitor/log-indexer/helper | §3 | 1 | T-INST-SYSD | Verified — five roles on the VM and on 4 CI hosts |
| NGM-ARCH-002 | P0 | Unix socket IPC with peer credentials, strict perms, schema-validated | §3,§11 | 2 | T-IPC-*, T-IPC-PEERCRED, T-SEC-PRIVSEP | Verified — unit + live (TEST_REPORT Phases 1–4) |
| NGM-ARCH-003 | P0 | Helper: typed allowlist only, no exec/env/arbitrary paths, fd-relative FS | §3,§11 | 2 | T-IPC-*, T-SEC-PRIVSEP | Verified — typed allowlisted helper ops; IPC tests (incl. the CI-found EPIPE race); live suites |
| NGM-ARCH-004 | P1 | systemd units, dedicated users, cgroup budgets, hardening | §3 | 2 | T-INST-SYSD | Verified — helper sandbox: systemd-analyze 3.6 OK; all helper ops re-tested |
| NGM-ARCH-005 | P0 | Startup reconciliation; shutdown checkpoint; no nginx restart on API start | §3,§8.3 | 4 | T-REL-* | Verified — startup reconciliation (resolveUncertain, drift reconcile) in crash/kill-point/drift suites; nginx never restarted by API start |
| NGM-ARCH-006 | P0 | API binds 127.0.0.1:9999 by default; bootstrap local/SSH-tunnel only | §3,§11 | 1 | T-UNIT-CFG, T-SMOKE-VM, T-SEC-SETUP | Verified — unit + live |
| NGM-FS-001 | P1 | Canonical filesystem layout | §4 | 1-2 | T-INST-FRESH | Verified — installer layout on the VM and 4 CI hosts |
| NGM-FS-002 | P0 | Ownership ledger for every generated file/UFW rule; never overwrite non-NGM | §4 | 3 | T-HELPER-NGINX | Verified — owned markers/ledger; purge on 4 CI hosts removes only NGM paths, third-party kept |
| NGM-FS-003 | P1 | Drift detection on generated config | §4,§7.2 | 4 | T-DEP-DRIFT | Verified — drift suite: detect, reconcile (adopt/restore), drift guard (Phase 4, full runs) |

## Routing & gateway
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-ROUTE-001 | P0 | HTTP reverse proxy | §5 | 3 | T-E2E-GATEWAY | Verified — gateway E2E 26/26 on rc.3 + CI matrix |
| NGM-ROUTE-002 | P0 | HTTPS termination w/ cert-key validation | §5 | 3 | T-E2E-GATEWAY | Verified — gateway E2E |
| NGM-ROUTE-003 | P0 | TCP stream proxy (no Host/path match) | §5 | 3 | T-E2E-GATEWAY | Verified — gateway E2E |
| NGM-ROUTE-004 | P0 | TLS passthrough via ssl_preread | §5 | 3 | T-E2E-GATEWAY | Verified — gateway E2E |
| NGM-ROUTE-005 | P0 | Shared public 443 stream front dispatch | §5.1 | 3 | T-E2E-GATEWAY | Verified — gateway E2E |
| NGM-ROUTE-006 | P1 | WebSocket bidirectional | §5 | 3 | T-E2E-GATEWAY | Verified — WebSocket over HTTP and over terminated TLS (e2e_p8_routing) |
| NGM-ROUTE-007 | P0 | ECH / absent SNI explicit fallback or reject | §5,§5.1 | 3 | T-E2E-GATEWAY, T-UNIT-SIM | Verified — gateway E2E |
| NGM-ROUTE-008 | P1 | HTTP/2 capability probe; reject HTTP/3/UDP assumptions | §5 | 3 | T-UNIT-COMPILER | Implemented (version-gated HTTP/2; no HTTP/3 by design) |
| NGM-ROUTE-009 | P1 | IPv6 listeners + family conflict detection | §5 | 3 | T-E2E-GATEWAY | Verified — gateway E2E + simulation vs observed |
| NGM-ROUTE-010 | P0 | Deterministic precedence; reject ties/overlaps/unreachable/ambiguous defaults | §5.1 | 3 | T-UNIT-COMPILER | Verified — gateway E2E |
| NGM-ROUTE-011 | P1 | Route Simulation Lab vs observed traffic | §5.2 | 3 | T-UNIT-SIM, T-E2E-GATEWAY (9/9) | Verified — gateway E2E |
| NGM-ROUTE-012 | P1 | Backend endpoint/pool schema | §5.2 | 3 | T-UNIT-GWSTORE | Verified — gateway E2E |
| NGM-ROUTE-013 | P1 | Go active health checks, SSRF-safe, rate-limited | §5.2 | 4 | T-MON-HEALTH | Verified — monitor suite: SSRF guard, anti-flap, freshness → Unknown |
| NGM-ROUTE-014 | P1 | Failover for new connections only; documented limits | §5.2 | 3 | T-UNIT-COMPILER | Verified — passive max_fails + backup; active health live |
| NGM-ROUTE-015 | P1 | Generated read-only config preview | §15 | 3 | T-CONTRACT, T-UI-GATEWAY | Verified — gateway E2E |

## Domains, DNS, TLS, websites
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-DNS-001 | P1 | Domain registry, uniqueness, dependency checks | §6.1 | 5 | T-UNIT-DOMAIN | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-DNS-002 | P1 | A/AAAA/CNAME/CAA/NS/TXT monitoring, TTL-aware | §6.1 | 5 | T-MON-DNS | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-DNS-003 | P1 | Optional Cloudflare DNS w/ preview/confirm/audit, preserve external | §6.1 | 5 | T-E2E-CF | Implemented (unit tests against a fake API only; live Cloudflare not tested, see O-18) |
| NGM-CERT-001 | P1 | ACME issuance/renewal (staging-tested) | §6.2 | 5 | T-E2E-ACME | Verified — live E2E (TEST_REPORT Phase 5: Let's Encrypt staging issue + renew + rollback) + CI matrix 50dfb01 |
| NGM-CERT-002 | P0 | Private key protection & Nginx-readable deployment | §6.2 | 5 | T-HELPER-NGINX, T-UNIT-GWSTORE | Verified — vault + 0600 deployed keys; ACME production cert live for the published panel |
| NGM-CERT-003 | P0 | Validate SAN/key/chain/expiry before activation; keep known-good | §6.2 | 5 | T-UNIT-GWSTORE, T-UNIT-COMPILER | Verified — validation unit tests + ACME staging and production live |
| NGM-WEB-001 | P0 | ZIP upload hardening (ratio/traversal/symlink/device/MIME) | §6.3 | 5 | T-SEC-ZIP | Verified — ZIP hardening unit tests + websites E2E |
| NGM-WEB-002 | P1 | Six structured templates | §6.3 | 5 | T-WEB-TPL | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-WEB-003 | P1 | Block editor, media, SEO, drafts | §6.3 | 5 | T-WEB-EDIT | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-WEB-004 | P0 | Preview on isolated origin | §6.3 | 5 | T-SEC-PREVIEW | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-WEB-005 | P1 | Path locales, hreflang, canonical, sitemap, RTL/LTR | §6.3 | 5 | T-WEB-I18N | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |
| NGM-WEB-006 | P1 | Publish job, atomic pointer switch, rollback | §6.3 | 5 | T-WEB-PUB | Verified — live E2E (TEST_REPORT Phase 5) + CI matrix 50dfb01 |

## Data, deployment, recovery
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-DATA-001 | P1 | Core entities with ID/timestamps/revision/scope | §7.1 | 1 | T-UNIT-MIG | Verified — migrations 0001–0006 with checksums; schema tests; restore on 4 CI hosts |
| NGM-DATA-002 | P0 | SQLite WAL, FKs, integrity check, online backup, busy handling | §7.1 | 1 | T-UNIT-DB | Verified — unit + live |
| NGM-DATA-003 | P0 | ETag/If-Match optimistic concurrency + Idempotency-Key | §7.2,§12 | 1 | T-CONTRACT-* | Verified — If-Match/412-428 and Idempotency-Key used by every E2E mutation; contract tests |
| NGM-DATA-004 | P0 | Desired/Active/Runtime separation | §7.2 | 3 | T-DEP-SM, T-E2E-GATEWAY | Verified — unit + live |
| NGM-DATA-005 | P0 | Checksummed versioned migrations, fail closed | §7.3 | 1 | T-UNIT-MIG | Verified — upgrades 0.6.x → 0.8.1-rc.3 with migrations through `ngm update` on the VM; restore with migrate on CI |
| NGM-DEP-001 | P0 | Safe Apply state machine | §8.1 | 3 | T-DEP-SM, T-E2E-GATEWAY | Verified — Safe Apply state machine in every deploy; full runs |
| NGM-DEP-002 | P0 | Durable lock leases, total order, fencing tokens | §8.2 | 1/4 | T-UNIT-LOCK | Verified — helper-side fencing; crash injection live |
| NGM-DEP-003 | P0 | Staged generation + nginx -t on prospective include graph | §8.1 | 3 | T-HELPER-NGINX, T-NGINX-SYNTAX | Verified — nginx -t with automatic revert; failed-apply rollback live |
| NGM-DEP-004 | P0 | Verify after reload; compensate & verify on failure | §8.1 | 3 | T-DEP-ROLLBACK, T-E2E-GATEWAY | Verified — unit + live |
| NGM-DEP-005 | P0 | Supervised recovery + Recovery Center | §8.3 | 4 | T-E2E-CRASH | Verified — Recovery Center API/UI, evidence-based resolution; kill-point suite |
| NGM-DEP-006 | P1 | Persistent job journal with steps | §8 | 1 | T-UNIT-JOBS | Verified — unit + live |

## Firewall, vault, backups
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-FW-001 | P0 | NGM-owned UFW rules ledger, preserve external rules | §9 | 4 | T-FW-OWN | Verified — owned ledger, foreign rule preserved; IPv6 rules mirrored |
| NGM-FW-002 | P0 | SSH path protection, dry-run, confirm, watchdog rollback | §9 | 4 | T-FW-SSH | Verified — SSH guard, dead-man revert, watchdog (firewall + dead-man suites) |
| NGM-FW-003 | P0 | Never flush/reset UFW | §9 | 4 | T-FW-OWN | Verified — no reset/flush path; purge keeps the only SSH rule (unit) and foreign rules (CI) |
| NGM-VAULT-001 | P0 | Envelope encryption AES-256-GCM w/ AAD binding, versioned KEK | §10.1 | 2 | T-SEC-VAULT | Verified — unit + live |
| NGM-VAULT-002 | P0 | Argon2id passwords; API tokens as non-reversible hashes | §10.1 | 2 | T-SEC-AUTH, T-SEC-TOKEN | Verified — unit + live |
| NGM-VAULT-003 | P0 | TOTP seeds encrypted; no secret read-back | §10.1 | 2 | T-SEC-VAULT, T-SEC-AUTH | Verified — unit + live |
| NGM-VAULT-004 | P1 | Journaled crash-resumable KEK rotation | §10.1 | 4 | T-REL-ROTATE (unit) | Verified — rotation killed after key creation and mid-rewrap (650/20005), resume verified 20000/20000 |
| NGM-BAK-001 | P1 | Local encrypted backups + manual download, scheduler, retention | §10.2 | 4 | T-BAK-* | Verified — archives, verify, scheduler observed firing (08:17Z), retention |
| NGM-BAK-002 | P0 | Portable Argon2id+AEAD backup, recoverable on new host, rekey | §10.2 | 4 | T-BAK-XHOST | Verified — NGMBAK1 Argon2id + AES-GCM; cross-host restore with a new KEK on 4 CI hosts |
| NGM-BAK-003 | P0 | Restore preview/staged/verify; wrong pass/corrupt leaves Active | §10.2 | 4 | T-BAK-RESTORE | Verified — preview, safety backup, staged rekey/migrate/verify; wrong passphrase leaves state unchanged; CI restore |

## Security & access
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-SEC-001 | P1 | Seven-step first-run wizard | §11 | 2 | T-E2E-WIZARD | Verified — first-run wizard steps 1–7 evidence-based; management origin published live (e2e_p8_origin, publish_panel) |
| NGM-SEC-002 | P0 | Sessions: rotation, HttpOnly/SameSite/Secure, idle/absolute expiry | §11 | 2 | T-SEC-AUTH | Verified — unit + live |
| NGM-SEC-003 | P0 | CSRF, CSP, origin checks | §11 | 1-2 | T-SEC-CSRF, T-SEC-CSP-NONCE | Verified — unit + live |
| NGM-SEC-004 | P0 | Login throttling | §11 | 2 | T-SEC-THROTTLE | Verified — unit + live |
| NGM-SEC-005 | P0 | TOTP MFA + step-up for critical actions | §11 | 2 | T-SEC-MFA | Verified — unit + live |
| NGM-SEC-006 | P0 | RBAC Owner/Admin/Operator/Viewer + custom, scoped, deny-by-default | §11 | 2 | T-SEC-RBAC | Verified — RBAC sweep with a scoped token over all 136 operations |
| NGM-SEC-007 | P1 | Scoped API tokens | §11 | 2 | T-SEC-TOKEN | Verified — unit + live |
| NGM-SEC-008 | P0 | SSRF protection incl. DNS rebinding | §11 | 3-4 | T-SEC-SSRF | Verified — monitor SSRF guard; webhook guard at creation and dial time (DNS rebinding), unit + live |
| NGM-SEC-009 | P1 | Audit events (tamper-evident chain) | §11 | 1-2 | T-SEC-AUDIT | Verified — unit + live |
| NGM-SEC-010 | P0 | Security test suite (XSS/CSRF/SSRF/IDOR/traversal/ZIP/IPC/backup tamper) | §11,§18 | 8 | T-SEC-* | Implemented (sweep: authn/CSRF/Origin/RBAC on 136 ops; XSS-CSP, SSRF, traversal/ZIP, IPC, backup tamper tests; no dedicated cross-user IDOR test, no third-party pentest) |

## API, observability, topology, performance
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-API-001 | P1 | Versioned /api/v1 + OpenAPI contract validated | §12 | 1 | T-CONTRACT-ROUTES | Verified — contract test on every route; live sweep of all 136 operations |
| NGM-API-002 | P1 | Standard error schema, no leakage | §12 | 1 | T-CONTRACT-ERR | Verified — one error schema across handlers; contract tests; sweep observed no leakage |
| NGM-API-003 | P1 | Cursor pagination, validated filter/sort, per-user rate limits | §12 | 1-2 | T-CONTRACT-PAGE | Verified — cursor pagination; token-bucket limiter with 429 test (authflow_test) |
| NGM-API-004 | P1 | 202 + durable Job ID for long ops | §12 | 1 | T-CONTRACT-JOB | Verified — 202 + durable job id for every long operation; jobs survive restarts (crash suite) |
| NGM-API-005 | P1 | SSE: replay Last-Event-ID, scope authz, heartbeat, resync, backpressure | §12 | 1/6 | T-UNIT-SSE | Verified — SSE unit tests + live tail |
| NGM-API-006 | P0 | No direct system commands in handlers | §12 | 1 | T-LINT-NOEXEC | Verified — no-exec import-graph test |
| NGM-LOG-001 | P1 | Structured JSONL source logs, correlation | §13.1 | 6 | T-LOG-* | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-LOG-002 | P1 | Indexer with rotation/truncation checkpoints, rebuildable | §13.1 | 6 | T-LOG-ROTATE | Verified — live E2E (TEST_REPORT Phase 6: real logrotate) + CI matrix 50dfb01 |
| NGM-LOG-003 | P0 | No secrets/auth headers; query strings redacted | §13.1 | 6 | T-SEC-LOGLEAK | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-LOG-004 | P1 | Retention/quotas; low-disk never deletes DB/certs/backups | §13.1 | 6 | T-LOG-DISK | Verified — disk guard unit + live tmpfs-full test (e2e_p8_disk) |
| NGM-LOG-005 | P1 | Explorer, live tail SSE, export TXT/CSV/JSONL | §13.1 | 6 | T-UI-LOGS | Verified — live E2E (TEST_REPORT Phase 6; UI unit-level) + CI matrix 50dfb01 |
| NGM-MON-001 | P0 | Healthy/Degraded/Unknown/Disabled with freshness; Unknown≠Healthy | §13.2 | 4/6 | T-MON-* | Verified — live E2E (TEST_REPORT Phase 4/6) + CI matrix 50dfb01 |
| NGM-MON-002 | P1 | System metrics, queue, job failures, nginx version/module drift, log lag | §13.2 | 6 | T-MON-SYS | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-MON-003 | P1 | Telegram/webhook alerts w/ retry, rate-limit, no leaks | §13.2 | 6 | T-MON-NOTIFY | Implemented (retry/rate-limit/SSRF live; successful delivery untested, see O-19) |
| NGM-TOPO-001 | P1 | Read-only typed graph, desired/active/observed views | §13.3 | 6 | T-TOPO-* | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-TOPO-002 | P1 | Dependency impact analyzer blocks critical deps | §13.3 | 3 | T-UNIT-GWSTORE | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-PERF-001 | P1 | Profiles (provisional) w/ recommendation | §14 | 6 | T-PERF-* | Implemented (profiles provisional; benchmarks on one 2-vCPU VM only) |
| NGM-PERF-002 | P1 | Adaptive internal-only concurrency | §14 | 6 | T-PERF-ADAPT | Verified — adaptive monitor concurrency + log batch, unit + live run |
| NGM-PERF-003 | P1 | Guarded tuning allowlist, context-aware, Safe Apply | §14 | 6 | T-PERF-TUNE | Verified — live E2E (TEST_REPORT Phase 6) + CI matrix 50dfb01 |
| NGM-PERF-004 | P1 | Benchmarks; no fabricated capacity | §14,§18 | 8 | T-PERF-BENCH | Implemented (same-host loopback benchmarks on a 2-vCPU VM recorded in TEST_REPORT Phase 8; no capacity SLA claimed; profiles stay provisional) |

## UX & lifecycle
| ID | Pri | Requirement | Spec | Phase | Tests | Status |
|---|---|---|---|---|---|---|
| NGM-UX-001 | P1 | React/TS/Tailwind/Radix/Lucide, themes, tokens | §15 | 1 | T-UI-BUILD | Verified — React/TS/Tailwind/Radix/Lucide build + 28 tests in CI |
| NGM-UX-002 | P1 | Persian RTL + English LTR first-class; LTR islands for IPs/domains | §15 | 1/6 | T-UI-I18N, T-E2E-* | Verified — UI QA: 22 pages × 3 viewports × fa/en, dir/lang checks; LTR islands |
| NGM-UX-003 | P1 | Primary navigation structure | §15 | 1 | T-UI-NAV | Verified — permission-filtered navigation; UI QA |
| NGM-UX-004 | P1 | Evidence-based dashboard, no placeholders | §15 | 6 | T-UI-DASH | Verified — evidence-based dashboard with health, jobs, alerts and setup checklist |
| NGM-UX-005 | P1 | Route Builder wizard | §15 | 3/6 | T-UI-GATEWAY | Verified — route builder unit tests + UI QA |
| NGM-UX-006 | P1 | Loading/empty/error/denied/partial/unknown states everywhere | §15 | 6 | T-UI-STATES | Verified — UI QA all pages; denied states via RBAC sweep |
| NGM-UX-007 | P1 | Command palette (safe actions only) | §15 | 6 | T-UI-CMDK | Verified — command palette unit test + UI QA |
| NGM-UX-008 | P1 | Visual regression QA desktop/tablet/mobile × fa/en | §15 | 6 | T-UI-VISUAL | Implemented — 132 automated screenshots (desktop/tablet/mobile × fa/en) with overflow/dir/console checks (TEST_REPORT Phase 8); no pixel-diff baseline yet |
| NGM-UX-009 | P1 | WCAG 2.2 AA target, keyboard, reduced motion | §15 | 6 | T-UI-A11Y | Verified — axe-core WCAG 2.x A/AA 0 violations on 44 views (no manual screen-reader audit) |
| NGM-LIFE-001 | P0 | Signed artifacts & manifests, both arches | §16 | 7 | T-LIFE-SIGN | Implemented (Ed25519 manifests, both arches built and executed in CI; stable channel waits for the production key, O-24) |
| NGM-LIFE-002 | P0 | Installer verifies pinned publisher key; fail closed | §16 | 2/7 | T-LIFE-VERIFY | Verified — live E2E (TEST_REPORT Phase 7: install.sh + binary self-check reject every tamper case) + CI matrix 50dfb01 |
| NGM-LIFE-003 | P1 | Installer preflight | §16 | 2 | T-INST-FRESH | Verified — installer preflight on the VM and 4 CI hosts |
| NGM-LIFE-004 | P1 | Idempotent rerun/repair, smoke tests | §16 | 2/7 | T-INST-REPAIR | Verified — live E2E (TEST_REPORT Phase 7: repair restores modes/units, refuses a modified binary) + CI matrix 50dfb01 |
| NGM-LIFE-005 | P1 | CLI: status/doctor/config test/rollback/backup/restore/admin reset/update | §16 | 2-7 | T-CLI-* | Verified — live E2E (TEST_REPORT Phase 7: config test, rollback, update, repair, nginx, uninstall added to the earlier commands) + CI matrix 50dfb01 |
| NGM-LIFE-006 | P1 | Admin-approved signed updates + rollback compatibility | §16 | 7 | T-LIFE-UPD | Verified — live E2E (TEST_REPORT Phase 7: approval, snapshot, automatic rollback on a broken release, explicit rollback) + CI matrix 50dfb01 |
| NGM-LIFE-007 | P1 | Coordinated Nginx APT upgrade, drift reconciliation | §16 | 7 | T-LIFE-APT | Verified — real upgrade 1.24.0-2ubuntu7 → 7.18 by `ngm nginx upgrade` (CI nginx-upgrade 3a4bb7d) + drift detection/reconcile on the VM |
| NGM-LIFE-008 | P0 | Uninstall Keep Data / Purge, preserve third-party | §16 | 7 | T-LIFE-UNINST | Verified — keep-data, reinstall and purge executed on 4 CI hosts; plans and safeguards live on the VM |

## Phase status
| Phase | Status | Notes |
|---|---|---|
| 1 Foundation | Gate passed locally (CI not yet run on a remote) | Evidence in TEST_REPORT Phase 1 |
| 2 Security & Installer | Gate evidence recorded; open items: wizard steps 3–7 (later phases), installer signature verification (Phase 7), helper hardening | Evidence in TEST_REPORT Phase 2 |
| 3 Gateway & Routing | Gate evidence recorded (26/26 E2E, live crash injection); open: HTTPS-backend & WS-over-TLS E2E, ARM64/22.04 | Evidence in TEST_REPORT Phase 3 |
| 4 Reliability | Gate evidence recorded (monitor 6/6, firewall 12/12 + dead-man 3/3, backup/restore 16/16, rotation, exact-point crash injection, drift reconcile); 4 product bugs found and fixed | Evidence in TEST_REPORT Phase 4 |
| 5 Domains, TLS, Websites | Gate evidence recorded (DNS 7/7, ACME staging 5/5 + renew 4/4, websites 15/15); open: Cloudflare live (O-18) | Evidence in TEST_REPORT Phase 5 |
| 6 Ops UX | Gate evidence recorded (logs 10/10, monitoring/alerts/notify/perf/topology 15/15); open: O-19..O-22, visual QA (O-20) | Evidence in TEST_REPORT Phase 6 |
| 7 Lifecycle | Gate evidence recorded (bootstrap 7 checks, update 7/7, rollback/repair/nginx/uninstall/cli 14/14); open: O-24..O-28 | Evidence in TEST_REPORT Phase 7 |
| 8 Integration & Release | RC 0.8.1-rc.3 on the VM; CI matrix green (4 OS/arch fresh install, uninstall, cross-host restore, govulncheck); panel published at https://example.test. Stable still needs the production signing key (O-24) | Evidence in TEST_REPORT |

## Open items (consolidated; updated every phase)
| # | Item | Origin | Blocking | Status |
|---|---|---|---|---|
| O-1 | No Git commit yet; CI workflow never executed on a remote | P1 | Delivery gate | Closed (private repo Saj-1992/ngm; CI green on 50dfb01) |
| O-2 | Compatibility matrix: Ubuntu 22.04 AMD64/ARM64 and 24.04 ARM64 not available (arm64 binary built, never executed) | P1 | Stable release | Closed (CI install job: fresh install on 22.04/24.04 x amd64/arm64; go tests on arm64) |
| O-3 | First-run wizard steps 3–7 (management origin, HTTPS cert, default website, first route, verification) | P2 | NGM-SEC-001 | Closed (post-RC 2: steps 3–7 evidence-based; dashboard checklist with links; live 7/7 complete) |
| O-4 | Installer release-signature verification | P2 | NGM-LIFE-002 (P0) | Closed (Phase 7: install.sh + binary verification) |
| O-5 | ngm-helper systemd hardening score 6.3 MEDIUM | P2 | Security gate | Closed (post-RC 2: systemd-analyze exposure 6.3 MEDIUM → 3.6 OK; all helper operations re-tested) |
| O-6 | Management UI exposure over HTTPS through Nginx (public origin); currently SSH tunnel only | P2 | NGM-SEC-001 step 3 | Closed (post-RC 2: `ngm admin set-origin`; only an exact-host TLS route may reach the API; live 10/10) |
| O-7 | Server messages (health details, issue text) are English-only in the fa UI | P2 | NGM-UX-002 | Closed (alerts, job kinds, backend summary and all gateway validation codes translated; raw technical detail kept as LTR text) |
| O-8 | E2E not yet run for: HTTPS backends with proxy_ssl_verify, WebSocket over terminated TLS, backend PROXY-protocol passthrough | P3 | Routing gate | Closed (post-RC: HTTPS backend verify on/off + WSS; PROXY-to-backend not a spec requirement) |
| O-9 | Full dependency-impact graph analyzer (only in-use protection exists) | P3 | NGM-TOPO-002 | Closed (Phase 6 topology analyzer) |
| O-10 | Test state on the VM: routes on example.test, public TCP echo :7000, testkit backends, NGM firewall rules (desired; UFW left inactive), a test backup passphrase and archives, KEK versions v1–v12 (v1 retired) | P3 | — | Clean up on owner request |
| O-11 | `window.confirm` replaced by an accessible in-app dialog; typed confirmation for critical actions (purge, owner transfer) still missing | P3 | NGM-UX-006 | Closed (post-RC 2: typed confirmation for user/certificate/website deletion; purge typed in CLI) |
| O-12 | Cross-host restore never run on a real second host (unit test + same-host live restore only) | P0 evidence gap | NGM-BAK-002 | Closed (CI: backup → purge → fresh install with a new KEK → restore, on 4 hosts) |
| O-13 | KEK rotation killed inside the rewrap window not reproduced live (only after key creation) | P2 | NGM-VAULT-004 | Closed (post-RC 2: killed mid-rewrap with 650/20005 rewrapped; resume completed; 20000/20000 verified) |
| O-14 | Scheduled backup not observed firing on the VM (unit-tested; minimum interval 1 h) | P2 | NGM-BAK-001 | Closed (post-RC 2: scheduled archive observed 2026-10-09 08:17Z) |
| O-15 | UFW IPv6 rule behaviour not verified separately | P2 | NGM-FW-001 | Closed (post-RC 2: NGM rules mirrored in user6.rules incl. SSH guard; purge also handles inactive UFW) |
| O-16 | Old KEK files stay on disk after retire (by design, removed manually after a verified backup); no UI for rotation/retire (CLI only) | P3 | NGM-VAULT-004 | Open |
| O-17 | Restore is CLI-only (ADR-022); the UI only shows instructions | P3 | NGM-BAK-003 | By design (ADR-022/033: restore and update are root CLI actions) |
| O-18 | Cloudflare DNS never exercised against the real API (no token) | P1 evidence gap | NGM-DNS-003 | Blocked: needs a scoped token |
| O-19 | Telegram/webhook successful delivery never observed (only failure + retry path live) | P1 evidence gap | NGM-MON-003 | Blocked: needs a bot token or receiver |
| O-20 | Visual regression screenshots desktop/tablet/mobile × fa/en not produced | P1 | NGM-UX-008 | Closed (Phase 8 UI QA; pixel-diff baseline still absent) |
| O-21 | Adaptive internal concurrency is computed but not consumed by monitor/indexer | P2 | NGM-PERF-002 | Closed (post-RC) |
| O-22 | Dashboard has no active-alert summary | P3 | NGM-UX-004 | Closed (post-RC) |
| O-23 | VM SSH sees continuous brute-force (1,604 failures observed); root password login enabled — recommend key-only SSH | P1 (ops) | — | Owner decision |
| O-24 | Only a development signing key exists; stable/beta need an offline publisher key ceremony and its fingerprint published out of band | P0 (release) | NGM-LIFE-001 | Owner decision |
| O-25 | Signed bootstrap tested only as an upgrade from a local directory; fresh install on a clean host and HTTPS download path not run | P1 | NGM-LIFE-002 | Partially closed (fresh install on 4 clean CI hosts; signed bootstrap via install.sh tested as an upgrade on the VM; HTTPS download path still untested) |
| O-26 | Uninstall Keep Data / Purge never executed on a real host (plans live, execution unit-tested) | P1 evidence gap | NGM-LIFE-008 | Closed on disposable CI hosts (keep-data, reinstall, purge with typed confirmation); not run on the owner VM (tool permission) |
| O-27 | Coordinated Nginx upgrade never ran with actual package changes (VM up to date) | P2 | NGM-LIFE-007 | Closed (CI nginx-upgrade job: real package upgrade) |
| O-28 | Old releases are never garbage-collected under /opt/ngm/releases | P3 | NGM-LIFE-006 | Closed (post-RC: GC keeps current, previous, newest 3) |
| O-29 | Go dependency vulnerability scan (govulncheck/OSV) blocked from the development network; npm audit = 0. CI `security` job added but never run | P1 (security gate) | Release | Closed (offline OSV scan via GitHub vulndb: go1.26.5 stdlib findings fixed by toolchain go1.26.9 + x/crypto v0.57.0; rescan clean; CI govulncheck still to run with O-1) |
| O-30 | No requirement is marked `Verified`: the compatibility matrix (O-2) and CI (O-1) are prerequisites of the Definition of Done | P0 (release) | All | Closed (requirements with live VM evidence + CI matrix marked Verified; the rest stay Implemented with their named gaps) |
| O-31 | Disk-full scenario (§18.6) not exercised live; only the log-indexer disk guard is unit-tested | P2 | NGM-LOG-004 | Closed (post-RC 2: tmpfs-full index → pause + alert, sources kept, nothing deleted, resumes and catches up) |
| O-32 | Fallback website (ADR-036) is live with the template placeholder site ("My site"); the owner should publish realistic content and use a certificate for a real domain | P1 (ops) | ADR-036 | Owner action |
