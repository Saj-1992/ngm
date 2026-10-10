# NGM V1.0 — MASTER IMPLEMENTATION SPECIFICATION

**Product:** Nginx Gateway Manager (NGM)  
**Baseline:** Architecture Freeze V1.0  
**Status:** Normative implementation contract; software has not yet been built or verified  
**Audience:** Claude Code and engineering reviewers  
**Language:** English (UI must support Persian RTL and English LTR)

> **Primary directive to Claude Code:** Build a real, installable, secure Nginx OSS gateway manager. This document is authoritative for product behavior and acceptance. Do not silently omit, mock, defer, weaken, or claim completion of a P0/P1 requirement. Where a technical contradiction or unavailable test environment exists, document the evidence, stop the affected release gate, and escalate a precise decision. Continue independent work when safe. Never claim an unexecuted test passed.

## 0. Normative language, priorities, and source of truth

- **MUST / MUST NOT:** mandatory. **SHOULD:** default unless documented, justified exception. **MAY:** optional.
- **P0 Critical:** safety, security, data integrity, access continuity, and correct gateway behavior. Blocks Stable release.
- **P1 Must-Have:** required V1 functionality. Cannot be dropped or postponed without explicit owner approval. Blocks Stable release.
- **P2 Enhancement:** optional improvements, explicitly tracked; never misrepresent as shipped.
- This document defines product scope and technical invariants. `DECISIONS.md` records decisions/change control; `API_CONTRACT.md`, `DEPLOYMENT_CONTRACT.md`, and `SECURITY_MODEL.md` refine this baseline but MUST NOT contradict it.
- Baseline changes require a recorded change request with rationale, alternatives, security/compatibility impact, tests, and explicit approval when P0/P1 or architecture is affected.
- No mock service, fake metric, dummy route, UI-only operation, or skipped test can count as a Verified feature. Demo fixtures are allowed only in isolated development/test environments and visibly identified.
- The implementation is for one independently operated Ubuntu gateway, not a multi-node control plane.

## 1. Product purpose and boundaries

NGM manages **Nginx Open Source** as an HTTP/HTTPS and TCP stream gateway, hosts static/structured websites, and proxies traffic to external backends (including independently operated Xray services). NGM does **not** install or administer Xray, x-ui, or other VPN control panels, nor claim DPI evasion. NGM manages backend endpoints and pools, not backend host processes.

**P1 included:** listeners; routes; domain/SNI/ALPN/HTTP host/path matching where technically visible; upstream endpoints/pools; HTTP reverse proxy; WebSocket; TCP stream; TLS passthrough; shared-public-443 routing for supported cases; conflict analysis; route simulation; SSL; domain/DNS monitoring and optional Cloudflare DNS; managed UFW; static website builder/publisher; encrypted local/manual-download backups; restore; supervised recovery; drift detection; RBAC/MFA/audit; local encrypted secrets vault; advanced logging; monitoring/alerts/SSE; adaptive performance profiles and guarded tuning; premium bilingual UI; read-only hybrid topology; signed releases; installer/update/repair/uninstall.

**Out of V1:** UDP proxy as a general gateway feature; arbitrary Nginx configuration editor; arbitrary shell execution; custom kernel tuning; installing/managing Xray; running untrusted website server-side code; external KMS/Vault as a requirement; automated cloud backups; provider-side firewall management; multi-gateway cluster orchestration or DNS failover; general-purpose distributed tracing; unrestricted plugin execution.

## 2. Platform and compatibility contract

- **P0/P1 support matrix:** Ubuntu Server 22.04 LTS AMD64, 22.04 LTS ARM64, 24.04 LTS AMD64, 24.04 LTS ARM64. Test all four on actual matching environments before advertising Stable support.
- Install Nginx OSS and matching stream module from the **Ubuntu distribution APT repositories** (typically `nginx` and `libnginx-mod-stream`), not a mixed nginx.org installation. Probe actual package versions, dynamic module load, directives, and module availability rather than assuming a specific build layout.
- If a pre-existing Nginx installation is found, inspect package origin, ownership, include graph, active listeners, and conflicting configuration. Never overwrite third-party configuration or convert its ownership without explicit informed approval. Refuse unsafe adoption and offer diagnostic steps.
- Provisional minimum: 1 vCPU, 1 GiB RAM, 10 GiB disk; recommended: 2 vCPU, 2 GiB RAM, 20 GiB disk. These are **planning targets**, not validated capacity guarantees. Profile suitability is determined by real measurements and benchmarks.
- Nginx is the data plane, managed by its own systemd service. API/worker failures MUST NOT automatically stop Nginx.
- Detect host IPv4/IPv6 availability, bind conflicts, provider firewall limitations, low disk, apt locks, systemd capabilities, and cgroup limits.

## 3. Runtime architecture and process model

Use a **modular Go monolith with separate worker modes/processes**, not a microservice mesh or external message broker:

| Unit | Responsibility | Privilege |
| --- | --- | --- |
| `ngm-api` | REST `/api/v1`, sessions, authz, SSE, business services | Dedicated unprivileged account |
| `ngm-ops` | Persistent jobs, deployment/backup/restore/update orchestration | Unprivileged, narrow file/socket rights |
| `ngm-monitor` | Backend health, DNS/SSL checks, drift, alert evaluation | Unprivileged |
| `ngm-log-indexer` | Incremental log collection/indexing and retention | Unprivileged, read-only source access |
| `ngm-helper` | Small allowlisted privileged operations | Root where strictly required; hardened |
| `nginx` | Actual HTTP/stream forwarding and static serving | Distro-managed systemd service |

A shared Go binary with role-specific execution modes is acceptable. Boundaries are enforced by systemd, Unix-domain sockets, filesystem ACLs, authorization and explicit command schemas. No Redis/RabbitMQ dependency in V1. SQLite WAL is the durable state/journal store; use bounded transactions and explicit busy handling.

- The API listens on **127.0.0.1:9999** by default; Nginx exposes the management UI via HTTPS on an administrator-selected domain or path. A dedicated management origin is recommended and must be documented as safer than path-sharing with hosted sites. Initial bootstrap is via SSH tunnel/local-only access until admin credentials, TOTP, and TLS exposure are configured.
- Use peer credentials on Unix sockets (e.g. `SO_PEERCRED` where supported), strict socket permissions, per-operation authorization, replay resistance where relevant, and schema-validated requests. A socket's presence alone does not confer authority.
- Helper must NOT accept arbitrary command lines, environment overrides, unrestricted file paths, shell snippets, or arbitrary service names. Use allowlisted operations and secure file-descriptor-relative filesystem access; prevent symlink/path traversal and TOCTOU where possible.
- Separate worker resource budgets with systemd/cgroups. Preserve Nginx priority under memory/disk pressure. Harden systemd units after functional testing; never blindly enable directives that break required behavior.
- Startup performs supervised reconciliation; shutdown drains or checkpoints jobs at safe boundaries. Never restart Nginx merely because the NGM API starts.

## 4. Filesystem and ownership

Canonical locations (may be refined by distro constraints, but remain stable and documented):

- `/opt/ngm/releases/` — immutable versioned application bundles
- `/opt/ngm/current` — active release pointer
- `/etc/ngm/` — NGM configuration and protected local key material
- `/var/lib/ngm/` — SQLite, jobs, revision metadata, vault ciphertext
- `/var/lib/ngm/websites/` — site drafts, builds, published generations
- `/var/lib/ngm/backups/` — local encrypted backups
- `/var/log/ngm/` — application and audit log files
- `/run/ngm/` — restricted runtime sockets and locks

Use a distinct NGM-owned include tree for generated Nginx configuration and record ownership of every generated file and managed UFW rule. **Do not overwrite non-NGM resources.** Detect external edits (drift), report and require deliberate reconciliation. Preserve third-party include graphs and distribution package configuration. Atomic file replacement is not an atomic transaction across Nginx, UFW, DNS, SQLite and systemd.

## 5. Routing and protocol support matrix (normative)

The route compiler MUST understand what information is visible at each layer. **Do not infer HTTP path/Host inside un-terminated TLS.** All routes must have explicit listener, protocol, match priority, destination, and fallback semantics.

| Incoming case | Matching inputs visible at gateway | Supported behavior | Required guardrail |
| --- | --- | --- | --- |
| Plain HTTP on HTTP listener | Host, method, path, headers | Static website or HTTP reverse proxy, WebSocket upgrade | HTTP host/path precedence, no duplicate ambiguous locations |
| HTTPS terminated at NGM | TLS SNI/ALPN, then decrypted HTTP Host/path | NGM certificate + HTTP virtual host, website or proxy | Cert/key compatibility, HTTP route only after termination |
| TCP stream without TLS termination | IP/port and bytes available to stream | TCP proxy to endpoint/pool | No HTTP path or Host matching |
| TLS passthrough stream | ClientHello SNI/ALPN only if actually visible | `ssl_preread` dispatch to TCP backend | Backend terminates TLS; NGM cannot inspect HTTP payload |
| Shared public IP:443 | Stream front listener; visible SNI/ALPN | Dispatch some names to internal local HTTP TLS termination, others to passthrough | Only one public bind per IP:port; explicit default/fallback; no dual HTTP+stream public bind |
| WebSocket over HTTP(S) | HTTP upgrade headers after HTTP parsing | Reverse proxy with appropriate HTTP version and upgrade handling | Test handshake and bidirectional traffic |
| ECH, absent/hidden SNI | Potentially no usable outer name | Only explicit fallback/known routing strategy | No claim of reliable hidden-name discrimination |
| HTTP/2 / HTTP/3 | HTTP/2 when supported by actual build; HTTP/3 requires explicit capability and UDP | Do not promise HTTP/3 in V1 | Reject unsupported ALPN/UDP assumptions |
| Cloudflare proxied hostname | Depends on CF proxy product/protocol | Standard proxied HTTP(S) when supported | Do not claim arbitrary TCP passes through ordinary CF orange-cloud proxy |
| IPv6 listener | Address-specific IPv6 bind | Supported if OS/network configured and tested | Detect IPv4/IPv6 bind conflicts and address family behavior |

### 5.1 Shared 443 compiler requirements

- For a single public `IP:443`, Nginx `stream` owns the public socket. Route by `ssl_preread_server_name` / `ssl_preread_alpn_protocols` only where actual ClientHello fields are available; forward selected names to loopback TLS-terminating `http` listeners, or to external TCP passthrough backends.
- Preserve SNI end-to-end for passthrough. The HTTP branch terminates TLS at NGM and can then evaluate Host/path; ensure certificate/SNI and HTTP Host validation policies prevent unintended cross-host dispatch.
- Define exact precedence: address/port -> stream rule specificity -> deterministic fallback -> HTTP virtual host -> HTTP location. Reject ties, overlapping wildcard patterns, unreachable branches, incompatible `listen` options and ambiguous default servers.
- `ssl_preread` does not decrypt TLS, cannot see HTTP path, and is not a universal protocol detector. ECH and missing SNI must have a documented explicit fallback or be rejected.
- Test with real `openssl s_client`/TLS clients, HTTP requests, WebSocket sessions and TCP echo backends. Verify backend certificate identity as appropriate to the chosen TLS mode.

### 5.2 Backends and failover

- Backend endpoint schema includes host/IP, port, transport (HTTP/HTTPS/TCP), TLS validation policy where applicable, health policy, weight/priority, connect/read/write timeouts, and disabled state. No arbitrary backend-side execution.
- Go monitor performs active health checks; Nginx OSS does not provide a universal active health-check feature. Health probes must be protocol-correct, rate-limited, and SSRF-protected. Passive Nginx behavior may supplement but not replace explicit Go health status.
- Failover is for **new connections/requests** as permitted by actual Nginx upstream behavior. Never promise migration of established TCP/TLS sessions. Document DNS caching and reload/keepalive limitations.
- Route Simulation Lab takes a proposed listener/IP/port, SNI, ALPN, Host, path, scheme and optional test metadata; reports selected branch, reasons, fallback and uncertainty. It simulates the compiled configuration model and MUST NOT claim to prove all runtime packet behavior.

## 6. Domain, DNS, certificate and website contracts

### 6.1 Domains/DNS

- Domain Registry is the single source for domain ownership/mapping, with uniqueness and dependency checks across websites, routes, certificates and management origin.
- Monitor A, AAAA, CNAME, CAA, NS, TXT records with status, last check, errors and TTL awareness. Distinguish authoritative data, resolver cache and expected records.
- Optional Cloudflare DNS integration uses least-privilege scoped token, preview, audit and explicit confirmation for create/update/delete; preserve external records. Detect provider drift. No V1 multi-gateway DNS failover; never promise immediate propagation or rollback due to TTL/caching.

### 6.2 TLS and certificates

- Manage certificate issuance/renewal and installation through a verified ACME-compatible workflow, with challenge prerequisites, rate limits, DNS/HTTP challenge support only where actually implemented, staging tests and renewal alerts. Never claim all DNS providers support automated DNS-01.
- Protect private keys using strict filesystem permissions and appropriate Nginx-readable deployment paths; do not imply the runtime TLS private key can remain only in encrypted SQLite if Nginx requires an operational file.
- Validate certificate SAN/domain, key match, chain, expiry and routing impact before activation. Preserve previous known-good cert until new cert is verified.

### 6.3 Websites

- Static ZIP upload must enforce archive size, decompression ratio, path normalization, symlink/device-file rejection, file type/size limits, MIME validation, malware-risk handling and strict publish-root isolation.
- Structured templates: Landing, Corporate, Portfolio, Documentation, Blog, App Showcase. Provide block-based content editor, media management, metadata/SEO, drafts, preview on an isolated origin, deterministic build, versioned publish and rollback.
- Localized sites use path locales (e.g. `/fa/`, `/en/`), hreflang, canonical URLs, locale-aware sitemap, RTL/LTR and per-locale content. Never execute user-uploaded server-side code.
- Website publish is a persistent job with dependency analysis, build validation, staged files, atomic per-site pointer switch where supported, runtime verification and compensating rollback.

## 7. Persistent state, revision model and data contracts

### 7.1 Core entities

| Domain | Required entities |
| --- | --- |
| Configuration | Listener, Route, MatchRule, BackendEndpoint, BackendPool, Domain, DNSRecordExpectation, Certificate, Website, WebsiteVersion |
| Deployment | DesiredRevision, ActiveRevision, ConfigGeneration, DeploymentJob, JobStep, LockLease, RuntimeObservation, DriftFinding |
| Identity/security | User, Role, PermissionGrant, Session, APITokenHash, TOTPSecret, VaultSecret, VaultKeyVersion, AuditEvent |
| Operations | ManagedFirewallRule, BackupArtifact, RestoreJob, UpdateJob, RecoveryIncident, NotificationTarget |
| Observability | HealthSample, Alert, LogIndexEntry, SSEEvent, TopologyNode/Edge projection |

Every mutable entity has stable ID, timestamps, version/revision for optimistic concurrency, owner/scope, and a validated schema. SQLite WAL, foreign keys, integrity checks, online backup API, bounded transactions and migration checksums are mandatory. Define uniqueness and deletion/dependency behavior explicitly; use soft delete only when justified.

### 7.2 Desired / Active / Runtime

- **Desired:** administrator-approved candidate state (including staged draft revisions).
- **Active:** last generation NGM successfully deployed and verified; immutable snapshot and hash.
- **Runtime:** observed Nginx processes/listeners/config ownership, UFW, certs and backend probes. Runtime may be partial or Unknown; never fabricate complete certainty.
- UI displays all three separately. Drift is a first-class finding; external changes are never silently overwritten.
- Only the Deployment Coordinator can promote a generation to Active. Changes use optimistic concurrency (`ETag`/revision preconditions) and idempotency keys.

### 7.3 Migrations

Migrations are versioned, tested on fresh and upgrade installations, backed up before destructive steps, and fail closed when schema/API incompatibility exists. Rollback of app binaries is permitted only if database migration compatibility is verified; a migration need not be reversible, so safe restore paths must be explicit.

## 8. Deployment Coordinator, locks and state machine

### 8.1 Safe Apply state machine

`Queued -> Validating -> ImpactAnalyzed -> Staging -> Preflight -> Applying -> Verifying -> Succeeded`

Exceptional states: `Blocked`, `Failed`, `Compensating`, `RolledBack`, `RecoveryRequired`, `Cancelled` (only before or at documented safe cancellation boundaries).

1. Authorize action, bind actor/request ID/idempotency key and expected base revision.
2. Validate schema, dependencies, routing precedence, resource and security constraints.
3. Acquire required durable lock leases in globally defined order; use fencing tokens to prevent stale workers from committing.
4. Create immutable staged generation, manifests/hashes and ownership ledger; preserve last-known-good generation.
5. Test actual prospective Nginx include graph (`nginx -t` with correct configuration root), UFW changes, certificate dependencies, ports and management access safety.
6. Apply ordered resource changes with checkpoints and explicit compensating actions; no claim of multi-resource atomicity.
7. Reload Nginx gracefully where appropriate; verify process status, expected listener binds, relevant HTTP/TLS/TCP probes and route-specific invariants. Existing long-lived connections may continue using old workers; do not claim instant switchover.
8. Commit Active only after verified success. Publish SSE/audit and release leases.
9. On failure, attempt compensation and verify it. If recovery is uncertain, enter `RecoveryRequired`, retain evidence and require supervised action.

### 8.2 Locking and concurrency

Durable resource locks: gateway-config, firewall, certificate, website-publish, backup-restore, system-update. Define a total acquisition order and conflict graph; prohibit deadlocks and stale worker writes using lease expiration, heartbeat and fencing. DB transaction commits and helper actions must verify current job/lease authority. Crash/restart reconciliation must distinguish safe resumable steps from ambiguous external side effects.

### 8.3 Supervised Recovery

Systemd restarts NGM services, then startup reconciliation compares SQLite jobs/revisions with Nginx include graph, actual listeners, managed UFW rules, certificates and website pointers. Resume only idempotent/provably safe steps; otherwise stop and surface a Recovery Center with diagnostics and guided manual actions. No blind destructive cleanup, reload, or overwrite. Data plane remains independent.

## 9. Managed firewall contract

- UFW is the supported local firewall interface. Track NGM-owned rule IDs/markers, exact protocol/port/source, reference counts, desired/active status and audit; preserve all external rules.
- Before changing ingress, identify management SSH path, UFW enablement, IPv4/IPv6 rules and existing allow policies. Provide dry-run, explicit confirmation, rollback plan and time-bounded watchdog for risky changes where technically feasible.
- Never assert external SSH reachability solely from local probes. Provider/network firewalls remain outside scope.
- Firewall changes participate in Coordinator locking and recovery. Never flush all UFW rules or apply blanket reset.

## 10. Local encrypted secrets vault and backups

### 10.1 Vault

- Encrypt recoverable secrets at rest using envelope encryption: random per-secret DEK, authenticated encryption (e.g. AES-256-GCM), versioned local KEK, cryptographic random nonce, and authenticated binding to record ID/type/scope/version.
- Store ciphertext/metadata in SQLite; KEK in protected filesystem material outside web root and ordinary exports. Limit process access; keep plaintext lifetime short and redact all logs/errors/diagnostics.
- Passwords use Argon2id; NGM bearer API tokens are stored as **non-reversible hashes**. TOTP seeds are encrypted. Never offer UI read-back of stored recoverable secrets; replace/revoke/test instead.
- Root compromise with access to local KEK and live process remains outside the guarantee of at-rest encryption. State this explicitly.
- Key rotation is journaled and crash-resumable, using staged new KEK, rewrap, verification and delayed retirement of old key material. External credential rotation may require provider action.

### 10.2 Backups

- **Only local encrypted backups + manual download in V1**; configurable scheduler and retention. Warn that local-only copies can be lost with the VPS.
- Capture a WAL-consistent SQLite snapshot plus required site/config/certificate/vault material with versioned manifest, checksums, integrity/authenticity protection, and strict exclusion of transient caches and logs as configured.
- Portable backup encryption uses a strong user-held recovery passphrase with memory-hard KDF (e.g. Argon2id with calibrated parameters), random salt and AEAD. Ensure backup key material is recoverable on a *new host* without the source server KEK; rekey imported secrets into destination vault after verified restore.
- Restore has preview/simulation, schema/version and filesystem checks, ownership/permission validation, compatibility assessment, snapshot of current state, staged restore, post-restore verification and compensating recovery. Wrong passphrase or corrupt archive must leave Active untouched.
- Never include recovery passphrase in archive, logs or database. Explicitly document that lost passphrase and unavailable source KEK can make secrets unrecoverable.

## 11. Security model and access control

- First-run wizard (seven steps): system preflight; owner account + TOTP enrollment; management URL/origin; HTTPS certificate; default website; first backend/route; verification. Initial setup via local access/SSH tunnel until secure exposure is ready.
- Argon2id password hashing; strong password policy; TOTP MFA; session rotation, secure HttpOnly/SameSite cookies, CSRF defense, CSP, origin checks, login throttling, audit, idle/absolute expiration, step-up MFA for critical actions.
- RBAC roles: Owner, Admin, Operator, Viewer plus custom roles; resource/site scope and explicit API token scopes. Deny by default. Every endpoint, SSE subscription, export, topology projection and background job rechecks authorization appropriately.
- SSRF protection: validate endpoint/URL/redirect/DNS rebinding risks; default-deny sensitive metadata/local networks where not explicitly required; allow controlled loopback only for documented gateway internal targets. Validate TLS identity where applicable.
- Audit: actor, action, target, result, request/job ID, timestamp and minimal safe context; tamper-evident design where practical. Audit is not equivalent to a cryptographically immutable external ledger.
- Helper: typed allowlisted privileged actions only; verify peer identity, job authorization/fencing, path ownership, and operation parameters; no generic `exec` endpoint.
- Security testing includes XSS/CSRF/SSRF, auth bypass, IDOR, path traversal, symlink/TOCTOU, config injection, malicious ZIP, token leakage, IPC privilege escalation, backup tampering and supply chain checks.

## 12. API, jobs and SSE contract

- Versioned REST `/api/v1` with OpenAPI generated/validated contract. Canonical resource paths include `/listeners`, `/routes`, `/backends`, `/pools`, `/domains`, `/certificates`, `/websites`, `/deployments`, `/jobs`, `/firewall`, `/backups`, `/updates`, `/monitoring`, `/logs`, `/topology`, `/secrets`, `/users`, `/roles`, `/performance`.
- Standard errors include stable `code`, human-readable `message`, structured `details`, `request_id`, and retryability when relevant; correct HTTP status. Do not expose secrets, stack traces or internal paths to unprivileged users.
- Cursor pagination for large collections, validated filtering/sorting, per-user request limits, ETag/If-Match or equivalent optimistic concurrency, Idempotency-Key for unsafe repeatable operations, and `202 Accepted` + durable Job ID for long-running operations.
- SSE supports bounded replay using Last-Event-ID, authorization by event scope, heartbeat, resync on replay gaps, backpressure and disconnect behavior. SQLite is source of truth; SSE is notification transport, not sole durable state.
- API must never execute direct Nginx/UFW/system commands in request handlers; use authorized job/worker/helper workflow.

## 13. Logging, monitoring, alerts and topology

### 13.1 Logs

- Source of truth: bounded structured files/JSONL with per-service/site/route/listener correlation where possible; separate rebuildable SQLite metadata/optional FTS5 index. Collector checkpoints across rotation, truncation and restarts; avoid duplicating or silently losing known log ranges.
- Categories: HTTP access/error, stream access/error where supported, API, backend health, security, deployment, audit, website. **Never log secrets or raw authentication headers.** Query strings excluded/redacted by default; consider IP/privacy policy and access controls.
- Default configurable retention targets: access 7d, error 30d, health 30d, API 14d, security 90d, audit 180d. Bounded disk quotas, backpressure, low-disk emergency behavior that never deletes databases, certs or backups as an automatic log cleanup strategy.
- UI log explorer with server-side search/filter, live tail over SSE, export TXT/CSV/JSONL, RBAC and size limits. Index corruption must not destroy source logs.

### 13.2 Monitoring and alerts

- Real service health, backend probes, SSL expiry, DNS drift, disk/CPU/memory, queue state, job failures, Nginx version/module drift and log pipeline lag. Show Healthy/Degraded/Unknown/Disabled with evidence freshness and timestamps; Unknown is not Healthy.
- Telegram/webhook notifications use protected credentials, retry/backoff, delivery status, rate limiting and no secret leakage. Do not claim guaranteed delivery.

### 13.3 Read-only hybrid topology

- Graph nodes: Domain, Listener, StreamMatch, HTTPVirtualHost, Route, Website, BackendPool, Endpoint, Certificate, ManagedFirewallRule. Typed edges: receives, matches, forwards_to, serves, uses_certificate, requires_firewall_rule; distinguish traffic flow from dependency edges.
- Support desired/active/observed views, search, filter, grouping, zoom/pan, node details, permission-filtered projections and links to regular edit forms. **No drag-and-drop production configuration editor in V1.**
- Dependency Impact Analyzer evaluates proposed mutations against a typed graph and blocks unresolved critical dependencies. Route Simulation shows reasons, selected path, fallback and uncertainty. Bound graph sizes and support scoped requests.

## 14. Performance profiles and guarded tuning

- Profiles: Low Resource (~1 GiB), Balanced (~2 GiB), High Performance (~4 GiB+), **provisional** until benchmarks. Recommend using usable CPU, RAM/cgroup limits, disk and observed workload. Manual selection overrides recommendation.
- Adaptive behavior may change only bounded internal worker concurrency/scheduling for noncritical tasks (log indexing, backup scheduling, health probing) and must never silently alter sensitive Nginx routing, firewall or kernel sysctls.
- Guarded manual allowlist, context-aware: `worker_processes` (main), `worker_connections` (events), HTTP keepalive/client/proxy timeouts, proxy buffers, client body limits, selected `limit_req`/`limit_conn` with validated zones; separate stream `proxy_timeout` and `proxy_connect_timeout`. Validate directive context, package/module support, resource/FD budgets and impact.
- `worker_connections` is **not** equal to maximum concurrent clients: upstream connections, open file limits and per-worker capacity matter. Avoid unjustified hardcoded 'safe' maxima; compute and test ranges per environment.
- Display profile default, user override and effective value. Overrides persist across profile changes until explicitly reset. All changes use diff, impact, `nginx -t`, Safe Apply, runtime verification and rollback. No arbitrary raw config editing or automatic sysctl tuning.

## 15. Premium Control Center UX and localization

- Frontend: React + TypeScript + Tailwind CSS + shadcn/ui/Radix; Lucide icons. Responsive desktop/tablet/mobile, light/dark/system themes, design tokens, WCAG 2.2 AA target, keyboard focus management and reduced motion.
- Persian RTL and English LTR are first-class. Use logical CSS properties; IPs, domains, URLs, code and config remain readable LTR in Persian context. Test mixed-language strings, mobile drawers, tables, breadcrumbs and modal focus.
- Primary navigation: Overview (Dashboard/Monitoring/Logs); Gateway (Listeners/Routes/Backends/Route Simulation); Web & Domains (Websites/Domains/DNS/SSL); Operations (Firewall/Backups/Deployments/Recovery); System (Performance/Users/Roles/Settings/Help).
- Dashboard: evidence-based service health, listeners/routes/backends/websites counts, active alerts, recent jobs and safe quick actions. All numbers are real production data; no sample placeholders.
- Route Builder wizard: Listener -> Match -> Backend -> Security -> Review, with draft save, immediate conflict feedback, dependency impact, simulation, generated read-only config preview and Safe Apply confirmation.
- Every view implements loading/empty/error/permission denied/partial/unknown states; meaningful validation, unsaved-changes protection, responsive tables, accessible controls, genuine job progress and safe destructive confirmations.
- Global Command Palette supports navigation and safe actions only; risky actions still enter preview/step-up/confirmation workflow.
- Browser-based visual regression QA required for Dashboard, Route Builder, Topology, Websites, Firewall, Recovery, Logs and Settings at desktop/tablet/mobile and both locales. No inert controls in production.

## 16. Installer, lifecycle and distribution

- Prebuilt release artifacts for both CPU architectures, signed manifests/artifacts, verified checksums/signatures, immutable versioned releases and safe current-pointer switching. Manifest includes version, arch, OS support, schema/API version, migrations, dependencies and module expectations.
- One-command installer may download artifacts but MUST verify publisher signature against a trustworthy pinned/verified public key, not merely compare checksums fetched from the same untrusted source. Fail closed on verification errors.
- Preflight: root/sudo, Ubuntu release/arch, Nginx origin, stream module, ports, DNS/SSL prerequisites, SSH/UFW, disk/memory, apt locks, existing files and backups. No silent takeover of an existing Nginx install.
- systemd units, dedicated users, secure paths, seven-step bootstrap, smoke tests, idempotent rerun/repair and actionable diagnostics.
- CLI: `ngm status`, `ngm doctor`, `ngm config test`, `ngm rollback`, `ngm backup create`, `ngm restore`, `ngm admin reset`, `ngm update`.
- Stable/Beta signed releases; Nightly only in developer CI. Self-check/download/verify may be automatic; **installation requires administrator approval**. NGM Coordinated Nginx APT upgrade preflights distro packages/modules/apt locks, takes backup, updates and verifies; external unattended upgrades are detected and reconciled, not guaranteed blocked. Do not promise APT package downgrade as generic config rollback.
- Uninstall has **Keep Data** and explicit **Purge** modes with dependency warnings, backup advice, confirmation and no deletion of third-party files/rules.

## 17. Eight-phase implementation plan and gates

| Phase | Deliverables | Required evidence before advancing |
| --- | --- | --- |
| 1 Foundation | Repo, Go modules, schema/migrations, job journal, API/OpenAPI, UI shell, CI | Build, migration, contract, baseline security tests |
| 2 Security & Installer | Identity, MFA, RBAC, helper IPC, systemd, installer, wizard, CLI bootstrap | Authz/IPC tests, secure fresh install on test VM |
| 3 Gateway & Routing | HTTP/stream compiler, listeners/routes/pools, TLS passthrough/shared 443, simulation, safe apply | Real HTTP/TLS/TCP/WS E2E, conflict and reload tests |
| 4 Reliability | Locks, fencing, UFW, health, supervised recovery, backup/restore | Crash injection, SSH-safety scenarios, cross-host restore |
| 5 Domains & Websites | DNS/Cloudflare, ACME, website templates/editor/publish | Real provider sandbox/staging tests, publish/rollback |
| 6 Operations & UX | Logs/index, SSE, alerts, performance, topology, premium UI | Load/disk tests, access control, bilingual visual QA |
| 7 Lifecycle | Updates, package coordination, repair, signed artifacts, uninstall | Signed install/upgrade/recovery/uninstall tests |
| 8 Integration & Release | Full matrix, security audit, benchmark, documentation, RC | All P0/P1 Verified, release checklist and evidence |

Six cross-cutting quality gates: Functional, Routing, Security, Reliability, Compatibility, Delivery. Apply relevant gates per phase, then all release-wide gates at Phase 8. Claude Code advances automatically only when the relevant gates have **actually passed**. Stop for architecture/security/destructive blockers or missing approvals; continue independent safe work.

## 18. Release acceptance matrix and mandatory scenarios

**P0 release blockers:** incorrect route dispatch, management lockout, unauthenticated privileged operations, secret exposure, loss of Active config without recovery evidence, invalid signed-update verification, false health/success claims, broken backup integrity, unresolved high/critical exploitable security findings.

**P1 mandatory end-to-end evidence:**

1. Fresh install on each of Ubuntu 22.04/24.04 x AMD64/ARM64, with actual machine identity recorded.
2. HTTP reverse proxy, HTTPS termination, WebSocket bidirectional traffic, TCP stream and TLS passthrough against real test backends.
3. Shared public 443 for supported SNI/ALPN cases; explicit failure/fallback for absent SNI/ECH/ambiguous rules.
4. Route conflict rejection, deterministic precedence and Route Simulation comparison with actual observed test traffic.
5. Nginx config staging/test/reload/verify and failed-deploy rollback, including long-lived connections.
6. API crash, worker crash, helper crash, stale lock/lease, disk-full, interrupted job and startup reconciliation.
7. Managed UFW change/rollback with protected SSH access scenarios and preserved external rules.
8. Vault encrypt/decrypt, tamper detection, key rotation interruption/recovery, no token leaks, and cross-host portable restore.
9. ACME staging issuance/renewal, domain/DNS drift, Cloudflare API preview/authorization (when configured).
10. Website upload hardening, build, preview isolation, multilingual publish and rollback.
11. RBAC matrix, MFA/step-up, CSRF/XSS/SSRF, path traversal, malicious archives, IPC escalation and scoped SSE/export.
12. Log rotation/reindex/rebuild, retention/disk pressure, real metrics and Unknown-state behavior.
13. Performance guarded tuning validation, resource ceilings, and real capacity benchmarks (no fabricated SLA).
14. NGM signed update and rollback compatibility; Ubuntu Nginx package upgrade/drift detection.
15. RTL/LTR, mobile, keyboard accessibility, visual screenshots and all primary workflows.
16. Uninstall Keep Data/Purge safeguards and preservation of unrelated Nginx/UFW resources.

A test is recorded as `Pass`, `Fail`, `Blocked`, `Skipped` or `Not Tested`, with command, environment, artifact/log, timestamp and reviewer context. `Skipped` and `Not Tested` are not Pass. Stable is forbidden until P0/P1 required gates are satisfied.

## 19. Developer execution contract (Claude Code)

### 19.1 Required repository documents

Maintain these in the implementation repository when development starts:

- `MASTER_SPEC.md` — this normative product specification
- `CLAUDE.md` — operating instructions, execution guardrails and quality gates
- `IMPLEMENTATION_PLAN.md` — phased dependencies, deliverables and acceptance
- `DECISIONS.md` — architecture decision records and approved changes
- `PROGRESS.md` — real status by requirement ID and phase
- `TEST_REPORT.md` — exact tests, environments, outcomes and evidence
- `SECURITY_MODEL.md` — threat model, privilege boundaries, key lifecycle
- `DEPLOYMENT_CONTRACT.md` — state machine, lock ordering, compensation, recovery
- `API_CONTRACT.md` — OpenAPI, error schemas, RBAC, jobs and SSE
- `RELEASE_CHECKLIST.md` — signed artifacts and release gates

### 19.2 Required working behavior

1. Read the full specification and existing repository state before making changes. Derive a traceability matrix from every P0/P1 requirement to implementation, tests and evidence.
2. Implement real working vertical slices: schema -> backend -> authorization -> worker/helper -> UI -> integration tests -> documentation.
3. Run tests rather than asserting they would pass. Never mark a feature Verified because code compiles or a page renders.
4. After each phase, report changed files, migrations, API changes, actual commands/tests/results, security findings, known limitations, compatibility environments and next phase.
5. When blocked, investigate root cause, try valid alternatives, preserve logs and present options. Never remove a required feature, weaken tests or invent results. Request explicit approval for architecture/P0/P1 changes.
6. No production secrets in repository, fixtures, screenshots or logs. Never run destructive actions against a real user server without explicit authorization and a recovery plan.
7. Do not claim Stable, Production Ready, supported architecture or performance capacity without required executed evidence.
8. Ensure each phase leaves repository in a reproducible, buildable state, or clearly marks why it cannot.

### 19.3 Definition of Done for every P0/P1 feature

- Implemented backend, API and UI (where applicable) with no inert production controls.
- Validated inputs, resource ownership, RBAC, error handling and audit.
- Automated unit/contract tests plus applicable real integration/E2E and failure tests.
- Correct desired/active/runtime semantics, job lifecycle and safe recovery for mutations.
- Docs/help, observability and migration/release implications updated.
- Evidence recorded and all applicable quality gates passed. **Only then set `Verified`.**

## 20. Final decisions, technical caveats and change control

The following decisions are **closed** for V1 unless an approved change request reopens them:

1. Ubuntu 22.04/24.04 LTS, AMD64/ARM64; distro Nginx OSS + stream module.
2. Single gateway, Go modular monolith + separate worker modes, hardened privileged helper.
3. Nginx data plane independent of control plane.
4. HTTP/stream shared 443 only through technically valid stream front dispatch; no hidden TLS HTTP-path inspection.
5. SQLite WAL, persistent jobs, fencing locks, supervised recovery, desired/active/runtime distinction.
6. Managed UFW only for owned rules; protect SSH; no external firewall management.
7. Local encrypted backups with manual download; portable recovery and vault rekey.
8. Local encrypted secrets vault; nonreversible hashes for user passwords and API tokens.
9. Advanced Logging via source files plus bounded rebuildable index.
10. Adaptive performance profiles plus Advanced Guarded Tuning; no raw Nginx or kernel editing.
11. Premium Control Center, Persian RTL + English LTR, read-only Hybrid Topology.
12. NGM Coordinated updates with admin-approved installation and signed releases.
13. Strict Quality Gates and Strict Must-Have Enforcement.
14. Stable only with real four-platform compatibility evidence and complete P0/P1 verification.

**Important limitations:** Nginx OSS cannot promise arbitrary active upstream health features, seamless migration of existing TCP connections, guaranteed instantaneous rollback of DNS/apt package changes, arbitrary TCP over standard Cloudflare HTTP proxy, perfect SNI routing under ECH, or perfect safety against a full root compromise. NGM MUST explain these limits rather than misrepresent them.

## 21. Implementation kickoff instructions

When the owner asks Claude Code to implement:

1. Create the repository documentation above from this master baseline and assign stable requirement IDs (`NGM-SEC-*`, `NGM-ROUTE-*`, `NGM-DEP-*`, etc.).
2. Produce a requirement-to-test traceability matrix and dependency-ordered phase plan.
3. Perform environment capability checks; record what can and cannot be tested locally, including access to actual ARM64/Ubuntu environments.
4. Start Phase 1 and work through all eight phases under the strict gate and blocker rules. Do not request trivial decisions already resolved here.
5. Request owner approval only for material architecture changes, destructive operations, credentials/external access, or unavoidable P0/P1 conflicts.
6. At the end, provide reproducible release artifacts, install/update instructions, test evidence and an honest Stable/RC/Development classification.

---

**End of frozen NGM V1.0 master specification.** This document is a design/implementation contract, not evidence that any software, security control, benchmark, installer or release has been built or tested.
