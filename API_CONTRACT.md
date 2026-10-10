# API_CONTRACT

The machine-readable contract is `api/openapi.json`. A contract test (`TestRoutesMatchOpenAPI` in `internal/httpapi/httpapi_test.go`) fails if a route is
registered but not documented, or documented but not registered.

## Conventions
- Base path `/api/v1`, JSON only (`application/json; charset=utf-8`). SSE uses `text/event-stream`.
- **Errors** look like `{"error":{"code":"string","message":"string","details":{},"request_id":"string","retryable":bool}}`.
  Codes are stable snake_case (`validation_failed`, `not_found`, `conflict`, `precondition_failed`, `precondition_required`,
  `unauthenticated`, `forbidden`, `csrf_failed`, `rate_limited`, `internal`). `internal` never includes stack traces or paths.
- **Request ID**: `X-Request-ID` is echoed if it is valid (`[A-Za-z0-9-]{8,64}`), otherwise generated.
- **Concurrency**: mutable resources return `ETag: "r<revision>"`. PUT/PATCH/DELETE require `If-Match`. If it is missing the response is `428`, and if it does not match the response is `412`.
- **Idempotency**: unsafe POSTs that create jobs accept `Idempotency-Key` (8–128 chars). A replay with the same key and body returns
  the original response. The same key with a different body returns `409 idempotency_key_reuse`.
- **Long operations** return `202 Accepted` with `{"job_id": "...", "status": "Queued"}` and `Location: /api/v1/jobs/{id}`.
- **Pagination** uses `?limit=` (1–200, default 50) and `?cursor=` (opaque). Responses look like `{"items":[...],"next_cursor":"..."|null}`.
- **CSRF**: unsafe methods with cookie auth must send `X-CSRF-Token` matching the `ngm_csrf` cookie, and Origin (or Sec-Fetch-Site)
  must be same-origin. Bearer-token requests are exempt from CSRF but bound to token scopes.
- **SSE** endpoint is `/api/v1/events`. It supports `Last-Event-ID` replay from the durable `events` table. If the requested ID is older than the
  retained window, the server sends `event: resync`. A heartbeat comment goes out every 15 s, and events are filtered by the subscriber's scopes.

## RBAC (built-in roles; deny by default)
| Permission | Owner | Admin | Operator | Viewer |
|---|---|---|---|---|
| `*.read` | ✓ | ✓ | ✓ | ✓ |
| `gateway.write`, `websites.write`, `domains.write`, `certificates.write` | ✓ | ✓ | ✓ | |
| `deploy.apply` | ✓ | ✓ | ✓ | |
| `backups.create` (create, verify, download, delete archives) | ✓ | ✓ | ✓ | |
| `firewall.write`, `recovery.write`, `settings.write`, `backups.restore`, `updates.install` (step-up MFA) | ✓ | ✓ | | |
| `users.read`, `roles.read`, `audit.read`, `secrets.read` | ✓ | ✓ | | |
| `users.write`, `roles.write`, `secrets.write` | ✓ | ✓ | | |
| `owner.transfer`, `system.purge` | ✓ | | | |

## Implemented endpoints (Phases 1–2)
All 27 paths are listed in `api/openapi.json`: system (health, version), jobs, events (SSE), setup, auth (login, logout, session, MFA enroll/confirm/verify, step-up, password), users, roles, permissions, tokens, audit, secrets (metadata only). Mutating endpoints require an active session or token, CSRF for cookie sessions, `If-Match` for updates, and step-up MFA for critical permissions.

## Implemented endpoints (Phases 3–4)
`api/openapi.json` now lists 63 paths. The contract test fails on any route that is registered but undocumented, or documented but missing.
- **Gateway (Phase 3)**: listeners, routes, backends, pools, certificates, validation (+preview), simulation, deployments (apply, rollback, active).
- **Monitoring (Phase 4)**: `GET /monitoring/backends`. Health per endpoint, with stale evidence reported as `unknown`.
- **Firewall**:
  - `GET /firewall`: desired rules plus the observed UFW state.
  - `POST /firewall/rules`, `POST /firewall/rules/from-listeners`, `DELETE /firewall/rules/{id}`.
  - `POST /firewall/apply {enable}` returns 202 and a job.
  - `POST /firewall/confirm {job_id}` is the dead-man confirmation. The deadline is in the `Verifying` step evidence, and an SSE `firewall.confirm_required` event is sent.
- **Backups**:
  - `GET/POST /backups`; POST returns 409 `no_passphrase` until a passphrase is set.
  - `GET /backups/settings`, `PUT /backups/schedule`, `POST /backups/passphrase`.
  - `GET /backups/{id}/download`, `POST /backups/{id}/verify` (422 `backup_invalid`), `DELETE /backups/{id}`.
  - Restore is CLI-only (ADR-022).
- **Recovery**:
  - `GET /recovery/incidents[?status=open]`, `GET /recovery/incidents/{id}` (includes `drift`).
  - `POST /recovery/incidents/{id}/resolve {outcome, note}`. Returns 409 `no_evidence` or `active_drift` when the data plane disagrees.
  - `POST /recovery/incidents/{id}/reconcile {mode: adopt|restore}`, `GET /recovery/drift`, `POST /recovery/reconcile {mode}`.
