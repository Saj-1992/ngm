-- NGM schema v1: core entity families (MASTER_SPEC §7.1).
-- Conventions: TEXT ids (ULID-shaped), RFC3339Nano UTC timestamps, revision for optimistic concurrency.

CREATE TABLE settings (
  key         TEXT PRIMARY KEY,
  value_json  TEXT NOT NULL,
  revision    INTEGER NOT NULL DEFAULT 1,
  updated_at  TEXT NOT NULL
) STRICT;

-- ───────────── Configuration ─────────────
CREATE TABLE listeners (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  kind         TEXT NOT NULL CHECK (kind IN ('http','https','stream','stream_tls_front')),
  address      TEXT NOT NULL,
  port         INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  family       TEXT NOT NULL CHECK (family IN ('ipv4','ipv6')),
  options_json TEXT NOT NULL DEFAULT '{}',
  enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  scope        TEXT NOT NULL DEFAULT 'global',
  revision     INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (address, port)
) STRICT;

CREATE TABLE backend_endpoints (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,
  host               TEXT NOT NULL,
  port               INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport          TEXT NOT NULL CHECK (transport IN ('http','https','tcp')),
  tls_verify         INTEGER NOT NULL DEFAULT 1 CHECK (tls_verify IN (0,1)),
  tls_server_name    TEXT,
  health_policy_json TEXT NOT NULL DEFAULT '{}',
  weight             INTEGER NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 1000),
  priority           INTEGER NOT NULL DEFAULT 0,
  connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
  read_timeout_ms    INTEGER NOT NULL DEFAULT 60000,
  write_timeout_ms   INTEGER NOT NULL DEFAULT 60000,
  disabled           INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
  scope              TEXT NOT NULL DEFAULT 'global',
  revision           INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE backend_pools (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  strategy     TEXT NOT NULL CHECK (strategy IN ('round_robin','least_conn','hash','failover')),
  options_json TEXT NOT NULL DEFAULT '{}',
  scope        TEXT NOT NULL DEFAULT 'global',
  revision     INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
) STRICT;

CREATE TABLE backend_pool_members (
  pool_id     TEXT NOT NULL REFERENCES backend_pools(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES backend_endpoints(id) ON DELETE RESTRICT,
  weight      INTEGER NOT NULL DEFAULT 1,
  is_backup   INTEGER NOT NULL DEFAULT 0 CHECK (is_backup IN (0,1)),
  PRIMARY KEY (pool_id, endpoint_id)
) STRICT;

CREATE TABLE domains (
  id         TEXT PRIMARY KEY,
  fqdn       TEXT NOT NULL UNIQUE COLLATE NOCASE,
  purpose    TEXT NOT NULL DEFAULT 'general' CHECK (purpose IN ('general','management','website','route')),
  notes      TEXT NOT NULL DEFAULT '',
  scope      TEXT NOT NULL DEFAULT 'global',
  revision   INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE dns_record_expectations (
  id         TEXT PRIMARY KEY,
  domain_id  TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  rtype      TEXT NOT NULL CHECK (rtype IN ('A','AAAA','CNAME','CAA','NS','TXT')),
  value      TEXT NOT NULL,
  ttl        INTEGER,
  revision   INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (domain_id, name, rtype, value)
) STRICT;

CREATE TABLE certificates (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,
  source             TEXT NOT NULL CHECK (source IN ('acme','uploaded','self_signed')),
  sans_json          TEXT NOT NULL DEFAULT '[]',
  not_before         TEXT,
  not_after          TEXT,
  fingerprint_sha256 TEXT,
  status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','valid','expiring','expired','failed','revoked')),
  acme_json          TEXT NOT NULL DEFAULT '{}',
  scope              TEXT NOT NULL DEFAULT 'global',
  revision           INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE websites (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL UNIQUE,
  kind              TEXT NOT NULL CHECK (kind IN ('static_zip','template')),
  template          TEXT CHECK (template IN ('landing','corporate','portfolio','documentation','blog','app_showcase')),
  default_locale    TEXT NOT NULL DEFAULT 'en',
  locales_json      TEXT NOT NULL DEFAULT '["en"]',
  active_version_id TEXT,
  scope             TEXT NOT NULL DEFAULT 'global',
  revision          INTEGER NOT NULL DEFAULT 1,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
) STRICT;

CREATE TABLE website_versions (
  id           TEXT PRIMARY KEY,
  website_id   TEXT NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  number       INTEGER NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('draft','built','published','superseded','failed')),
  content_hash TEXT,
  created_by   TEXT,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  UNIQUE (website_id, number)
) STRICT;

CREATE TABLE routes (
  id               TEXT PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  listener_id      TEXT NOT NULL REFERENCES listeners(id) ON DELETE RESTRICT,
  protocol         TEXT NOT NULL CHECK (protocol IN ('http','tcp','tls_passthrough','tls_terminate_http')),
  priority         INTEGER NOT NULL DEFAULT 100,
  destination_kind TEXT NOT NULL CHECK (destination_kind IN ('pool','endpoint','website','redirect','reject')),
  destination_id   TEXT,
  is_fallback      INTEGER NOT NULL DEFAULT 0 CHECK (is_fallback IN (0,1)),
  certificate_id   TEXT REFERENCES certificates(id) ON DELETE RESTRICT,
  options_json     TEXT NOT NULL DEFAULT '{}',
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  scope            TEXT NOT NULL DEFAULT 'global',
  revision         INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
) STRICT;
CREATE INDEX routes_listener ON routes(listener_id);

CREATE TABLE match_rules (
  id       TEXT PRIMARY KEY,
  route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
  field    TEXT NOT NULL CHECK (field IN ('sni','alpn','host','path_prefix','path_exact','method','header')),
  operator TEXT NOT NULL CHECK (operator IN ('exact','wildcard','prefix')),
  value    TEXT NOT NULL,
  arg      TEXT,
  UNIQUE (route_id, field, operator, value, arg)
) STRICT;

-- ───────────── Deployment ─────────────
CREATE TABLE desired_revisions (
  id         TEXT PRIMARY KEY,
  number     INTEGER NOT NULL UNIQUE,
  base_generation_id TEXT,
  model_hash TEXT NOT NULL,
  model_json TEXT NOT NULL,
  state      TEXT NOT NULL CHECK (state IN ('draft','approved','superseded')),
  created_by TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE config_generations (
  id                  TEXT PRIMARY KEY,
  number              INTEGER NOT NULL UNIQUE,
  desired_revision_id TEXT NOT NULL REFERENCES desired_revisions(id) ON DELETE RESTRICT,
  stage_path          TEXT NOT NULL,
  manifest_hash       TEXT NOT NULL,
  status              TEXT NOT NULL CHECK (status IN ('staged','active','superseded','failed','rolled_back')),
  created_at          TEXT NOT NULL,
  activated_at        TEXT
) STRICT;

-- Singleton pointer to the Active generation; only the Deployment Coordinator updates it.
CREATE TABLE active_state (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  generation_id TEXT REFERENCES config_generations(id) ON DELETE RESTRICT,
  last_known_good_id TEXT REFERENCES config_generations(id) ON DELETE RESTRICT,
  revision      INTEGER NOT NULL DEFAULT 1,
  updated_at    TEXT NOT NULL
) STRICT;

CREATE TABLE jobs (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL,
  state           TEXT NOT NULL CHECK (state IN ('Queued','Validating','ImpactAnalyzed','Staging','Preflight','Applying','Verifying','Succeeded','Blocked','Failed','Compensating','RolledBack','RecoveryRequired','Cancelled')),
  actor_id        TEXT,
  request_id      TEXT,
  idempotency_key TEXT,
  base_revision   INTEGER,
  lock_set_json   TEXT NOT NULL DEFAULT '[]',
  payload_json    TEXT NOT NULL DEFAULT '{}',
  result_json     TEXT,
  error_json      TEXT,
  attempts        INTEGER NOT NULL DEFAULT 0,
  worker_id       TEXT,
  revision        INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  started_at      TEXT,
  finished_at     TEXT
) STRICT;
CREATE INDEX jobs_state ON jobs(state, created_at);
CREATE UNIQUE INDEX jobs_idem ON jobs(actor_id, kind, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE job_steps (
  id             TEXT PRIMARY KEY,
  job_id         TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  seq            INTEGER NOT NULL,
  name           TEXT NOT NULL,
  from_state     TEXT,
  to_state       TEXT,
  step_class     TEXT NOT NULL CHECK (step_class IN ('idempotent','external')),
  status         TEXT NOT NULL CHECK (status IN ('started','completed','failed','compensated')),
  fencing_token  INTEGER,
  evidence_json  TEXT NOT NULL DEFAULT '{}',
  started_at     TEXT NOT NULL,
  finished_at    TEXT,
  UNIQUE (job_id, seq)
) STRICT;

CREATE TABLE fencing_counter (
  id    INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
) STRICT;
INSERT INTO fencing_counter (id, value) VALUES (1, 0);

CREATE TABLE lock_leases (
  resource      TEXT PRIMARY KEY CHECK (resource IN ('system-update','backup-restore','gateway-config','certificate','website-publish','firewall')),
  holder_job_id TEXT NOT NULL,
  holder_worker TEXT NOT NULL,
  fencing_token INTEGER NOT NULL,
  acquired_at   TEXT NOT NULL,
  heartbeat_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL
) STRICT;

-- Highest fencing token ever granted per resource (survives lease release, enforces monotonicity).
CREATE TABLE lock_fences (
  resource     TEXT PRIMARY KEY,
  latest_token INTEGER NOT NULL
) STRICT;

CREATE TABLE runtime_observations (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  data_json   TEXT NOT NULL,
  hash        TEXT NOT NULL
) STRICT;
CREATE INDEX runtime_obs_kind ON runtime_observations(kind, observed_at);

CREATE TABLE drift_findings (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  resource_ref TEXT NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  status       TEXT NOT NULL CHECK (status IN ('open','acknowledged','reconciled')),
  details_json TEXT NOT NULL DEFAULT '{}',
  detected_at  TEXT NOT NULL,
  resolved_at  TEXT,
  revision     INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE ownership_ledger (
  id            TEXT PRIMARY KEY,
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('file','dir','ufw_rule','symlink')),
  resource_key  TEXT NOT NULL,
  generation_id TEXT,
  sha256        TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  UNIQUE (resource_kind, resource_key)
) STRICT;

-- ───────────── Identity / security ─────────────
CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name  TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  locale        TEXT NOT NULL DEFAULT 'en' CHECK (locale IN ('en','fa')),
  mfa_enabled   INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0,1)),
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until  TEXT,
  last_login_at TEXT,
  revision      INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
) STRICT;

CREATE TABLE roles (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  builtin     INTEGER NOT NULL DEFAULT 0 CHECK (builtin IN (0,1)),
  description TEXT NOT NULL DEFAULT '',
  revision    INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
) STRICT;

CREATE TABLE role_permissions (
  role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  PRIMARY KEY (role_id, permission)
) STRICT;

CREATE TABLE permission_grants (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  scope_kind TEXT NOT NULL DEFAULT 'global' CHECK (scope_kind IN ('global','website','route','domain')),
  scope_id   TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (user_id, role_id, scope_kind, scope_id)
) STRICT;

CREATE TABLE sessions (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash          TEXT NOT NULL UNIQUE,
  csrf_hash           TEXT NOT NULL,
  created_at          TEXT NOT NULL,
  last_seen_at        TEXT NOT NULL,
  idle_expires_at     TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  mfa_verified_at     TEXT,
  client_ip           TEXT,
  user_agent          TEXT,
  revoked_at          TEXT
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE api_tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  scopes_json  TEXT NOT NULL DEFAULT '[]',
  expires_at   TEXT,
  last_used_at TEXT,
  revoked_at   TEXT,
  created_at   TEXT NOT NULL
) STRICT;

CREATE TABLE vault_key_versions (
  version      INTEGER PRIMARY KEY,
  status       TEXT NOT NULL CHECK (status IN ('staged','active','retiring','retired')),
  check_value  BLOB NOT NULL,
  created_at   TEXT NOT NULL,
  activated_at TEXT,
  retired_at   TEXT
) STRICT;

CREATE TABLE vault_secrets (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  scope       TEXT NOT NULL,
  name        TEXT NOT NULL,
  kek_version INTEGER NOT NULL REFERENCES vault_key_versions(version) ON DELETE RESTRICT,
  wrapped_dek BLOB NOT NULL,
  dek_nonce   BLOB NOT NULL,
  nonce       BLOB NOT NULL,
  ciphertext  BLOB NOT NULL,
  version     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (type, scope, name)
) STRICT;

CREATE TABLE totp_secrets (
  user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  vault_secret_id TEXT NOT NULL REFERENCES vault_secrets(id) ON DELETE RESTRICT,
  confirmed_at    TEXT,
  last_used_step  INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE audit_events (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  id           TEXT NOT NULL UNIQUE,
  at           TEXT NOT NULL,
  actor_kind   TEXT NOT NULL CHECK (actor_kind IN ('user','token','system','cli')),
  actor_id     TEXT NOT NULL DEFAULT '',
  action       TEXT NOT NULL,
  target_kind  TEXT NOT NULL DEFAULT '',
  target_id    TEXT NOT NULL DEFAULT '',
  result       TEXT NOT NULL CHECK (result IN ('success','failure','denied')),
  request_id   TEXT NOT NULL DEFAULT '',
  job_id       TEXT NOT NULL DEFAULT '',
  context_json TEXT NOT NULL DEFAULT '{}',
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL
) STRICT;

CREATE TABLE idempotency_keys (
  actor_id      TEXT NOT NULL,
  key           TEXT NOT NULL,
  method        TEXT NOT NULL,
  path          TEXT NOT NULL,
  body_hash     TEXT NOT NULL,
  status_code   INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  PRIMARY KEY (actor_id, key)
) STRICT;

-- ───────────── Operations ─────────────
CREATE TABLE managed_firewall_rules (
  id            TEXT PRIMARY KEY,
  rule_key      TEXT NOT NULL UNIQUE,
  action        TEXT NOT NULL CHECK (action IN ('allow','deny','limit')),
  proto         TEXT NOT NULL CHECK (proto IN ('tcp','udp','any')),
  port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  source        TEXT NOT NULL DEFAULT 'any',
  family        TEXT NOT NULL CHECK (family IN ('ipv4','ipv6','both')),
  refcount      INTEGER NOT NULL DEFAULT 0,
  desired_state TEXT NOT NULL CHECK (desired_state IN ('present','absent')),
  active_state  TEXT NOT NULL CHECK (active_state IN ('present','absent','unknown')),
  revision      INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
) STRICT;

CREATE TABLE backup_artifacts (
  id            TEXT PRIMARY KEY,
  file_name     TEXT NOT NULL UNIQUE,
  size_bytes    INTEGER NOT NULL,
  sha256        TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('creating','complete','failed','deleted')),
  trigger_kind  TEXT NOT NULL CHECK (trigger_kind IN ('manual','scheduled','pre_restore','pre_update','pre_migration')),
  created_by    TEXT,
  created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE recovery_incidents (
  id            TEXT PRIMARY KEY,
  job_id        TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  status        TEXT NOT NULL CHECK (status IN ('open','in_progress','resolved')),
  summary       TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  opened_at     TEXT NOT NULL,
  resolved_at   TEXT,
  resolved_by   TEXT,
  revision      INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE notification_targets (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL CHECK (kind IN ('telegram','webhook')),
  secret_id   TEXT REFERENCES vault_secrets(id) ON DELETE RESTRICT,
  config_json TEXT NOT NULL DEFAULT '{}',
  enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  revision    INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
) STRICT;

-- ───────────── Observability ─────────────
CREATE TABLE health_samples (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_kind TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('healthy','degraded','down','unknown','disabled')),
  latency_ms   INTEGER,
  detail       TEXT NOT NULL DEFAULT '',
  observed_at  TEXT NOT NULL
) STRICT;
CREATE INDEX health_subject ON health_samples(subject_kind, subject_id, observed_at);

CREATE TABLE alerts (
  id           TEXT PRIMARY KEY,
  rule         TEXT NOT NULL,
  subject      TEXT NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  state        TEXT NOT NULL CHECK (state IN ('firing','acknowledged','resolved')),
  details_json TEXT NOT NULL DEFAULT '{}',
  first_at     TEXT NOT NULL,
  last_at      TEXT NOT NULL,
  resolved_at  TEXT,
  revision     INTEGER NOT NULL DEFAULT 1
) STRICT;

-- Durable SSE notification log (bounded; source of truth remains the entity tables).
CREATE TABLE events (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  type      TEXT NOT NULL,
  scope     TEXT NOT NULL DEFAULT 'global',
  at        TEXT NOT NULL,
  data_json TEXT NOT NULL
) STRICT;
