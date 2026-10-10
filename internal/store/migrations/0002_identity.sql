-- Phase 2: identity, sessions, throttling, service heartbeats.

-- Session stage: a password-verified session must still pass MFA before it is
-- fully active (pending_mfa) or must enrol TOTP first (mfa_enroll).
ALTER TABLE sessions ADD COLUMN stage TEXT NOT NULL DEFAULT 'active' CHECK (stage IN ('pending_mfa','mfa_enroll','active'));
ALTER TABLE sessions ADD COLUMN secure INTEGER NOT NULL DEFAULT 1 CHECK (secure IN (0,1));
CREATE INDEX sessions_expiry ON sessions(absolute_expires_at);

-- Login throttling buckets keyed by "user:<name>" or "ip:<addr>".
CREATE TABLE login_throttle (
  key          TEXT PRIMARY KEY,
  failures     INTEGER NOT NULL,
  window_start TEXT NOT NULL,
  locked_until TEXT
) STRICT;

-- Liveness of NGM processes, written by each role (Unknown when stale).
CREATE TABLE service_heartbeats (
  service     TEXT PRIMARY KEY,
  pid         INTEGER NOT NULL,
  version     TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('healthy','degraded','down')),
  detail      TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL
) STRICT;

CREATE INDEX audit_at ON audit_events(at);
CREATE INDEX grants_user ON permission_grants(user_id);
CREATE INDEX tokens_user ON api_tokens(user_id);
