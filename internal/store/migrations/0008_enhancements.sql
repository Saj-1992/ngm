-- MFA recovery codes (single-use, SHA-256 hashed) and remote backup tracking.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

ALTER TABLE backup_artifacts ADD COLUMN remote_status TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_artifacts ADD COLUMN remote_key TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_artifacts ADD COLUMN remote_error TEXT NOT NULL DEFAULT '';
