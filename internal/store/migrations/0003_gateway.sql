-- Phase 3: certificate material references and generation metadata.

ALTER TABLE certificates ADD COLUMN cert_pem TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates ADD COLUMN issuer TEXT NOT NULL DEFAULT '';
-- Private key lives in the vault (type tls_key); only its secret id is here.
ALTER TABLE certificates ADD COLUMN key_secret_id TEXT REFERENCES vault_secrets(id) ON DELETE RESTRICT;

ALTER TABLE config_generations ADD COLUMN files_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE config_generations ADD COLUMN probe_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_generations ADD COLUMN job_id TEXT;
ALTER TABLE config_generations ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}';

INSERT INTO active_state(id, generation_id, last_known_good_id, revision, updated_at)
  VALUES (1, NULL, NULL, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'));

CREATE INDEX match_rules_route ON match_rules(route_id);
CREATE INDEX pool_members_endpoint ON backend_pool_members(endpoint_id);
