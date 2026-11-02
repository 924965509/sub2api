-- Additive audit-workspace schema. Existing migrations remain immutable.
CREATE TABLE IF NOT EXISTS risk_gate_ruleset (
 id SMALLINT PRIMARY KEY DEFAULT 1 CHECK(id=1), version BIGINT NOT NULL DEFAULT 0,
 customized BOOLEAN NOT NULL DEFAULT FALSE, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO risk_gate_ruleset(id) VALUES(1) ON CONFLICT DO NOTHING;
ALTER TABLE risk_gate_rules ADD COLUMN IF NOT EXISTS rule_key TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_rules ADD COLUMN IF NOT EXISTS builtin BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE risk_gate_rules SET rule_key='custom-'||id WHERE rule_key='';
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_gate_rule_key ON risk_gate_rules(rule_key);
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS rule_key TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS pattern TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS client_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS user_preview TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS submitted_text TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS scores JSONB NOT NULL DEFAULT '{}';
ALTER TABLE risk_gate_events ADD COLUMN IF NOT EXISTS terminal_outcome TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_risk_gate_events_reason ON risk_gate_events(reason,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_gate_events_rule_key ON risk_gate_events(rule_key,created_at DESC);
CREATE TABLE IF NOT EXISTS risk_gate_decisions (
 decision_key TEXT PRIMARY KEY, request_id TEXT NOT NULL, user_id BIGINT NOT NULL DEFAULT 0,
 api_key_id BIGINT NOT NULL DEFAULT 0, provider TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT '', gate TEXT NOT NULL DEFAULT '', rule_key TEXT NOT NULL DEFAULT '',
 would_block BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_gate_decisions_time ON risk_gate_decisions(created_at);
CREATE TABLE IF NOT EXISTS risk_gate_classifier_usage (
 id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), request_id TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '', key_fingerprint TEXT NOT NULL DEFAULT '', http_status INTEGER,
 outcome TEXT NOT NULL, duration_ms BIGINT NOT NULL, input_tokens BIGINT, output_tokens BIGINT,
 estimated_cost_nano_usd BIGINT
);
CREATE INDEX IF NOT EXISTS idx_risk_gate_classifier_usage_time ON risk_gate_classifier_usage(created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS risk_gate_classifier_totals (
 id SMALLINT PRIMARY KEY DEFAULT 1 CHECK(id=1), started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 requests BIGINT NOT NULL DEFAULT 0, successful BIGINT NOT NULL DEFAULT 0,
 input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0,
 unknown_usage_requests BIGINT NOT NULL DEFAULT 0, known_cost_nano_usd BIGINT NOT NULL DEFAULT 0,
 unknown_cost_requests BIGINT NOT NULL DEFAULT 0
);
INSERT INTO risk_gate_classifier_totals(id) VALUES(1) ON CONFLICT DO NOTHING;
ALTER TABLE risk_gate_refusals ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE risk_gate_refusals ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE risk_gate_refusals ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 1;
ALTER TABLE risk_gate_refusals ADD COLUMN IF NOT EXISTS source_request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE risk_gate_refusals ADD COLUMN IF NOT EXISTS error_message TEXT NOT NULL DEFAULT '';
