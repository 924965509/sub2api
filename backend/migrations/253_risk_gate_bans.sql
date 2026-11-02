-- 身份封禁表：scope 为 api_key | user | client_fingerprint（指纹默认只记录不封禁）。
-- expires_at 为空表示永久封禁；过期封禁在查询时直接忽略。
CREATE TABLE IF NOT EXISTS risk_gate_bans (
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,          -- api_key | user | client_fingerprint
  subject TEXT NOT NULL,        -- id 或指纹 hash
  reason TEXT NOT NULL DEFAULT '',
  gate TEXT NOT NULL DEFAULT '',
  hit_count INT NOT NULL DEFAULT 1,
  banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  created_by TEXT NOT NULL DEFAULT 'system'
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_gate_bans_subject ON risk_gate_bans (scope, subject);
