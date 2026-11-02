-- 风险闸门事件表：blocked（命中）/ allowed / upstream_pass / upstream_refusal。
-- evidence 只存放已脱敏片段，禁止落原文。
CREATE TABLE IF NOT EXISTS risk_gate_events (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL,
  user_id BIGINT, api_key_id BIGINT, group_id BIGINT,
  provider TEXT NOT NULL DEFAULT '', endpoint TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,            -- blocked | allowed | upstream_pass | upstream_refusal
  gate TEXT NOT NULL DEFAULT '', -- ban | distill | regex | refusal_cache | decision_model | ''
  rule_id BIGINT, reason TEXT NOT NULL DEFAULT '',
  score NUMERIC(6,4), prompt_hash TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',  -- 已脱敏片段
  action TEXT NOT NULL DEFAULT '',    -- none | banned | would_block
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_gate_events_time ON risk_gate_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_gate_events_kind_time ON risk_gate_events (kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_gate_events_user_time ON risk_gate_events (user_id, created_at DESC);
