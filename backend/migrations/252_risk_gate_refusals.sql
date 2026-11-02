-- 上游拒答语料表（拒答缓存闸门的数据源，P3 阶段启用；本阶段只建表不读写）。
CREATE TABLE IF NOT EXISTS risk_gate_refusals (
  id BIGSERIAL PRIMARY KEY,
  provider TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  prompt_hash TEXT NOT NULL,
  normalized_prompt TEXT NOT NULL,
  shingle JSONB,
  source TEXT NOT NULL,         -- upstream_refusal | silent_refusal
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_gate_refusals_hash ON risk_gate_refusals (prompt_hash);
