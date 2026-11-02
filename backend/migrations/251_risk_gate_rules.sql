-- 风险闸门面板自定义规则：gate=distill 时 pattern 为 needle/指纹，gate=regex 时为正则。
-- 内置规则写在代码里，本表只存放管理员新增的规则。
CREATE TABLE IF NOT EXISTS risk_gate_rules (
  id BIGSERIAL PRIMARY KEY,
  gate TEXT NOT NULL,           -- distill | regex
  category TEXT NOT NULL,       -- distill | sexual | jailbreak | bypass | custom
  pattern TEXT NOT NULL,        -- 正则或 needle
  is_regex BOOLEAN NOT NULL DEFAULT TRUE,
  action TEXT NOT NULL DEFAULT 'block',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INT NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_gate_rules_enabled ON risk_gate_rules (gate, enabled, sort_order);
