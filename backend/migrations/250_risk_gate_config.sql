-- 风险闸门（risk gate）单行配置表。默认 mode=off，关闭时不产生任何查询与写入。
-- 使用 version 做乐观锁，管理端保存时必须携带读取时的版本号。
CREATE TABLE IF NOT EXISTS risk_gate_config (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  version BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
