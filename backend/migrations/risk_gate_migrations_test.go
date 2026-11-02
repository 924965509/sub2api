package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// 风险闸门 5 个迁移文件必须全部幂等（IF NOT EXISTS），且不得改动历史迁移。
func TestRiskGateMigrationsAreIdempotent(t *testing.T) {
	files := []string{
		"250_risk_gate_config.sql",
		"251_risk_gate_rules.sql",
		"252_risk_gate_refusals.sql",
		"253_risk_gate_bans.sql",
		"254_risk_gate_events.sql",
	}
	for _, name := range files {
		name := name
		t.Run(name, func(t *testing.T) {
			content, err := FS.ReadFile(name)
			require.NoError(t, err)
			sql := strings.Join(strings.Fields(string(content)), " ")
			upper := strings.ToUpper(sql)

			// 建表/建索引必须幂等。
			require.NotContains(t, upper, "CREATE TABLE risk_gate")
			require.NotContains(t, upper, "CREATE INDEX risk_gate")
			require.NotContains(t, upper, "CREATE UNIQUE INDEX risk_gate")
			require.NotContains(t, upper, "DROP TABLE")
			require.NotContains(t, upper, "DROP INDEX")
			require.NotContains(t, upper, "TRUNCATE")

			// 不允许修改既有业务表。
			require.NotContains(t, upper, "ALTER TABLE USERS")
			require.NotContains(t, upper, "ALTER TABLE ACCOUNTS")
			require.NotContains(t, upper, "ALTER TABLE API_KEYS")
			require.NotContains(t, upper, "ALTER TABLE GROUPS")
		})
	}
}

func TestRiskGateConfigMigrationSchema(t *testing.T) {
	content, err := FS.ReadFile("250_risk_gate_config.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS risk_gate_config")
	require.Contains(t, sql, "id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)")
	require.Contains(t, sql, "config JSONB NOT NULL")
	require.Contains(t, sql, "version BIGINT NOT NULL DEFAULT 0")
	require.Contains(t, sql, "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()")
}

func TestRiskGateRulesMigrationSchema(t *testing.T) {
	content, err := FS.ReadFile("251_risk_gate_rules.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS risk_gate_rules")
	require.Contains(t, sql, "gate TEXT NOT NULL")
	require.Contains(t, sql, "pattern TEXT NOT NULL")
	require.Contains(t, sql, "is_regex BOOLEAN NOT NULL DEFAULT TRUE")
	require.Contains(t, sql, "enabled BOOLEAN NOT NULL DEFAULT TRUE")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_risk_gate_rules_enabled")
}

func TestRiskGateRefusalsMigrationSchema(t *testing.T) {
	content, err := FS.ReadFile("252_risk_gate_refusals.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS risk_gate_refusals")
	require.Contains(t, sql, "prompt_hash TEXT NOT NULL")
	require.Contains(t, sql, "normalized_prompt TEXT NOT NULL")
	require.Contains(t, sql, "shingle JSONB")
	// P3 阶段按 prompt_hash 去重。
	require.Contains(t, sql, "CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_gate_refusals_hash")
}

func TestRiskGateBansMigrationSchema(t *testing.T) {
	content, err := FS.ReadFile("253_risk_gate_bans.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS risk_gate_bans")
	require.Contains(t, sql, "scope TEXT NOT NULL")
	require.Contains(t, sql, "subject TEXT NOT NULL")
	require.Contains(t, sql, "hit_count INT NOT NULL DEFAULT 1")
	require.Contains(t, sql, "expires_at TIMESTAMPTZ")
	require.Contains(t, sql, "CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_gate_bans_subject")
}

func TestRiskGateEventsMigrationSchema(t *testing.T) {
	content, err := FS.ReadFile("254_risk_gate_events.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")

	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS risk_gate_events")
	require.Contains(t, sql, "request_id TEXT NOT NULL")
	require.Contains(t, sql, "kind TEXT NOT NULL")
	require.Contains(t, sql, "prompt_hash TEXT NOT NULL DEFAULT ''")
	require.Contains(t, sql, "evidence TEXT NOT NULL DEFAULT ''")
	require.Contains(t, sql, "action TEXT NOT NULL DEFAULT ''")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_risk_gate_events_time")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_risk_gate_events_kind_time")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_risk_gate_events_user_time")
}
