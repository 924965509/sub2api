package riskgate

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

// newRuleStoreMock 构造带 sqlmock 的规则仓库。
func newRuleStoreMock(t *testing.T) (*RuleStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store := NewRuleStore(db)
	store.SetClock(ClockFunc(func() time.Time { return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) }))
	return store, mock
}

// 校验失败：任何非法规则都返回 400 且不碰数据库。
func TestRuleStoreReplaceRejectsInvalidRules(t *testing.T) {
	tooMany := make([]Rule, 0, maxAdminRules+1)
	for index := 0; index <= maxAdminRules; index++ {
		tooMany = append(tooMany, Rule{Gate: GateRegex, Category: CategoryCustom, Pattern: `\d+`, IsRegex: true})
	}
	cases := []struct {
		name  string
		rules []Rule
	}{
		{"非法 gate", []Rule{{Gate: "ban", Category: CategoryCustom, Pattern: "x"}}},
		{"非法 category", []Rule{{Gate: GateRegex, Category: "unknown", Pattern: "x"}}},
		{"空 pattern", []Rule{{Gate: GateDistill, Category: CategoryDistill, Pattern: "   "}}},
		{"坏正则", []Rule{{Gate: GateRegex, Category: CategoryCustom, Pattern: "([a-z", IsRegex: true}}},
		{"pattern 过长", []Rule{{Gate: GateDistill, Category: CategoryCustom, Pattern: string(make([]byte, maxRulePatternBytes+1))}}},
		{"非法 action", []Rule{{Gate: GateRegex, Category: CategoryCustom, Pattern: "x", Action: "drop"}}},
		{"超过 200 条", tooMany},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, mock := newRuleStoreMock(t)
			_, err := store.Replace(context.Background(), testCase.rules)
			require.Error(t, err)
			require.True(t, infraerrors.IsBadRequest(err))
			require.Equal(t, ErrorCodeInvalidRule, infraerrors.Reason(err))
			require.NoError(t, mock.ExpectationsWereMet(), "校验失败不应触达数据库")
		})
	}
}

// The compatibility endpoint shares stable upsert/version semantics. It never
// deletes every row before inserting replacements.
func TestRuleStoreReplaceWritesInTransaction(t *testing.T) {
	store, mock := newRuleStoreMock(t)
	expectRuleReplace(mock, 3, 11, "custom-stable", "(?i)jailbreak")
	saved, err := store.Replace(context.Background(), []Rule{{ID: 11, Gate: " REGEX ", Category: " Custom ", Pattern: " (?i)jailbreak ", IsRegex: true, Enabled: true}})
	require.NoError(t, err)
	require.Len(t, saved, 1)
	require.EqualValues(t, 11, saved[0].ID)
	require.Equal(t, "custom-stable", saved[0].RuleKey)
	require.Equal(t, "(?i)jailbreak", saved[0].Pattern)
	require.NoError(t, mock.ExpectationsWereMet())
}
func expectRuleReplace(mock sqlmock.Sqlmock, version, id int64, key, pattern string) {
	mock.ExpectQuery(`SELECT version FROM risk_gate_ruleset`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(version))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT version FROM risk_gate_ruleset.*FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(version))
	mock.ExpectQuery(`SELECT id,rule_key FROM risk_gate_rules`).WillReturnRows(sqlmock.NewRows([]string{"id", "rule_key"}).AddRow(id, key))
	mock.ExpectQuery(`INSERT INTO risk_gate_rules.*ON CONFLICT\(rule_key\) DO UPDATE`).WithArgs(GateRegex, CategoryCustom, pattern, true, "block", true, 0, "", key, false).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	mock.ExpectExec(`DELETE FROM risk_gate_rules WHERE id NOT IN`).WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE risk_gate_ruleset SET version=version\+1`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}
func TestRuleStoreReplaceInvalidatesCache(t *testing.T) {
	store, mock := newRuleStoreMock(t)
	cols := []string{"id", "gate", "category", "pattern", "is_regex", "action", "enabled", "sort_order", "description"}
	mock.ExpectQuery(`FROM risk_gate_rules`).WillReturnRows(sqlmock.NewRows(cols).AddRow(11, GateRegex, CategoryCustom, "a", true, "block", true, 0, ""))
	first, err := store.Rules(context.Background())
	require.NoError(t, err)
	require.Equal(t, "a", first[0].Pattern)
	expectRuleReplace(mock, 3, 11, "custom-stable", "b")
	_, err = store.Replace(context.Background(), []Rule{{ID: 11, Gate: GateRegex, Category: CategoryCustom, Pattern: "b", IsRegex: true, Enabled: true}})
	require.NoError(t, err)
	mock.ExpectQuery(`FROM risk_gate_rules`).WillReturnRows(sqlmock.NewRows(cols).AddRow(11, GateRegex, CategoryCustom, "b", true, "block", true, 0, ""))
	second, err := store.Rules(context.Background())
	require.NoError(t, err)
	require.Equal(t, "b", second[0].Pattern)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ListAll 返回含停用规则的全量列表。
func TestRuleStoreListAllIncludesDisabled(t *testing.T) {
	store, mock := newRuleStoreMock(t)
	mock.ExpectQuery(`FROM risk_gate_rules\s+ORDER BY gate, sort_order, id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "gate", "category", "pattern", "is_regex", "action", "enabled", "sort_order", "description"}).
			AddRow(1, GateRegex, CategoryCustom, `\d+`, true, "block", true, 0, "启用").
			AddRow(2, GateRegex, CategoryCustom, `\w+`, true, "block", false, 1, "停用"))

	rules, err := store.ListAll(context.Background())
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.False(t, rules[1].Enabled)
	require.NoError(t, mock.ExpectationsWereMet())
}

// 无 DB 时 Replace 只做校验并返回内存结果，不 panic。
func TestRuleStoreReplaceWithoutDB(t *testing.T) {
	store := NewRuleStore(nil)
	saved, err := store.Replace(context.Background(), []Rule{{Gate: GateRegex, Category: CategoryCustom, Pattern: "x"}})
	require.NoError(t, err)
	require.Len(t, saved, 1)
	require.Equal(t, int64(1), saved[0].ID)

	rules, err := store.ListAll(context.Background())
	require.NoError(t, err)
	require.Nil(t, rules)
}
