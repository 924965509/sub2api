package riskgate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// eventColumns 与 EventRepository 的 SELECT 列顺序一致。
var eventColumns = []string{
	"id", "request_id", "user_id", "api_key_id", "group_id", "provider", "endpoint", "protocol", "model",
	"kind", "gate", "rule_id", "reason", "score", "prompt_hash", "evidence", "action", "created_at", "category", "rule_key", "pattern", "client_fingerprint", "user_preview", "submitted_text", "scores", "terminal_outcome",
}

// newEventRepositoryMock 构造带 sqlmock 的事件仓库。
func newEventRepositoryMock(t *testing.T) (*EventRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return NewEventRepository(db), mock
}

// 所有过滤字段都会拼进 WHERE，且顺序稳定。
func TestEventWhereBuildsAllClauses(t *testing.T) {
	from := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	groupID := int64(9)
	condition, args := eventWhere(EventFilter{
		Kind: EventKindBlocked, Gate: GateRegex, Provider: "anthropic",
		RequestID: "req-1", PromptHash: "hash-1", UserID: 3, APIKeyID: 4, GroupID: &groupID,
		From: &from, To: &to,
	})
	require.Equal(t, "WHERE kind = $1 AND gate = $2 AND provider = $3 AND request_id = $4 AND "+
		"prompt_hash = $5 AND user_id = $6 AND api_key_id = $7 AND group_id = $8 AND "+
		"created_at >= $9 AND created_at < $10", condition)
	require.Len(t, args, 10)
	require.Equal(t, EventKindBlocked, args[0])
	require.Equal(t, int64(9), args[7])
	require.Equal(t, from, args[8])
	require.Equal(t, to, args[9])
}

// 空过滤条件不产生 WHERE。
func TestEventWhereEmpty(t *testing.T) {
	condition, args := eventWhere(EventFilter{Kind: "  ", UserID: 0})
	require.Empty(t, condition)
	require.Empty(t, args)
}

// List：带过滤条件的分页查询，默认分页 50、上限 200。
func TestEventRepositoryListAppliesFilterAndPaging(t *testing.T) {
	repository, mock := newEventRepositoryMock(t)
	condition, args := eventWhere(EventFilter{Kind: EventKindBlocked})
	require.Equal(t, "WHERE kind = $1", condition)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_events " + condition)).
		WithArgs(driverValues(args)...).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`(?s)FROM risk_gate_events WHERE kind = \$1\s+ORDER BY created_at DESC, id DESC LIMIT \$2 OFFSET \$3`).
		WithArgs(EventKindBlocked, eventListDefaultPageSize, 0).
		WillReturnRows(sqlmock.NewRows(eventColumns).AddRow(
			11, "req-11", 3, nil, 9, "anthropic", "/v1/messages", "anthropic", "claude-3",
			EventKindBlocked, GateRegex, 5, "regex_hit", 0.9, "hash-11", "脱敏片段", EventActionBanned, banStoreNow, "", "", "", "", "", "", []byte("{}"), "blocked"))

	rows, total, err := repository.List(context.Background(), EventFilter{Kind: EventKindBlocked})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, rows, 1)
	require.Equal(t, int64(11), rows[0].ID)
	require.Equal(t, int64(0), rows[0].APIKeyID)
	require.Equal(t, int64(9), *rows[0].GroupID)
	require.Equal(t, int64(5), rows[0].RuleID)
	require.InDelta(t, 0.9, rows[0].Score, 1e-9)
	require.NoError(t, mock.ExpectationsWereMet())
}

// List：page_size 超过上限被压到 200。
func TestEventRepositoryListClampsPageSize(t *testing.T) {
	repository, mock := newEventRepositoryMock(t)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_events ")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?s)FROM risk_gate_events\s+ORDER BY created_at DESC, id DESC LIMIT \$1 OFFSET \$2`).
		WithArgs(eventListMaxPageSize, 0).
		WillReturnRows(sqlmock.NewRows(eventColumns))

	rows, total, err := repository.List(context.Background(), EventFilter{Page: 1, PageSize: 5000})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, rows)
	require.NoError(t, mock.ExpectationsWereMet())
}

// CountByFilter 与 DeleteByFilter 使用完全一致的 WHERE 与参数。
func TestEventRepositoryCountAndDeleteShareWhere(t *testing.T) {
	repository, mock := newEventRepositoryMock(t)
	from := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	filter := EventFilter{Kind: EventKindBlocked, Gate: GateDistill, Provider: "openai", From: &from, To: &to}
	condition, args := eventWhere(filter)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_events " + condition)).
		WithArgs(driverValues(args)...).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_events " + condition)).
		WithArgs(driverValues(args)...).
		WillReturnResult(sqlmock.NewResult(0, 4))

	total, err := repository.CountByFilter(context.Background(), filter)
	require.NoError(t, err)
	require.Equal(t, int64(4), total)

	deleted, err := repository.DeleteByFilter(context.Background(), filter)
	require.NoError(t, err)
	require.Equal(t, int64(4), deleted)
	require.NoError(t, mock.ExpectationsWereMet())
}

// From/To 是闭开区间：SQL 里必须是 >= From 与 < To。
func TestEventRepositoryFromToBoundaries(t *testing.T) {
	repository, mock := newEventRepositoryMock(t)
	from := time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)
	to := time.Date(2026, 5, 2, 8, 0, 0, 0, time.UTC)
	condition, args := eventWhere(EventFilter{From: &from, To: &to})
	require.Equal(t, "WHERE created_at >= $1 AND created_at < $2", condition)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_events "+condition)).
		WithArgs(from, to).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	total, err := repository.CountByFilter(context.Background(), EventFilter{From: &from, To: &to})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Equal(t, []any{from, to}, args)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Get：命中与未命中。
func TestEventRepositoryGet(t *testing.T) {
	repository, mock := newEventRepositoryMock(t)
	mock.ExpectQuery(`(?s)FROM risk_gate_events WHERE id = \$1`).
		WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows(eventColumns).AddRow(
			12, "req-12", nil, nil, nil, "anthropic", "", "", "claude-3",
			EventKindUpstreamPass, GateDecisionModel, nil, decisionUnavailable, nil, "hash-12", "", EventActionNone, banStoreNow, "", "", "", "", "", "", []byte("{}"), ""))

	row, err := repository.Get(context.Background(), 12)
	require.NoError(t, err)
	require.NotNil(t, row)
	require.Equal(t, decisionUnavailable, row.Reason)
	require.Nil(t, row.GroupID)

	mock.ExpectQuery(`(?s)FROM risk_gate_events WHERE id = \$1`).
		WithArgs(int64(13)).
		WillReturnError(sql.ErrNoRows)
	missing, err := repository.Get(context.Background(), 13)
	require.NoError(t, err)
	require.Nil(t, missing)
	require.NoError(t, mock.ExpectationsWereMet())
}

// HasCondition：只有分页参数不算过滤条件。
func TestEventFilterHasCondition(t *testing.T) {
	require.False(t, EventFilter{}.HasCondition())
	require.False(t, EventFilter{Kind: "  ", Page: 2, PageSize: 50}.HasCondition())
	require.True(t, EventFilter{Kind: EventKindBlocked}.HasCondition())
	groupID := int64(1)
	require.True(t, EventFilter{GroupID: &groupID}.HasCondition())
}

// driverValues 把 []any 转成 sqlmock 需要的 []driver.Value。
func driverValues(args []any) []driver.Value {
	values := make([]driver.Value, len(args))
	for index, arg := range args {
		values[index] = arg
	}
	return values
}
