package riskgate

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// newRefusalStoreMock 构造带 sqlmock 的拒答语料仓库。
func newRefusalStoreMock(t *testing.T) (*RefusalStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store := NewRefusalStore(db)
	store.SetClock(ClockFunc(func() time.Time { return banStoreNow }))
	return store, mock
}

// List：过滤条件、排序与分页参数。
func TestRefusalStoreListFiltersAndPaging(t *testing.T) {
	store, mock := newRefusalStoreMock(t)
	createdAt := banStoreNow.Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_refusals WHERE provider = $1 AND source = $2")).
		WithArgs("anthropic", EventKindUpstreamRefusal).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectQuery(`(?s)FROM risk_gate_refusals WHERE provider = \$1 AND source = \$2\s+ORDER BY created_at DESC, id DESC LIMIT \$3 OFFSET \$4`).
		WithArgs("anthropic", EventKindUpstreamRefusal, 10, 10).
		WillReturnRows(sqlmock.NewRows([]string{"id", "provider", "model", "prompt_hash", "normalized_prompt", "source", "created_at", "first_seen_at", "last_seen_at", "hit_count", "source_request_id", "error_message"}).
			AddRow(9, "anthropic", "claude-3", "hash-9", "已脱敏片段", EventKindUpstreamRefusal, createdAt, createdAt, createdAt, 3, "fixture-request", "fixture refusal"))

	rows, total, err := store.List(context.Background(), RefusalFilter{Provider: "anthropic", Source: EventKindUpstreamRefusal, Page: 2, PageSize: 10})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, rows, 1)
	require.Equal(t, int64(9), rows[0].ID)
	require.Equal(t, "已脱敏片段", rows[0].NormalizedPrompt)
	require.NoError(t, mock.ExpectationsWereMet())
}

// DeleteByID：删除后内存索引立刻失效，Match 不再命中该 hash。
func TestRefusalStoreDeleteByIDClearsIndex(t *testing.T) {
	store, mock := newRefusalStoreMock(t)
	store.Enqueue(RefusalRecord{PromptHash: "hash-a", Shingle: []uint64{1, 2, 3}})
	require.Contains(t, store.byHash, "hash-a")

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_refusals WHERE id = $1")).
		WithArgs(int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// 索引清空后 Match 会重新查库，这里返回空结果集。
	mock.ExpectQuery(`(?s)SELECT prompt_hash, shingle FROM risk_gate_refusals`).
		WillReturnRows(sqlmock.NewRows([]string{"prompt_hash", "shingle"}))

	deleted, err := store.DeleteByID(context.Background(), 4)
	require.NoError(t, err)
	require.True(t, deleted)
	require.NotContains(t, store.byHash, "hash-a", "删除后必须清空内存索引")

	hit, err := store.Match(context.Background(), "hash-a", nil, 0)
	require.NoError(t, err)
	require.Nil(t, hit)
	require.NoError(t, mock.ExpectationsWereMet())
}

// DeleteByID：没有删除任何行时返回 false。
func TestRefusalStoreDeleteByIDMissing(t *testing.T) {
	store, mock := newRefusalStoreMock(t)
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_refusals WHERE id = $1")).
		WithArgs(int64(77)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	deleted, err := store.DeleteByID(context.Background(), 77)
	require.NoError(t, err)
	require.False(t, deleted)
	require.NoError(t, mock.ExpectationsWereMet())
}

// DeleteAll：返回删除行数并清空索引。
func TestRefusalStoreDeleteAllClearsIndex(t *testing.T) {
	store, mock := newRefusalStoreMock(t)
	store.Enqueue(RefusalRecord{PromptHash: "hash-b"})
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_refusals")).
		WillReturnResult(sqlmock.NewResult(0, 5))

	deleted, err := store.DeleteAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(5), deleted)
	require.Empty(t, store.byHash)
	require.Empty(t, store.order)
	require.True(t, store.loadedAt.IsZero())
	require.NoError(t, mock.ExpectationsWereMet())
}

// 无 DB 时列表为空、删除为 no-op。
func TestRefusalStoreAdminWithoutDB(t *testing.T) {
	store := NewRefusalStore(nil)
	rows, total, err := store.List(context.Background(), RefusalFilter{})
	require.NoError(t, err)
	require.Empty(t, rows)
	require.Equal(t, int64(0), total)

	deleted, err := store.DeleteByID(context.Background(), 1)
	require.NoError(t, err)
	require.False(t, deleted)

	count, err := store.DeleteAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(0), count)
}

// One SQL upsert per hash avoids PostgreSQL's "cannot affect row a second time"
// error, preserves the observation window, and drains safely after cancellation.
func TestRefusalStoreInsertBatchCombinesHashesAndFlushesOnShutdown(t *testing.T) {
	store, mock := newRefusalStoreMock(t)
	first := banStoreNow.Add(-2 * time.Minute)
	last := banStoreNow
	mock.ExpectExec(`INSERT INTO risk_gate_refusals`).WithArgs(
		"anthropic", "claude-test", "same-hash", "latest evidence", "[]", EventKindUpstreamRefusal,
		first, first, last, 3, "latest-request", "fixture refusal",
	).WillReturnResult(sqlmock.NewResult(1, 1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.insertBatch(ctx, []RefusalRecord{
		{PromptHash: "same-hash", CreatedAt: first, NormalizedPrompt: "first evidence"},
		{PromptHash: "same-hash", CreatedAt: last, Provider: "anthropic", Model: "claude-test", NormalizedPrompt: "latest evidence", SourceRequestID: "latest-request", ErrorMessage: "fixture refusal"},
		{PromptHash: "same-hash", CreatedAt: first.Add(time.Minute), NormalizedPrompt: "middle evidence"},
	})
	written, dropped, lastErr := store.Stats()
	require.EqualValues(t, 3, written)
	require.Zero(t, dropped)
	require.Empty(t, lastErr)
	require.NoError(t, mock.ExpectationsWereMet())
}
