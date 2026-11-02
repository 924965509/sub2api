package riskgate

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

// banStoreNow 是封禁测试统一使用的时钟时刻。
var banStoreNow = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

// newBanStoreMock 构造带 sqlmock 的封禁仓库（redis 为 nil，只测本地缓存失效）。
func newBanStoreMock(t *testing.T) (*BanStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store := NewBanStore(db, nil)
	store.SetClock(ClockFunc(func() time.Time { return banStoreNow }))
	return store, mock
}

// List：scope + active_only + 分页的 SQL 与参数。
func TestBanStoreListFiltersAndPaging(t *testing.T) {
	store, mock := newBanStoreMock(t)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_bans WHERE scope = $1 AND (expires_at IS NULL OR expires_at > $2)")).
		WithArgs(BanScopeAPIKey, banStoreNow).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	mock.ExpectQuery(`(?s)FROM risk_gate_bans WHERE scope = \$1 AND \(expires_at IS NULL OR expires_at > \$2\).*ORDER BY banned_at DESC, id DESC LIMIT \$3 OFFSET \$4`).
		WithArgs(BanScopeAPIKey, banStoreNow, 10, 20).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope", "subject", "reason", "gate", "hit_count", "banned_at", "expires_at", "created_by"}).
			AddRow(3, BanScopeAPIKey, "key-3", "手动封禁", GateRegex, 2, banStoreNow, nil, "admin:1"))

	bans, total, err := store.List(context.Background(), BanFilter{Scope: BanScopeAPIKey, ActiveOnly: true, Page: 3, PageSize: 10})
	require.NoError(t, err)
	require.Equal(t, int64(7), total)
	require.Len(t, bans, 1)
	require.Equal(t, "key-3", bans[0].Subject)
	require.Nil(t, bans[0].ExpiresAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

// List：无过滤条件 + 分页上限（page_size 超过 200 被压到 200）。
func TestBanStoreListWithoutFilterClampsPageSize(t *testing.T) {
	store, mock := newBanStoreMock(t)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(1) FROM risk_gate_bans ")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?s)FROM risk_gate_bans\s+ORDER BY banned_at DESC, id DESC LIMIT \$1 OFFSET \$2`).
		WithArgs(banListMaxPageSize, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope", "subject", "reason", "gate", "hit_count", "banned_at", "expires_at", "created_by"}))

	bans, total, err := store.List(context.Background(), BanFilter{Page: 1, PageSize: 5000})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, bans)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Create：banned_at 由时钟填充，写入走 upsert 并保留 reason/gate/created_by。
func TestBanStoreCreateFillsClockAndUpserts(t *testing.T) {
	store, mock := newBanStoreMock(t)
	expiresAt := banStoreNow.Add(24 * time.Hour)
	mock.ExpectExec(`(?s)INSERT INTO risk_gate_bans.*ON CONFLICT \(scope, subject\) DO UPDATE`).
		WithArgs(BanScopeAPIKey, "key-9", "手动封禁", GateRegex, banStoreNow, expiresAt, "admin:7").
		WillReturnResult(sqlmock.NewResult(1, 1))

	ban, err := store.Create(context.Background(), Ban{
		Scope: BanScopeAPIKey, Subject: " key-9 ", Reason: " 手动封禁 ", Gate: " REGEX ",
		ExpiresAt: &expiresAt, CreatedBy: "admin:7",
	})
	require.NoError(t, err)
	require.Equal(t, banStoreNow, ban.BannedAt)
	require.Equal(t, "key-9", ban.Subject)
	require.Equal(t, "手动封禁", ban.Reason)
	require.Equal(t, GateRegex, ban.Gate)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Create：非法 scope / 空 subject / 超长 subject 都返回 400 且不写库。
func TestBanStoreCreateRejectsInvalidInput(t *testing.T) {
	longSubject := make([]byte, maxBanSubjectBytes+1)
	for index := range longSubject {
		longSubject[index] = 'x'
	}
	cases := []struct {
		name string
		ban  Ban
	}{
		{"非法 scope", Ban{Scope: "group", Subject: "x"}},
		{"空 subject", Ban{Scope: BanScopeUser, Subject: "   "}},
		{"subject 过长", Ban{Scope: BanScopeUser, Subject: string(longSubject)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, mock := newBanStoreMock(t)
			_, err := store.Create(context.Background(), testCase.ban)
			require.Error(t, err)
			require.True(t, infraerrors.IsBadRequest(err))
			require.Equal(t, ErrorCodeInvalidBan, infraerrors.Reason(err))
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// DeleteByID：不存在时返回 false 且不发 DELETE。
func TestBanStoreDeleteByIDMissing(t *testing.T) {
	store, mock := newBanStoreMock(t)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT scope, subject FROM risk_gate_bans WHERE id = $1")).
		WithArgs(int64(42)).
		WillReturnError(sql.ErrNoRows)

	deleted, err := store.DeleteByID(context.Background(), 42)
	require.NoError(t, err)
	require.False(t, deleted)
	require.NoError(t, mock.ExpectationsWereMet())
}

// DeleteByID：存在时删除并让本地缓存失效。
func TestBanStoreDeleteByIDClearsLocalCache(t *testing.T) {
	store, mock := newBanStoreMock(t)
	key := banCacheKey(BanScopeAPIKey, "key-5")
	store.local[key] = banCacheEntry{ban: &Ban{Scope: BanScopeAPIKey, Subject: "key-5"}, expiresAt: banStoreNow.Add(time.Minute)}

	mock.ExpectQuery(regexp.QuoteMeta("SELECT scope, subject FROM risk_gate_bans WHERE id = $1")).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows([]string{"scope", "subject"}).AddRow(BanScopeAPIKey, "key-5"))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_bans WHERE id = $1")).
		WithArgs(int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	deleted, err := store.DeleteByID(context.Background(), 5)
	require.NoError(t, err)
	require.True(t, deleted)
	require.NotContains(t, store.local, key, "删除后必须让本地缓存失效")
	require.NoError(t, mock.ExpectationsWereMet())
}
