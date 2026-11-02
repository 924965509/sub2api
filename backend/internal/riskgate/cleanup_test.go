package riskgate

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// fakeIndexResetter 记录索引失效调用次数。
type fakeIndexResetter struct{ calls int }

func (f *fakeIndexResetter) ResetIndex() { f.calls++ }

func cleanupTestClock(at time.Time) Clock {
	return ClockFunc(func() time.Time { return at })
}

// newCleanupSchedulerForTest 组装调度器；config 为 nil 表示配置来源未就绪。
func newCleanupSchedulerForTest(t *testing.T, mode Mode, retentionDays int, resetter RefusalIndexResetter) (*CleanupScheduler, sqlmock.Sqlmock, time.Time) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	source := &fakeConfigSource{
		ready:  true,
		config: Config{Mode: string(mode), RetentionDays: retentionDays},
	}
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	scheduler := NewCleanupScheduler(db, source, resetter)
	scheduler.SetClock(cleanupTestClock(now))
	return scheduler, mock, now
}

// mode=off 是默认部署状态：不产生数据，也绝不碰数据库。
func TestCleanupSkippedWhenModeOff(t *testing.T) {
	scheduler, mock, _ := newCleanupSchedulerForTest(t, ModeOff, 30, &fakeIndexResetter{})

	result, err := scheduler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !result.Skipped {
		t.Fatalf("mode=off 应跳过清理，得到 %+v", result)
	}
	if result.Events != 0 || result.Refusals != 0 || result.Bans != 0 {
		t.Fatalf("mode=off 不应产生影响行数，得到 %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mode=off 不应执行任何 SQL: %v", err)
	}
	runs, _, last, lastErr := scheduler.Stats()
	if runs != 1 || last == nil || !last.Skipped || lastErr != "" {
		t.Fatalf("统计异常 runs=%d last=%+v err=%q", runs, last, lastErr)
	}
}

func TestCleanupSkippedWhenConfigNotReady(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	resetter := &fakeIndexResetter{}
	scheduler := NewCleanupScheduler(db, &fakeConfigSource{}, resetter)
	scheduler.SetClock(cleanupTestClock(time.Unix(0, 0).UTC()))

	result, err := scheduler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !result.Skipped {
		t.Fatalf("配置未就绪应跳过清理，得到 %+v", result)
	}
	if resetter.calls != 0 {
		t.Fatalf("跳过时不应重置索引，调用 %d 次", resetter.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("配置未就绪不应执行 SQL: %v", err)
	}
}

// 分批删除：第一批满 5000 行继续，第二批不足 5000 行即停；封禁按 expires_at 清理。
func TestCleanupDeletesExpiredRowsInBatches(t *testing.T) {
	resetter := &fakeIndexResetter{}
	scheduler, mock, now := newCleanupSchedulerForTest(t, ModeObserve, 7, resetter)
	cutoff := now.Add(-7 * 24 * time.Hour)

	eventsStmt := regexp.QuoteMeta("DELETE FROM risk_gate_events WHERE id IN (" +
		"SELECT id FROM risk_gate_events WHERE created_at < $1 LIMIT $2)")
	refusalsStmt := regexp.QuoteMeta("DELETE FROM risk_gate_refusals WHERE id IN (" +
		"SELECT id FROM risk_gate_refusals WHERE created_at < $1 LIMIT $2)")
	bansStmt := regexp.QuoteMeta("DELETE FROM risk_gate_bans WHERE expires_at IS NOT NULL AND expires_at < $1")

	mock.ExpectExec(eventsStmt).WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, cleanupBatchSize))
	mock.ExpectExec(eventsStmt).WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 10))
	mock.ExpectExec(refusalsStmt).WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(bansStmt).WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 2))
	expectAlignmentCleanup(mock, cutoff)

	result, err := scheduler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if result.Events != cleanupBatchSize+10 {
		t.Fatalf("事件删除行数 = %d，期望 %d", result.Events, cleanupBatchSize+10)
	}
	if result.Refusals != 3 || result.Bans != 2 {
		t.Fatalf("删除行数异常 %+v", result)
	}
	if resetter.calls != 1 {
		t.Fatalf("语料被删后应重置索引一次，实际 %d 次", resetter.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQL 期望未满足: %v", err)
	}
	runs, deleted, _, _ := scheduler.Stats()
	if runs != 1 || deleted != int64(cleanupBatchSize+10+3+2) {
		t.Fatalf("统计异常 runs=%d deleted=%d", runs, deleted)
	}
}

// 语料没有被删时不重置索引（避免无谓地让热路径重新查库）。
func TestCleanupSkipsIndexResetWhenNothingDeleted(t *testing.T) {
	resetter := &fakeIndexResetter{}
	scheduler, mock, now := newCleanupSchedulerForTest(t, ModeBlocking, 30, resetter)
	cutoff := now.Add(-30 * 24 * time.Hour)

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_events WHERE id IN ("+
		"SELECT id FROM risk_gate_events WHERE created_at < $1 LIMIT $2)")).
		WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_refusals WHERE id IN ("+
		"SELECT id FROM risk_gate_refusals WHERE created_at < $1 LIMIT $2)")).
		WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_bans WHERE expires_at IS NOT NULL AND expires_at < $1")).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectAlignmentCleanup(mock, cutoff)

	if _, err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if resetter.calls != 0 {
		t.Fatalf("没有删除时不应重置索引，实际 %d 次", resetter.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQL 期望未满足: %v", err)
	}
}

// retention_days 非法（<=0）时按默认 30 天兜底。
func TestCleanupFallsBackToDefaultRetention(t *testing.T) {
	scheduler, mock, now := newCleanupSchedulerForTest(t, ModeObserve, 0, nil)
	cutoff := now.Add(-cleanupDefaultRetentionDays * 24 * time.Hour)

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_events WHERE id IN ("+
		"SELECT id FROM risk_gate_events WHERE created_at < $1 LIMIT $2)")).
		WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_refusals WHERE id IN ("+
		"SELECT id FROM risk_gate_refusals WHERE created_at < $1 LIMIT $2)")).
		WithArgs(cutoff, cleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_bans WHERE expires_at IS NOT NULL AND expires_at < $1")).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectAlignmentCleanup(mock, cutoff)

	if _, err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("默认保留天数未生效: %v", err)
	}
}

// 清理失败只记录错误，不 panic；下一次调度仍会执行。
func TestCleanupRecordsErrorAndStops(t *testing.T) {
	scheduler, mock, _ := newCleanupSchedulerForTest(t, ModeObserve, 7, &fakeIndexResetter{})

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_gate_events WHERE id IN (" +
		"SELECT id FROM risk_gate_events WHERE created_at < $1 LIMIT $2)")).
		WillReturnError(context.DeadlineExceeded)

	if _, err := scheduler.RunOnce(context.Background()); err == nil {
		t.Fatal("期望返回错误")
	}
	_, _, _, lastErr := scheduler.Stats()
	if lastErr == "" {
		t.Fatal("期望记录最后一次错误")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQL 期望未满足: %v", err)
	}
}

// Start/Shutdown 必须幂等，且 Shutdown 不阻塞过久。
func TestCleanupSchedulerStartShutdownIdempotent(t *testing.T) {
	scheduler, _, _ := newCleanupSchedulerForTest(t, ModeOff, 30, nil)
	// 首次延迟调大，避免测试里真的执行清理。
	scheduler.initialDelay = time.Hour

	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("重复 Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := scheduler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := scheduler.Shutdown(ctx); err != nil {
		t.Fatalf("重复 Shutdown: %v", err)
	}
}

// nil 接收者必须安全：引擎构造失败时会传入 typed nil。
func TestCleanupSchedulerNilReceiver(t *testing.T) {
	var scheduler *CleanupScheduler
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("nil Start: %v", err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatalf("nil Shutdown: %v", err)
	}
	result, err := scheduler.RunOnce(context.Background())
	if err != nil || !result.Skipped {
		t.Fatalf("nil RunOnce = %+v, %v", result, err)
	}
	if runs, deleted, last, lastErr := scheduler.Stats(); runs != 0 || deleted != 0 || last != nil || lastErr != "" {
		t.Fatalf("nil Stats = %d %d %+v %q", runs, deleted, last, lastErr)
	}
}

// fakeLifecycle 同时实现 starter / shutter。
type fakeLifecycle struct{ starts, stops int }

func (f *fakeLifecycle) Start(context.Context) error    { f.starts++; return nil }
func (f *fakeLifecycle) Shutdown(context.Context) error { f.stops++; return nil }

// NewEngine 必须接管 extras 里的 starter/shutter（清理调度器靠这条接入生命周期）。
func TestNewEngineRegistersCleanupLifecycle(t *testing.T) {
	extra := &fakeLifecycle{}
	engine, err := NewEngine(&fakeConfigSource{}, nil, nil, nil, nil, nil, extra, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(engine.starters) != 1 || len(engine.shutters) != 1 {
		t.Fatalf("extras 未注册 starters=%d shutters=%d", len(engine.starters), len(engine.shutters))
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := engine.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if extra.starts != 1 || extra.stops != 1 {
		t.Fatalf("extras 生命周期未执行 starts=%d stops=%d", extra.starts, extra.stops)
	}
}

func expectAlignmentCleanup(mock sqlmock.Sqlmock, cutoff time.Time) {
	mock.ExpectExec(`DELETE FROM risk_gate_decisions`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM risk_gate_classifier_usage`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 0))
}

func TestCleanupV2AlsoRetainsAlignmentLedgers(t *testing.T) {
	scheduler, mock, now := newCleanupSchedulerForTest(t, ModeObserve, 14, nil)
	cutoff := now.Add(-14 * 24 * time.Hour)
	mock.ExpectExec(`DELETE FROM risk_gate_events`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM risk_gate_refusals`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM risk_gate_bans`).WithArgs(cutoff).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM risk_gate_decisions`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, cleanupBatchSize))
	mock.ExpectExec(`DELETE FROM risk_gate_decisions`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`DELETE FROM risk_gate_classifier_usage`).WithArgs(cutoff, cleanupBatchSize).WillReturnResult(sqlmock.NewResult(0, 3))
	result, err := scheduler.RunOnce(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, cleanupBatchSize+2, result.Decisions)
	require.EqualValues(t, 3, result.ClassifierUsage)
	_, deleted, _, _ := scheduler.Stats()
	require.EqualValues(t, cleanupBatchSize+5, deleted)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCleanupAlignmentRejectsUnapprovedTable(t *testing.T) {
	scheduler, mock, now := newCleanupSchedulerForTest(t, ModeObserve, 14, nil)
	_, err := scheduler.cleanAlignmentTable(context.Background(), "risk_gate_classifier_totals", now)
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
