package riskgate

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 清理任务的参数：首次延迟 5 分钟（避开启动高峰），之后每 6 小时一次，
// 单批 5000 行、最多 200 批，避免长事务把库拖住。
const (
	cleanupInitialDelay = 5 * time.Minute
	cleanupInterval     = 6 * time.Hour
	cleanupBatchSize    = 5000
	cleanupMaxBatches   = 200
	cleanupQueryTimeout = 30 * time.Second
	// cleanupDefaultRetentionDays 在配置里没有可用值时兜底。
	cleanupDefaultRetentionDays = 30
)

// CleanupResult 汇总一次清理的影响行数。
type CleanupResult struct {
	// Skipped 表示本次没有执行（配置未就绪或 mode=off）。
	Skipped         bool
	Events          int64
	Refusals        int64
	Bans            int64
	Decisions       int64
	ClassifierUsage int64
	At              time.Time
}

// RefusalIndexResetter 是拒答语料索引的重置接口（清理后必须让内存索引失效）。
type RefusalIndexResetter interface {
	ResetIndex()
}

// CleanupScheduler 按配置的 retention_days 定期清理 risk_gate_events /
// risk_gate_refusals / 过期封禁。
//
// 语义约定：
//   - mode=off 时整体跳过：默认部署不产生数据，也不需要动数据库；
//   - 清理按批进行，单批失败只记录错误并停止，不影响下一次调度；
//   - 清理不是安全边界，失败也只是数据留久一点，绝不 panic 或阻塞启动。
type CleanupScheduler struct {
	db       *sql.DB
	config   ConfigSource
	refusals RefusalIndexResetter
	clock    Clock

	initialDelay time.Duration
	interval     time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	cancel    context.CancelFunc

	runs     atomic.Int64
	deleted  atomic.Int64
	lastErr  atomic.Pointer[string]
	lastRun  atomic.Pointer[CleanupResult]
	lastTime atomic.Pointer[time.Time]
}

func NewCleanupScheduler(db *sql.DB, config ConfigSource, refusals RefusalIndexResetter) *CleanupScheduler {
	return &CleanupScheduler{
		db: db, config: config, refusals: refusals, clock: realClock{},
		initialDelay: cleanupInitialDelay, interval: cleanupInterval,
	}
}

// SetClock 注入测试时钟。
func (s *CleanupScheduler) SetClock(clock Clock) {
	if s == nil || clock == nil {
		return
	}
	s.clock = clock
}

func (s *CleanupScheduler) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now()
}

// Start 启动后台调度协程（首次延迟 initialDelay，之后按 interval 重复）。
func (s *CleanupScheduler) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.startOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}
		runCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel
		s.wg.Add(1)
		go s.loop(runCtx)
	})
	return nil
}

// Shutdown 停止调度协程。
func (s *CleanupScheduler) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (s *CleanupScheduler) loop(ctx context.Context) {
	defer s.wg.Done()
	initial := time.NewTimer(s.duration(s.initialDelay))
	defer initial.Stop()
	select {
	case <-ctx.Done():
		return
	case <-initial.C:
	}
	ticker := time.NewTicker(s.duration(s.interval))
	defer ticker.Stop()
	for {
		if _, err := s.RunOnce(ctx); err != nil {
			s.recordError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *CleanupScheduler) duration(value time.Duration) time.Duration {
	if value <= 0 {
		return cleanupInterval
	}
	return value
}

// RunOnce 执行一次清理，返回影响行数；mode=off 或配置未就绪时直接跳过。
func (s *CleanupScheduler) RunOnce(ctx context.Context) (CleanupResult, error) {
	result := CleanupResult{At: s.now()}
	if s == nil || s.db == nil || s.config == nil {
		result.Skipped = true
		return result, nil
	}
	cfg, _, ok := s.config.Current()
	if !ok || cfg.EffectiveMode() == ModeOff {
		// 默认部署（mode=off）不产生任何数据，也就没有必要动数据库。
		result.Skipped = true
		s.storeResult(result)
		return result, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	days := cfg.RetentionDays
	if days <= 0 {
		days = cleanupDefaultRetentionDays
	}
	cutoff := s.now().Add(-time.Duration(days) * 24 * time.Hour)

	events, err := s.deleteInBatches(ctx, "risk_gate_events", cutoff)
	result.Events = events
	if err != nil {
		s.recordError(err)
		s.storeResult(result)
		return result, err
	}
	refusals, err := s.deleteInBatches(ctx, "risk_gate_refusals", cutoff)
	result.Refusals = refusals
	if refusals > 0 && s.refusals != nil {
		// 语料被删掉后必须让内存索引失效，否则闸门还会按旧索引命中。
		s.refusals.ResetIndex()
	}
	if err != nil {
		s.recordError(err)
		s.storeResult(result)
		return result, err
	}
	bans, err := s.db.ExecContext(ctx,
		`DELETE FROM risk_gate_bans WHERE expires_at IS NOT NULL AND expires_at < $1`, cutoff)
	if err != nil {
		s.recordError(err)
		s.storeResult(result)
		return result, err
	}
	if affected, affectedErr := bans.RowsAffected(); affectedErr == nil {
		result.Bans = affected
	}
	// Retain bounded detail tables, but never delete the cumulative model totals.
	result.Decisions, err = s.cleanAlignmentTable(ctx, "risk_gate_decisions", cutoff)
	if err == nil {
		result.ClassifierUsage, err = s.cleanAlignmentTable(ctx, "risk_gate_classifier_usage", cutoff)
	}
	if err != nil {
		s.recordError(err)
		s.storeResult(result)
		return result, err
	}
	s.storeResult(result)
	return result, nil
}

// deleteInBatches 分批删除过期行：每批 cleanupBatchSize，最多 cleanupMaxBatches 批。
func (s *CleanupScheduler) deleteInBatches(ctx context.Context, table string, cutoff time.Time) (int64, error) {
	// 表名来自内部常量，不接受外部输入。
	statement := "DELETE FROM " + table + " WHERE id IN (" +
		"SELECT id FROM " + table + " WHERE created_at < $1 LIMIT $2)"
	total := int64(0)
	for batch := 0; batch < cleanupMaxBatches; batch++ {
		outcome, err := s.db.ExecContext(ctx, statement, cutoff, cleanupBatchSize)
		if err != nil {
			return total, err
		}
		affected, err := outcome.RowsAffected()
		if err != nil {
			return total, nil
		}
		total += affected
		if affected < cleanupBatchSize {
			break
		}
	}
	return total, nil
}

// ResetIndex 让拒答语料的内存索引立即失效，下次匹配重新从库里加载。
func (s *RefusalStore) ResetIndex() {
	if s == nil {
		return
	}
	s.resetIndex()
}

func (s *CleanupScheduler) storeResult(result CleanupResult) {
	if s == nil {
		return
	}
	s.runs.Add(1)
	s.deleted.Add(result.Events + result.Refusals + result.Bans + result.Decisions + result.ClassifierUsage)
	now := result.At
	s.lastRun.Store(&result)
	s.lastTime.Store(&now)
}

func (s *CleanupScheduler) recordError(err error) {
	if s == nil || err == nil {
		return
	}
	message := err.Error()
	s.lastErr.Store(&message)
}

// Stats 返回调度统计与最后一次结果，供 status/日志展示。
func (s *CleanupScheduler) Stats() (runs, deleted int64, last *CleanupResult, lastErr string) {
	if s == nil {
		return 0, 0, nil, ""
	}
	if value := s.lastErr.Load(); value != nil {
		lastErr = *value
	}
	return s.runs.Load(), s.deleted.Load(), s.lastRun.Load(), lastErr
}

// Keep bounded details while the independent model totals survive retention.
func (s *CleanupScheduler) cleanAlignmentTable(ctx context.Context, table string, cutoff time.Time) (int64, error) {
	key := "id"
	if table == "risk_gate_decisions" {
		key = "decision_key"
	} else if table != "risk_gate_classifier_usage" {
		return 0, fmt.Errorf("invalid alignment cleanup table: %s", table)
	}
	statement := fmt.Sprintf("DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE created_at < $1 ORDER BY %s LIMIT $2)", table, key, key, table, key)
	var total int64
	for batch := 0; batch < cleanupMaxBatches; batch++ {
		callCtx, cancel := context.WithTimeout(ctx, cleanupQueryTimeout)
		result, err := s.db.ExecContext(callCtx, statement, cutoff, cleanupBatchSize)
		cancel()
		if err != nil {
			return total, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(cleanupBatchSize) {
			return total, nil
		}
	}
	return total, nil
}
