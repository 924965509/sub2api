package riskgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 事件写入缓冲参数。命中拦截时事件异步落库，绝不阻塞请求路径；
// 写库失败只降级为计数与内存中的最后错误，不影响请求结果。
const (
	eventQueueSize     = 1024
	eventBatchSize     = 200
	eventFlushInterval = time.Second
)

// EventSink 是事件写入端抽象。
type EventSink interface {
	Write(event Event)
}

// EventWriter 是 risk_gate_events 的批量异步写入器。
type EventWriter struct {
	db    *sql.DB
	clock Clock
	queue chan Event

	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	cancel    context.CancelFunc

	written atomic.Int64
	dropped atomic.Int64
	lastErr atomic.Pointer[string]
}

func NewEventWriter(db *sql.DB) *EventWriter {
	return &EventWriter{db: db, clock: realClock{}, queue: make(chan Event, eventQueueSize)}
}

// SetClock 注入测试时钟。
func (w *EventWriter) SetClock(clock Clock) {
	if w == nil || clock == nil {
		return
	}
	w.clock = clock
}

// Start 启动后台批量写入协程。
func (w *EventWriter) Start(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.ensureStarted(ctx)
	return nil
}

func (w *EventWriter) ensureStarted(ctx context.Context) {
	w.startOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}
		runCtx, cancel := context.WithCancel(ctx)
		w.cancel = cancel
		w.wg.Add(1)
		go w.loop(runCtx)
	})
}

// Write 非阻塞投递事件；队列满时丢事件并计数，保证请求路径永不阻塞。
func (w *EventWriter) Write(event Event) {
	if w == nil {
		return
	}
	if event.Kind == "" {
		event.Kind = EventKindBlocked
	}
	if event.Action == "" {
		event.Action = EventActionNone
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = w.clock.Now()
	}
	w.ensureStarted(context.Background())
	select {
	case w.queue <- event:
	default:
		w.dropped.Add(1)
	}
}

// Flush 等待队列排空（关闭与测试用）。
func (w *EventWriter) Flush(ctx context.Context) error {
	if w == nil {
		return nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(w.queue) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Shutdown 停止后台协程并把剩余事件写完。
func (w *EventWriter) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.stopOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
	})
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// Stats 返回已写入/丢弃数量与最后一次错误，供 status 展示。
func (w *EventWriter) Stats() (written, dropped int64, lastErr string) {
	if w == nil {
		return 0, 0, ""
	}
	if value := w.lastErr.Load(); value != nil {
		lastErr = *value
	}
	return w.written.Load(), w.dropped.Load(), lastErr
}

// loop 是批量写库循环：攒够 eventBatchSize 或超过 eventFlushInterval 即落库。
func (w *EventWriter) loop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(eventFlushInterval)
	defer ticker.Stop()
	batch := make([]Event, 0, eventBatchSize)
	writePending := func() {
		if len(batch) == 0 {
			return
		}
		w.insertBatch(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// 关闭前把队列里剩余事件尽量写完。
			for {
				select {
				case event := <-w.queue:
					batch = append(batch, event)
					if len(batch) >= eventBatchSize {
						writePending()
					}
				default:
					writePending()
					return
				}
			}
		case event := <-w.queue:
			batch = append(batch, event)
			if len(batch) >= eventBatchSize {
				writePending()
			}
		case <-ticker.C:
			writePending()
		}
	}
}

// insertBatch 一次性写入一批事件；失败只记录，不重试也不外抛。
func (w *EventWriter) insertBatch(ctx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}
	if w.db == nil {
		w.dropped.Add(int64(len(batch)))
		return
	}
	placeholders := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*25)
	for _, event := range batch {
		createdAt := event.CreatedAt
		if createdAt.IsZero() {
			createdAt = w.clock.Now()
		}
		scores, _ := json.Marshal(event.Scores)
		if event.Scores == nil {
			scores = []byte("{}")
		}
		values := []any{event.RequestID, nullableInt64(event.UserID), nullableInt64(event.APIKeyID), event.GroupID, event.Provider, event.Endpoint, event.Protocol, event.Model, event.Kind, event.Gate, nullableInt64(event.RuleID), event.Reason, event.Score, event.PromptHash, event.Evidence, event.Action, createdAt, event.Category, event.RuleKey, event.Pattern, event.ClientFingerprint, event.UserPreview, event.SubmittedText, string(scores), event.TerminalOutcome}
		p := make([]string, len(values))
		for i := range values {
			p[i] = placeholder(len(args) + i + 1)
		}
		placeholders = append(placeholders, "("+strings.Join(p, ",")+")")
		args = append(args, values...)
	}
	statement := "INSERT INTO risk_gate_events (request_id,user_id,api_key_id,group_id,provider,endpoint,protocol,model,kind,gate,rule_id,reason,score,prompt_hash,evidence,action,created_at,category,rule_key,pattern,client_fingerprint,user_preview,submitted_text,scores,terminal_outcome) VALUES " + strings.Join(placeholders, ",")
	// A cancelled request must not cancel the final buffered audit flush.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := w.db.ExecContext(ctx, statement, args...); err != nil {
		w.dropped.Add(int64(len(batch)))
		message := err.Error()
		w.lastErr.Store(&message)
		return
	}
	w.written.Add(int64(len(batch)))
}

func placeholder(index int) string {
	return "$" + strconv.Itoa(index)
}

func nullableInt64(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullableFloat(value float64) any {
	if value <= 0 {
		return nil
	}
	return value
}
