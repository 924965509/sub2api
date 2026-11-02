package riskgate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
)

type terminalRecord struct {
	Key, RequestID, Provider, Outcome, Reason, Gate, RuleKey string
	UserID, APIKeyID                                         int64
	WouldBlock                                               bool
	At                                                       time.Time
}
type UsageRecord struct {
	ID             int64     `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	RequestID      string    `json:"request_id"`
	Model          string    `json:"model"`
	KeyFingerprint string    `json:"key_fingerprint"`
	HTTPStatus     *int      `json:"http_status"`
	Outcome        string    `json:"outcome"`
	DurationMS     int64     `json:"duration_ms"`
	InputTokens    *int64    `json:"input_tokens"`
	OutputTokens   *int64    `json:"output_tokens"`
	Cost           *int64    `json:"estimated_cost_nano_usd"`
}
type auditJob struct {
	decision *terminalRecord
	usage    *UsageRecord
}
type AuditStore struct {
	db     *sql.DB
	queue  chan auditJob
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	errors atomic.Int64
	closed atomic.Bool
}

func NewAuditStore(db *sql.DB) *AuditStore {
	if db == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &AuditStore{db: db, queue: make(chan auditJob, 2048), cancel: cancel}
	s.wg.Add(1)
	go s.loop(ctx)
	return s
}
func (s *AuditStore) enqueue(job auditJob) {
	if s == nil || s.closed.Load() {
		return
	}
	select {
	case s.queue <- job:
	default:
		s.errors.Add(1)
	}
}
func (s *AuditStore) RecordUsage(row UsageRecord) {
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	s.enqueue(auditJob{usage: &row})
}
func (s *AuditStore) RecordDecision(req securityaudit.Request, outcome, reason string, hit GateResult, would bool, at time.Time) {
	if s == nil {
		return
	}
	stage := req.Stage
	if req.AuditTurn != "" {
		stage = req.AuditTurn
	}
	raw := req.RequestID + "\x00" + stage
	// Each websocket user turn has its own security-audit stage; body identity also
	// differentiates turn payloads while deduplicating provider retries of a turn.
	if strings.Contains(req.Protocol, "websocket") || req.RequestID == "" {
		digest := sha256.Sum256(req.Body)
		raw += "\x00" + hex.EncodeToString(digest[:])
	}
	if req.RequestID == "" {
		raw += fmt.Sprint(at.UnixNano())
	}
	hash := sha256.Sum256([]byte(raw))
	s.enqueue(auditJob{decision: &terminalRecord{Key: hex.EncodeToString(hash[:]), RequestID: req.RequestID, Provider: req.Provider, Outcome: outcome, Reason: reason, Gate: hit.Gate, RuleKey: hit.RuleKey, UserID: req.UserID, APIKeyID: req.APIKeyID, WouldBlock: would, At: at}})
}
func (s *AuditStore) loop(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case job := <-s.queue:
			s.persist(job)
		case <-ctx.Done():
			for {
				select {
				case job := <-s.queue:
					s.persist(job)
				default:
					return
				}
			}
		}
	}
}
func (s *AuditStore) persist(job auditJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var err error
	if d := job.decision; d != nil {
		_, err = s.db.ExecContext(ctx, `INSERT INTO risk_gate_decisions(decision_key,request_id,user_id,api_key_id,provider,outcome,reason,gate,rule_key,would_block,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(decision_key) DO UPDATE SET outcome=CASE WHEN risk_gate_decisions.outcome='blocked' THEN 'blocked' ELSE EXCLUDED.outcome END,reason=CASE WHEN risk_gate_decisions.outcome='blocked' THEN risk_gate_decisions.reason ELSE EXCLUDED.reason END,gate=CASE WHEN risk_gate_decisions.outcome='blocked' THEN risk_gate_decisions.gate ELSE EXCLUDED.gate END,rule_key=CASE WHEN risk_gate_decisions.outcome='blocked' THEN risk_gate_decisions.rule_key ELSE EXCLUDED.rule_key END,would_block=risk_gate_decisions.would_block OR EXCLUDED.would_block`, d.Key, d.RequestID, d.UserID, d.APIKeyID, d.Provider, d.Outcome, d.Reason, d.Gate, d.RuleKey, d.WouldBlock, d.At)
	}
	if u := job.usage; u != nil {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			err = e
		} else {
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `INSERT INTO risk_gate_classifier_usage(created_at,request_id,model,key_fingerprint,http_status,outcome,duration_ms,input_tokens,output_tokens,estimated_cost_nano_usd) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, u.CreatedAt, u.RequestID, u.Model, u.KeyFingerprint, u.HTTPStatus, u.Outcome, u.DurationMS, u.InputTokens, u.OutputTokens, u.Cost)
			if err == nil {
				success, unknownUsage, unknownCost := 0, 0, 0
				var in, out, cost int64
				if u.Outcome == "success" {
					success = 1
				}
				if u.InputTokens == nil || u.OutputTokens == nil {
					unknownUsage = 1
				}
				if u.InputTokens != nil {
					in = *u.InputTokens
				}
				if u.OutputTokens != nil {
					out = *u.OutputTokens
				}
				if u.Cost == nil {
					unknownCost = 1
				} else {
					cost = *u.Cost
				}
				_, err = tx.ExecContext(ctx, `UPDATE risk_gate_classifier_totals SET requests=requests+1,successful=successful+$1,input_tokens=input_tokens+$2,output_tokens=output_tokens+$3,unknown_usage_requests=unknown_usage_requests+$4,known_cost_nano_usd=known_cost_nano_usd+$5,unknown_cost_requests=unknown_cost_requests+$6 WHERE id=1`, success, in, out, unknownUsage, cost, unknownCost)
			}
			if err == nil {
				err = tx.Commit()
			}
		}
	}
	if err != nil {
		s.errors.Add(1)
	}
}
func (s *AuditStore) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.once.Do(func() { s.closed.Store(true); s.cancel() })
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type HitRow struct {
	Gate     string `json:"gate"`
	RuleID   int64  `json:"rule_id"`
	RuleKey  string `json:"rule_key"`
	Category string `json:"category"`
	Keyword  string `json:"keyword"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	Count    int64  `json:"count"`
}
type PassRow struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}
type RiskStats struct {
	Since         time.Time  `json:"since"`
	Until         time.Time  `json:"until"`
	Timezone      string     `json:"timezone"`
	Total         int64      `json:"total"`
	Blocked       int64      `json:"blocked"`
	Passed        int64      `json:"passed"`
	WouldBlock    int64      `json:"would_block"`
	Blocks        []HitRow   `json:"blocks"`
	Passes        []PassRow  `json:"passes"`
	CoverageStart *time.Time `json:"coverage_start"`
	StorageErrors int64      `json:"storage_errors"`
}

func auditWindow(from, to *time.Time, zone string) (time.Time, time.Time, *time.Location, error) {
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, time.Time{}, nil, invalidConfig("时区无效")
	}
	now := time.Now().In(loc)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	end := now
	if from != nil {
		start = *from
	}
	if to != nil {
		end = *to
	}
	if !end.After(start) || end.Sub(start) > 93*24*time.Hour {
		return start, end, loc, invalidConfig("统计时间范围必须大于零且不超过 93 天")
	}
	return start, end, loc, nil
}
func (s *AdminService) Stats(ctx context.Context, from, to *time.Time, zone string) (RiskStats, error) {
	start, end, loc, err := auditWindow(from, to, zone)
	if err != nil {
		return RiskStats{}, err
	}
	result := RiskStats{Since: start, Until: end, Timezone: loc.String(), Blocks: []HitRow{}, Passes: []PassRow{}}
	if s == nil || s.config == nil || s.config.db == nil {
		return result, invalidConfig("审计统计数据库不可用")
	}
	db := s.config.db
	err = db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE outcome='blocked'),COUNT(*) FILTER(WHERE outcome='passed'),COUNT(*) FILTER(WHERE would_block) FROM risk_gate_decisions WHERE created_at >=$1 AND created_at<$2`, start, end).Scan(&result.Total, &result.Blocked, &result.Passed, &result.WouldBlock)
	if err != nil {
		return result, err
	}
	var first sql.NullTime
	if err = db.QueryRowContext(ctx, `SELECT MIN(created_at) FROM risk_gate_decisions`).Scan(&first); err != nil {
		return result, err
	}
	if first.Valid {
		result.CoverageStart = &first.Time
	}
	rows, err := db.QueryContext(ctx, `SELECT gate,COALESCE(rule_id,0),rule_key,category,evidence,pattern,action,COUNT(*) FROM risk_gate_events WHERE created_at >=$1 AND created_at<$2 AND kind='blocked' GROUP BY gate,rule_id,rule_key,category,evidence,pattern,action ORDER BY COUNT(*) DESC LIMIT 200`, start, end)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var row HitRow
		if err = rows.Scan(&row.Gate, &row.RuleID, &row.RuleKey, &row.Category, &row.Keyword, &row.Pattern, &row.Action, &row.Count); err != nil {
			rows.Close()
			return result, err
		}
		result.Blocks = append(result.Blocks, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = db.QueryContext(ctx, `SELECT reason,COUNT(*) FROM risk_gate_decisions WHERE created_at >=$1 AND created_at<$2 AND outcome='passed' GROUP BY reason ORDER BY COUNT(*) DESC`, start, end)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var row PassRow
		if err = rows.Scan(&row.Reason, &row.Count); err != nil {
			return result, err
		}
		result.Passes = append(result.Passes, row)
	}
	if s.engine != nil && s.engine.audit != nil {
		result.StorageErrors = s.engine.audit.errors.Load()
	}
	return result, rows.Err()
}

type UsageSummary struct {
	Requests     int64  `json:"requests"`
	Successful   int64  `json:"successful"`
	Input        int64  `json:"input_tokens"`
	Output       int64  `json:"output_tokens"`
	UnknownUsage int64  `json:"unknown_usage_requests"`
	Cost         *int64 `json:"estimated_cost_nano_usd"`
	UnknownCost  int64  `json:"unknown_cost_requests"`
}
type UsagePage struct {
	Items         []UsageRecord `json:"items"`
	Total         int64         `json:"total"`
	Page          int           `json:"page"`
	PageSize      int           `json:"page_size"`
	Pages         int           `json:"pages"`
	Summary       UsageSummary  `json:"summary"`
	Today         UsageSummary  `json:"today"`
	StartedAt     *time.Time    `json:"started_at"`
	StorageErrors int64         `json:"storage_errors_since_start"`
}

func (s *AdminService) ClassifierUsage(ctx context.Context, page, size int, from, to *time.Time, zone string) (UsagePage, error) {
	page, size = normalizeEventPage(page, size)
	result := UsagePage{Items: []UsageRecord{}, Page: page, PageSize: size}
	if s == nil || s.config == nil || s.config.db == nil {
		return result, invalidConfig("审计用量数据库不可用")
	}
	db := s.config.db
	var cost int64
	var started time.Time
	err := db.QueryRowContext(ctx, `SELECT started_at,requests,successful,input_tokens,output_tokens,unknown_usage_requests,known_cost_nano_usd,unknown_cost_requests FROM risk_gate_classifier_totals WHERE id=1`).Scan(&started, &result.Summary.Requests, &result.Summary.Successful, &result.Summary.Input, &result.Summary.Output, &result.Summary.UnknownUsage, &cost, &result.Summary.UnknownCost)
	if err != nil {
		return result, err
	}
	result.StartedAt = &started
	if result.Summary.Requests > result.Summary.UnknownCost {
		result.Summary.Cost = &cost
	}
	start, end, _, err := auditWindow(nil, nil, zone)
	if err != nil {
		return result, err
	}
	var todayCost sql.NullInt64
	err = db.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE outcome='success'),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COUNT(*) FILTER(WHERE input_tokens IS NULL OR output_tokens IS NULL),SUM(estimated_cost_nano_usd),COUNT(*) FILTER(WHERE estimated_cost_nano_usd IS NULL) FROM risk_gate_classifier_usage WHERE created_at >=$1 AND created_at<$2`, start, end).Scan(&result.Today.Requests, &result.Today.Successful, &result.Today.Input, &result.Today.Output, &result.Today.UnknownUsage, &todayCost, &result.Today.UnknownCost)
	if err != nil {
		return result, err
	}
	if todayCost.Valid {
		result.Today.Cost = &todayCost.Int64
	}
	condition := "WHERE TRUE"
	args := []any{}
	if from != nil {
		args = append(args, *from)
		condition += " AND created_at >=" + placeholder(len(args))
	}
	if to != nil {
		args = append(args, *to)
		condition += " AND created_at <" + placeholder(len(args))
	}
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM risk_gate_classifier_usage `+condition, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	result.Pages = int((result.Total + int64(size) - 1) / int64(size))
	rows, err := db.QueryContext(ctx, `SELECT id,created_at,request_id,model,key_fingerprint,http_status,outcome,duration_ms,input_tokens,output_tokens,estimated_cost_nano_usd FROM risk_gate_classifier_usage `+condition+` ORDER BY created_at DESC,id DESC LIMIT `+placeholder(len(args)+1)+` OFFSET `+placeholder(len(args)+2), append(args, size, (page-1)*size)...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var row UsageRecord
		if err = rows.Scan(&row.ID, &row.CreatedAt, &row.RequestID, &row.Model, &row.KeyFingerprint, &row.HTTPStatus, &row.Outcome, &row.DurationMS, &row.InputTokens, &row.OutputTokens, &row.Cost); err != nil {
			return result, err
		}
		result.Items = append(result.Items, row)
	}
	if s.engine != nil && s.engine.audit != nil {
		result.StorageErrors = s.engine.audit.errors.Load()
	}
	return result, rows.Err()
}
