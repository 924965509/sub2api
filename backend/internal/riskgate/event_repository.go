package riskgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// 事件列表的分页上下界：管理端一页最多 200 条，避免一次拉爆事件表。
const (
	eventListDefaultPageSize = 50
	eventListMaxPageSize     = 200
)

// EventFilter 是 risk_gate_events 的查询/删除过滤条件。
//
// 注意：Page/PageSize 只影响列表读取，不影响 CountByFilter / DeleteByFilter，
// 两者共用同一套 WHERE 构造，保证「先预览再删」数量一致。
type EventFilter struct {
	Reason     string
	Action     string
	RuleID     int64
	View       string
	Kind       string
	Gate       string
	Provider   string
	RequestID  string
	PromptHash string
	UserID     int64
	APIKeyID   int64
	GroupID    *int64
	// From/To 是闭开区间：created_at >= From AND created_at < To。
	From, To       *time.Time
	Page, PageSize int
}

// HasCondition 报告过滤条件里是否至少有一个真正的筛选条件。
// 批量删除必须要求 true，避免误清空全表。
func (f EventFilter) HasCondition() bool {
	return f.Reason != "" || f.Action != "" || f.RuleID > 0 || f.View != "" || strings.TrimSpace(f.Kind) != "" || strings.TrimSpace(f.Gate) != "" ||
		strings.TrimSpace(f.Provider) != "" || strings.TrimSpace(f.RequestID) != "" ||
		strings.TrimSpace(f.PromptHash) != "" || f.UserID > 0 || f.APIKeyID > 0 ||
		f.GroupID != nil || f.From != nil || f.To != nil
}

// EventRow 是管理端展示的一行事件（与 Event 同字段，另带自增 id）。
type EventRow struct {
	Category          string             `json:"category"`
	RuleKey           string             `json:"rule_key"`
	Pattern           string             `json:"pattern"`
	ClientFingerprint string             `json:"client_fingerprint"`
	UserPreview       string             `json:"user_preview"`
	SubmittedText     string             `json:"submitted_text"`
	Scores            map[string]float64 `json:"scores"`
	TerminalOutcome   string             `json:"terminal_outcome"`
	ID                int64              `json:"id"`
	RequestID         string             `json:"request_id"`
	UserID            int64              `json:"user_id"`
	APIKeyID          int64              `json:"api_key_id"`
	GroupID           *int64             `json:"group_id,omitempty"`
	Provider          string             `json:"provider"`
	Endpoint          string             `json:"endpoint"`
	Protocol          string             `json:"protocol"`
	Model             string             `json:"model"`
	Kind              string             `json:"kind"`
	Gate              string             `json:"gate"`
	RuleID            int64              `json:"rule_id"`
	Reason            string             `json:"reason"`
	Score             float64            `json:"score"`
	PromptHash        string             `json:"prompt_hash"`
	Evidence          string             `json:"evidence"`
	Action            string             `json:"action"`
	CreatedAt         time.Time          `json:"created_at"`
}

// EventAdmin 是事件的管理端只读/删除接口。
type EventAdmin interface {
	List(ctx context.Context, filter EventFilter) ([]EventRow, int64, error)
	Get(ctx context.Context, id int64) (*EventRow, error)
	CountByFilter(ctx context.Context, filter EventFilter) (int64, error)
	DeleteByFilter(ctx context.Context, filter EventFilter) (int64, error)
}

// EventRepository 读取/删除 risk_gate_events；写入仍由 EventWriter 异步批量完成。
type EventRepository struct {
	db *sql.DB
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

// normalizeEventPage 规范化分页参数。
func normalizeEventPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = eventListDefaultPageSize
	}
	if pageSize > eventListMaxPageSize {
		pageSize = eventListMaxPageSize
	}
	return page, pageSize
}

// eventWhere 拼装事件过滤的 WHERE 子句（List / Count / Delete 共用）。
func eventWhere(filter EventFilter) (string, []any) {
	clauses := make([]string, 0, 10)
	args := make([]any, 0, 10)
	addString := func(column, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		args = append(args, value)
		clauses = append(clauses, column+" = "+placeholder(len(args)))
	}
	addString("reason", filter.Reason)
	addString("action", filter.Action)
	if filter.RuleID > 0 {
		args = append(args, filter.RuleID)
		clauses = append(clauses, "rule_id = "+placeholder(len(args)))
	}
	if filter.View == "pass" {
		clauses = append(clauses, "kind IN ('upstream_pass','upstream_refusal')")
	} else if filter.View != "" {
		clauses = append(clauses, "kind = 'blocked'")
		if gate := map[string]string{"distill": "distill", "hard-regex": "regex", "refusal": "refusal_cache", "jev": "decision_model"}[filter.View]; gate != "" && filter.Gate == "" {
			addString("gate", gate)
		}
	}
	addString("kind", filter.Kind)
	addString("gate", filter.Gate)
	addString("provider", filter.Provider)
	addString("request_id", filter.RequestID)
	addString("prompt_hash", filter.PromptHash)
	if filter.UserID > 0 {
		args = append(args, filter.UserID)
		clauses = append(clauses, "user_id = "+placeholder(len(args)))
	}
	if filter.APIKeyID > 0 {
		args = append(args, filter.APIKeyID)
		clauses = append(clauses, "api_key_id = "+placeholder(len(args)))
	}
	if filter.GroupID != nil {
		args = append(args, *filter.GroupID)
		clauses = append(clauses, "group_id = "+placeholder(len(args)))
	}
	if filter.From != nil {
		args = append(args, *filter.From)
		clauses = append(clauses, "created_at >= "+placeholder(len(args)))
	}
	if filter.To != nil {
		args = append(args, *filter.To)
		clauses = append(clauses, "created_at < "+placeholder(len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// List 返回当前页事件与总数，排序固定为 created_at DESC, id DESC。
func (r *EventRepository) List(ctx context.Context, filter EventFilter) ([]EventRow, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, nil
	}
	condition, args := eventWhere(filter)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM risk_gate_events `+condition, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	page, pageSize := normalizeEventPage(filter.Page, filter.PageSize)
	query := `SELECT id, request_id, user_id, api_key_id, group_id, provider, endpoint, protocol, model,
		kind, gate, rule_id, reason, score, prompt_hash, evidence, action, created_at, category, rule_key, pattern, client_fingerprint, user_preview, submitted_text, scores, terminal_outcome
		FROM risk_gate_events ` + condition +
		` ORDER BY created_at DESC, id DESC LIMIT ` + placeholder(len(args)+1) + ` OFFSET ` + placeholder(len(args)+2)
	rows, err := r.db.QueryContext(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	list := make([]EventRow, 0, pageSize)
	for rows.Next() {
		row, err := scanEventRow(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// Get 读取单条事件；不存在返回 (nil, nil)，由 handler 转成 404。
func (r *EventRepository) Get(ctx context.Context, id int64) (*EventRow, error) {
	if r == nil || r.db == nil || id <= 0 {
		return nil, nil
	}
	row := r.db.QueryRowContext(ctx, `SELECT id, request_id, user_id, api_key_id, group_id, provider, endpoint, protocol, model,
		kind, gate, rule_id, reason, score, prompt_hash, evidence, action, created_at, category, rule_key, pattern, client_fingerprint, user_preview, submitted_text, scores, terminal_outcome
		FROM risk_gate_events WHERE id = $1`, id)
	event, err := scanEventRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// CountByFilter 统计符合条件的事件数（删除前预览）。
func (r *EventRepository) CountByFilter(ctx context.Context, filter EventFilter) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	condition, args := eventWhere(filter)
	var total int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM risk_gate_events `+condition, args...).Scan(&total)
	return total, err
}

// DeleteByFilter 按条件删除事件并返回删除行数。
func (r *EventRepository) DeleteByFilter(ctx context.Context, filter EventFilter) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	condition, args := eventWhere(filter)
	result, err := r.db.ExecContext(ctx, `DELETE FROM risk_gate_events `+condition, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// rowScanner 抽象 *sql.Row / *sql.Rows 的 Scan，供单条与列表复用。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanEventRow 把一行结果扫描成 EventRow；score/rule_id 可能为空。
func scanEventRow(scanner rowScanner) (EventRow, error) {
	var row EventRow
	var scores []byte
	var userID, apiKeyID, groupID, ruleID sql.NullInt64
	var score sql.NullFloat64
	if err := scanner.Scan(&row.ID, &row.RequestID, &userID, &apiKeyID, &groupID,
		&row.Provider, &row.Endpoint, &row.Protocol, &row.Model,
		&row.Kind, &row.Gate, &ruleID, &row.Reason, &score,
		&row.PromptHash, &row.Evidence, &row.Action, &row.CreatedAt, &row.Category, &row.RuleKey, &row.Pattern, &row.ClientFingerprint, &row.UserPreview, &row.SubmittedText, &scores, &row.TerminalOutcome); err != nil {
		return EventRow{}, err
	}
	if userID.Valid {
		_ = json.Unmarshal(scores, &row.Scores)
		row.UserID = userID.Int64
	}
	if apiKeyID.Valid {
		row.APIKeyID = apiKeyID.Int64
	}
	if groupID.Valid {
		value := groupID.Int64
		row.GroupID = &value
	}
	if ruleID.Valid {
		row.RuleID = ruleID.Int64
	}
	if score.Valid {
		row.Score = score.Float64
	}
	return row, nil
}
