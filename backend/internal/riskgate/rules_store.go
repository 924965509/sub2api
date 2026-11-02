package riskgate

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// rulesCacheTTL 是面板自定义规则的进程内缓存时长：规则变化不频繁，
// 30s 缓存既能让改动快速生效，也不会每请求打库。
const rulesCacheTTL = 30 * time.Second

// RuleSource 是自定义规则来源抽象。
type RuleSource interface {
	Rules(ctx context.Context) ([]Rule, error)
}

// RuleStore 读取 risk_gate_rules（gate=regex / gate=distill 的自定义规则）。
// 无自定义规则时（默认部署）只会在闸门真正启用后才查一次库。
type RuleStore struct {
	policyMu       sync.Mutex
	policySnapshot *RuleSet
	policyLoadedAt time.Time
	db             *sql.DB
	clock          Clock

	mu       sync.Mutex
	cached   []Rule
	loadedAt time.Time
	loaded   bool
	lastErr  string
}

func NewRuleStore(db *sql.DB) *RuleStore {
	return &RuleStore{db: db, clock: realClock{}}
}

// SetClock 注入测试时钟。
func (s *RuleStore) SetClock(clock Clock) {
	if s == nil || clock == nil {
		return
	}
	s.clock = clock
}

func (s *RuleStore) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now()
}

// Rules 返回启用中的规则；失败时回落到上次成功缓存的结果。
func (s *RuleStore) Rules(ctx context.Context) ([]Rule, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	now := s.now()
	s.mu.Lock()
	if s.loaded && now.Sub(s.loadedAt) < rulesCacheTTL {
		cached := s.cached
		s.mu.Unlock()
		return cached, nil
	}
	s.mu.Unlock()

	rules, err := s.query(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err.Error()
		return s.cached, err
	}
	s.cached = rules
	s.loadedAt = now
	s.loaded = true
	s.lastErr = ""
	return rules, nil
}

// LastError 返回最近一次查询失败原因。
func (s *RuleStore) LastError() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func (s *RuleStore) query(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, gate, category, pattern, is_regex, action, enabled, sort_order, description
		FROM risk_gate_rules
		WHERE enabled = TRUE AND gate IN ('regex', 'distill')
		ORDER BY gate, sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	rules := make([]Rule, 0, 16)
	for rows.Next() {
		var rule Rule
		if err := rows.Scan(&rule.ID, &rule.Gate, &rule.Category, &rule.Pattern, &rule.IsRegex,
			&rule.Action, &rule.Enabled, &rule.SortOrder, &rule.Description); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// RuleAdmin 是规则的管理端读写接口（*RuleStore 同时实现 RuleSource 与 RuleAdmin）。
type RuleAdmin interface {
	// ListAll 返回全部规则（含停用），按 gate, sort_order, id 排序。
	ListAll(ctx context.Context) ([]Rule, error)
	// Replace 在一个事务内全量替换规则表，返回落库结果（带自增 id）。
	Replace(ctx context.Context, rules []Rule) ([]Rule, error)
}

// 规则校验的取值集合与上限。
var (
	ruleAdminGates      = []string{GateRegex, GateDistill}
	ruleAdminCategories = []string{CategoryDistill, CategorySexual, CategoryJailbreak, CategoryBypass, CategoryCustom, "nsfw", "crack"}
)

const (
	// maxAdminRules 是规则总数上限：单进程每次全量加载，太多会拖慢热路径。
	maxAdminRules = 200
	// maxRulePatternBytes 是单条 pattern 的长度上限。
	maxRulePatternBytes = 2048
)

// ListAll 读取全部规则（含 enabled=false）。管理端只看当前落库内容，走短查询。
func (s *RuleStore) ListAll(ctx context.Context) ([]Rule, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, gate, category, pattern, is_regex, action, enabled, sort_order, description
		FROM risk_gate_rules
		ORDER BY gate, sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	rules := make([]Rule, 0, 16)
	for rows.Next() {
		var rule Rule
		if err := rows.Scan(&rule.ID, &rule.Gate, &rule.Category, &rule.Pattern, &rule.IsRegex,
			&rule.Action, &rule.Enabled, &rule.SortOrder, &rule.Description); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// Replace retains the historical endpoint while using the same stable-identity
// transaction and version conflict protection as the new ruleset editor.
func (s *RuleStore) Replace(ctx context.Context, rules []Rule) ([]Rule, error) {
	normalized, err := normalizeAdminRules(rules)
	if err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		for i := range normalized {
			normalized[i].ID = int64(i + 1)
		}
		return normalized, nil
	}
	var version int64
	if err = s.db.QueryRowContext(ctx, `SELECT version FROM risk_gate_ruleset WHERE id=1`).Scan(&version); err != nil {
		return nil, err
	}
	saved, err := s.SaveRuleSet(ctx, version, normalized, false)
	return saved.Rules, err
}

// invalidateCache 清空规则缓存，下一个请求重新查库。
func (s *RuleStore) invalidateCache() {
	if s == nil {
		return
	}
	s.policyMu.Lock()
	s.policySnapshot = nil
	s.policyLoadedAt = time.Time{}
	s.policyMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = nil
	s.loaded = false
	s.loadedAt = time.Time{}
}

// normalizeAdminRules 校验并规范一批规则；任何非法输入返回 400。
func normalizeAdminRules(rules []Rule) ([]Rule, error) {
	if len(rules) > maxAdminRules {
		return nil, invalidRule(fmt.Sprintf("规则总数不能超过 %d 条", maxAdminRules))
	}
	normalized := make([]Rule, 0, len(rules))
	for index, rule := range rules {
		position := index + 1
		rule.Gate = strings.ToLower(strings.TrimSpace(rule.Gate))
		if !slices.Contains(ruleAdminGates, rule.Gate) {
			return nil, invalidRule(fmt.Sprintf("第 %d 条规则的 gate 必须是 regex / distill", position))
		}
		rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
		if !slices.Contains(ruleAdminCategories, rule.Category) {
			return nil, invalidRule(fmt.Sprintf("第 %d 条规则的 category 非法: %s", position, rule.Category))
		}
		rule.Pattern = strings.TrimSpace(rule.Pattern)
		if rule.Pattern == "" {
			return nil, invalidRule(fmt.Sprintf("第 %d 条规则的 pattern 不能为空", position))
		}
		if len(rule.Pattern) > maxRulePatternBytes {
			return nil, invalidRule(fmt.Sprintf("第 %d 条规则的 pattern 超过 %d 字节", position, maxRulePatternBytes))
		}
		if rule.IsRegex {
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return nil, invalidRule(fmt.Sprintf("第 %d 条规则的正则非法: %s (%v)", position, truncateRunes(rule.Pattern, 64), err))
			}
		}
		rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
		if rule.Action == "" {
			rule.Action = "block"
		}
		if !slices.Contains([]string{"block", "observe"}, rule.Action) {
			return nil, invalidRule(fmt.Sprintf("第 %d 条规则的 action 必须是 block / observe", position))
		}
		rule.Description = strings.TrimSpace(rule.Description)
		normalized = append(normalized, rule)
	}
	return normalized, nil
}

// invalidRule 构造规则校验失败错误（400 + risk_gate_invalid_rule）。
func invalidRule(message string) error {
	return infraerrors.BadRequest(ErrorCodeInvalidRule, message)
}
