package riskgate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// BuiltinRules is a Go/RE2 implementation of the reference policy categories.
// Stable keys, rather than SQL row positions, identify shipped rules in history.
func BuiltinRules() []Rule {
	specs := [][2]string{
		{"jailbreak", `\b(jailbreak|dan)\s+mode\b`},
		{"jailbreak", `\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)\b`},
		{"jailbreak", `\b(bypass|disable|remove)\s+(your\s+|the\s+|all\s+)?(safety|content)\s+(filters?|policies|restrictions|limits)\b`},
		{"jailbreak", `(解除|关闭|绕过|无视)(你的|所有|全部)?(安全|内容)?(限制|审查|过滤|策略)`},
		{"jailbreak", `(越狱|破限)(模式|提示词|提示|指令)`},
		{"crack", `(^|[^\w-])(keygen|warez)($|[^\w-])`},
		{"crack", `(破解补丁|注册机|激活码生成器)`},
		{"crack", `\bcrack(ing)?\s+(this\s+|the\s+)?(software|license|drm|activation)\b`},
		{"nsfw", `\b(write|generate|describe)\s+(an?\s+)?(explicit|pornographic)\s+(sex|sexual)\b`},
		{"nsfw", `(生成|写一段|描述)(露骨|色情)(内容|小说|场景)`},
		{"distill", `\bdistill(ation|ing)?\s+(of\s+)?((the|your|a|an|reusable|durable|rollout|hidden|internal|full|complete)\s+)?(reasoning(\s+traces?)?|chain[- ]of[- ]thoughts?|teacher(\s+model)?)\b`},
		{"distill", `\b(extract|export|dump|reveal|harvest|exfiltrate)(ing|ed|ion|s)?\s+((the|your|a|an|full|hidden|internal|complete|raw|durable|entire)\s+){0,4}(chain[- ]of[- ]thoughts?|reasoning\s+traces?|hidden\s+reasoning|internal\s+reasoning|internal\s+monologues?)\b`},
		{"distill", `\b(chain[- ]of[- ]thought|reasoning\s+trace)\s+extraction\b`},
		{"distill", `(思维链蒸馏|推理蒸馏|思考链蒸馏)`},
		{"distill", `(提取|导出|抽取|蒸馏|收割|扒取)\s*(出|取)?\s*(你的|本人的|完整|全部|隐藏|内部)?\s*的?\s*(思维链|思考链|推理链)`},
		{"distill", `(思维链|思考链|推理链)\s*的?\s*(提取|导出|抽取|蒸馏|收割)`},
		{"distill", `(提取|导出|抽取)\s*出?\s*(隐藏|内部)\s*的?\s*(推理|思维|思考)`},
		{"custom", `\bphishing\s+kit\b`},
	}
	result := make([]Rule, 0, len(specs))
	for i, s := range specs {
		result = append(result, Rule{Gate: GateRegex, Category: s[0], Pattern: s[1], IsRegex: true, Action: "block", Enabled: true, SortOrder: i, RuleKey: fmt.Sprintf("builtin-%s-%02d", s[0], i+1), Builtin: true})
	}
	return result
}
func canonicalCategory(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sexual":
		return "nsfw"
	case "bypass":
		return "crack"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

type RuleSet struct {
	Version      int64  `json:"version"`
	Rules        []Rule `json:"rules"`
	BuiltinRules []Rule `json:"builtin_rules"`
	Customized   bool   `json:"customized"`
}
type RuleValidationError struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}
type RuleMatch struct {
	Index       int    `json:"index"`
	RuleID      int64  `json:"rule_id,omitempty"`
	MatchedText string `json:"matched_text"`
}
type RuleValidation struct {
	Valid   bool                  `json:"valid"`
	Errors  []RuleValidationError `json:"errors"`
	Matches []RuleMatch           `json:"matches"`
}

func ValidateRuleSet(rules []Rule, text string) RuleValidation {
	result := RuleValidation{Valid: true, Errors: []RuleValidationError{}, Matches: []RuleMatch{}}
	if len(rules) > maxAdminRules {
		result.Valid = false
		result.Errors = append(result.Errors, RuleValidationError{-1, "最多支持 200 条规则"})
		return result
	}
	cache := newRegexCache()
	text = truncateBytes(text, DefaultRegexMaxInputBytes)
	for i, rule := range rules {
		if _, err := normalizeAdminRules([]Rule{rule}); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, RuleValidationError{i, err.Error()})
			continue
		}
		if rule.Enabled && text != "" {
			if matched, hit := matchRule(rule, text, cache); hit {
				result.Matches = append(result.Matches, RuleMatch{i, rule.ID, redactEvidence(matched, 512)})
			}
		}
	}
	return result
}
func (s *RuleStore) RuleSet(ctx context.Context) (RuleSet, error) {
	result := RuleSet{Rules: []Rule{}, BuiltinRules: BuiltinRules()}
	if s == nil || s.db == nil {
		result.Rules = BuiltinRules()
		return result, nil
	}
	if err := s.db.QueryRowContext(ctx, `SELECT version,customized FROM risk_gate_ruleset WHERE id=1`).Scan(&result.Version, &result.Customized); err != nil {
		return result, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,gate,category,pattern,is_regex,action,enabled,sort_order,description,rule_key,builtin FROM risk_gate_rules ORDER BY sort_order,id`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Rule
		if err = rows.Scan(&r.ID, &r.Gate, &r.Category, &r.Pattern, &r.IsRegex, &r.Action, &r.Enabled, &r.SortOrder, &r.Description, &r.RuleKey, &r.Builtin); err != nil {
			return result, err
		}
		result.Rules = append(result.Rules, r)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if !result.Customized {
		result.Rules = append(BuiltinRules(), result.Rules...)
	}
	return result, nil
}
func (s *RuleStore) SaveRuleSet(ctx context.Context, expected int64, rules []Rule, reset bool) (RuleSet, error) {
	if reset {
		rules = BuiltinRules()
	}
	normalized, err := normalizeAdminRules(rules)
	if err != nil {
		return RuleSet{}, err
	}
	if s == nil || s.db == nil {
		return RuleSet{Version: expected + 1, Rules: normalized, BuiltinRules: BuiltinRules(), Customized: !reset}, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RuleSet{}, err
	}
	defer tx.Rollback()
	var version int64
	if err = tx.QueryRowContext(ctx, `SELECT version FROM risk_gate_ruleset WHERE id=1 FOR UPDATE`).Scan(&version); err != nil {
		return RuleSet{}, err
	}
	if expected != version {
		return RuleSet{}, infraerrors.Conflict("risk_gate_rules_conflict", "规则已被其他管理员修改；草稿保留，请比较后重试")
	}
	existing := map[int64]string{}
	rows, err := tx.QueryContext(ctx, `SELECT id,rule_key FROM risk_gate_rules`)
	if err != nil {
		return RuleSet{}, err
	}
	for rows.Next() {
		var id int64
		var key string
		if err = rows.Scan(&id, &key); err != nil {
			rows.Close()
			return RuleSet{}, err
		}
		existing[id] = key
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return RuleSet{}, err
	}
	keys := map[string]bool{}
	ids := []int64{}
	for i := range normalized {
		r := &normalized[i]
		if key, ok := existing[r.ID]; ok {
			r.RuleKey = key
		} else if !r.Builtin || !strings.HasPrefix(r.RuleKey, "builtin-") {
			var b [12]byte
			if _, err = rand.Read(b[:]); err != nil {
				return RuleSet{}, err
			}
			r.RuleKey = "custom-" + hex.EncodeToString(b[:])
		}
		if keys[r.RuleKey] {
			return RuleSet{}, invalidRule("规则标识重复")
		}
		keys[r.RuleKey] = true
		err = tx.QueryRowContext(ctx, `INSERT INTO risk_gate_rules(gate,category,pattern,is_regex,action,enabled,sort_order,description,rule_key,builtin) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(rule_key) DO UPDATE SET gate=EXCLUDED.gate,category=EXCLUDED.category,pattern=EXCLUDED.pattern,is_regex=EXCLUDED.is_regex,action=EXCLUDED.action,enabled=EXCLUDED.enabled,sort_order=EXCLUDED.sort_order,description=EXCLUDED.description,builtin=EXCLUDED.builtin,updated_at=NOW() RETURNING id`, r.Gate, r.Category, r.Pattern, r.IsRegex, r.Action, r.Enabled, r.SortOrder, r.Description, r.RuleKey, r.Builtin).Scan(&r.ID)
		if err != nil {
			return RuleSet{}, err
		}
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		_, err = tx.ExecContext(ctx, `DELETE FROM risk_gate_rules`)
	} else {
		args := make([]any, len(ids))
		p := make([]string, len(ids))
		for i, id := range ids {
			args[i] = id
			p[i] = placeholder(i + 1)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM risk_gate_rules WHERE id NOT IN (`+strings.Join(p, ",")+`)`, args...)
	}
	if err != nil {
		return RuleSet{}, err
	}
	// Materialized defaults remain a versioned ruleset so disabled builtins cannot reappear.
	_, err = tx.ExecContext(ctx, `UPDATE risk_gate_ruleset SET version=version+1,customized=TRUE,updated_at=NOW() WHERE id=1`)
	if err != nil {
		return RuleSet{}, err
	}
	if err = tx.Commit(); err != nil {
		return RuleSet{}, err
	}
	s.invalidateCache()
	return RuleSet{Version: version + 1, Rules: normalized, BuiltinRules: BuiltinRules(), Customized: true}, nil
}

// PolicyRules avoids a database roundtrip on every inspected request. Local
// edits invalidate immediately; other instances refresh within the existing TTL.
func (s *RuleStore) PolicyRules(ctx context.Context) ([]Rule, error) {
	if s == nil {
		return BuiltinRules(), nil
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	now := s.clock.Now()
	if s.policySnapshot != nil && now.Sub(s.policyLoadedAt) < 30*time.Second {
		return append([]Rule(nil), s.policySnapshot.Rules...), nil
	}
	snapshot, err := s.RuleSet(ctx)
	if err != nil {
		return nil, err
	}
	s.policySnapshot = &snapshot
	s.policyLoadedAt = now
	return append([]Rule(nil), snapshot.Rules...), nil
}
