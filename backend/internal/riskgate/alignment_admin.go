package riskgate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func (s *AdminService) GetRuleSet(ctx context.Context) (RuleSet, error) {
	store, ok := s.ruleRepo.(*RuleStore)
	if !ok {
		return RuleSet{}, invalidRule("规则仓库不可用")
	}
	return store.RuleSet(ctx)
}
func (s *AdminService) UpdateRuleSet(ctx context.Context, version int64, rules []Rule, reset bool) (RuleSet, error) {
	store, ok := s.ruleRepo.(*RuleStore)
	if !ok {
		return RuleSet{}, invalidRule("规则仓库不可用")
	}
	return store.SaveRuleSet(ctx, version, rules, reset)
}
func (s *AdminService) ListClassifierModels(ctx context.Context, endpoint *ClassifierEndpoint) ([]map[string]string, error) {
	target, err := s.probeEndpoint(ctx, 0, endpoint)
	if err != nil {
		return nil, err
	}
	client := s.modelClient()
	return client.Models(ctx, target)
}
func (s *AdminService) modelClient() *OpenAIClassifier {
	if s.engine != nil {
		if client, ok := s.engine.classifier.(*OpenAIClassifier); ok {
			return client
		}
	}
	return NewOpenAIClassifier()
}
func (s *AdminService) ClearBans(ctx context.Context, scope string) (int64, error) {
	store, ok := s.banRepo.(*BanStore)
	if !ok || store.db == nil {
		return 0, invalidBan("封禁仓库不可用")
	}
	if scope != "" && scope != BanScopeAPIKey && scope != BanScopeUser && scope != BanScopeClientFingerprint {
		return 0, invalidBan("封禁作用域无效")
	}
	rows, err := store.db.QueryContext(ctx, `DELETE FROM risk_gate_bans WHERE $1='' OR scope=$1 RETURNING scope,subject`, scope)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var scope, subject string
		if err = rows.Scan(&scope, &subject); err != nil {
			return total, err
		}
		store.invalidate(ctx, banCacheKey(scope, subject))
		total++
	}
	return total, rows.Err()
}

type ScopeAccount struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Platform    string `json:"platform"`
	AccountType string `json:"account_type,omitempty"`
	BaseURL     string `json:"base_url,omitempty"`
	PlanType    string `json:"plan_type"`
	ScopeKey    string `json:"scope_key"`
	Schedulable bool   `json:"schedulable"`
}
type ScopeOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Count int    `json:"count"`
}
type ScopeInventory struct {
	AccountsTotal int            `json:"accounts_total"`
	Accounts      []ScopeAccount `json:"accounts"`
	Options       []ScopeOption  `json:"account_platform_plan_options"`
	Truncated     bool           `json:"truncated"`
}

func canonicalPlatform(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "anthropic", "claude":
		return "claude"
	case "openai", "gpt":
		return "gpt"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
}
func canonicalPlan(plan string) string {
	plan = strings.ToLower(strings.TrimSpace(plan))
	switch plan {
	case "team", "business premium", "business_premium":
		return "business"
	case "claude_pro", "pro_account":
		return "pro"
	case "max_5x", "max_20x", "claude_max":
		return "max"
	case "api", "api_key", "apikey":
		return "apikey"
	case "":
		return "unknown"
	default:
		return plan
	}
}
func sanitizeScopeBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/")
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}
func (s *AdminService) ScopeInventory(ctx context.Context) (ScopeInventory, error) {
	result := ScopeInventory{Accounts: []ScopeAccount{}, Options: []ScopeOption{}}
	if s == nil || s.config == nil || s.config.db == nil {
		return result, invalidConfig("账号数据库不可用")
	}
	// Select only the harmless metadata needed by the selector. Credentials JSON is
	// never returned from SQL, serialized into an API response, or written to logs.
	rows, err := s.config.db.QueryContext(ctx, `SELECT id,name,platform,COALESCE(type,''),COALESCE(credentials->>'email',extra->>'email',''),COALESCE(NULLIF(credentials->>'plan_type',''),NULLIF(extra->>'subscription_tier',''),NULLIF(extra->>'plan_type',''),'unknown'),COALESCE(credentials->>'base_url',extra->>'base_url',''),schedulable AND status='active' FROM accounts WHERE deleted_at IS NULL ORDER BY id LIMIT 10001`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var r ScopeAccount
		var id int64
		if err = rows.Scan(&id, &r.Name, &r.Platform, &r.AccountType, &r.Email, &r.PlanType, &r.BaseURL, &r.Schedulable); err != nil {
			return result, err
		}
		if len(result.Accounts) >= 10000 {
			result.Truncated = true
			break
		}
		r.ID = fmt.Sprint(id)
		r.AccountType = strings.ToLower(strings.TrimSpace(r.AccountType))
		r.BaseURL = sanitizeScopeBaseURL(r.BaseURL)
		r.Platform = canonicalPlatform(r.Platform)
		r.PlanType = canonicalPlan(r.PlanType)
		if r.PlanType == "unknown" && r.AccountType == "apikey" {
			r.PlanType = "apikey"
		}
		r.ScopeKey = r.Platform + ":" + r.PlanType
		result.Accounts = append(result.Accounts, r)
		counts[r.ScopeKey]++
	}
	result.AccountsTotal = len(result.Accounts)
	for key, count := range counts {
		result.Options = append(result.Options, ScopeOption{ID: key, Label: strings.ReplaceAll(key, ":", " · "), Count: count})
	}
	sort.Slice(result.Options, func(i, j int) bool { return result.Options[i].ID < result.Options[j].ID })
	return result, rows.Err()
}

// configQuestionsJSON is also useful to protocol adapters that need to build a
// consistent model request without exposing any stored secret.
func configQuestionsJSON(cfg DecisionModelConfig) string {
	data, _ := json.Marshal(enabledQuestions(cfg))
	return string(data)
}
