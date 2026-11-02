package riskgate

import (
	"regexp"
	"strings"
	"sync"
)

// 硬正则闸门：内置类别 + 面板自定义规则，扫 UserTranscript。
// 命中只写事件、不写拒答缓存（拒答缓存属于 P3）。
const (
	maxCompiledRegexCache = 512
)

// regexCache 缓存已编译的正则，避免每请求重新编译。
type regexCache struct {
	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

func newRegexCache() *regexCache {
	return &regexCache{cache: make(map[string]*regexp.Regexp, 16)}
}

// compile 编译（大小写不敏感）并缓存正则；非法正则返回 false。
func (c *regexCache) compile(pattern string) (*regexp.Regexp, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, false
	}
	if c == nil {
		compiled, err := regexp.Compile("(?i)" + pattern)
		return compiled, err == nil
	}
	c.mu.Lock()
	if compiled, ok := c.cache[pattern]; ok {
		c.mu.Unlock()
		return compiled, true
	}
	c.mu.Unlock()
	compiled, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, false
	}
	c.mu.Lock()
	if len(c.cache) >= maxCompiledRegexCache {
		// 规则集只在面板里变化，触顶时整体清空即可，代价可忽略。
		c.cache = make(map[string]*regexp.Regexp, 16)
	}
	c.cache[pattern] = compiled
	c.mu.Unlock()
	return compiled, true
}

// evaluateRegex 执行硬正则闸门：内置类别在前，自定义规则在后。
func evaluateRegex(cfg Config, view TextView, rules []Rule, cache *regexCache) GateResult {
	limit := cfg.Regex.MaxInputBytes
	if limit <= 0 {
		limit = DefaultRegexMaxInputBytes
	}
	// 超长输入截断保护：正则回溯在超大文本上会拖垮请求路径。
	text := truncateBytes(view.UserTranscript, limit)
	if strings.TrimSpace(text) == "" {
		return GateResult{}
	}
	for _, category := range sortedCategories(cfg.Regex.Categories) {
		patterns, ok := DefaultCategoryRegexes[category]
		if !ok {
			continue
		}
		for _, pattern := range patterns {
			compiled, ok := cache.compile(pattern)
			if !ok {
				continue
			}
			if match := compiled.FindString(text); match != "" {
				return GateResult{
					Hit: true, Gate: GateRegex, Category: category,
					Reason: "命中内置硬正则类别: " + category, Evidence: sanitizeEvidence(match),
					BanSignal: cfg.Ban.OnRegex,
				}
			}
		}
	}
	if !cfg.Regex.CustomRules {
		return GateResult{}
	}
	for _, rule := range rules {
		if !rule.Enabled || rule.Gate != GateRegex {
			continue
		}
		if match, hit := matchRule(rule, text, cache); hit {
			category := strings.TrimSpace(rule.Category)
			if category == "" {
				category = CategoryCustom
			}
			reason := "命中自定义规则: " + rule.Pattern
			if description := strings.TrimSpace(rule.Description); description != "" {
				reason = "命中自定义规则: " + description
			}
			return GateResult{
				Hit: true, Gate: GateRegex, Category: category, RuleID: rule.ID,
				Reason: reason, Evidence: sanitizeEvidence(match),
				BanSignal: cfg.Ban.OnRegex,
			}
		}
	}
	return GateResult{}
}

// matchRule 匹配单条自定义规则；非正则规则按规范化后的子串比较。
func matchRule(rule Rule, text string, cache *regexCache) (string, bool) {
	if rule.IsRegex {
		compiled, ok := cache.compile(rule.Pattern)
		if !ok {
			return "", false
		}
		match := compiled.FindString(text)
		return match, match != ""
	}
	needle := strings.ToLower(strings.Join(strings.Fields(rule.Pattern), " "))
	if needle == "" {
		return "", false
	}
	if strings.Contains(strings.ToLower(text), needle) {
		return rule.Pattern, true
	}
	return "", false
}

// evaluatePolicyRules evaluates the editable complete v2 rule set. A disabled
// builtin is not re-added. Observe-only rules never stop later enforcement.
func evaluatePolicyRules(cfg Config, view TextView, rules []Rule, cache *regexCache, openai bool) (GateResult, []GateResult) {
	text := view.UserTranscript
	if cfg.Regex.StripReminders {
		text = systemReminderPattern.ReplaceAllString(text, " ")
	}
	text, _ = stripEnvironmentSection(text)
	if cfg.Regex.ExpandBase64 {
		text = replaceBase64Blocks(text, true)
	}
	text = truncateBytes(text, cfg.Regex.MaxInputBytes)
	observations := []GateResult{}
	candidates := append([]Rule(nil), rules...)
	if cfg.Gates.Regex {
		for _, pattern := range cfg.Regex.Patterns {
			candidates = append(candidates, Rule{Gate: GateRegex, Category: CategoryCustom, Pattern: pattern, Enabled: true, IsRegex: true, Action: "block"})
		}
	}
	for _, rule := range candidates {
		if !rule.Enabled || rule.Gate != GateRegex {
			continue
		}
		category := canonicalCategory(rule.Category)
		if category == "distill" {
			if !cfg.Gates.Distill || openai {
				continue
			}
		} else if !cfg.Gates.Regex {
			continue
		}
		if matched, hit := matchRule(rule, text, cache); hit {
			result := GateResult{Hit: true, Gate: GateRegex, Category: category, RuleID: rule.ID, RuleKey: rule.RuleKey, Pattern: rule.Pattern, Reason: category, Evidence: sanitizeEvidence(strings.TrimSpace(matched)), Action: rule.Action, BanSignal: cfg.Ban.OnRegex}
			if rule.Action == "observe" {
				result.BanSignal = false
				observations = append(observations, result)
				continue
			}
			return result, observations
		}
	}
	return GateResult{}, observations
}
