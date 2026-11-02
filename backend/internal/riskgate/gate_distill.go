package riskgate

import (
	"fmt"
	"strings"
)

// evaluateDistill 执行蒸馏/赛题指纹闸门。
//
// 顺序固定：hard_needles（始终扫）→ needles + fingerprints（受 skip 开关控制）
// → structure_harvest（max_tokens 与思考预算都 >= min_max_tokens 且正文命中
// contest_pattern）。前一项命中即返回，不再执行后续匹配。
func evaluateDistillRules(cfg Config, view TextView, meta RequestMeta, identity Identity, cache *regexCache, rules []Rule) (GateResult, []GateResult) {
	text := strings.TrimSpace(view.NormalizedUser() + " " + strings.ToLower(strings.Join(strings.Fields(view.SystemText), " ")))
	observations := make([]GateResult, 0, 2)
	if needles := matchNeedles(cfg.Distill.HardNeedles, text); needles != "" {
		return GateResult{
			Hit: true, Gate: GateDistill, Category: CategoryDistill,
			Reason: "命中蒸馏收割词: " + needles, Evidence: sanitizeEvidence(needles),
			BanSignal: cfg.Ban.OnDistill,
		}, observations
	}
	for _, pattern := range cfg.Distill.Patterns {
		if match, ok := matchPattern(pattern, text, cache); ok {
			result := GateResult{Hit: true, Gate: GateDistill, Category: CategoryDistill,
				Reason: "命中蒸馏附加规则: " + strings.TrimSpace(pattern), Evidence: sanitizeEvidence(match), BanSignal: cfg.Ban.OnDistill}
			if strings.EqualFold(ruleAction(rules, GateDistill, pattern), "observe") {
				result.Action = EventActionObserve
				observations = append(observations, result)
				continue
			}
			return result, observations
		}
	}
	for _, rule := range rules {
		if !rule.Enabled || rule.Gate != GateDistill {
			continue
		}
		if match, ok := matchRule(rule, text, cache); ok {
			result := GateResult{Hit: true, Gate: GateDistill, Category: canonicalCategory(rule.Category), RuleID: rule.ID,
				Reason: "命中自定义蒸馏规则: " + rule.Pattern, Evidence: func() string {
					if cfg.SchemaVersion >= 2 {
						return "contest+harvest"
					}
					return sanitizeEvidence(match)
				}(), BanSignal: cfg.Ban.OnDistill,
				Action: strings.ToLower(strings.TrimSpace(rule.Action))}
			if result.Action == "observe" {
				observations = append(observations, result)
				continue
			}
			return result, observations
		}
	}
	if !skipDistillNeedles(cfg.Distill, identity) {
		if needles := matchNeedles(cfg.Distill.Needles, text); needles != "" {
			return GateResult{
				Hit: true, Gate: GateDistill, Category: CategoryDistill,
				Reason: "命中蒸馏指纹针: " + needles, Evidence: sanitizeEvidence(needles),
				BanSignal: cfg.Ban.OnDistill,
			}, observations
		}
		if needles := matchNeedles(cfg.Distill.Fingerprints, view.NormalizedUser()); needles != "" {
			return GateResult{
				Hit: true, Gate: GateDistill, Category: CategoryDistill,
				Reason: "命中题目指纹: " + needles, Evidence: redactEvidence(needles, evidenceMaxRunes),
				BanSignal: cfg.Ban.OnDistill,
			}, observations
		}
	}
	if !skipDistillNeedles(cfg.Distill, identity) {
		if result, hit := evaluateStructureHarvest(cfg, view, meta, cache); hit {
			return result, observations
		}
	}
	return GateResult{}, observations
}

func matchPattern(pattern, text string, cache *regexCache) (string, bool) {
	compiled, ok := cache.compile(pattern)
	if !ok {
		return "", false
	}
	match := compiled.FindString(text)
	return match, match != ""
}

func ruleAction(rules []Rule, gate, pattern string) string {
	for _, rule := range rules {
		if rule.Gate == gate && rule.Pattern == pattern {
			return rule.Action
		}
	}
	return "block"
}

// evaluateStructureHarvest 判定「结构收割」：超长输出 + 思考预算 + 赛题正文三者同时满足。
// contest_pattern 为空表示该闸不启用（默认样式）。
func evaluateStructureHarvest(cfg Config, view TextView, meta RequestMeta, cache *regexCache) (GateResult, bool) {
	if cfg.SchemaVersion >= 2 && ((cfg.Distill.RequireNoTools && view.HasTools) || (cfg.Distill.RequireSingleTurn && view.UserTurnCount != 1)) {
		return GateResult{}, false
	}
	if cfg.Distill.MinMaxTokens <= 0 || cfg.Distill.ContestPattern == "" {
		return GateResult{}, false
	}
	if meta.MaxTokens < cfg.Distill.MinMaxTokens || meta.ThinkingBudget < cfg.Distill.MinMaxTokens {
		return GateResult{}, false
	}
	contest, ok := cache.compile(cfg.Distill.ContestPattern)
	if !ok {
		return GateResult{}, false
	}
	match := contest.FindString(view.LatestUser)
	if match == "" {
		return GateResult{}, false
	}
	return GateResult{
		Hit: true, Gate: GateDistill, Category: CategoryDistill,
		Reason: fmt.Sprintf("结构收割: max_tokens=%d 思考预算=%d 且正文命中赛题特征", meta.MaxTokens, meta.ThinkingBudget),
		Evidence: func() string {
			if cfg.SchemaVersion >= 2 {
				return "contest+harvest"
			}
			return sanitizeEvidence(match)
		}(), BanSignal: cfg.Ban.OnDistill,
	}, true
}

// matchNeedles 在已规范化的文本里做子串匹配，返回命中的原始 needle。
func matchNeedles(needles []string, normalizedText string) string {
	if normalizedText == "" {
		return ""
	}
	for _, needle := range needles {
		candidate := strings.ToLower(strings.Join(strings.Fields(needle), " "))
		if candidate == "" {
			continue
		}
		if strings.Contains(normalizedText, candidate) {
			return needle
		}
	}
	return ""
}

// Compatibility helper retained for existing engine-level tests and integrations.
func evaluateDistill(cfg Config, view TextView, meta RequestMeta, identity Identity, cache *regexCache) GateResult {
	hit, _ := evaluateDistillRules(cfg, view, meta, identity, cache, nil)
	return hit
}
