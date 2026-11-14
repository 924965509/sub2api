package service

import (
	"encoding/json"
	"math"
	"strings"
)

const (
	channelCacheTransferRatioKey  = "channel_cache_transfer_ratio"
	channelCacheTransferTargetKey = "channel_cache_transfer_target"
	channelCacheTransferModelsKey = "channel_cache_transfer_models"

	channelCacheTransferTargetInput         = "input"
	channelCacheTransferTargetCacheCreation = "cache_creation"
)

type channelCacheTransferConfig struct {
	RatioPercent float64
	Target       string
	ModelRules   []string
}

func resolveChannelCacheTransferConfig(account *Account, requestModel string) (channelCacheTransferConfig, bool) {
	if account == nil || account.Extra == nil {
		return channelCacheTransferConfig{}, false
	}
	ratio := account.getExtraFloat64(channelCacheTransferRatioKey)
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio <= 0 {
		return channelCacheTransferConfig{}, false
	}
	ratio = math.Min(ratio, 100)

	target := strings.ToLower(strings.TrimSpace(account.GetExtraString(channelCacheTransferTargetKey)))
	switch target {
	case "", channelCacheTransferTargetInput:
		target = channelCacheTransferTargetInput
	case channelCacheTransferTargetCacheCreation, "cache_write", "cache-write":
		target = channelCacheTransferTargetCacheCreation
	default:
		target = channelCacheTransferTargetInput
	}

	rules := parseChannelCacheTransferModelRules(account.Extra[channelCacheTransferModelsKey])
	if !channelCacheTransferModelMatches(requestModel, rules) {
		return channelCacheTransferConfig{}, false
	}
	return channelCacheTransferConfig{RatioPercent: ratio, Target: target, ModelRules: rules}, true
}

func parseChannelCacheTransferModelRules(value any) []string {
	appendRule := func(out []string, rule string) []string {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			return out
		}
		return append(out, rule)
	}

	out := make([]string, 0, 4)
	switch v := value.(type) {
	case nil:
		return out
	case string:
		for _, rule := range strings.Split(v, ",") {
			out = appendRule(out, rule)
		}
	case []string:
		for _, rule := range v {
			out = appendRule(out, rule)
		}
	case []any:
		for _, item := range v {
			if rule, ok := item.(string); ok {
				out = appendRule(out, rule)
			}
		}
	default:
		if raw, err := json.Marshal(v); err == nil {
			var rules []string
			if json.Unmarshal(raw, &rules) == nil {
				for _, rule := range rules {
					out = appendRule(out, rule)
				}
			}
		}
	}
	return out
}

func channelCacheTransferModelMatches(model string, rules []string) bool {
	if len(rules) == 0 {
		return true
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix)) {
				return true
			}
			continue
		}
		if strings.EqualFold(model, rule) {
			return true
		}
	}
	return false
}

func channelCacheTransferAmount(cacheRead int, ratioPercent float64) int {
	if cacheRead <= 0 || ratioPercent <= 0 {
		return 0
	}
	ratioPercent = math.Min(math.Max(ratioPercent, 0), 100)
	amount := int(math.Round(float64(cacheRead) * ratioPercent / 100))
	return min(max(amount, 0), cacheRead)
}

// applyChannelCacheTransferClaudeUsage converts a percentage of cache-read tokens
// into ordinary input or 5-minute cache creation. Claude usage buckets are
// mutually exclusive, so ordinary input increases explicitly.
func applyChannelCacheTransferClaudeUsage(account *Account, requestModel string, usage *ClaudeUsage) (int, string) {
	if usage == nil {
		return 0, ""
	}
	cfg, ok := resolveChannelCacheTransferConfig(account, requestModel)
	if !ok {
		return 0, ""
	}
	amount := channelCacheTransferAmount(usage.CacheReadInputTokens, cfg.RatioPercent)
	if amount <= 0 {
		return 0, cfg.Target
	}

	usage.CacheReadInputTokens -= amount
	switch cfg.Target {
	case channelCacheTransferTargetCacheCreation:
		usage.CacheCreationInputTokens += amount
		usage.CacheCreation5mTokens += amount
	default:
		usage.InputTokens += amount
	}
	return amount, cfg.Target
}

// applyChannelCacheTransferOpenAIUsage keeps OpenAI input_tokens unchanged because
// OpenAI reports it as total input. Reducing cached_tokens implicitly moves the
// transferred amount into ordinary input; cache_creation additionally gets its
// own explicit bucket.
func applyChannelCacheTransferOpenAIUsage(account *Account, requestModel string, usage *OpenAIUsage) (int, string) {
	if usage == nil {
		return 0, ""
	}
	cfg, ok := resolveChannelCacheTransferConfig(account, requestModel)
	if !ok {
		return 0, ""
	}
	amount := channelCacheTransferAmount(usage.CacheReadInputTokens, cfg.RatioPercent)
	if amount <= 0 {
		return 0, cfg.Target
	}

	usage.CacheReadInputTokens -= amount
	if cfg.Target == channelCacheTransferTargetCacheCreation {
		hadTTLBreakdown := usage.CacheCreationInputTokens > 0 &&
			usage.CacheCreation30mInputTokens >= 0 &&
			usage.CacheCreation12hInputTokens >= 0 &&
			usage.CacheCreation30mInputTokens+usage.CacheCreation12hInputTokens == usage.CacheCreationInputTokens
		usage.CacheCreationInputTokens += amount
		if hadTTLBreakdown {
			usage.CacheCreation30mInputTokens += amount
		}
	}
	return amount, cfg.Target
}

func rewriteAnthropicUsageMapForChannelCache(usageObj map[string]any, account *Account, requestModel string) bool {
	if len(usageObj) == 0 {
		return false
	}
	input, _ := parseSSEUsageInt(usageObj["input_tokens"])
	cacheRead, _ := parseSSEUsageInt(usageObj["cache_read_input_tokens"])
	cacheCreation, _ := parseSSEUsageInt(usageObj["cache_creation_input_tokens"])
	usage := ClaudeUsage{
		InputTokens:              max(input, 0),
		CacheReadInputTokens:     max(cacheRead, 0),
		CacheCreationInputTokens: max(cacheCreation, 0),
	}
	if cc, ok := usageObj["cache_creation"].(map[string]any); ok {
		usage.CacheCreation5mTokens, _ = parseSSEUsageInt(cc["ephemeral_5m_input_tokens"])
		usage.CacheCreation1hTokens, _ = parseSSEUsageInt(cc["ephemeral_1h_input_tokens"])
	}
	amount, target := applyChannelCacheTransferClaudeUsage(account, requestModel, &usage)
	if amount <= 0 {
		return false
	}

	usageObj["input_tokens"] = usage.InputTokens
	usageObj["cache_read_input_tokens"] = usage.CacheReadInputTokens
	if target == channelCacheTransferTargetCacheCreation {
		usageObj["cache_creation_input_tokens"] = usage.CacheCreationInputTokens
		cc, _ := usageObj["cache_creation"].(map[string]any)
		if cc == nil {
			cc = map[string]any{}
			usageObj["cache_creation"] = cc
		}
		cc["ephemeral_5m_input_tokens"] = usage.CacheCreation5mTokens
		cc["ephemeral_1h_input_tokens"] = usage.CacheCreation1hTokens
	}
	return true
}

func rewriteAnthropicChannelCacheTransferJSON(body []byte, account *Account, requestModel string) ([]byte, bool) {
	if _, ok := resolveChannelCacheTransferConfig(account, requestModel); !ok || len(body) == 0 {
		return body, false
	}
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return body, false
	}
	usageObj, _ := root["usage"].(map[string]any)
	if len(usageObj) == 0 {
		if message, ok := root["message"].(map[string]any); ok {
			usageObj, _ = message["usage"].(map[string]any)
		}
	}
	if len(usageObj) == 0 || !rewriteAnthropicUsageMapForChannelCache(usageObj, account, requestModel) {
		return body, false
	}
	if account.IsCacheTTLOverrideEnabled() {
		rewriteCacheCreationJSON(usageObj, account.GetCacheTTLOverrideTarget())
	}
	rewritten, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return rewritten, true
}

func findOpenAIUsageMap(root map[string]any) map[string]any {
	if usage, ok := root["usage"].(map[string]any); ok {
		return usage
	}
	if response, ok := root["response"].(map[string]any); ok {
		if usage, ok := response["usage"].(map[string]any); ok {
			return usage
		}
	}
	if data, ok := root["data"].(map[string]any); ok {
		if usage, ok := data["usage"].(map[string]any); ok {
			return usage
		}
		if response, ok := data["response"].(map[string]any); ok {
			if usage, ok := response["usage"].(map[string]any); ok {
				return usage
			}
		}
	}
	return nil
}

func setOpenAICachedTokens(usageObj map[string]any, value int) {
	if details, ok := usageObj["input_tokens_details"].(map[string]any); ok {
		details["cached_tokens"] = value
	} else if details, ok := usageObj["prompt_tokens_details"].(map[string]any); ok {
		details["cached_tokens"] = value
	} else if _, ok := usageObj["prompt_tokens"]; ok {
		usageObj["prompt_tokens_details"] = map[string]any{"cached_tokens": value}
	} else {
		usageObj["input_tokens_details"] = map[string]any{"cached_tokens": value}
	}
	if _, ok := usageObj["cache_read_input_tokens"]; ok {
		usageObj["cache_read_input_tokens"] = value
	}
	if _, ok := usageObj["cached_tokens"]; ok {
		usageObj["cached_tokens"] = value
	}
}

func addOpenAICacheCreationTokens(usageObj map[string]any, value int) {
	if value <= 0 {
		return
	}

	existingTotal := 0
	updatedTopLevel := false
	for _, key := range []string{"cache_write_tokens", "cache_creation_input_tokens", "cache_write_input_tokens", "cache_creation_tokens"} {
		if _, exists := usageObj[key]; !exists {
			continue
		}
		current, _ := parseSSEUsageInt(usageObj[key])
		existingTotal = max(current, 0)
		usageObj[key] = existingTotal + value
		updatedTopLevel = true
		break
	}

	for _, detailsKey := range []string{"input_tokens_details", "prompt_tokens_details"} {
		details, ok := usageObj[detailsKey].(map[string]any)
		if !ok {
			continue
		}
		updated := false
		for _, key := range []string{"cache_write_tokens", "cache_creation_tokens"} {
			if _, exists := details[key]; !exists {
				continue
			}
			current, _ := parseSSEUsageInt(details[key])
			current = max(current, 0)
			if !updatedTopLevel {
				existingTotal = current
			}
			details[key] = current + value
			updated = true
			break
		}
		if !updated {
			details["cache_write_tokens"] = existingTotal + value
		}
		if writeDetails, ok := details["cache_write_tokens_details"].(map[string]any); ok {
			if short, okS := parseSSEUsageInt(writeDetails["ttl_30m_tokens"]); okS {
				if long, okL := parseSSEUsageInt(writeDetails["ttl_12h_tokens"]); okL && short >= 0 && long >= 0 {
					writeDetails["ttl_30m_tokens"] = short + value
				}
			}
		}
		break
	}

	if !updatedTopLevel {
		usageObj["cache_creation_input_tokens"] = existingTotal + value
	}
}

func rewriteOpenAIChannelCacheTransferJSON(body []byte, account *Account, requestModel string) ([]byte, bool) {
	if _, ok := resolveChannelCacheTransferConfig(account, requestModel); !ok || len(body) == 0 {
		return body, false
	}
	rawUsage, ok := extractOpenAIUsageFromJSONBytes(body)
	if !ok {
		return body, false
	}
	clientUsage := rawUsage
	amount, target := applyChannelCacheTransferOpenAIUsage(account, requestModel, &clientUsage)
	if amount <= 0 {
		return body, false
	}

	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return body, false
	}
	usageObj := findOpenAIUsageMap(root)
	if usageObj == nil {
		return body, false
	}
	setOpenAICachedTokens(usageObj, clientUsage.CacheReadInputTokens)
	if target == channelCacheTransferTargetCacheCreation {
		addOpenAICacheCreationTokens(usageObj, amount)
	}
	rewritten, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return rewritten, true
}
