package riskgate

import (
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
)

// TextView 是风险闸门使用的文本视图。
//
// 它只读消费 securityaudit.ExtractTextSegments 的分段结果，与提示词审计的
// 快照/脱敏互不干扰：提示词审计事件仍按原样落库。
type TextView struct {
	// LatestUser 是最新一条有正文的 user 消息（同一次输入的多个分段会拼接），
	// 已经跳过 tool_result / function_call_output 之类的工具回传。
	LatestUser string
	// UserTranscript 是全部 user 正文（硬正则扫这个）。
	UserTranscript string
	// SystemText 是客户端可控的注入文本（system/developer/instructions）。
	SystemText string
	// EnvText 是被剥离出来的 "# Environment" 段原文。
	EnvText string
	// AllText 是 user 正文 + 注入文本，供不区分角色的蒸馏针扫描。
	AllText string
	// NormalizedHash 是 sha256(规范化 LatestUser)。
	NormalizedHash string
	// Shingle 是规范化 LatestUser 的 4-gram min-hash 签名（<512 字不生成）。
	Shingle []uint64
	// ToolResultOnly 表示本次请求没有 user 正文（只有工具回传或助手输出）。
	ToolResultOnly bool
	HasTools       bool
	UserTurns      []string
	UserLabels     []string
	UserTurnCount  int

	// normalizedUser / normalizedAll 是规范化之后的内部缓存，避免重复计算。
	normalizedUser string
	normalizedAll  string
}

// RequestMeta 是从原始请求体里抽取的结构性参数，供结构收割闸使用。
type RequestMeta struct {
	MaxTokens      int
	ThinkingBudget int
}

// BuildTextView 解析请求体并产出文本视图。解析失败时返回错误，
// 由调用方决定是否跳过文本类闸门（封禁闸不依赖正文）。
func BuildTextView(req securityaudit.Request, opts NormalizeOptions) (TextView, RequestMeta, error) {
	meta := extractRequestMeta(req.Body)
	segments, err := securityaudit.ExtractTextSegments(req)
	if err != nil {
		return TextView{AllText: ""}, meta, err
	}
	userTexts, labels, systemText, hasTools := requestUserTurns(req.Body)
	if len(userTexts) == 0 && systemText == "" {
		for _, segment := range segments {
			if segment.User {
				userTexts = append(userTexts, strings.TrimSpace(segment.Text))
			} else if segment.Role == "system" || segment.Role == "developer" {
				systemText += "\n" + segment.Text
			}
		}
	}
	view := TextView{UserTranscript: strings.Join(userTexts, "\n\n"), SystemText: strings.TrimSpace(systemText), ToolResultOnly: len(userTexts) == 0, HasTools: hasTools, UserTurnCount: len(userTexts), UserTurns: userTexts, UserLabels: labels}
	if len(userTexts) > 0 {
		view.LatestUser = userTexts[len(userTexts)-1]
	}
	normalizedUser, env := Normalize(view.LatestUser, opts)
	view.EnvText = env
	if view.EnvText == "" {
		_, view.EnvText = Normalize(view.SystemText, opts)
	}
	view.normalizedUser = normalizedUser
	view.NormalizedHash = NormalizeHash(normalizedUser)
	view.Shingle = Shingle(normalizedUser)
	allText := strings.Join(append(append([]string(nil), userTexts...), view.SystemText), "\n\n")
	view.AllText = allText
	normalizedAll, _ := Normalize(allText, opts)
	view.normalizedAll = normalizedAll
	return view, meta, nil
}

// NormalizedUser 返回规范化后的最新 user 正文（小写、空白折叠）。
func (v TextView) NormalizedUser() string { return v.normalizedUser }

// NormalizedAll 返回规范化后的「user 正文 + 注入文本」。
func (v TextView) NormalizedAll() string { return v.normalizedAll }

// HasUserText 表示是否存在可扫描的 user 正文。
func (v TextView) HasUserText() bool { return strings.TrimSpace(v.UserTranscript) != "" }

// extractRequestMeta 从原始请求体里取 max_tokens 与思考预算，
// 兼容 Chat Completions / Responses / Anthropic Messages / Gemini 四种形态。
func extractRequestMeta(body []byte) RequestMeta {
	if len(body) == 0 {
		return RequestMeta{}
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return RequestMeta{}
	}
	meta := RequestMeta{MaxTokens: firstPositiveInt(root,
		"max_tokens", "max_completion_tokens", "max_output_tokens", "maxOutputTokens")}
	if meta.MaxTokens == 0 {
		if generation, ok := root["generationConfig"].(map[string]any); ok {
			meta.MaxTokens = firstPositiveInt(generation, "maxOutputTokens", "max_output_tokens")
		}
	}
	if meta.MaxTokens == 0 {
		if generation, ok := root["generation_config"].(map[string]any); ok {
			meta.MaxTokens = firstPositiveInt(generation, "maxOutputTokens", "max_output_tokens")
		}
	}
	meta.ThinkingBudget = extractThinkingBudget(root)
	return meta
}

// extractThinkingBudget 取思考预算，缺省为 0。
func extractThinkingBudget(root map[string]any) int {
	if thinking, ok := root["thinking"].(map[string]any); ok {
		if budget := firstPositiveInt(thinking, "budget_tokens", "budgetTokens"); budget > 0 {
			return budget
		}
	}
	if reasoning, ok := root["reasoning"].(map[string]any); ok {
		if budget := firstPositiveInt(reasoning, "max_tokens", "budget_tokens"); budget > 0 {
			return budget
		}
	}
	for _, key := range []string{"thinkingConfig", "thinking_config"} {
		if config, ok := root[key].(map[string]any); ok {
			if budget := firstPositiveInt(config, "thinkingBudget", "thinking_budget"); budget > 0 {
				return budget
			}
		}
	}
	if generation, ok := root["generationConfig"].(map[string]any); ok {
		for _, key := range []string{"thinkingConfig", "thinking_config"} {
			if config, ok := generation[key].(map[string]any); ok {
				if budget := firstPositiveInt(config, "thinkingBudget", "thinking_budget"); budget > 0 {
					return budget
				}
			}
		}
	}
	return 0
}

// firstPositiveInt 依次尝试多个键，返回第一个正整数。
func firstPositiveInt(values map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := values[key].(float64); ok && value > 0 {
			return int(value)
		}
	}
	return 0
}
