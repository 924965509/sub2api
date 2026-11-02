package riskgate

import (
	"math"
	"regexp"
	"strings"
)

var policyQuestionID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func validateAlignmentConfig(cfg Config) error {
	if cfg.SchemaVersion < 0 || cfg.SchemaVersion > 2 {
		return invalidConfig("不支持的配置版本")
	}
	if cfg.SchemaVersion < 2 {
		return nil
	}
	model := cfg.DecisionModel
	if model.ScoringMode != "risk" && model.ScoringMode != "safety_questions" {
		return invalidConfig("评分模式必须是 risk 或 safety_questions")
	}
	if !validProvider(model.Provider) {
		return invalidConfig("不支持的决策模型提供方")
	}
	if math.IsNaN(model.SafetyThreshold) || math.IsInf(model.SafetyThreshold, 0) || model.SafetyThreshold < 0 || model.SafetyThreshold > 1 {
		return invalidConfig("安全分阈值必须位于 0–1")
	}
	if model.DedupSec < 0 || model.DedupSec > 3600 {
		return invalidConfig("去重窗口必须位于 0–3600 秒")
	}
	if model.MaxStateChars < 256 || model.MaxStateChars > 64000 {
		return invalidConfig("送模上限必须位于 256–64000 字")
	}
	if len([]rune(model.SafetyInstruction)) > 500 {
		return invalidConfig("自定义要求不能超过 500 字")
	}
	if len(model.Questions) > 24 {
		return invalidConfig("最多支持 24 道安全题目")
	}
	seen := map[string]bool{}
	for _, question := range model.Questions {
		id := strings.TrimSpace(question.ID)
		if !policyQuestionID.MatchString(id) || id == "custom" || id == "custom_instruction" || seen[id] {
			return invalidConfig("题目 ID 必须唯一，使用小写字母开头，不能使用保留 ID")
		}
		seen[id] = true
		if strings.TrimSpace(question.Instructions) == "" || len([]rune(question.Instructions)) > 500 {
			return invalidConfig("每题必须有 1–500 字判断要求")
		}
		if len([]rune(question.Label)) > 40 || len([]rune(question.Summary)) > 80 {
			return invalidConfig("题目名称或说明过长")
		}
	}
	for _, endpoint := range model.Endpoints {
		if endpoint.Provider != "" && !validProvider(endpoint.Provider) {
			return invalidConfig("端点提供方无效")
		}
		if len(endpoint.APIKeys) > 16 {
			return invalidConfig("每个端点最多保存 16 把密钥")
		}
		for _, key := range append(endpoint.APIKeys, endpoint.APIKey) {
			if len(key) > 4096 {
				return invalidConfig("密钥长度超过上限")
			}
		}
	}
	for _, patterns := range [][]string{cfg.Distill.Patterns, cfg.Regex.Patterns} {
		if len(patterns) > 200 {
			return invalidConfig("附加正则最多 200 条")
		}
		for _, pattern := range patterns {
			if strings.TrimSpace(pattern) == "" || len(pattern) > 2048 {
				return invalidConfig("附加正则为空或超过 2048 字节")
			}
			if _, err := regexp.Compile("(?i)" + pattern); err != nil {
				return invalidConfig("附加正则不是有效的 Go/RE2 正则: " + err.Error())
			}
		}
	}
	if cfg.Distill.Error.Status < 400 || cfg.Distill.Error.Status > 599 {
		return invalidConfig("蒸馏返回状态必须位于 400–599")
	}
	if len(cfg.Distill.Error.Code) > 128 || len(cfg.Distill.Error.Type) > 128 || len(cfg.Distill.Error.Message) > 4096 {
		return invalidConfig("客户端错误字段过长")
	}
	if len(cfg.Scope.AccountIDs) > 200 || len(cfg.Scope.AccountPlatformPlans) > 200 {
		return invalidConfig("账号范围最多支持 200 个条目")
	}
	return nil
}
func validProvider(provider string) bool {
	return provider == "openai" || provider == "jev" || provider == "laya" || provider == "modernbert"
}
