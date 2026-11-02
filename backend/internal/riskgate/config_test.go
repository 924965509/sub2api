package riskgate

import (
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfigIsDisabled(t *testing.T) {
	cfg := DefaultConfig()
	require.Equal(t, ModeOff, cfg.EffectiveMode())
	require.NoError(t, Validate(cfg))
	require.Nil(t, cfg.EnabledGates(), "off 模式不得声明任何生效闸门")
	require.Equal(t, BanScopeAPIKey, cfg.Ban.Scope)
}

func TestValidateRejectsInvalidConfig(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(cfg *Config)
	}{
		{"未知 mode", func(cfg *Config) { cfg.Mode = "enforcing" }},
		{"非法封禁作用域", func(cfg *Config) { cfg.Ban.Scope = "device" }},
		{"封禁时长越界", func(cfg *Config) { cfg.Ban.DurationHours = -1 }},
		{"相似度阈值越界", func(cfg *Config) { cfg.RefusalCache.SimilarityThreshold = 1.5 }},
		{"决策模型阈值越界", func(cfg *Config) { cfg.DecisionModel.Threshold = -0.1 }},
		{"决策超时过小", func(cfg *Config) { cfg.DecisionModel.TimeoutMS = 10 }},
		{"决策并发越界", func(cfg *Config) { cfg.DecisionModel.MaxConcurrent = -1 }},
		{"未知失败策略", func(cfg *Config) { cfg.DecisionModel.OnUnavailable = "retry" }},
		{"未知正则类别", func(cfg *Config) { cfg.Regex.Categories = []string{"unknown"} }},
		{"正则输入上限越界", func(cfg *Config) { cfg.Regex.MaxInputBytes = maxRegexInputBytes + 1 }},
		{"蒸馏针含空串", func(cfg *Config) { cfg.Distill.HardNeedles = []string{"  "} }},
		{"赛题正则为空正则", func(cfg *Config) { cfg.Distill.ContestPattern = "([unclosed" }},
		{"分组列表为空", func(cfg *Config) { cfg.Scope.AllGroups = false; cfg.Scope.GroupIDs = nil }},
		{"分组 ID 非法", func(cfg *Config) { cfg.Scope.AllGroups = false; cfg.Scope.GroupIDs = []int64{0} }},
		{"provider 列表为空", func(cfg *Config) { cfg.Scope.AllProviders = false }},
		{"保留天数越界", func(cfg *Config) { cfg.RetentionDays = maxRetentionDays + 1 }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := DefaultConfig()
			testCase.mutate(&cfg)
			err := Validate(cfg.WithDefaults())
			require.Error(t, err)
			require.True(t, infraerrors.IsBadRequest(err), "校验失败必须是 400: %v", err)
			require.Equal(t, ErrorCodeInvalidConfig, infraerrors.Reason(err))
		})
	}
}

// 决策模型端点的结构化校验：非法地址、空 model、重复 id、无可用端点都必须 400。
func TestValidateRejectsInvalidClassifierEndpoints(t *testing.T) {
	testCases := []struct {
		name      string
		endpoints []ClassifierEndpoint
		enabled   bool
	}{
		{"重复端点 id", []ClassifierEndpoint{
			{ID: "a", BaseURL: "https://api.example.com", Model: "m", Enabled: true},
			{ID: "a", BaseURL: "https://api.example.com", Model: "m", Enabled: true},
		}, true},
		{"非法 base_url", []ClassifierEndpoint{
			{ID: "a", BaseURL: "not-a-url", Model: "m", Enabled: true},
		}, true},
		{"空 model", []ClassifierEndpoint{
			{ID: "a", BaseURL: "https://api.example.com", Model: "  ", Enabled: true},
		}, true},
		{"端点超时越界", []ClassifierEndpoint{
			{ID: "a", BaseURL: "https://api.example.com", Model: "m", Enabled: true, TimeoutMS: 5},
		}, true},
		{"启用但无可用端点", []ClassifierEndpoint{
			{ID: "a", BaseURL: "https://api.example.com", Model: "m", Enabled: false},
		}, true},
		{"启用但端点为空", nil, true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DecisionModel.Enabled = testCase.enabled
			cfg.Gates.DecisionModel = testCase.enabled
			cfg.DecisionModel.Endpoints = testCase.endpoints
			err := Validate(cfg.WithDefaults())
			require.Error(t, err)
			require.True(t, infraerrors.IsBadRequest(err), "校验失败必须是 400: %v", err)
			require.Equal(t, ErrorCodeInvalidConfig, infraerrors.Reason(err))
		})
	}
}

// 合规端点必须通过校验，并且 WithDefaults 会补齐 id 与 timeout_ms。
func TestValidateAcceptsClassifierEndpointsAndFillsDefaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DecisionModel.Enabled = true
	cfg.DecisionModel.Endpoints = []ClassifierEndpoint{
		{BaseURL: "https://api.example.com", Model: "gpt-4o-mini", Enabled: true},
	}
	cfg = cfg.WithDefaults()
	require.NoError(t, Validate(cfg))
	require.Len(t, cfg.DecisionModel.Endpoints, 1)
	require.Equal(t, "endpoint-0", cfg.DecisionModel.Endpoints[0].ID)
	require.Equal(t, DefaultDecisionTimeoutMS, cfg.DecisionModel.Endpoints[0].TimeoutMS)
}

// Clone 必须深拷贝端点切片，调用方改动不能影响内部快照。
func TestCloneDeepCopiesClassifierEndpoints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DecisionModel.Endpoints = []ClassifierEndpoint{
		{ID: "a", BaseURL: "https://api.example.com", Model: "m", Enabled: true, APIKey: "secret"},
	}
	cloned := cfg.Clone()
	require.Equal(t, cfg.DecisionModel.Endpoints, cloned.DecisionModel.Endpoints)
	cloned.DecisionModel.Endpoints[0].APIKey = "changed"
	require.Equal(t, "secret", cfg.DecisionModel.Endpoints[0].APIKey)
}

func TestWithDefaultsFillsZeroValues(t *testing.T) {
	cfg := Config{Mode: " BLOCKING "}.WithDefaults()
	require.Equal(t, string(ModeBlocking), cfg.Mode)
	require.Equal(t, BanScopeAPIKey, cfg.Ban.Scope)
	require.Equal(t, DefaultRegexMaxInputBytes, cfg.Regex.MaxInputBytes)
	require.Equal(t, DefaultSimilarityThreshold, cfg.RefusalCache.SimilarityThreshold)
	require.Equal(t, DefaultRetentionDays, cfg.RetentionDays)
	require.Equal(t, DefaultDecisionTimeoutMS, cfg.DecisionModel.TimeoutMS)
	require.NoError(t, Validate(cfg))
}

// refusal_cache 与 decision_model 自 P4 起都计入生效闸门。
func TestEnabledGatesIncludesRefusalCacheAndDecisionModel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = string(ModeBlocking)
	cfg.Gates.RefusalCache = true
	cfg.Gates.DecisionModel = true
	require.Equal(t, []string{GateBan, GateRefusalCache, GateDecisionModel}, cfg.EnabledGates())
}

// decision_model.enabled 为真时，即使 gates 开关没打开也计入生效闸门。
func TestEnabledGatesIncludesDecisionModelFromSectionToggle(t *testing.T) {
	cfg := legacyRiskConfigForTest()
	cfg.Mode = string(ModeObserve)
	cfg.DecisionModel.Enabled = true
	require.True(t, cfg.DecisionModelActive())
	require.Equal(t, []string{GateBan, GateDecisionModel}, cfg.EnabledGates())
}

// refusal_cache.enabled（历史兼容字段）单独为真时闸门同样生效。
func TestRefusalCacheActiveFromLegacyToggle(t *testing.T) {
	cfg := legacyRiskConfigForTest()
	cfg.Mode = string(ModeObserve)
	cfg.RefusalCache.Enabled = true
	require.True(t, cfg.RefusalCacheActive())
	require.Equal(t, []string{GateBan, GateRefusalCache}, cfg.EnabledGates())
}

// 两个开关都关闭时拒答缓存闸不生效。
func TestRefusalCacheActiveDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = string(ModeBlocking)
	require.False(t, cfg.RefusalCacheActive())
	require.Equal(t, []string{GateBan}, cfg.EnabledGates())
}
