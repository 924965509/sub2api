package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func channelCacheAccount(ratio float64, target string, models any) *Account {
	return &Account{Extra: map[string]any{
		channelCacheTransferRatioKey:  ratio,
		channelCacheTransferTargetKey: target,
		channelCacheTransferModelsKey: models,
	}}
}

func TestChannelCacheTransferModelMatching(t *testing.T) {
	account := channelCacheAccount(25, "input", []any{"claude-opus-*", "gpt-5.6-terra"})
	_, ok := resolveChannelCacheTransferConfig(account, "claude-opus-4-6")
	require.True(t, ok)
	_, ok = resolveChannelCacheTransferConfig(account, "GPT-5.6-TERRA")
	require.True(t, ok)
	_, ok = resolveChannelCacheTransferConfig(account, "gpt-5.4")
	require.False(t, ok)

	account.Extra[channelCacheTransferModelsKey] = ""
	_, ok = resolveChannelCacheTransferConfig(account, "anything")
	require.True(t, ok)
}

func TestChannelCacheTransferClaudeUsageToInput(t *testing.T) {
	usage := ClaudeUsage{InputTokens: 100, CacheCreationInputTokens: 50, CacheReadInputTokens: 10_000}
	amount, target := applyChannelCacheTransferClaudeUsage(channelCacheAccount(25, "input", nil), "claude-opus-4-6", &usage)
	require.Equal(t, 2500, amount)
	require.Equal(t, channelCacheTransferTargetInput, target)
	require.Equal(t, 2600, usage.InputTokens)
	require.Equal(t, 7500, usage.CacheReadInputTokens)
	require.Equal(t, 50, usage.CacheCreationInputTokens)
}

func TestChannelCacheTransferClaudeUsageToCacheCreation(t *testing.T) {
	usage := ClaudeUsage{InputTokens: 100, CacheCreationInputTokens: 50, CacheCreation5mTokens: 50, CacheReadInputTokens: 1000}
	amount, _ := applyChannelCacheTransferClaudeUsage(channelCacheAccount(20, "cache_creation", nil), "claude-opus-4-6", &usage)
	require.Equal(t, 200, amount)
	require.Equal(t, 800, usage.CacheReadInputTokens)
	require.Equal(t, 250, usage.CacheCreationInputTokens)
	require.Equal(t, 250, usage.CacheCreation5mTokens)
}

func TestChannelCacheTransferOpenAIKeepsTotalInput(t *testing.T) {
	usage := OpenAIUsage{InputTokens: 1000, CacheReadInputTokens: 600, CacheCreationInputTokens: 100}
	amount, target := applyChannelCacheTransferOpenAIUsage(channelCacheAccount(25, "input", nil), "gpt-5.6-terra", &usage)
	require.Equal(t, 150, amount)
	require.Equal(t, channelCacheTransferTargetInput, target)
	require.Equal(t, 1000, usage.InputTokens)
	require.Equal(t, 450, usage.CacheReadInputTokens)
	require.Equal(t, 100, usage.CacheCreationInputTokens)
}

func TestRewriteOpenAIChannelCacheTransferJSON(t *testing.T) {
	body := []byte("{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":1000,\"output_tokens\":10,\"input_tokens_details\":{\"cached_tokens\":600}}}")
	got, changed := rewriteOpenAIChannelCacheTransferJSON(body, channelCacheAccount(25, "input", nil), "gpt-5.6-terra")
	require.True(t, changed)
	require.Equal(t, int64(450), gjson.GetBytes(got, "usage.input_tokens_details.cached_tokens").Int())
	require.Equal(t, int64(1000), gjson.GetBytes(got, "usage.input_tokens").Int())
}

func TestRewriteAnthropicChannelCacheTransferJSON(t *testing.T) {
	body := []byte("{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":100,\"output_tokens\":10,\"cache_read_input_tokens\":10000,\"cache_creation_input_tokens\":100}}")
	got, changed := rewriteAnthropicChannelCacheTransferJSON(body, channelCacheAccount(25, "input", nil), "claude-opus-4-6")
	require.True(t, changed)
	require.Equal(t, int64(2600), gjson.GetBytes(got, "usage.input_tokens").Int())
	require.Equal(t, int64(7500), gjson.GetBytes(got, "usage.cache_read_input_tokens").Int())
	require.Equal(t, int64(100), gjson.GetBytes(got, "usage.cache_creation_input_tokens").Int())
}

func TestRewriteOpenAIChannelCacheTransferJSONToCacheCreationPreservesExistingWrite(t *testing.T) {
	body := []byte("{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":1000,\"output_tokens\":10,\"input_tokens_details\":{\"cached_tokens\":600,\"cache_write_tokens\":100}}}")
	got, changed := rewriteOpenAIChannelCacheTransferJSON(body, channelCacheAccount(25, "cache_creation", nil), "gpt-5.6-terra")
	require.True(t, changed)
	require.Equal(t, int64(450), gjson.GetBytes(got, "usage.input_tokens_details.cached_tokens").Int())
	require.Equal(t, int64(250), gjson.GetBytes(got, "usage.input_tokens_details.cache_write_tokens").Int())
	require.Equal(t, int64(250), gjson.GetBytes(got, "usage.cache_creation_input_tokens").Int())
	require.Equal(t, int64(1000), gjson.GetBytes(got, "usage.input_tokens").Int())
}
