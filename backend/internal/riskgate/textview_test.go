package riskgate

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/stretchr/testify/require"
)

func buildView(t *testing.T, protocol, body string) (TextView, RequestMeta) {
	t.Helper()
	request := securityaudit.Request{
		RequestID: "req-tv", UserID: 1, APIKeyID: 2, Protocol: protocol,
		Provider: "openai", Endpoint: "/v1/x", Model: "m", Body: []byte(body),
	}
	view, meta, err := BuildTextView(request, NormalizeOptions{ExpandBase64: true})
	require.NoError(t, err)
	return view, meta
}

func TestTextViewOpenAIChatCompletions(t *testing.T) {
	body := `{"model":"gpt-4o","max_tokens":4096,"messages":[
		{"role":"system","content":"you are helpful"},
		{"role":"user","content":"first question"},
		{"role":"assistant","content":"first answer"},
		{"role":"user","content":"second question"},
		{"role":"user","content":[{"type":"text","text":"second question part two"}]}
	]}`
	view, meta := buildView(t, "openai_chat_completions", body)

	require.Equal(t, 4096, meta.MaxTokens)
	require.Contains(t, view.SystemText, "you are helpful")
	require.Contains(t, view.UserTranscript, "first question")
	require.Contains(t, view.UserTranscript, "second question")
	// 最新一条 user 消息包含同一轮的多个 part。
	require.Contains(t, view.LatestUser, "second question")
	require.Contains(t, view.LatestUser, "part two")
	require.False(t, view.ToolResultOnly)
	require.NotEmpty(t, view.NormalizedHash)
	require.Len(t, view.NormalizedHash, 64)
}

func TestTextViewAnthropicMessagesSkipsToolResult(t *testing.T) {
	body := `{"model":"claude-3","max_tokens":1024,"system":[{"type":"text","text":"You are Claude Code"}],
	"messages":[
		{"role":"user","content":[{"type":"text","text":"real question"}]},
		{"role":"assistant","content":[{"type":"text","text":"partial"}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"tool output text"}]},
		{"role":"user","content":[{"type":"text","text":"final question"},{"type":"tool_result","content":"ignored output"}]}
	]}`
	view, _ := buildView(t, "anthropic_messages", body)

	require.Contains(t, view.SystemText, "You are Claude Code")
	require.Contains(t, view.LatestUser, "final question")
	require.NotContains(t, view.LatestUser, "tool output text")
	require.NotContains(t, view.LatestUser, "ignored output")
	require.False(t, view.ToolResultOnly)
}

func TestTextViewToolResultOnly(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"assistant","content":"only output"},
	{"role":"user","content":[{"type":"tool_result","content":"tool output"}]}]}`
	view, _ := buildView(t, "openai_chat_completions", body)

	require.True(t, view.ToolResultOnly)
	require.Empty(t, view.LatestUser)
	require.Empty(t, view.SystemText, "tool results are neither user text nor system instructions")
}

func TestTextViewOpenAIResponses(t *testing.T) {
	body := `{"model":"gpt-5","max_output_tokens":8192,"instructions":"follow the rules",
	"input":[{"role":"user","content":[{"type":"input_text","text":"responses question"}]}]}`
	view, meta := buildView(t, "openai_responses", body)

	require.Equal(t, 8192, meta.MaxTokens)
	require.Contains(t, view.SystemText, "follow the rules")
	require.Contains(t, view.LatestUser, "responses question")
}

func TestTextViewGemini(t *testing.T) {
	body := `{"model":"gemini-2.5-pro","generationConfig":{"maxOutputTokens":4096,"thinkingConfig":{"thinkingBudget":2048}},
	"systemInstruction":{"parts":[{"text":"gemini system"}]},
	"contents":[{"role":"model","parts":[{"text":"previous answer"}]},
	{"role":"user","parts":[{"text":"gemini question"}]}]}`
	view, meta := buildView(t, "gemini", body)

	require.Equal(t, 4096, meta.MaxTokens)
	require.Equal(t, 2048, meta.ThinkingBudget)
	require.Contains(t, view.SystemText, "gemini system")
	require.Contains(t, view.LatestUser, "gemini question")
	require.NotContains(t, view.LatestUser, "previous answer")
}

func TestTextViewStripsEnvironmentSection(t *testing.T) {
	body := `{"model":"claude-3","system":"You are Claude Code.\n# Environment\n - cwd: /tmp\n","messages":[{"role":"user","content":"hi"}]}`
	view, _ := buildView(t, "anthropic_messages", body)

	require.Contains(t, view.EnvText, "# Environment")
	require.Contains(t, view.EnvText, "cwd")
	require.NotContains(t, view.NormalizedAll(), "cwd")
}

func TestTextViewEmptyBodyIsError(t *testing.T) {
	request := securityaudit.Request{Protocol: "openai_chat_completions"}
	_, _, err := BuildTextView(request, NormalizeOptions{})
	require.Error(t, err)
}

func TestExtractIdentityDetectsOfficialClaudeCode(t *testing.T) {
	view := TextView{SystemText: "You are Claude Code, Anthropic's official CLI for Claude."}
	identity := ExtractIdentity(securityaudit.Request{Model: "claude-sonnet-4"}, view)
	require.True(t, identity.OfficialClaudeCode)
	require.False(t, identity.ZeroInjection)

	empty := ExtractIdentity(securityaudit.Request{}, TextView{})
	require.False(t, empty.OfficialClaudeCode)
	require.True(t, empty.ZeroInjection)
}

func TestFingerprintFromHeadersIsStable(t *testing.T) {
	headers := map[string][]string{
		"User-Agent": {"Claude-CLI/1.0"}, "Originator": {"claude-code"}, "X-Client-Id": {"abc"},
	}
	first := FingerprintFromHeaders(headers)
	require.Len(t, first, 64)
	require.Equal(t, first, FingerprintFromHeaders(map[string][]string{
		"user-agent": {"claude-cli/1.0"}, "originator": {"claude-code"}, "x-client-id": {"ABC"},
	}))
	require.NotEqual(t, first, FingerprintFromHeaders(map[string][]string{"User-Agent": {"other"}}))
	require.Empty(t, FingerprintFromHeaders(nil))
}
