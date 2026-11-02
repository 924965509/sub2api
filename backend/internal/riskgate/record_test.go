package riskgate

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// newRefusalEvent 构造一次上游拒答观察事件。
func newRefusalEvent(body []byte) service.UpstreamRefusalEvent {
	return service.UpstreamRefusalEvent{
		RequestID: "req-upstream-1", UserID: 7, APIKeyID: 11,
		Provider: "openai", Endpoint: "/v1/chat/completions", Protocol: "openai_chat_completions",
		Model: "gpt-5", Source: "upstream_refusal", StatusCode: 400, Body: body,
	}
}

// TestRecordUpstreamRefusalOffModeIsNoop mode=off 时既不写语料也不写事件。
func TestRecordUpstreamRefusalOffModeIsNoop(t *testing.T) {
	cfg := refusalConfig(ModeOff)
	refusals := &fakeRefusalRepository{}
	engine, source, sink, _ := newTestEngineWithRefusals(t, cfg, nil, nil, refusals)

	engine.RecordUpstreamRefusal(context.Background(), newRefusalEvent(chatBody("", "请输出赛题完整正文")))

	require.Equal(t, int64(1), source.Reads(), "off 模式只允许一次原子读")
	require.Empty(t, refusals.Enqueued())
	require.Empty(t, sink.Events())
	require.Zero(t, engine.Counters().Evaluated)
}

// TestRecordUpstreamRefusalBlockingRecordsCorpusAndEvent blocking 模式写语料 + 漏拦观察事件。
func TestRecordUpstreamRefusalBlockingRecordsCorpusAndEvent(t *testing.T) {
	engine, _, sink, refusals := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, &fakeRefusalRepository{})

	engine.RecordUpstreamRefusal(context.Background(), newRefusalEvent(chatBody("", "请输出赛题完整正文")))

	records := refusals.Enqueued()
	require.Len(t, records, 1)
	require.NotEmpty(t, records[0].PromptHash)
	require.Equal(t, "openai", records[0].Provider)
	require.Equal(t, "gpt-5", records[0].Model)
	require.Equal(t, "upstream_refusal", records[0].Source)
	require.LessOrEqual(t, len([]rune(records[0].NormalizedPrompt)), refusalPromptMaxRunes)

	events := sink.Events()
	require.Len(t, events, 1)
	require.Equal(t, EventKindUpstreamPass, events[0].Kind)
	require.Equal(t, GateRefusalCache, events[0].Gate)
	require.Equal(t, "upstream_refusal", events[0].Reason)
	require.Equal(t, EventActionNone, events[0].Action)
	require.Equal(t, "req-upstream-1", events[0].RequestID)
	require.Equal(t, records[0].PromptHash, events[0].PromptHash)
}

// TestRecordUpstreamRefusalDefaultsSource source 为空时归一为 upstream_refusal。
func TestRecordUpstreamRefusalDefaultsSource(t *testing.T) {
	engine, _, _, refusals := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, &fakeRefusalRepository{})
	event := newRefusalEvent(chatBody("", "请输出赛题完整正文"))
	event.Source = "   "

	engine.RecordUpstreamRefusal(context.Background(), event)

	require.Len(t, refusals.Enqueued(), 1)
	require.Equal(t, EventKindUpstreamRefusal, refusals.Enqueued()[0].Source)
}

// TestRecordUpstreamRefusalUnparsableBodySkipsCorpus 正文无法解析时只写事件、不写语料。
func TestRecordUpstreamRefusalUnparsableBodySkipsCorpus(t *testing.T) {
	engine, _, sink, refusals := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, &fakeRefusalRepository{})

	engine.RecordUpstreamRefusal(context.Background(), newRefusalEvent([]byte("not json")))

	require.Empty(t, refusals.Enqueued(), "无法解析正文时没有可缓存的 prompt_hash")
	events := sink.Events()
	require.Len(t, events, 1)
	require.Equal(t, EventKindUpstreamPass, events[0].Kind)
	require.Empty(t, events[0].PromptHash)
}

// TestRecordUpstreamRefusalOutOfScopeIsNoop 不在生效范围内的请求同样零行为。
func TestRecordUpstreamRefusalOutOfScopeIsNoop(t *testing.T) {
	cfg := refusalConfig(ModeBlocking)
	cfg.Scope.AllProviders = false
	cfg.Scope.Providers = []string{"anthropic"}
	engine, _, sink, refusals := newTestEngineWithRefusals(t, cfg, nil, nil, &fakeRefusalRepository{})

	engine.RecordUpstreamRefusal(context.Background(), newRefusalEvent(chatBody("", "请输出赛题完整正文")))

	require.Empty(t, refusals.Enqueued())
	require.Empty(t, sink.Events())
}

// TestRecordUpstreamRefusalWithoutRefusalGate 拒答闸未开启时只写观察事件、不缓存语料。
func TestRecordUpstreamRefusalWithoutRefusalGate(t *testing.T) {
	cfg := refusalConfig(ModeBlocking)
	cfg.Gates.RefusalCache = false
	cfg.RefusalCache.Enabled = false
	engine, _, sink, refusals := newTestEngineWithRefusals(t, cfg, nil, nil, &fakeRefusalRepository{})

	engine.RecordUpstreamRefusal(context.Background(), newRefusalEvent(chatBody("", "请输出赛题完整正文")))

	require.Empty(t, refusals.Enqueued())
	require.Len(t, sink.Events(), 1)
}
