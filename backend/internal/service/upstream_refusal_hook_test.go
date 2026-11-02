package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// recordingUpstreamRefusalRecorder 记录收到的上游拒答事件，用于断言接线行为。
type recordingUpstreamRefusalRecorder struct {
	mu     sync.Mutex
	events []UpstreamRefusalEvent
	panic  bool
}

func (r *recordingUpstreamRefusalRecorder) RecordUpstreamRefusal(_ context.Context, event UpstreamRefusalEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	if r.panic {
		panic("recorder boom")
	}
}

func (r *recordingUpstreamRefusalRecorder) snapshot() []UpstreamRefusalEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := make([]UpstreamRefusalEvent, len(r.events))
	copy(events, r.events)
	return events
}

// newGinContextWithObservation 构造带（或不带）观察值的 gin 上下文。
func newGinContextWithObservation(observation *ctxkey.UpstreamObservation) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	ctx := context.Background()
	if observation != nil {
		ctx = ctxkey.WithUpstreamObservation(ctx, *observation)
	}
	c.Request = c.Request.WithContext(ctx)
	return c
}

func TestNotifyUpstreamRefusalWithoutRecorderIsNoop(t *testing.T) {
	SetUpstreamRefusalRecorder(nil)
	defer SetUpstreamRefusalRecorder(nil)
	require.False(t, UpstreamRefusalRecorderInstalled())

	groupID := int64(3)
	c := newGinContextWithObservation(&ctxkey.UpstreamObservation{RequestID: "req-1", GroupID: &groupID})
	// 未安装记录器时不得 panic，也不产生任何副作用。
	require.NotPanics(t, func() { NotifyUpstreamRefusal(c, "silent_refusal", http.StatusBadGateway) })
}

func TestNotifyUpstreamRefusalDeliversObservation(t *testing.T) {
	recorder := &recordingUpstreamRefusalRecorder{}
	SetUpstreamRefusalRecorder(recorder)
	defer SetUpstreamRefusalRecorder(nil)
	require.True(t, UpstreamRefusalRecorderInstalled())

	groupID := int64(3)
	c := newGinContextWithObservation(&ctxkey.UpstreamObservation{
		RequestID: "req-2", UserID: 7, APIKeyID: 9, GroupID: &groupID,
		Provider: "openai", Endpoint: "/v1/responses", Protocol: "openai_responses", Model: "gpt-5",
		Body: []byte(`{"input":"hello"}`),
	})
	NotifyUpstreamRefusal(c, "upstream_refusal", http.StatusForbidden)

	events := recorder.snapshot()
	require.Len(t, events, 1)
	require.Equal(t, "req-2", events[0].RequestID)
	require.Equal(t, int64(7), events[0].UserID)
	require.Equal(t, int64(9), events[0].APIKeyID)
	require.NotNil(t, events[0].GroupID)
	require.Equal(t, int64(3), *events[0].GroupID)
	require.Equal(t, "openai", events[0].Provider)
	require.Equal(t, "gpt-5", events[0].Model)
	require.Equal(t, "upstream_refusal", events[0].Source)
	require.Equal(t, http.StatusForbidden, events[0].StatusCode)
	require.Equal(t, `{"input":"hello"}`, string(events[0].Body))
}

func TestNotifyUpstreamRefusalWithoutObservationIsSkipped(t *testing.T) {
	recorder := &recordingUpstreamRefusalRecorder{}
	SetUpstreamRefusalRecorder(recorder)
	defer SetUpstreamRefusalRecorder(nil)

	// 请求没有走审计前置（上下文里没有观察值）时不上报。
	c := newGinContextWithObservation(nil)
	NotifyUpstreamRefusal(c, "upstream_refusal", http.StatusForbidden)
	require.Empty(t, recorder.snapshot())
}

func TestNotifyUpstreamRefusalToleratesNilContextAndPanickingRecorder(t *testing.T) {
	require.NotPanics(t, func() { NotifyUpstreamRefusal(nil, "upstream_refusal", http.StatusForbidden) })

	recorder := &recordingUpstreamRefusalRecorder{panic: true}
	SetUpstreamRefusalRecorder(recorder)
	defer SetUpstreamRefusalRecorder(nil)

	c := newGinContextWithObservation(&ctxkey.UpstreamObservation{RequestID: "req-3"})
	// 记录器内部 panic 必须被吞掉，不能影响上游错误处理链路。
	require.NotPanics(t, func() { NotifyUpstreamRefusal(c, "upstream_refusal", http.StatusForbidden) })
	require.Len(t, recorder.snapshot(), 1)
}

func TestStructuredUpstreamRefusalIndicators(t *testing.T) {
	cases := []struct {
		name, payload string
		refused       bool
	}{
		{"claude refusal", `{"stop_reason":"refusal"}`, true},
		{"claude streaming", `{"type":"message_delta","delta":{"stop_reason":"refusal"}}`, true},
		{"claude normal", `{"stop_reason":"end_turn"}`, false},
		{"gemini prompt", `{"promptFeedback":{"blockReason":"SAFETY"}}`, true},
		{"gemini candidate", `{"candidates":[{"finishReason":"PROHIBITED_CONTENT"}]}`, true},
		{"gemini normal", `{"candidates":[{"finishReason":"STOP"}]}`, false},
		{"openai finish", `{"choices":[{"finish_reason":"content_filter"}]}`, true},
		{"responses refusal", `{"response":{"incomplete_details":{"reason":"content_filter"}}}`, true},
		{"normal max tokens", `{"incomplete_details":{"reason":"max_output_tokens"}}`, false},
		{"unstructured error", `{"error":"temporary network problem"}`, false},
		{"bad json", `not a response`, false},
		{"truncated refusal json", `{"stop_reason":"refusal"`, false},
		{"gemini wrapped", `{"response":{"candidates":[{"finishReason":"SAFETY"}]}}`, true},
		{"gemini array", `[{"response":{"candidates":[{"finishReason":"IMAGE_PROHIBITED_CONTENT"}]}}]`, true},
		{"chat refusal", `{"choices":[{"message":{"refusal":"policy refusal"}}]}`, true},
		{"responses content", `{"output":[{"content":[{"type":"refusal","refusal":"policy refusal"}]}]}`, true},
		{"responses stream", `{"type":"response.refusal.done","refusal":"policy refusal"}`, true},
		{"ordinary text", `{"output":[{"content":[{"type":"output_text","text":"refusal"}]}]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingUpstreamRefusalRecorder{}
			SetUpstreamRefusalRecorder(rec)
			defer SetUpstreamRefusalRecorder(nil)
			ctx := ctxkey.WithUpstreamObservation(context.Background(), ctxkey.UpstreamObservation{RequestID: "synthetic", Body: []byte(`{"input":"fixture"}`)})
			NotifyStructuredUpstreamRefusal(ctx, []byte(tc.payload))
			want := 0
			if tc.refused {
				want = 1
			}
			require.Len(t, rec.snapshot(), want)
		})
	}
}

func TestStructuredUpstreamRefusalObserverIntegration(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic", "gemini"} {
		t.Run(provider, func(t *testing.T) {
			rec := &recordingUpstreamRefusalRecorder{}
			SetUpstreamRefusalRecorder(rec)
			t.Cleanup(func() { SetUpstreamRefusalRecorder(nil) })
			c := newGinContextWithObservation(&ctxkey.UpstreamObservation{
				RequestID: "fixture-request", Provider: provider, APIKeyID: 7,
				SelectedAccountID: 11, AuditTurn: "turn:2", Body: []byte(`{"input":"test"}`),
			})
			observer := beginUpstreamResponseModelObservation(c)
			for i := 0; i < 2; i++ {
				switch provider {
				case "openai":
					observer.ObserveOpenAI([]byte(`{"model":"fixture-model","choices":[{"finish_reason":"content_filter"}]}`), "")
				case "anthropic":
					observer.ObserveAnthropic([]byte(`{"model":"fixture-model","delta":{"stop_reason":"refusal"}}`))
				case "gemini":
					observer.ObserveGemini([]byte(`{"modelVersion":"fixture-model","candidates":[{"finishReason":"SAFETY"}]}`))
				}
			}
			events := rec.snapshot()
			require.Len(t, events, 1, "repeated stream frames are recorded once per forwarding attempt")
			require.Equal(t, "fixture-model", observer.Model(), "model observation remains unchanged")
			require.Equal(t, "turn:2", events[0].AuditTurn)
			require.Equal(t, int64(11), events[0].SelectedAccountID)
			require.Equal(t, http.StatusOK, events[0].StatusCode)
		})
	}
}

type disabledUpstreamRefusalRecorder struct {
	recordingUpstreamRefusalRecorder
}

func (*disabledUpstreamRefusalRecorder) UpstreamObservationEnabled() bool { return false }
func TestStructuredUpstreamRefusalDisabledAndNilContexts(t *testing.T) {
	rec := &disabledUpstreamRefusalRecorder{}
	SetUpstreamRefusalRecorder(rec)
	t.Cleanup(func() { SetUpstreamRefusalRecorder(nil) })
	ctx := ctxkey.WithUpstreamObservation(context.Background(), ctxkey.UpstreamObservation{RequestID: "disabled"})
	NotifyStructuredUpstreamRefusal(ctx, []byte(`{"stop_reason":"refusal"}`))
	NotifyStructuredUpstreamRefusal(nil, []byte(`{"stop_reason":"refusal"}`))
	NotifyStructuredUpstreamRefusal(context.Background(), []byte(`{"stop_reason":"refusal"}`))
	require.Empty(t, rec.snapshot())
}
