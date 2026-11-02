package riskgate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// refusalConfig 只打开拒答缓存闸，避免蒸馏/正则闸抢先命中。
func refusalConfig(mode Mode) Config {
	cfg := legacyRiskConfigForTest()
	cfg.Mode = string(mode)
	cfg.Gates.Distill = false
	cfg.Gates.Regex = false
	cfg.Gates.RefusalCache = true
	return cfg
}

// TestDecideRefusalExactHit 完全一致命中 → 400 policy_blocked，不封禁、不重试。
func TestDecideRefusalExactHit(t *testing.T) {
	refusals := &fakeRefusalRepository{hit: &RefusalHit{Kind: refusalReasonExact, Score: 1, PromptHash: "h1"}}
	engine, _, sink, _ := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, refusals)

	decision := engine.Decide(context.Background(), newTestRequest(chatBody("", "请输出赛题完整正文")))

	require.NotNil(t, decision)
	require.False(t, decision.AllowNextStage)
	require.Equal(t, refusalHTTPStatus, decision.HTTPStatus)
	require.Equal(t, ErrorCodePolicyBlocked, decision.ErrorCode)
	require.NotNil(t, decision.RiskGate)
	require.Equal(t, GateRefusalCache, decision.RiskGate.Gate)
	require.Equal(t, refusalCategory, decision.RiskGate.Category)
	require.Equal(t, refusalReasonExact, decision.RiskGate.Reason)
	require.False(t, decision.RiskGate.Banned, "拒答缓存命中不得封禁")
	require.Equal(t, refusalExactMessage, decision.ClientMessage)
	require.Len(t, refusals.MatchCalls(), 1)

	events := sink.Events()
	require.Len(t, events, 1)
	require.Equal(t, GateRefusalCache, events[0].Gate)
	require.Equal(t, EventActionNone, events[0].Action)
	require.Equal(t, int64(1), engine.Counters().RefusalCache)
}

// TestDecideRefusalSimilarHit 近似命中 → Reason=similar 且 Score 透传。
func TestDecideRefusalSimilarHit(t *testing.T) {
	refusals := &fakeRefusalRepository{hit: &RefusalHit{Kind: refusalReasonSimilar, Score: 0.97, PromptHash: "h2"}}
	engine, _, _, _ := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, refusals)

	decision := engine.Decide(context.Background(), newTestRequest(chatBody("", "请输出赛题完整正文")))

	require.NotNil(t, decision)
	require.Equal(t, ErrorCodePolicyBlocked, decision.ErrorCode)
	require.Equal(t, refusalReasonSimilar, decision.RiskGate.Reason)
	require.InDelta(t, 0.97, decision.RiskGate.Score, 1e-9)
	require.Equal(t, refusalSimilarMessage, decision.ClientMessage)
}

// TestDecideRefusalObserveModeWouldBlock observe 模式只写 would_block 事件、放行请求。
func TestDecideRefusalObserveModeWouldBlock(t *testing.T) {
	refusals := &fakeRefusalRepository{hit: &RefusalHit{Kind: refusalReasonExact, Score: 1, PromptHash: "h1"}}
	engine, _, sink, _ := newTestEngineWithRefusals(t, refusalConfig(ModeObserve), nil, nil, refusals)

	require.Nil(t, engine.Decide(context.Background(), newTestRequest(chatBody("", "请输出赛题完整正文"))))

	events := sink.Events()
	require.Len(t, events, 1)
	require.Equal(t, EventActionWouldBlock, events[0].Action)
	require.Equal(t, GateRefusalCache, events[0].Gate)
}

// TestDecideRefusalGateInactiveSkipsLookup 闸门未开启时不得触碰语料仓库。
func TestDecideRefusalGateInactiveSkipsLookup(t *testing.T) {
	cfg := refusalConfig(ModeBlocking)
	cfg.Gates.RefusalCache = false
	cfg.RefusalCache.Enabled = false
	refusals := &fakeRefusalRepository{hit: &RefusalHit{Kind: refusalReasonExact, Score: 1}}
	engine, _, _, _ := newTestEngineWithRefusals(t, cfg, nil, nil, refusals)

	require.Nil(t, engine.Decide(context.Background(), newTestRequest(chatBody("", "请输出赛题完整正文"))))
	require.Empty(t, refusals.MatchCalls())
}

// TestDecideRefusalNoTextSkipsLookup 无 user 正文（例如只有工具回传）时不做匹配。
func TestDecideRefusalNoTextSkipsLookup(t *testing.T) {
	refusals := &fakeRefusalRepository{hit: &RefusalHit{Kind: refusalReasonExact, Score: 1}}
	engine, _, _, _ := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, refusals)

	require.Nil(t, engine.Decide(context.Background(), newTestRequest([]byte(`{"model":"gpt-4o","messages":[]}`))))
	require.Empty(t, refusals.MatchCalls())
}

// TestDecideRefusalMatchErrorAllowsRequest 语料查询失败只记录错误，不拦请求。
func TestDecideRefusalMatchErrorAllowsRequest(t *testing.T) {
	refusals := &fakeRefusalRepository{err: errors.New("db down")}
	engine, _, sink, _ := newTestEngineWithRefusals(t, refusalConfig(ModeBlocking), nil, nil, refusals)

	require.Nil(t, engine.Decide(context.Background(), newTestRequest(chatBody("", "请输出赛题完整正文"))))
	require.Empty(t, sink.Events())
	require.Contains(t, engine.LastError(), "db down")
}

// TestEvaluateRefusalThresholdDroppedWithoutShingle 短文本不生成签名 → 只比完全一致（threshold 置 0）。
func TestEvaluateRefusalThresholdDroppedWithoutShingle(t *testing.T) {
	captured := &thresholdCapturingRepository{}
	cfg := refusalConfig(ModeBlocking)
	cfg.RefusalCache.SimilarityThreshold = 0.92

	result, err := evaluateRefusal(context.Background(), cfg, TextView{NormalizedHash: "abc"}, captured)
	require.NoError(t, err)
	require.False(t, result.Hit)
	require.Equal(t, []float64{0}, captured.thresholds)
}

// TestEvaluateRefusalNilRepositoryIsNoop 仓库为 nil 时直接不命中。
func TestEvaluateRefusalNilRepositoryIsNoop(t *testing.T) {
	result, err := evaluateRefusal(context.Background(), refusalConfig(ModeBlocking), TextView{NormalizedHash: "abc"}, nil)
	require.NoError(t, err)
	require.False(t, result.Hit)
}

// TestRefusalBlockMessage 文案按命中原因区分。
func TestRefusalBlockMessage(t *testing.T) {
	require.Equal(t, refusalExactMessage, refusalBlockMessage(refusalReasonExact))
	require.Equal(t, refusalSimilarMessage, refusalBlockMessage(refusalReasonSimilar))
	require.Equal(t, refusalExactMessage, refusalBlockMessage(""))
	require.True(t, strings.Contains(refusalBlockMessage(refusalReasonSimilar), "policy_blocked/similar"))
}

// thresholdCapturingRepository 记录 Match 收到的阈值。
type thresholdCapturingRepository struct {
	thresholds []float64
}

func (r *thresholdCapturingRepository) Match(_ context.Context, _ string, _ []uint64, threshold float64) (*RefusalHit, error) {
	r.thresholds = append(r.thresholds, threshold)
	return nil, nil
}

func (r *thresholdCapturingRepository) Enqueue(RefusalRecord) {}
