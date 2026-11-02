package securityaudit

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakePreGate struct {
	decision *Decision
	panics   bool
	calls    atomic.Int64
	lastReq  Request
}

func (f *fakePreGate) Decide(_ context.Context, req Request) *Decision {
	f.calls.Add(1)
	f.lastReq = req
	if f.panics {
		panic("risk gate exploded")
	}
	return f.decision
}

// 未安装前置闸门时，行为必须与历史版本完全一致。
func TestCoordinatorWithoutPreGateKeepsLegacyBehavior(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		legacy   *LegacyDecision
		prompt   *PromptDecision
		wantKind DecisionKind
		wantCode string
		wantEnq  int64
		wantEval int64
	}{
		{name: "off allows", mode: ModeOff, wantKind: DecisionAllow, wantCode: ""},
		{name: "async enqueues", mode: ModeAsync, wantKind: DecisionAllow, wantEnq: 1},
		{name: "legacy block still wins", mode: ModeBlocking,
			legacy: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden, Message: "legacy"},
			prompt: &PromptDecision{Kind: DecisionBlock}, wantKind: DecisionBlock, wantCode: "content_policy_violation", wantEval: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacy := &fakeLegacyEngine{decision: tt.legacy}
			prompt := &fakePromptEngine{mode: tt.mode, decision: tt.prompt}
			decision := NewCoordinator(legacy, prompt).Check(context.Background(), Request{Body: []byte(`{}`)})
			require.Equal(t, tt.wantKind, decision.Kind)
			require.Equal(t, tt.wantCode, decision.ErrorCode)
			require.Nil(t, decision.RiskGate)
			require.Equal(t, int64(1), legacy.calls.Load())
			require.Equal(t, tt.wantEnq, prompt.enqueues.Load())
			require.Equal(t, tt.wantEval, prompt.evaluates.Load())
		})
	}
}

// 前置闸门返回 nil / AllowNextStage=true 时不得影响既有流程。
func TestCoordinatorPreGateNonBlockingContinuesLegacyPath(t *testing.T) {
	tests := []struct {
		name     string
		decision *Decision
	}{
		{name: "nil decision", decision: nil},
		{name: "allow next stage", decision: &Decision{Kind: DecisionAllow, HTTPStatus: http.StatusOK, AllowNextStage: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacy := &fakeLegacyEngine{decision: &LegacyDecision{Blocked: true, StatusCode: http.StatusForbidden, Message: "legacy"}}
			prompt := &fakePromptEngine{mode: ModeBlocking, decision: &PromptDecision{Kind: DecisionBlock}}
			preGate := &fakePreGate{decision: tt.decision}
			decision := NewCoordinator(legacy, prompt).WithPreGate(preGate).
				Check(context.Background(), Request{Body: []byte(`{}`), Stage: "request"})

			require.Equal(t, int64(1), preGate.calls.Load())
			require.Equal(t, "request", preGate.lastReq.Stage)
			require.Equal(t, int64(1), legacy.calls.Load())
			require.Equal(t, DecisionBlock, decision.Kind)
			require.Equal(t, "legacy", decision.ClientMessage)
			require.Nil(t, decision.RiskGate)
		})
	}
}

// AllowNextStage=false 时必须立即短路，不再执行 legacy 与 prompt 审计。
func TestCoordinatorPreGateShortCircuits(t *testing.T) {
	blocked := &Decision{
		Kind: DecisionBlock, HTTPStatus: http.StatusForbidden, ErrorCode: ErrorCodeRiskGateBanned,
		ClientMessage: "request blocked by risk gate",
		RiskGate:      &RiskGateDecision{Gate: "ban", Reason: "distill", BanScope: "api_key", Banned: true},
	}
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{Blocked: false}}
	prompt := &fakePromptEngine{mode: ModeAsync}
	preGate := &fakePreGate{decision: blocked}

	decision := NewCoordinator(legacy, prompt).WithPreGate(preGate).Check(context.Background(), Request{Body: []byte(`{}`)})

	require.Equal(t, int64(1), preGate.calls.Load())
	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, http.StatusForbidden, decision.HTTPStatus)
	require.Equal(t, ErrorCodeRiskGateBanned, decision.ErrorCode)
	require.False(t, decision.AllowNextStage)
	require.NotNil(t, decision.RiskGate)
	require.Equal(t, "ban", decision.RiskGate.Gate)
	require.True(t, decision.RiskGate.Banned)
	require.Equal(t, int64(0), legacy.calls.Load())
	require.Equal(t, int64(0), prompt.enqueues.Load())
	require.Equal(t, int64(0), prompt.evaluates.Load())
}

// 前置闸门 panic 时降级为不干预，请求继续走既有流程。
func TestCoordinatorPreGatePanicIsDegraded(t *testing.T) {
	legacy := &fakeLegacyEngine{}
	prompt := &fakePromptEngine{mode: ModeOff}
	preGate := &fakePreGate{panics: true}

	decision := NewCoordinator(legacy, prompt).WithPreGate(preGate).Check(context.Background(), Request{Body: []byte(`{}`)})

	require.Equal(t, DecisionAllow, decision.Kind)
	require.True(t, decision.AllowNextStage)
	require.Equal(t, int64(1), legacy.calls.Load())
}

func TestCoordinatorWithPreGateHandlesNilReceiver(t *testing.T) {
	var coordinator *Coordinator
	require.Nil(t, coordinator.WithPreGate(&fakePreGate{}))
	// nil 协调器仍然放行，且不会 panic。
	decision := coordinator.Check(context.Background(), Request{Body: []byte(`{}`)})
	require.Equal(t, DecisionAllow, decision.Kind)
	require.True(t, decision.AllowNextStage)
}

type selectedPreGate struct {
	entered, selected int
	decision          *Decision
}

func (g *selectedPreGate) Decide(context.Context, Request) *Decision { g.entered++; return nil }
func (g *selectedPreGate) DecideSelected(context.Context, Request) *Decision {
	g.selected++
	return g.decision
}
func TestSelectedAccountGateDoesNotRepeatOtherAudits(t *testing.T) {
	legacy := &fakeLegacyEngine{decision: &LegacyDecision{}}
	prompt := &fakePromptEngine{mode: ModeAsync}
	gate := &selectedPreGate{decision: &Decision{Kind: DecisionBlock, HTTPStatus: 403}}
	coordinator := NewCoordinator(legacy, prompt).WithPreGate(gate)
	decision := coordinator.CheckSelectedAccount(context.Background(), Request{SelectedAccountID: 12})
	require.Same(t, gate.decision, decision)
	require.Equal(t, 1, gate.selected)
	require.Zero(t, gate.entered)
	require.Zero(t, legacy.calls.Load())
	require.Zero(t, prompt.enqueues.Load())
	require.Zero(t, prompt.evaluates.Load())
}
