package riskgate

import (
	"context"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// RecordUpstreamRefusal 实现 service.UpstreamRefusalRecorder：上游拒答时记录语料
// （供拒答缓存闸使用）并写「漏拦观察」事件。mode=off 时只做一次原子读后立即返回。
//
// 设计约束：
//   - 绝不改变上游错误的返回/写响应/日志，任何异常都被吞掉；
//   - 不保存上游响应正文，只保存脱敏后的用户正文片段；
//   - 落库全部异步，失败只计数。
func (e *Engine) RecordUpstreamRefusal(ctx context.Context, event service.UpstreamRefusalEvent) {
	if e == nil {
		return
	}
	cfg, _, ok := e.config.Current()
	if !ok || cfg.EffectiveMode() == ModeOff {
		// 默认配置（mode=off）零行为：不解析正文、不查库、不写事件。
		return
	}
	if len(cfg.Scope.AccountIDs) > 0 || len(cfg.Scope.AccountPlatformPlans) > 0 {
		return
	}
	if !cfg.inScopeRequest(securityaudit.Request{GroupID: event.GroupID, Provider: event.Provider, SelectedAccountID: event.SelectedAccountID, SelectedAccountPlan: event.SelectedAccountPlan, SelectedAccountName: event.SelectedAccountName, SelectedAccountEmail: event.SelectedAccountEmail, SelectedAccountPlatform: event.SelectedAccountPlatform}) {
		return
	}
	defer func() { _ = recover() }()

	source := strings.TrimSpace(event.Source)
	if source == "" {
		source = EventKindUpstreamRefusal
	}
	request := securityaudit.Request{
		RequestID: event.RequestID, UserID: event.UserID, APIKeyID: event.APIKeyID, GroupID: event.GroupID, Provider: event.Provider, Endpoint: event.Endpoint, Protocol: event.Protocol, Model: event.Model, Body: event.Body, Stage: event.Stage, AuditTurn: event.AuditTurn,
		InboundDeviceID: event.InboundDeviceID, ClientFingerprint: event.ClientFingerprint, SelectedAccountID: event.SelectedAccountID, SelectedAccountPlan: event.SelectedAccountPlan, SelectedAccountName: event.SelectedAccountName, SelectedAccountEmail: event.SelectedAccountEmail, SelectedAccountPlatform: event.SelectedAccountPlatform,
	}
	view, _, err := BuildTextView(request, NormalizeOptions{ExpandBase64: cfg.Regex.ExpandBase64})
	if err != nil {
		// 正文无法解析（例如非 JSON 的透传体）：只写观察事件，prompt_hash 留空。
		view = TextView{}
	}

	if cfg.RefusalCacheActive() && view.NormalizedHash != "" && e.refusals != nil {
		// normalized_prompt 落库前必须脱敏，只留片段。
		e.refusals.Enqueue(RefusalRecord{
			Provider: event.Provider, Model: event.Model,
			SourceRequestID: event.RequestID, ErrorMessage: source,
			PromptHash:       view.NormalizedHash,
			NormalizedPrompt: redactEvidence(view.LatestUser, refusalPromptMaxRunes),
			Shingle:          view.Shingle,
			Source:           source,
		})
	}
	// 漏拦观察事件与拒答缓存闸共用同一个写入路径（Gate 仍归拒答缓存闸）。
	e.writeUpstreamPassEvent(request, view.NormalizedHash, GateRefusalCache, upstreamRefusalReason, view.LatestUser)
}

// upstreamRefusalReason 是「上游拒答漏拦」事件的原因值。
const upstreamRefusalReason = "upstream_refusal"

// writeUpstreamPass 写一条 kind=upstream_pass 的「漏拦观察」事件。
// reason=classifier_unavailable 归决策模型闸，其余归拒答缓存闸。
func (e *Engine) writeUpstreamPass(ctx context.Context, request securityaudit.Request, view TextView, reason string) {
	_ = ctx // 事件异步落库，此处不需要请求上下文。
	gate := GateRefusalCache
	if reason == decisionUnavailable {
		gate = GateDecisionModel
	}
	e.writeUpstreamPassEvent(request, view.NormalizedHash, gate, reason, view.LatestUser)
}

// writeUpstreamPassEvent 是所有 upstream_pass 事件的唯一写入点。
func (e *Engine) writeUpstreamPassEvent(request securityaudit.Request, promptHash, gate, reason, latestUser string) {
	if e == nil {
		return
	}
	defer func() { _ = recover() }()
	observation := e.baseEvent(request, promptHash)
	observation.Kind = EventKindUpstreamPass
	observation.Gate = gate
	observation.Reason = reason
	observation.Evidence = redactEvidence(latestUser, evidenceMaxRunes)
	observation.Score = 0
	observation.RuleID = 0
	observation.Action = EventActionNone
	e.writeEvent(observation)
}

// UpstreamObservationEnabled keeps disabled-mode streaming frames on the
// atomic snapshot fast path before any JSON classification is attempted.
func (e *Engine) UpstreamObservationEnabled() bool {
	if e == nil {
		return false
	}
	cfg, _, ok := e.config.Current()
	return ok && cfg.EffectiveMode() != ModeOff
}
