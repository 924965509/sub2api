package service

import (
	"context"
	"net/http"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// UpstreamRefusalEvent 描述一次「上游拒绝了本次请求」的观察，字段全部来自请求上下文，
// 不含任何上游响应正文。
type UpstreamRefusalEvent struct {
	RequestID               string
	UserID                  int64
	APIKeyID                int64
	GroupID                 *int64
	Provider                string
	Endpoint                string
	Protocol                string
	Model                   string
	Source                  string // upstream_refusal | silent_refusal
	StatusCode              int
	Body                    []byte
	InboundDeviceID         string
	ClientFingerprint       string
	SelectedAccountID       int64
	SelectedAccountName     string
	SelectedAccountEmail    string
	SelectedAccountPlatform string
	AuditTurn               string
	Stage                   string
	SelectedAccountPlan     string
}

// UpstreamRefusalRecorder 由风险闸门实现。未安装时 NotifyUpstreamRefusal 立即返回，
// 因此默认配置（风险闸门未启用）对请求路径零影响。
type UpstreamRefusalRecorder interface {
	RecordUpstreamRefusal(ctx context.Context, event UpstreamRefusalEvent)
}

var (
	upstreamRefusalMu       sync.RWMutex
	upstreamRefusalRecorder UpstreamRefusalRecorder
)

// SetUpstreamRefusalRecorder 安装/卸载（传 nil）上游拒答记录器。
func SetUpstreamRefusalRecorder(recorder UpstreamRefusalRecorder) {
	upstreamRefusalMu.Lock()
	defer upstreamRefusalMu.Unlock()
	upstreamRefusalRecorder = recorder
}

// UpstreamRefusalRecorderInstalled 报告当前是否已安装记录器（测试与接线断言用）。
func UpstreamRefusalRecorderInstalled() bool {
	upstreamRefusalMu.RLock()
	defer upstreamRefusalMu.RUnlock()
	return upstreamRefusalRecorder != nil
}

// NotifyUpstreamRefusal 通知风险闸门本次请求被上游拒答。
//
// 约定：绝不改变既有响应、日志与返回值；任何异常都被吞掉。
// recorder 未安装或请求未走审计前置时直接返回，因此默认配置下为零开销。
func NotifyUpstreamRefusal(c *gin.Context, source string, statusCode int) {
	if c == nil || c.Request == nil {
		return
	}
	notifyUpstreamRefusalContext(c.Request.Context(), source, statusCode)
}

// notifyUpstreamRefusalContext bridges both Gin response handlers and parsers
// that only carry the request context. It never alters the upstream response.
func notifyUpstreamRefusalContext(ctx context.Context, source string, statusCode int) {
	defer func() { _ = recover() }()
	upstreamRefusalMu.RLock()
	recorder := upstreamRefusalRecorder
	upstreamRefusalMu.RUnlock()
	if recorder == nil || ctx == nil {
		return
	}
	if enabled, ok := recorder.(interface{ UpstreamObservationEnabled() bool }); ok && !enabled.UpstreamObservationEnabled() {
		return
	}
	observation, ok := ctxkey.UpstreamObservationFrom(ctx)
	if !ok {
		return
	}
	recorder.RecordUpstreamRefusal(context.WithoutCancel(ctx), UpstreamRefusalEvent{
		RequestID: observation.RequestID, UserID: observation.UserID, APIKeyID: observation.APIKeyID,
		GroupID: observation.GroupID, Provider: observation.Provider, Endpoint: observation.Endpoint,
		Protocol: observation.Protocol, Model: observation.Model, Source: source,
		StatusCode: statusCode, Body: observation.Body,
		InboundDeviceID: observation.InboundDeviceID, ClientFingerprint: observation.ClientFingerprint,
		SelectedAccountID: observation.SelectedAccountID, SelectedAccountPlan: observation.SelectedAccountPlan,
		SelectedAccountName: observation.SelectedAccountName, SelectedAccountEmail: observation.SelectedAccountEmail,
		SelectedAccountPlatform: observation.SelectedAccountPlatform, AuditTurn: observation.AuditTurn, Stage: observation.Stage,
	})
}

// NotifyStructuredUpstreamRefusal observes explicit provider refusal indicators
// in an already parsed response/frame. It never treats an ordinary stop/error as
// a refusal and does not retain or log response text.
func NotifyStructuredUpstreamRefusal(ctx context.Context, payload []byte) {
	observeStructuredUpstreamRefusal(ctx, payload)
}

// The boolean lets a response observer suppress duplicate refusal frames from
// the same forwarding attempt. Disabled/unobserved requests do not parse JSON.
func observeStructuredUpstreamRefusal(ctx context.Context, payload []byte) (refused bool) {
	defer func() {
		if recover() != nil {
			refused = false
		}
	}()
	upstreamRefusalMu.RLock()
	recorder := upstreamRefusalRecorder
	upstreamRefusalMu.RUnlock()
	if recorder == nil || ctx == nil || len(payload) == 0 {
		return false
	}
	if enabled, ok := recorder.(interface{ UpstreamObservationEnabled() bool }); ok && !enabled.UpstreamObservationEnabled() {
		return false
	}
	if _, ok := ctxkey.UpstreamObservationFrom(ctx); !ok {
		return false
	}
	if !structuredUpstreamRefusal(gjson.ParseBytes(payload), 0) || !gjson.ValidBytes(payload) {
		return false
	}
	notifyUpstreamRefusalContext(ctx, "upstream_refusal", http.StatusOK)
	return true
}

func structuredUpstreamRefusal(root gjson.Result, depth int) bool {
	if depth > 4 {
		return false
	}
	if root.IsArray() {
		for _, item := range root.Array() {
			if structuredUpstreamRefusal(item, depth+1) {
				return true
			}
		}
		return false
	}
	if !root.IsObject() {
		return false
	}
	for _, field := range []string{"stop_reason", "delta.stop_reason", "message.stop_reason"} {
		if root.Get(field).String() == "refusal" {
			return true
		}
	}
	safetyReason := func(reason string) bool {
		switch reason {
		case "SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT":
			return true
		}
		return false
	}
	if safetyReason(root.Get("promptFeedback.blockReason").String()) {
		return true
	}
	for _, candidate := range root.Get("candidates").Array() {
		if safetyReason(candidate.Get("finishReason").String()) {
			return true
		}
	}
	for _, choice := range root.Get("choices").Array() {
		if choice.Get("finish_reason").String() == "content_filter" ||
			choice.Get("message.refusal").String() != "" || choice.Get("delta.refusal").String() != "" {
			return true
		}
	}
	if root.Get("incomplete_details.reason").String() == "content_filter" {
		return true
	}
	switch root.Get("type").String() {
	case "response.refusal.done", "response.refusal.delta":
		return true
	}
	for _, item := range root.Get("output").Array() {
		for _, part := range item.Get("content").Array() {
			if part.Get("type").String() == "refusal" {
				return true
			}
		}
	}
	if response := root.Get("response"); response.Exists() {
		return structuredUpstreamRefusal(response, depth+1)
	}
	return false
}
