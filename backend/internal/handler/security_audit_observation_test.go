package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// runSecurityAudit 必须把本次请求的正文与身份写进请求上下文，
// 这样 service 层在上游拒答时才能把正文交给风险闸门（避免重复解析请求体）。
func TestRunSecurityAuditPublishesUpstreamObservation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	body := []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"hello observation"}]}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))

	groupID := int64(3)
	apiKey := &service.APIKey{
		ID: 9, UserID: 7, Name: "obs-key", GroupID: &groupID,
		User:  &service.User{ID: 7, Username: "obs-user", Email: "obs@example.test"},
		Group: &service.Group{ID: groupID, Name: "obs-group", Platform: service.PlatformOpenAI},
	}
	subject := middleware2.AuthSubject{UserID: 7, Concurrency: 1}
	h := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, nil)}

	decision := h.checkSecurityAudit(c, nil, apiKey, subject, service.ContentModerationProtocolOpenAIChat, "gpt-5", body)
	require.NotNil(t, decision)
	require.True(t, decision.AllowNextStage, "没有安装任何审计引擎时必须放行")

	observation, ok := ctxkey.UpstreamObservationFrom(c.Request.Context())
	require.True(t, ok, "runSecurityAudit 必须把观察值写进请求上下文")
	require.Equal(t, "gpt-5", observation.Model)
	require.Equal(t, "openai", observation.Provider)
	require.Equal(t, int64(7), observation.UserID)
	require.Equal(t, int64(9), observation.APIKeyID)
	require.NotNil(t, observation.GroupID)
	require.Equal(t, groupID, *observation.GroupID)
	require.Equal(t, body, observation.Body, "正文必须原样共享，不复制不改写")
}

// 协调器未安装（走历史内容审核路径）时不应写入观察值：那条路径没有闸门前置。
func TestRunSecurityAuditWithoutCoordinatorSkipsObservation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{}`)))

	groupID := int64(3)
	apiKey := &service.APIKey{ID: 9, UserID: 7, GroupID: &groupID}
	decision := runSecurityAudit(c, nil, nil, nil, apiKey, middleware2.AuthSubject{UserID: 7},
		service.ContentModerationProtocolOpenAIChat, "gpt-5", []byte(`{}`), "http")
	require.Nil(t, decision)

	_, ok := ctxkey.UpstreamObservationFrom(c.Request.Context())
	require.False(t, ok)
}
