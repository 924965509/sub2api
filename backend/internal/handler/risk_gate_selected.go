package handler

import (
	"fmt"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"strings"
)

func (h *GatewayHandler) checkSelectedRiskGate(c *gin.Context, account *service.Account) *securityaudit.Decision {
	if h == nil {
		return nil
	}
	return checkSelectedRiskGate(c, h.securityAuditCoordinator, account)
}
func (h *OpenAIGatewayHandler) checkSelectedRiskGate(c *gin.Context, account *service.Account) *securityaudit.Decision {
	if h == nil {
		return nil
	}
	return checkSelectedRiskGate(c, h.securityAuditCoordinator, account)
}
func checkSelectedRiskGate(c *gin.Context, coordinator *securityaudit.Coordinator, account *service.Account) *securityaudit.Decision {
	if c == nil || c.Request == nil || account == nil || coordinator == nil {
		return nil
	}
	observation, ok := ctxkey.UpstreamObservationFrom(c.Request.Context())
	if !ok {
		return nil
	}
	plan := account.GetCredential("plan_type")
	if plan == "" {
		plan = account.GetExtraString("subscription_tier")
	}
	if plan == "" {
		plan = account.GetExtraString("plan_type")
	}
	email := account.GetCredential("email")
	if email == "" {
		email = account.GetExtraString("email")
	}
	observation.SelectedAccountID = account.ID
	observation.SelectedAccountPlan = plan
	observation.SelectedAccountName = account.Name
	observation.SelectedAccountEmail = email
	observation.SelectedAccountPlatform = account.Platform
	// Retry attempts update the actual account; the original prompt and turn key
	// remain unchanged, so telemetry does not count a retry as a new request.
	c.Request = c.Request.WithContext(ctxkey.WithUpstreamObservation(c.Request.Context(), observation))
	request := securityaudit.Request{RequestID: observation.RequestID, UserID: observation.UserID, APIKeyID: observation.APIKeyID, GroupID: observation.GroupID, Provider: observation.Provider, Endpoint: observation.Endpoint, Protocol: observation.Protocol, Model: observation.Model, Body: observation.Body, Stage: observation.Stage, AuditTurn: observation.AuditTurn, InboundDeviceID: observation.InboundDeviceID, ClientFingerprint: observation.ClientFingerprint, SelectedAccountID: account.ID, SelectedAccountPlan: plan, SelectedAccountPlatform: account.Platform, SelectedAccountEmail: email, SelectedAccountName: account.Name}
	return coordinator.CheckSelectedAccount(c.Request.Context(), request)
}
func writeSelectedRiskGateError(c *gin.Context, decision *securityaudit.Decision) {
	if c == nil || decision == nil {
		return
	}
	observation, _ := ctxkey.UpstreamObservationFrom(c.Request.Context())
	if strings.Contains(observation.Protocol, "gemini") {
		googleSecurityAuditError(c, decision)
		c.Abort()
		return
	}
	errorType := decision.ClientErrorType
	if errorType == "" {
		errorType = "permission_error"
	}
	payload := gin.H{"error": gin.H{"type": errorType, "code": securityAuditErrorCode(decision), "message": securityAuditMessage(decision)}}
	if strings.Contains(observation.Protocol, "anthropic") || strings.Contains(observation.Protocol, "claude") {
		payload["type"] = "error"
	}
	service.SetOpsLocalErrorType(c, errorType, securityAuditErrorCode(decision))
	c.AbortWithStatusJSON(securityAuditStatus(decision), payload)
}

func riskAuditTurn(c *gin.Context, stage string) string {
	if isSecurityAuditWebSocketStage(stage) {
		if n, ok := securityAuditWSTurn(c); ok {
			return fmt.Sprintf("%s:%d", stage, n)
		}
	}
	return stage
}
