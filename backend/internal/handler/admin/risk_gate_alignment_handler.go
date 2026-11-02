package admin

import (
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/riskgate"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func (h *RiskGateHandler) GetStats(c *gin.Context) {
	from, to, ok := riskGateWindow(c)
	if !ok {
		return
	}
	result, err := h.service.Stats(c.Request.Context(), from, to, c.Query("timezone"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *RiskGateHandler) GetRuleSet(c *gin.Context) {
	result, err := h.service.GetRuleSet(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *RiskGateHandler) UpdateRuleSet(c *gin.Context) {
	var req struct {
		ExpectedVersion *int64          `json:"expected_version"`
		Rules           json.RawMessage `json:"rules"`
	}
	if c.ShouldBindJSON(&req) != nil || req.ExpectedVersion == nil || len(req.Rules) == 0 {
		response.BadRequest(c, "必须提供规则及版本号")
		return
	}
	var rules []riskgate.Rule
	if string(req.Rules) != "null" {
		if json.Unmarshal(req.Rules, &rules) != nil {
			response.BadRequest(c, "规则格式无效")
			return
		}
	}
	result, err := h.service.UpdateRuleSet(c.Request.Context(), *req.ExpectedVersion, rules, string(req.Rules) == "null")
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_rules_update_failed", nil)
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"rules_count": len(result.Rules), "config_version": result.Version})
	response.Success(c, result)
}
func (h *RiskGateHandler) ValidateRules(c *gin.Context) {
	var req struct {
		Rules []riskgate.Rule `json:"rules"`
		Text  string          `json:"text"`
	}
	if c.ShouldBindJSON(&req) != nil || len(req.Text) > 1<<20 {
		response.BadRequest(c, "规则测试请求无效或正文过长")
		return
	}
	response.Success(c, riskgate.ValidateRuleSet(req.Rules, req.Text))
}
func (h *RiskGateHandler) GetScopeInventory(c *gin.Context) {
	result, err := h.service.ScopeInventory(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *RiskGateHandler) ListClassifierModels(c *gin.Context) {
	var req struct {
		Endpoint *riskgate.ClassifierEndpoint `json:"endpoint"`
	}
	if c.ShouldBindJSON(&req) != nil || req.Endpoint == nil {
		response.BadRequest(c, "缺少模型端点")
		return
	}
	models, err := h.service.ListClassifierModels(c.Request.Context(), req.Endpoint)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"models": models})
}
func (h *RiskGateHandler) GetClassifierUsage(c *gin.Context) {
	from, to, ok := riskGateWindow(c)
	if !ok {
		return
	}
	page, size := response.ParsePagination(c)
	result, err := h.service.ClassifierUsage(c.Request.Context(), page, size, from, to, c.Query("timezone"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *RiskGateHandler) ClearBans(c *gin.Context) {
	var req struct {
		Confirm bool   `json:"confirm"`
		Scope   string `json:"scope"`
	}
	if c.ShouldBindJSON(&req) != nil || !req.Confirm {
		response.BadRequest(c, "解除全部封禁必须明确确认")
		return
	}
	total, err := h.service.ClearBans(c.Request.Context(), req.Scope)
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_clear_bans_failed", nil)
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"deleted": total, "scope": req.Scope})
	response.Success(c, gin.H{"deleted": total})
}
func riskGateWindow(c *gin.Context) (*time.Time, *time.Time, bool) {
	from, err := riskGateParseTime(c.Query("from"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "开始时间无效")
		return nil, nil, false
	}
	to, err := riskGateParseTime(c.Query("to"))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "结束时间无效")
		return nil, nil, false
	}
	if from != nil && to != nil && !to.After(*from) {
		response.BadRequest(c, "结束时间必须晚于开始时间")
		return nil, nil, false
	}
	return from, to, true
}
