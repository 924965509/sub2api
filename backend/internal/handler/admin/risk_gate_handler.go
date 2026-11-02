package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/riskgate"
	middleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

// RiskGateHandler 提供 /admin/risk-gate 的最小管理接口：
// 读取配置、保存配置（版本乐观锁）、读取运行态。
type RiskGateHandler struct {
	service *riskgate.AdminService
}

func NewRiskGateHandler(service *riskgate.AdminService) *RiskGateHandler {
	return &RiskGateHandler{service: service}
}

// GetConfig 返回当前配置与版本号。
func (h *RiskGateHandler) GetConfig(c *gin.Context) {
	view, err := h.service.GetConfig(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, view)
}

// UpdateConfig 保存配置：版本冲突返回 409，校验失败返回 400。
func (h *RiskGateHandler) UpdateConfig(c *gin.Context) {
	var request riskgate.UpdateConfigRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_config_request", nil)
		response.BadRequest(c, "风险闸门配置请求无效: "+err.Error())
		return
	}
	view, err := h.service.SaveConfig(c.Request.Context(), request, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), riskGateConfigFields(request, nil))
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", riskGateConfigFields(request, &view))
	response.Success(c, view)
}

// GetStatus 返回运行态：模式、生效闸门、命中计数、封禁数量与最后错误。
func (h *RiskGateHandler) GetStatus(c *gin.Context) {
	status, err := h.service.Status(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, status)
}

// ProbeClassifier 用一次真实调用探测决策模型端点。
//
// 语义约定：探测失败不是接口失败——HTTP 仍返回 200，错误放在 result.error 里；
// 只有请求非法或没有可用端点才由服务层返回 400。
// 审计字段只记结果摘要，绝不记录 api_key 与探测正文。
func (h *RiskGateHandler) ProbeClassifier(c *gin.Context) {
	var request riskgate.ProbeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_probe_request", nil)
		response.BadRequest(c, "风险闸门探测请求无效: "+err.Error())
		return
	}
	result, err := h.service.ProbeClassifier(c.Request.Context(), request)
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), riskGateProbeFields(request, nil))
		response.ErrorFrom(c, err)
		return
	}
	auditResult := "success"
	if !result.OK {
		auditResult = "failed"
	}
	setRiskGateAudit(c, auditResult, riskGateProbeErrorCode(result), riskGateProbeFields(request, &result))
	response.Success(c, result)
}

// riskGateProbeFields 汇总探测的审计字段（不含 api_key 与正文）。
func riskGateProbeFields(request riskgate.ProbeRequest, result *riskgate.ProbeResult) map[string]any {
	fields := map[string]any{"endpoint_index": request.EndpointIndex}
	if request.Endpoint != nil {
		fields["endpoint_id"] = request.Endpoint.ID
	}
	if result != nil {
		fields["probe_ok"] = result.OK
		fields["endpoint_id"] = result.EndpointID
		fields["score"] = result.Score
		fields["latency_ms"] = result.LatencyMS
	}
	return fields
}

// riskGateProbeErrorCode 把探测失败归成审计错误码。
func riskGateProbeErrorCode(result riskgate.ProbeResult) string {
	if result.OK {
		return ""
	}
	return "risk_gate_classifier_probe_failed"
}

// setRiskGateAudit 复用现有管理操作审计通道（changed-feilds 记录）。
func setRiskGateAudit(c *gin.Context, result, errorCode string, fields map[string]any) {
	details := make(map[string]any, len(fields)+2)
	details["result"] = result
	if errorCode != "" {
		details["error_code"] = errorCode
	}
	for key, value := range fields {
		details[key] = value
	}
	middleware.SetAuditExtra(c, details)
}

func riskGateConfigFields(request riskgate.UpdateConfigRequest, saved *riskgate.ConfigView) map[string]any {
	version := request.ExpectedVersion
	if saved != nil {
		version = saved.Version
	}
	return map[string]any{
		"expected_version": request.ExpectedVersion, "config_version": version,
		"mode": request.Config.Mode, "gates": request.Config.Gates,
		"ban_scope": request.Config.Ban.Scope,
	}
}

func riskGateAdminID(c *gin.Context) int64 {
	envelope, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		return 0
	}
	return envelope.UserID
}

// riskGateRulesRequest 是 PUT /risk-gate/rules 的请求体。
type riskGateRulesRequest struct {
	Rules []riskgate.Rule `json:"rules"`
}

// riskGateEventFilterRequest 是事件批量删除/预览的请求体（字段与查询参数一一对应）。
type riskGateEventFilterRequest struct {
	Reason     string `json:"reason"`
	Action     string `json:"action"`
	View       string `json:"view"`
	RuleID     int64  `json:"rule_id"`
	Kind       string `json:"kind"`
	Gate       string `json:"gate"`
	Provider   string `json:"provider"`
	RequestID  string `json:"request_id"`
	PromptHash string `json:"prompt_hash"`
	UserID     int64  `json:"user_id"`
	APIKeyID   int64  `json:"api_key_id"`
	GroupID    *int64 `json:"group_id"`
	// From/To 为 RFC3339 时间，闭开区间 [From, To)。
	From string `json:"from"`
	To   string `json:"to"`
}

// ListRules 返回全部自定义规则（含停用）。
func (h *RiskGateHandler) ListRules(c *gin.Context) {
	rules, err := h.service.ListRules(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"rules": rules})
}

// SaveRules 全量替换自定义规则（事务内完成），返回落库结果。
func (h *RiskGateHandler) SaveRules(c *gin.Context) {
	var request riskGateRulesRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setRiskGateAudit(c, "failed", riskgate.ErrorCodeInvalidRule, nil)
		response.BadRequest(c, "风险闸门规则请求无效: "+err.Error())
		return
	}
	rules, err := h.service.SaveRules(c.Request.Context(), request.Rules, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), map[string]any{"rule_count": len(request.Rules)})
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"rule_count": len(rules)})
	response.Success(c, gin.H{"rules": rules})
}

// ListBans 分页返回封禁列表（可按 scope / subject / active_only 过滤）。
func (h *RiskGateHandler) ListBans(c *gin.Context) {
	page, pageSize := response.ParsePagination(c)
	filter := riskgate.BanFilter{
		Scope:      c.Query("scope"),
		Subject:    c.DefaultQuery("subject", ""),
		ActiveOnly: riskGateQueryBool(c, "active_only"),
		Page:       page,
		PageSize:   pageSize,
	}
	bans, total, err := h.service.ListBans(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Paginated(c, bans, total, page, pageSize)
}

// CreateBan 手动新增封禁；审计只记录 scope 与 subject 哈希，绝不记录原文。
func (h *RiskGateHandler) CreateBan(c *gin.Context) {
	var request riskgate.CreateBanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setRiskGateAudit(c, "failed", riskgate.ErrorCodeInvalidBan, nil)
		response.BadRequest(c, "风险闸门封禁请求无效: "+err.Error())
		return
	}
	fields := riskGateBanFields(request)
	ban, err := h.service.CreateBan(c.Request.Context(), request, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), fields)
		response.ErrorFrom(c, err)
		return
	}
	fields["ban_id"] = ban.ID
	setRiskGateAudit(c, "success", "", fields)
	response.Created(c, ban)
}

// DeleteBan 按 id 解除封禁；不存在返回 404。
func (h *RiskGateHandler) DeleteBan(c *gin.Context) {
	id, ok := riskGatePathID(c)
	if !ok {
		return
	}
	deleted, err := h.service.DeleteBan(c.Request.Context(), id, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), map[string]any{"ban_id": id})
		response.ErrorFrom(c, err)
		return
	}
	if !deleted {
		setRiskGateAudit(c, "failed", "risk_gate_ban_not_found", map[string]any{"ban_id": id})
		response.NotFound(c, "风险闸门封禁不存在")
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"ban_id": id, "deleted": 1})
	response.Success(c, gin.H{"deleted": 1})
}

// ListEvents 分页返回事件列表。
func (h *RiskGateHandler) ListEvents(c *gin.Context) {
	filter, err := riskGateEventFilterFromQuery(c)
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_filter", nil)
		response.BadRequest(c, "风险闸门事件过滤条件无效: "+err.Error())
		return
	}
	rows, total, err := h.service.ListEvents(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Paginated(c, rows, total, filter.Page, filter.PageSize)
}

// GetEvent 返回单条事件；不存在返回 404。
func (h *RiskGateHandler) GetEvent(c *gin.Context) {
	id, ok := riskGatePathID(c)
	if !ok {
		return
	}
	row, err := h.service.GetEvent(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if row == nil {
		response.NotFound(c, "风险闸门事件不存在")
		return
	}
	response.Success(c, row)
}

// DeleteEventsPreview 预览符合条件的待删除事件数；没有过滤条件直接 400。
func (h *RiskGateHandler) DeleteEventsPreview(c *gin.Context) {
	filter, ok := riskGateEventFilterFromBody(c)
	if !ok {
		return
	}
	total, err := h.service.CountEvents(c.Request.Context(), filter)
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), riskGateEventFilterFields(filter))
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", riskGateEventFilterFields(filter))
	response.Success(c, gin.H{"total": total})
}

// DeleteEventsByFilter 按条件删除事件；没有过滤条件直接 400，避免误清空全表。
func (h *RiskGateHandler) DeleteEventsByFilter(c *gin.Context) {
	filter, ok := riskGateEventFilterFromBody(c)
	if !ok {
		return
	}
	deleted, err := h.service.DeleteEventsByFilter(c.Request.Context(), filter, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), riskGateEventFilterFields(filter))
		response.ErrorFrom(c, err)
		return
	}
	fields := riskGateEventFilterFields(filter)
	fields["deleted"] = deleted
	setRiskGateAudit(c, "success", "", fields)
	response.Success(c, gin.H{"deleted": deleted})
}

// ListRefusals 分页返回拒答语料列表。
func (h *RiskGateHandler) ListRefusals(c *gin.Context) {
	page, pageSize := response.ParsePagination(c)
	filter := riskgate.RefusalFilter{
		Provider:   c.Query("provider"),
		Source:     c.Query("source"),
		PromptHash: c.Query("prompt_hash"),
		Page:       page,
		PageSize:   pageSize,
	}
	rows, total, err := h.service.ListRefusals(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Paginated(c, rows, total, page, pageSize)
}

// DeleteRefusal 删除单条拒答语料；不存在返回 404。
func (h *RiskGateHandler) DeleteRefusal(c *gin.Context) {
	id, ok := riskGatePathID(c)
	if !ok {
		return
	}
	deleted, err := h.service.DeleteRefusal(c.Request.Context(), id, riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), map[string]any{"refusal_id": id})
		response.ErrorFrom(c, err)
		return
	}
	if !deleted {
		setRiskGateAudit(c, "failed", "risk_gate_refusal_not_found", map[string]any{"refusal_id": id})
		response.NotFound(c, "风险闸门拒答语料不存在")
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"refusal_id": id, "deleted": 1})
	response.Success(c, gin.H{"deleted": 1})
}

// DeleteAllRefusals 清空拒答语料，返回删除行数。
func (h *RiskGateHandler) DeleteAllRefusals(c *gin.Context) {
	deleted, err := h.service.DeleteAllRefusals(c.Request.Context(), riskGateAdminID(c))
	if err != nil {
		setRiskGateAudit(c, "failed", err.Error(), nil)
		response.ErrorFrom(c, err)
		return
	}
	setRiskGateAudit(c, "success", "", map[string]any{"deleted": deleted})
	response.Success(c, gin.H{"deleted": deleted})
}

// ExportEvents 把事件导出成 CSV 下载。
//
// 先在内存里生成完整文件再写响应头，避免中途出错时已经吐出半个 CSV。
func (h *RiskGateHandler) ExportEvents(c *gin.Context) {
	filter, err := riskGateEventFilterFromQuery(c)
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_filter", nil)
		response.BadRequest(c, "风险闸门事件过滤条件无效: "+err.Error())
		return
	}
	var buffer bytes.Buffer
	rows, exportErr := h.service.ExportEventsCSV(c.Request.Context(), filter, &buffer)
	if exportErr != nil {
		setRiskGateAudit(c, "failed", exportErr.Error(), riskGateEventFilterFields(filter))
		response.ErrorFrom(c, exportErr)
		return
	}
	fields := riskGateEventFilterFields(filter)
	fields["rows"] = rows
	setRiskGateAudit(c, "success", "", fields)
	filename := "risk-gate-events-" + h.now().UTC().Format("20060102T150405Z") + ".csv"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", buffer.Bytes())
}

// now 允许测试替换时间源（当前只用真实时钟）。
func (h *RiskGateHandler) now() time.Time { return time.Now() }

// riskGatePathID 解析路径里的 :id；非法时直接写 400 并返回 false。
func riskGatePathID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_id", map[string]any{"id": c.Param("id")})
		response.BadRequest(c, "风险闸门 id 参数无效")
		return 0, false
	}
	return id, true
}

// riskGateQueryBool 解析查询里的布尔开关，非法值按 false 处理。
func riskGateQueryBool(c *gin.Context, key string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(c.Query(key)))
	return err == nil && value
}

// riskGateParseTime 解析 RFC3339 时间；空值返回 nil 表示不限制。
func riskGateParseTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// riskGateEventFilterFromQuery 从查询参数构造事件过滤条件。
func riskGateEventFilterFromQuery(c *gin.Context) (riskgate.EventFilter, error) {
	page, pageSize := response.ParsePagination(c)
	filter := riskgate.EventFilter{
		Kind: c.Query("kind"), Gate: c.Query("gate"), Provider: c.Query("provider"),
		RequestID: c.Query("request_id"), PromptHash: c.Query("prompt_hash"),
		Page: page, PageSize: pageSize,
		Reason: c.Query("reason"), Action: c.Query("action"), View: c.Query("view"),
	}
	var err error
	if filter.RuleID, err = riskGateQueryInt64(c, "rule_id"); err != nil {
		return filter, err
	}
	if filter.UserID, err = riskGateQueryInt64(c, "user_id"); err != nil {
		return filter, err
	}
	if filter.APIKeyID, err = riskGateQueryInt64(c, "api_key_id"); err != nil {
		return filter, err
	}
	if value := strings.TrimSpace(c.Query("group_id")); value != "" {
		groupID, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return filter, parseErr
		}
		filter.GroupID = &groupID
	}
	if filter.From, err = riskGateParseTime(c.Query("from")); err != nil {
		return filter, err
	}
	if filter.To, err = riskGateParseTime(c.Query("to")); err != nil {
		return filter, err
	}
	return filter, nil
}

// riskGateEventFilterFromBody 从 JSON 请求体构造事件过滤条件。
func riskGateEventFilterFromBody(c *gin.Context) (riskgate.EventFilter, bool) {
	var request riskGateEventFilterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_filter", nil)
		response.BadRequest(c, "风险闸门事件过滤条件无效: "+err.Error())
		return riskgate.EventFilter{}, false
	}
	from, err := riskGateParseTime(request.From)
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_filter", nil)
		response.BadRequest(c, "风险闸门事件过滤条件无效: from 不是 RFC3339 时间")
		return riskgate.EventFilter{}, false
	}
	to, err := riskGateParseTime(request.To)
	if err != nil {
		setRiskGateAudit(c, "failed", "risk_gate_invalid_filter", nil)
		response.BadRequest(c, "风险闸门事件过滤条件无效: to 不是 RFC3339 时间")
		return riskgate.EventFilter{}, false
	}
	return riskgate.EventFilter{
		Kind: request.Kind, Gate: request.Gate, Provider: request.Provider,
		Reason: request.Reason, Action: request.Action, View: request.View, RuleID: request.RuleID,
		RequestID: request.RequestID, PromptHash: request.PromptHash,
		UserID: request.UserID, APIKeyID: request.APIKeyID, GroupID: request.GroupID,
		From: from, To: to,
	}, true
}

// riskGateQueryInt64 解析查询里的正整数，空值返回 0。
func riskGateQueryInt64(c *gin.Context, key string) (int64, error) {
	value := strings.TrimSpace(c.Query(key))
	if value == "" {
		return 0, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

// riskGateBanFields 汇总封禁创建的审计字段：subject 只记哈希。
func riskGateBanFields(request riskgate.CreateBanRequest) map[string]any {
	return map[string]any{
		"scope":          request.Scope,
		"subject_hash":   riskGateHashSubject(request.Subject),
		"duration_hours": request.DurationHours,
		"gate":           request.Gate,
	}
}

// riskGateHashSubject 对被封对象做短哈希，审计里不出现原文。
func riskGateHashSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:8])
}

// riskGateEventFilterFields 汇总事件过滤条件的审计字段（不含正文）。
func riskGateEventFilterFields(filter riskgate.EventFilter) map[string]any {
	fields := map[string]any{
		"kind": filter.Kind, "gate": filter.Gate, "provider": filter.Provider,
		"request_id": filter.RequestID, "prompt_hash": filter.PromptHash,
		"user_id": filter.UserID, "api_key_id": filter.APIKeyID,
	}
	if filter.GroupID != nil {
		fields["group_id"] = *filter.GroupID
	}
	if filter.From != nil {
		fields["from"] = filter.From.UTC().Format(time.RFC3339)
	}
	if filter.To != nil {
		fields["to"] = filter.To.UTC().Format(time.RFC3339)
	}
	return fields
}
