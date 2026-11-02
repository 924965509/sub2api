package admin

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/riskgate"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// riskGateAdminFixture 用一个 sqlmock 数据库装配四个仓储，构造完整的管理端 handler。
type riskGateAdminFixture struct {
	handler *RiskGateHandler
	mock    sqlmock.Sqlmock
	engine  *gin.Engine
}

// newRiskGateAdminFixture 装配 handler 与全部 /risk-gate 管理端路由。
func newRiskGateAdminFixture(t *testing.T) *riskGateAdminFixture {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	rules := riskgate.NewRuleStore(db)
	bans := riskgate.NewBanStore(db, nil)
	refusals := riskgate.NewRefusalStore(db)
	events := riskgate.NewEventRepository(db)
	service := riskgate.NewAdminService(nil, nil, bans, rules, rules, bans, refusals, events)

	gin.SetMode(gin.TestMode)
	handler := NewRiskGateHandler(service)
	engine := gin.New()
	engine.GET("/rules", handler.ListRules)
	engine.PUT("/rules", handler.SaveRules)
	engine.GET("/bans", handler.ListBans)
	engine.POST("/bans", handler.CreateBan)
	engine.DELETE("/bans/:id", handler.DeleteBan)
	engine.GET("/events", handler.ListEvents)
	engine.POST("/events/delete-preview", handler.DeleteEventsPreview)
	engine.POST("/events/delete-by-filter", handler.DeleteEventsByFilter)
	engine.GET("/events/:id", handler.GetEvent)
	engine.GET("/refusals", handler.ListRefusals)
	engine.DELETE("/refusals", handler.DeleteAllRefusals)
	engine.DELETE("/refusals/:id", handler.DeleteRefusal)
	engine.GET("/export", handler.ExportEvents)
	return &riskGateAdminFixture{handler: handler, mock: mock, engine: engine}
}

// do 走一次请求；body 为空表示不带请求体。
func (f *riskGateAdminFixture) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	return recorder
}

// envelope 只取用例关心的响应字段。
type riskGateAdminEnvelope struct {
	Code   int             `json:"code"`
	Reason string          `json:"reason"`
	Data   json.RawMessage `json:"data"`
}

// decode 解析响应信封。
func decodeEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) riskGateAdminEnvelope {
	t.Helper()
	var envelope riskGateAdminEnvelope
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &envelope))
	return envelope
}

// 规则列表：返回全部规则（含停用）。
func TestRiskGateAdminListRules(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT id, gate, category, pattern, is_regex, action, enabled, sort_order, description FROM risk_gate_rules ORDER BY gate, sort_order, id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "gate", "category", "pattern", "is_regex", "action", "enabled", "sort_order", "description"}).
			AddRow(1, "regex", "jailbreak", "忽略之前的指令", false, "block", false, 10, "内置禁用规则"))

	recorder := fixture.do(t, http.MethodGet, "/rules", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	var payload struct {
		Rules []riskgate.Rule `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(envelope.Data, &payload))
	require.Len(t, payload.Rules, 1)
	require.Equal(t, "jailbreak", payload.Rules[0].Category)
	require.False(t, payload.Rules[0].Enabled)
	require.Contains(t, recorder.Body.String(), `"sort_order"`)
}

// 保存规则：非法 gate 直接 400，且事务不开启。
func TestRiskGateAdminSaveRulesRejectsInvalidGate(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	body := `{"rules":[{"gate":"unknown","category":"sexual","pattern":"x"}]}`
	recorder := fixture.do(t, http.MethodPut, "/rules", body)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	require.Equal(t, riskgate.ErrorCodeInvalidRule, envelope.Reason)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 兼容规则接口也使用版本锁及稳定 rule_key，不再整表删除后重建 ID。
func TestRiskGateAdminSaveRulesPreservesIDsInVersionedTx(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT version FROM risk_gate_ruleset WHERE id=1`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(3))
	fixture.mock.ExpectBegin()
	fixture.mock.ExpectQuery(`SELECT version FROM risk_gate_ruleset WHERE id=1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(3))
	fixture.mock.ExpectQuery(`SELECT id,rule_key FROM risk_gate_rules`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "rule_key"}).AddRow(11, "custom-existing-11").AddRow(12, "custom-removed-12"))
	fixture.mock.ExpectQuery(`INSERT INTO risk_gate_rules.*ON CONFLICT\(rule_key\) DO UPDATE`).
		WithArgs("regex", "bypass", "^/etc/passwd", true, "block", true, 5, "", "custom-existing-11", false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(11))
	fixture.mock.ExpectExec(`DELETE FROM risk_gate_rules WHERE id NOT IN`).WithArgs(int64(11)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	fixture.mock.ExpectExec(`UPDATE risk_gate_ruleset SET version=version\+1`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	fixture.mock.ExpectCommit()

	body := `{"rules":[{"id":11,"rule_key":"ignored-client-key","gate":"regex","category":"bypass","pattern":"^/etc/passwd","is_regex":true,"action":"block","enabled":true,"sort_order":5}]}`
	recorder := fixture.do(t, http.MethodPut, "/rules", body)
	require.Equal(t, http.StatusOK, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	var payload struct {
		Rules []riskgate.Rule `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(envelope.Data, &payload))
	require.Len(t, payload.Rules, 1)
	require.Equal(t, int64(11), payload.Rules[0].ID)
	require.Equal(t, "custom-existing-11", payload.Rules[0].RuleKey)
	require.Equal(t, "bypass", payload.Rules[0].Category)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 封禁列表：COUNT + 分页查询，返回分页信封。
func TestRiskGateAdminListBans(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT COUNT\(1\) FROM risk_gate_bans`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	fixture.mock.ExpectQuery(`FROM risk_gate_bans ORDER BY banned_at DESC, id DESC LIMIT \$1 OFFSET \$2`).
		WithArgs(20, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope", "subject", "reason", "gate", "hit_count", "banned_at", "expires_at", "created_by"}).
			AddRow(3, "api_key", "key-9", "手动封禁", "regex", 1, time.Now(), nil, "admin"))

	recorder := fixture.do(t, http.MethodGet, "/bans", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	var payload struct {
		Items    []riskgate.Ban `json:"items"`
		Total    int64          `json:"total"`
		Page     int            `json:"page"`
		PageSize int            `json:"page_size"`
	}
	require.NoError(t, json.Unmarshal(envelope.Data, &payload))
	require.EqualValues(t, 1, payload.Total)
	require.Equal(t, 1, payload.Page)
	require.Len(t, payload.Items, 1)
	require.Equal(t, "key-9", payload.Items[0].Subject)
}

// 新增封禁：201，返回体里带换算后的过期时间与 created_by。
func TestRiskGateAdminCreateBan(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectExec(`INSERT INTO risk_gate_bans`).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := `{"scope":"api_key","subject":"key-9","reason":"手动封禁","duration_hours":24,"gate":"regex"}`
	recorder := fixture.do(t, http.MethodPost, "/bans", body)
	require.Equal(t, http.StatusCreated, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	var ban riskgate.Ban
	require.NoError(t, json.Unmarshal(envelope.Data, &ban))
	require.Equal(t, "api_key", ban.Scope)
	require.Equal(t, "key-9", ban.Subject)
	require.Equal(t, "admin", ban.CreatedBy)
	require.NotNil(t, ban.ExpiresAt)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 删除封禁：id 非法 400；记录不存在 404 且不发 DELETE。
func TestRiskGateAdminDeleteBanValidation(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)

	recorder := fixture.do(t, http.MethodDelete, "/bans/abc", "")
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	// 路径参数非法时 handler 直接回 400（body 为统一错误信封，无 reason 码）。
	decodeEnvelope(t, recorder)
	require.Contains(t, recorder.Body.String(), "id 参数无效")

	fixture.mock.ExpectQuery(`SELECT scope, subject FROM risk_gate_bans WHERE id = \$1`).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"scope", "subject"}))
	recorder = fixture.do(t, http.MethodDelete, "/bans/9", "")
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 删除封禁：存在时删除并返回 deleted=1。
func TestRiskGateAdminDeleteBanSuccess(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT scope, subject FROM risk_gate_bans WHERE id = \$1`).
		WithArgs(int64(4)).
		WillReturnRows(sqlmock.NewRows([]string{"scope", "subject"}).AddRow("user", "42"))
	fixture.mock.ExpectExec(`DELETE FROM risk_gate_bans WHERE id = \$1`).
		WithArgs(int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	recorder := fixture.do(t, http.MethodDelete, "/bans/4", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"code":0,"message":"success","data":{"deleted":1}}`, recorder.Body.String())
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 批量删除事件：没有过滤条件时 preview 与 delete 都必须 400。
func TestRiskGateAdminEventsDeleteRequiresFilter(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	for _, path := range []string{"/events/delete-preview", "/events/delete-by-filter"} {
		recorder := fixture.do(t, http.MethodPost, path, `{}`)
		require.Equalf(t, http.StatusBadRequest, recorder.Code, path)
		require.Equalf(t, riskgate.ErrorCodeFilterRequired, decodeEnvelope(t, recorder).Reason, path)
	}
	// 没有任何过滤条件时不能碰数据库。
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 批量删除事件：预览返回 total，删除返回实际删除行数。
func TestRiskGateAdminEventsPreviewAndDelete(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT COUNT\(1\) FROM risk_gate_events WHERE provider = \$1`).
		WithArgs("openai").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	fixture.mock.ExpectExec(`DELETE FROM risk_gate_events WHERE provider = \$1`).
		WithArgs("openai").
		WillReturnResult(sqlmock.NewResult(0, 2))

	recorder := fixture.do(t, http.MethodPost, "/events/delete-preview", `{"provider":"openai"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"total":3`)

	recorder = fixture.do(t, http.MethodPost, "/events/delete-by-filter", `{"provider":"openai"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"deleted":2`)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 事件列表：过滤条件与分页参数都进 SQL，非法时间 400。
func TestRiskGateAdminListEvents(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`SELECT COUNT\(1\) FROM risk_gate_events WHERE kind = \$1 AND user_id = \$2`).
		WithArgs("blocked", int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	fixture.mock.ExpectQuery(`FROM risk_gate_events WHERE kind = \$1 AND user_id = \$2 ORDER BY created_at DESC, id DESC LIMIT \$3 OFFSET \$4`).
		WithArgs("blocked", int64(7), 20, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "request_id", "user_id", "api_key_id", "group_id", "provider", "endpoint", "protocol", "model",
			"kind", "gate", "rule_id", "reason", "score", "prompt_hash", "evidence", "action", "created_at", "category", "rule_key", "pattern", "client_fingerprint", "user_preview", "submitted_text", "scores", "terminal_outcome"}))

	recorder := fixture.do(t, http.MethodGet, "/events?kind=blocked&user_id=7", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"items":[]`)
	require.NoError(t, fixture.mock.ExpectationsWereMet())

	recorder = fixture.do(t, http.MethodGet, "/events?from=yesterday", "")
	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

// 单条事件：不存在返回 404。
func TestRiskGateAdminGetEventNotFound(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectQuery(`FROM risk_gate_events WHERE id = \$1`).
		WithArgs(int64(88)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "request_id", "user_id", "api_key_id", "group_id", "provider", "endpoint", "protocol", "model",
			"kind", "gate", "rule_id", "reason", "score", "prompt_hash", "evidence", "action", "created_at", "category", "rule_key", "pattern", "client_fingerprint", "user_preview", "submitted_text", "scores", "terminal_outcome"}))

	recorder := fixture.do(t, http.MethodGet, "/events/88", "")
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 单条事件：命中返回完整字段。
func TestRiskGateAdminGetEventSuccess(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	createdAt := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	fixture.mock.ExpectQuery(`FROM risk_gate_events WHERE id = \$1`).
		WithArgs(int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "request_id", "user_id", "api_key_id", "group_id", "provider", "endpoint", "protocol", "model",
			"kind", "gate", "rule_id", "reason", "score", "prompt_hash", "evidence", "action", "created_at", "category", "rule_key", "pattern", "client_fingerprint", "user_preview", "submitted_text", "scores", "terminal_outcome"}).
			AddRow(12, "req-12", 5, 6, nil, "openai", "/v1/chat/completions", "openai", "gpt-4o",
				"upstream_refusal", "regex", 3, "命中规则", 0.87, "hash-12", "脱敏片段", "block", createdAt, "custom", "custom-3", "fixture", "", "", "", []byte("{}"), "blocked"))

	recorder := fixture.do(t, http.MethodGet, "/events/12", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	envelope := decodeEnvelope(t, recorder)
	var row riskgate.EventRow
	require.NoError(t, json.Unmarshal(envelope.Data, &row))
	require.Equal(t, int64(12), row.ID)
	require.Equal(t, "req-12", row.RequestID)
	require.Equal(t, "hash-12", row.PromptHash)
	require.InDelta(t, 0.87, row.Score, 1e-9)
	require.Equal(t, "脱敏片段", row.Evidence)
	require.True(t, createdAt.Equal(row.CreatedAt))
}

// CSV 导出：响应头正确、表头固定、行数与内容正确。
func TestRiskGateAdminExportEventsCSV(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	createdAt := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	fixture.mock.ExpectQuery(`SELECT COUNT\(1\) FROM risk_gate_events WHERE provider = \$1`).
		WithArgs("openai").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	fixture.mock.ExpectQuery(`FROM risk_gate_events WHERE provider = \$1 ORDER BY created_at DESC, id DESC LIMIT \$2 OFFSET \$3`).
		WithArgs("openai", 200, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "request_id", "user_id", "api_key_id", "group_id", "provider", "endpoint", "protocol", "model",
			"kind", "gate", "rule_id", "reason", "score", "prompt_hash", "evidence", "action", "created_at", "category", "rule_key", "pattern", "client_fingerprint", "user_preview", "submitted_text", "scores", "terminal_outcome"}).
			AddRow(1, "req-1", 5, 6, nil, "openai", "/v1/chat/completions", "openai", "gpt-4o",
				"blocked", "regex", 3, "命中规则", 0.5, "hash-1", "脱敏片段", "block", createdAt, "custom", "custom-3", "fixture", "", "", "", []byte("{}"), "blocked"))

	recorder := fixture.do(t, http.MethodGet, "/export?provider=openai", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "text/csv; charset=utf-8", recorder.Header().Get("Content-Type"))
	require.Contains(t, recorder.Header().Get("Content-Disposition"), `attachment; filename="risk-gate-events-`)
	require.Contains(t, recorder.Header().Get("Content-Disposition"), `.csv"`)

	records, err := csv.NewReader(strings.NewReader(recorder.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, "id", records[0][0])
	require.Equal(t, "created_at", records[0][17])
	require.Equal(t, "req-1", records[1][1])
	require.Equal(t, "hash-1", records[1][14])
	require.Equal(t, createdAt.Format(time.RFC3339), records[1][17])
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 清空拒答语料：返回删除行数。单条删除不存在返回 404。
func TestRiskGateAdminDeleteRefusals(t *testing.T) {
	fixture := newRiskGateAdminFixture(t)
	fixture.mock.ExpectExec(`DELETE FROM risk_gate_refusals`).
		WillReturnResult(sqlmock.NewResult(0, 4))
	fixture.mock.ExpectExec(`DELETE FROM risk_gate_refusals WHERE id = \$1`).
		WithArgs(int64(6)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	recorder := fixture.do(t, http.MethodDelete, "/refusals", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"deleted":4`)

	recorder = fixture.do(t, http.MethodDelete, "/refusals/6", "")
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.NoError(t, fixture.mock.ExpectationsWereMet())
}

// 审计字段只记 subject 的短哈希，绝不出现原文。
func TestRiskGateAdminBanAuditFieldsHideSubject(t *testing.T) {
	fields := riskGateBanFields(riskgate.CreateBanRequest{
		Scope: "api_key", Subject: "sk-secret-key", Reason: "手动封禁", DurationHours: 24, Gate: "regex",
	})
	require.Equal(t, "api_key", fields["scope"])
	require.Equal(t, 24, fields["duration_hours"])
	hash, ok := fields["subject_hash"].(string)
	require.True(t, ok)
	require.Len(t, hash, 16)
	require.NotContains(t, recorderKeys(fields), "subject")
	require.NotContains(t, fields, "reason")
	require.Equal(t, hash, riskGateHashSubject(" sk-secret-key "))
	require.NotEqual(t, hash, riskGateHashSubject("sk-secret-key-2"))
}

// recorderKeys 返回审计字段的键集合，便于断言不含敏感键。
func recorderKeys(fields map[string]any) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	return keys
}
