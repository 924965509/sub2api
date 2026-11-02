//go:build risk_alignment_integration

// This suite is deliberately opt-in and refuses non-local/non-test databases.
// It exercises real migrations, repositories and admin handlers, not sqlmock.
package riskgate_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/riskgate"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

type alignmentCipher struct{ aead cipher.AEAD }

func (e alignmentCipher) Encrypt(text string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(e.aead.Seal(nonce, nonce, []byte(text), nil)), nil
}
func (e alignmentCipher) Decrypt(text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < e.aead.NonceSize() {
		return "", fmt.Errorf("test ciphertext too short")
	}
	plain, err := e.aead.Open(nil, data[:e.aead.NonceSize()], data[e.aead.NonceSize():], nil)
	return string(plain), err
}

type alignmentHarness struct {
	t      *testing.T
	db     *sql.DB
	config *riskgate.ConfigManager
	engine *riskgate.Engine
	server *httptest.Server
	routes map[string]bool
}

func newAlignmentHarness(t *testing.T) *alignmentHarness {
	t.Helper()
	dsn := os.Getenv("RISK_ALIGNMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RISK_ALIGNMENT_TEST_DATABASE_URL to an isolated local test database")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	require.Contains(t, []string{"127.0.0.1", "localhost", "::1"}, u.Hostname(), "integration tests never connect to remote databases")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "risk_alignment_test"), "database name must start with risk_alignment_test")
	root, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, root.PingContext(ctx))
	schema := fmt.Sprintf("risk_alignment_%d", time.Now().UnixNano())
	_, err = root.ExecContext(ctx, `CREATE SCHEMA `+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = root.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`) })
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(6)

	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || len(name) < 3 {
			continue
		}
		n, err := strconv.Atoi(name[:3])
		if err != nil || n < 250 {
			continue
		}
		text, err := migrations.FS.ReadFile(name)
		require.NoError(t, err)
		if strings.Contains(string(text), "risk_gate_") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	require.GreaterOrEqual(t, len(names), 6, "alignment must include new migrations without changing 250-254")
	for round := 1; round <= 2; round++ {
		for _, name := range names {
			text, err := migrations.FS.ReadFile(name)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, string(text))
			require.NoErrorf(t, err, "migration %s, application %d", name, round)
		}
	}
	t.Logf("applied %d risk migrations twice to isolated schema", len(names))
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS accounts (
	 id BIGINT PRIMARY KEY, name TEXT NOT NULL, notes TEXT DEFAULT '', platform TEXT NOT NULL,
	 type TEXT DEFAULT 'oauth', status TEXT DEFAULT 'active', credentials JSONB DEFAULT '{}', extra JSONB DEFAULT '{}',
	 schedulable BOOLEAN DEFAULT TRUE, priority INTEGER DEFAULT 1, concurrency INTEGER DEFAULT 5,
	 rate_multiplier NUMERIC DEFAULT 1, load_factor INTEGER DEFAULT 1, deleted_at TIMESTAMPTZ,
	 last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, auto_pause_on_expired BOOLEAN DEFAULT FALSE,
	 temp_unschedulable_until TIMESTAMPTZ, temp_unschedulable_reason TEXT DEFAULT '', rate_limit_reset_at TIMESTAMPTZ,
	 overload_until TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
	 INSERT INTO accounts(id,name,platform,credentials,extra) VALUES
	 (1,'fixture Claude Max','anthropic','{"email":"max@example.test","plan_type":"max"}','{"subscription_tier":"max"}'),
	 (2,'fixture Claude Pro','anthropic','{"email":"pro@example.test","plan_type":"pro"}','{"subscription_tier":"pro"}'),
	 (3,'fixture GPT Plus','openai','{"email":"plus@example.test","plan_type":"plus"}','{}')`)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	config := riskgate.NewConfigManager(db, nil, alignmentCipher{aead})
	rules := riskgate.NewRuleStore(db)
	bans := riskgate.NewBanStore(db, nil)
	events := riskgate.NewEventWriter(db)
	refusals := riskgate.NewRefusalStore(db)
	eventRepo := riskgate.NewEventRepository(db)
	classifier := riskgate.NewOpenAIClassifier()
	engine, err := riskgate.NewEngine(config, rules, bans, events, refusals, classifier)
	require.NoError(t, err)
	require.NoError(t, engine.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, engine.Shutdown(context.Background())) })
	svc := riskgate.NewAdminService(config, engine, bans, rules, rules, bans, refusals, eventRepo)
	handler := admin.NewRiskGateHandler(svc)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	// Mirror the actual production registration surface instead of hand-registering
	// endpoints that might have been implemented but never wired into the app.
	registration, err := os.ReadFile("../server/routes/admin.go")
	require.NoError(t, err)
	expression := regexp.MustCompile(`riskGate\.(GET|POST|PUT|PATCH|DELETE)\("([^"]+)",\s*h\.Admin\.RiskGate\.(\w+)\)`)
	routes := make(map[string]bool)
	value := reflect.ValueOf(handler)
	for _, match := range expression.FindAllStringSubmatch(string(registration), -1) {
		method := value.MethodByName(match[3])
		require.Truef(t, method.IsValid(), "missing handler %s", match[3])
		fn, ok := method.Interface().(func(*gin.Context))
		require.True(t, ok)
		router.Handle(match[1], "/api/v1/admin/risk-gate"+match[2], fn)
		routes[match[1]+" "+match[2]] = true
	}
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return &alignmentHarness{t: t, db: db, config: config, engine: engine, server: server, routes: routes}
}

func (h *alignmentHarness) call(method, path string, body any, status int) map[string]any {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, h.server.URL+"/api/v1/admin/risk-gate"+path, reader)
	require.NoError(h.t, err)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	require.NoError(h.t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	require.NoError(h.t, err)
	require.Equalf(h.t, status, response.StatusCode, "%s %s: %s", method, path, data)
	var envelope map[string]any
	require.NoErrorf(h.t, json.Unmarshal(data, &envelope), "%s %s: %s", method, path, data)
	if status >= 400 {
		return envelope
	}
	require.EqualValues(h.t, 0, envelope["code"], "%s", data)
	if value, ok := envelope["data"].(map[string]any); ok {
		return value
	}
	return map[string]any{"value": envelope["data"]}
}

func (h *alignmentHarness) saveConfig(config map[string]any, version any) map[string]any {
	h.t.Helper()
	body := make(map[string]any, len(config)+1)
	for key, value := range config {
		body[key] = value
	}
	body["expected_version"] = version
	return h.call("PUT", "/config", body, http.StatusOK)
}

func alignmentRequest(id, text string) securityaudit.Request {
	body, _ := json.Marshal(map[string]any{"model": "claude-test", "messages": []map[string]string{{"role": "user", "content": text}}})
	return securityaudit.Request{RequestID: id, UserID: 10, APIKeyID: 20, Provider: "anthropic", Endpoint: "/v1/messages", Protocol: "anthropic", Model: "claude-test", Body: body, Stage: "entry"}
}

func TestRiskAuditAlignmentPostgresAPI(t *testing.T) {
	h := newAlignmentHarness(t)
	for _, route := range []string{"GET /config", "PUT /config", "GET /stats", "GET /ruleset", "PUT /ruleset", "POST /rules/validate", "GET /scope-inventory", "POST /classifier/models", "GET /classifier/usage", "DELETE /bans"} {
		require.True(t, h.routes[route], "required production route was not wired: %s", route)
	}
	view := h.call("GET", "/config", nil, 200)
	config := view["config"].(map[string]any)
	require.Equal(t, "off", config["mode"])
	initialVersion := view["version"]
	view = h.saveConfig(config, initialVersion)
	stale := make(map[string]any)
	for k, v := range config {
		stale[k] = v
	}
	stale["expected_version"] = initialVersion
	h.call("PUT", "/config", stale, 409)

	inventory := h.call("GET", "/scope-inventory", nil, 200)
	require.EqualValues(t, 3, inventory["accounts_total"])
	inventoryJSON, _ := json.Marshal(inventory)
	require.NotContains(t, string(inventoryJSON), "credentials")
	require.NotContains(t, string(inventoryJSON), "access_token")

	ruleset := h.call("GET", "/ruleset", nil, 200)
	rule := map[string]any{"gate": "regex", "category": "custom", "pattern": "(?i)alignment_trigger", "is_regex": true, "action": "block", "enabled": true, "sort_order": 1, "description": "isolated integration fixture"}
	validation := h.call("POST", "/rules/validate", map[string]any{"rules": []any{rule}, "text": "ALIGNMENT_TRIGGER"}, 200)
	require.Equal(t, true, validation["valid"])
	require.NotEmpty(t, validation["matches"])
	invalid := map[string]any{}
	for k, v := range rule {
		invalid[k] = v
	}
	invalid["pattern"] = "(?=unsupported)"
	validation = h.call("POST", "/rules/validate", map[string]any{"rules": []any{invalid}}, 200)
	require.Equal(t, false, validation["valid"], "validation must use the Go engine, not JavaScript regex syntax")
	before := ruleset["version"]
	ruleset = h.call("PUT", "/ruleset", map[string]any{"expected_version": before, "rules": []any{rule}}, 200)
	storedRules := ruleset["rules"].([]any)
	require.Len(t, storedRules, 1)
	firstID := storedRules[0].(map[string]any)["id"]
	require.NotEmpty(t, firstID)
	storedRules[0].(map[string]any)["description"] = "updated integration fixture"
	ruleset = h.call("PUT", "/ruleset", map[string]any{"expected_version": ruleset["version"], "rules": storedRules}, 200)
	require.Equal(t, firstID, ruleset["rules"].([]any)[0].(map[string]any)["id"], "saving must preserve stable rule identity")
	h.call("PUT", "/ruleset", map[string]any{"expected_version": before, "rules": []any{rule}}, 409)

	config = view["config"].(map[string]any)
	config["mode"] = "blocking"
	config["gates"] = map[string]any{"distill": false, "regex": true, "refusal_cache": false, "decision_model": false}
	config["refusal_cache"].(map[string]any)["enabled"] = false
	config["decision_model"].(map[string]any)["enabled"] = false
	config["regex"].(map[string]any)["categories"] = []string{}
	config["regex"].(map[string]any)["custom_rules"] = true
	config["ban"].(map[string]any)["on_regex"] = false
	config["scope"].(map[string]any)["openai_platform_enabled"] = true
	view = h.saveConfig(config, view["version"])
	decision := h.engine.Decide(context.Background(), alignmentRequest("integration-block", "ALIGNMENT_TRIGGER"))
	require.NotNil(t, decision)
	require.False(t, decision.AllowNextStage)
	require.Equal(t, 403, decision.HTTPStatus)

	config = view["config"].(map[string]any)
	config["mode"] = "observe"
	view = h.saveConfig(config, view["version"])
	require.Nil(t, h.engine.Decide(context.Background(), alignmentRequest("integration-observe", "ALIGNMENT_TRIGGER")))
	require.Nil(t, h.engine.Decide(context.Background(), alignmentRequest("integration-allow", "ordinary programming fixture")))
	query := "/stats?timezone=Asia%2FShanghai"
	var stats map[string]any
	require.Eventually(t, func() bool { stats = h.call("GET", query, nil, 200); return stats["total"] == float64(3) }, 8*time.Second, 100*time.Millisecond, "terminal event statistics must be persisted without duplicate observation rows")
	require.EqualValues(t, 1, stats["blocked"])
	require.EqualValues(t, 2, stats["passed"])
	require.EqualValues(t, 1, stats["would_block"])
	allowReq := alignmentRequest("integration-allow", "ordinary programming fixture")
	h.engine.RecordUpstreamRefusal(context.Background(), service.UpstreamRefusalEvent{RequestID: allowReq.RequestID, UserID: 10, APIKeyID: 20, Provider: allowReq.Provider, Endpoint: allowReq.Endpoint, Protocol: allowReq.Protocol, Model: allowReq.Model, Body: allowReq.Body, Source: "upstream_refusal"})
	require.Eventually(t, func() bool {
		rows := h.call("GET", "/events?view=pass&reason=upstream_refusal", nil, 200)
		return rows["total"] == float64(1)
	}, 8*time.Second, 100*time.Millisecond)
	stats = h.call("GET", query, nil, 200)
	require.EqualValues(t, 3, stats["total"], "upstream observation must not increase inbound denominator")
	rows := h.call("GET", "/events?action=would_block", nil, 200)
	require.EqualValues(t, 1, rows["total"])
	bans := h.call("GET", "/bans", nil, 200)
	require.EqualValues(t, 0, bans["total"], "observe never creates a ban")

	config = view["config"].(map[string]any)
	config["mode"] = "off"
	view = h.saveConfig(config, view["version"])
	status := h.call("GET", "/status", nil, 200)
	require.Empty(t, status["effective_gates"])
	oldCounters := h.engine.Counters()
	require.Nil(t, h.engine.Decide(context.Background(), alignmentRequest("integration-off", "ALIGNMENT_TRIGGER")))
	require.Equal(t, oldCounters, h.engine.Counters(), "off mode does not even change gate counters")
}

func TestRiskAuditAlignmentModelSecretsAndUsage(t *testing.T) {
	h := newAlignmentHarness(t)
	var calls atomic.Int64
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/models") {
			_, _ = io.WriteString(w, `{"data":[{"id":"jev-integration"}]}`)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		if r.Header.Get("Authorization") == "Bearer rejected-fixture-key" {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"fixture rejection"}`)
			return
		}
		if body["questions"] == nil {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"expected questions"}`)
			return
		}
		_, _ = io.WriteString(w, `{"model":"jev-integration","answers":{"usage_policy":{"noul":0.99},"nsfw":{"noul":0.99},"abuse":{"noul":0.98}},"usage":{"input_tokens":123,"output_tokens":9}}`)
	}))
	t.Cleanup(model.Close)
	view := h.call("GET", "/config", nil, 200)
	config := view["config"].(map[string]any)
	config["schema_version"] = 2
	modelConfig := config["decision_model"].(map[string]any)
	modelConfig["scoring_mode"] = "safety_questions"
	modelConfig["provider"] = "jev"
	modelConfig["safety_threshold"] = 0.5
	modelConfig["block_if_below"] = true
	modelConfig["questions"] = []any{
		map[string]any{"id": "usage_policy", "label": "Policy", "summary": "fixture", "instructions": "Check policy safety", "enabled": true},
		map[string]any{"id": "nsfw", "label": "NSFW", "summary": "fixture", "instructions": "Check sexual content safety", "enabled": true},
		map[string]any{"id": "abuse", "label": "Abuse", "summary": "fixture", "instructions": "Check harmful abuse", "enabled": true},
	}
	endpoint := map[string]any{"id": "fixture-model", "name": "Integration model", "provider": "jev", "base_url": model.URL, "model": "jev-integration", "timeout_ms": 1000, "enabled": true, "api_keys": []string{"rejected-fixture-key", "valid-fixture-key"}}
	modelConfig["endpoints"] = []any{endpoint}
	view = h.saveConfig(config, view["version"])
	encoded, _ := json.Marshal(view)
	require.NotContains(t, string(encoded), "rejected-fixture-key")
	require.NotContains(t, string(encoded), "valid-fixture-key")
	require.NotContains(t, string(encoded), "ciphertext")
	var stored string
	require.NoError(t, h.db.QueryRow(`SELECT config::text FROM risk_gate_config WHERE id=1`).Scan(&stored))
	require.NotContains(t, stored, "valid-fixture-key", "keys must be encrypted at rest")
	require.NotContains(t, stored, "rejected-fixture-key", "keys must be encrypted at rest")
	readModel := view["config"].(map[string]any)["decision_model"].(map[string]any)
	readEndpoint := readModel["endpoints"].([]any)[0].(map[string]any)
	require.EqualValues(t, 2, readEndpoint["api_key_count"])
	result := h.call("POST", "/classifier/probe", map[string]any{"endpoint": readEndpoint, "decision_model": readModel, "text": "ordinary programming fixture"}, 200)
	require.Equal(t, true, result["ok"])
	require.Len(t, result["scores"], 3)
	require.EqualValues(t, 2, calls.Load(), "401 should try the next configured key")
	models := h.call("POST", "/classifier/models", map[string]any{"endpoint": readEndpoint}, 200)
	require.NotEmpty(t, models["models"])
	var usage map[string]any
	require.Eventually(t, func() bool {
		usage = h.call("GET", "/classifier/usage", nil, 200)
		summary, ok := usage["summary"].(map[string]any)
		return ok && summary["requests"].(float64) >= 2
	}, 8*time.Second, 100*time.Millisecond)
	usageJSON, _ := json.Marshal(usage)
	require.NotContains(t, string(usageJSON), "valid-fixture-key")
	require.NotContains(t, string(usageJSON), "ordinary programming fixture")
	require.Nil(t, usage["summary"].(map[string]any)["estimated_cost_nano_usd"], "local endpoint has unknown cost, not official JEV pricing")
	var foreignCalls atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls.Add(1); w.WriteHeader(500) }))
	t.Cleanup(foreign.Close)
	changed := map[string]any{}
	for k, v := range readEndpoint {
		changed[k] = v
	}
	changed["base_url"] = foreign.URL
	// A changed destination without an explicitly supplied new key must not inherit
	// the saved secret associated with the endpoint ID.
	h.call("POST", "/classifier/models", map[string]any{"endpoint": changed}, 400)
	require.Zero(t, foreignCalls.Load(), "saved keys must not be sent to a changed origin")
}

// All values below are explicit operator choices, not missing defaults. A false
// direction or zero deduplication window must survive JSON persistence/readback.
func TestRiskAuditAlignmentExplicitZeroAndLegacyRoundTrip(t *testing.T) {
	h := newAlignmentHarness(t)
	view := h.call("GET", "/config", nil, 200)
	config := view["config"].(map[string]any)
	config["schema_version"] = 2
	model := config["decision_model"].(map[string]any)
	model["scoring_mode"] = "safety_questions"
	model["provider"] = "jev"
	model["block_if_below"] = false
	model["dedup_sec"] = 0
	model["safety_threshold"] = 0
	view = h.saveConfig(config, view["version"])
	model = view["config"].(map[string]any)["decision_model"].(map[string]any)
	require.Contains(t, model, "block_if_below")
	require.Equal(t, false, model["block_if_below"])
	require.Contains(t, model, "dedup_sec")
	require.EqualValues(t, 0, model["dedup_sec"])
	require.Contains(t, model, "safety_threshold")
	require.EqualValues(t, 0, model["safety_threshold"])

	legacy := map[string]any{
		"mode":           "observe",
		"gates":          map[string]any{"distill": true, "regex": true, "refusal_cache": false, "decision_model": false},
		"distill":        map[string]any{"hard_needles": []string{"fixture"}, "needles": []string{}, "fingerprints": []string{}, "skip_official": true, "skip_zero": true, "min_max_tokens": 32000, "contest_pattern": ""},
		"regex":          map[string]any{"categories": []string{"sexual", "distill", "jailbreak", "bypass"}, "custom_rules": true, "max_input_bytes": 1048576, "expand_base64": true, "block_message": "fixture"},
		"refusal_cache":  map[string]any{"enabled": true, "similarity_threshold": 0.92, "min_shingle_runes": 512},
		"decision_model": map[string]any{"enabled": false, "threshold": 0.8, "timeout_ms": 3000, "max_concurrent": 32, "on_unavailable": "pass", "endpoints": []any{}},
		"ban":            map[string]any{"scope": "api_key", "on_distill": true, "on_regex": false, "on_decision_model": false, "duration_hours": 0},
		"scope":          map[string]any{"all_groups": true, "group_ids": []int{}, "all_providers": true, "providers": []string{}},
		"retention_days": 30,
	}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	_, err = h.db.Exec(`UPDATE risk_gate_config SET config=$1::jsonb,version=21 WHERE id=1`, string(raw))
	require.NoError(t, err)
	require.NoError(t, h.config.Reload(context.Background()))
	view = h.call("GET", "/config", nil, 200)
	stored := view["config"].(map[string]any)
	model = stored["decision_model"].(map[string]any)
	require.EqualValues(t, 0.8, model["threshold"])
	require.True(t, model["scoring_mode"] == nil || model["scoring_mode"] == "" || model["scoring_mode"] == "risk", "legacy config must not silently invert to safety scoring")
	cfg, _, ok := h.config.Current()
	require.True(t, ok)
	require.True(t, cfg.RefusalCacheActive(), "legacy OR-enabled refusal cache must remain enabled during migration")
	stored["gates"].(map[string]any)["refusal_cache"] = false
	stored["refusal_cache"].(map[string]any)["enabled"] = false
	view = h.saveConfig(stored, view["version"])
	require.NoError(t, h.config.Reload(context.Background()))
	cfg, _, ok = h.config.Current()
	require.True(t, ok)
	require.False(t, cfg.RefusalCacheActive(), "explicitly turning off both aliases must persist after reload")
}

func TestRiskAuditAlignmentExplicitSettingsAreNotDefaults(t *testing.T) {
	config := riskgate.DefaultConfig()
	config.SchemaVersion = 2
	config.Regex.StripReminders = false
	config.RefusalCache.SimilarityEnabled = false
	config.RefusalCache.DeviceBlockEnabled = false
	config.DecisionModel.BlockIfBelow = false
	config.DecisionModel.DedupSec = 0
	config.DecisionModel.SafetyThreshold = 0
	config.Distill.HardNeedles = []string{}
	normalized := config.WithDefaults()
	t.Run("strip_reminders", func(t *testing.T) { require.False(t, normalized.Regex.StripReminders) })
	t.Run("similarity_enabled", func(t *testing.T) { require.False(t, normalized.RefusalCache.SimilarityEnabled) })
	t.Run("device_block_enabled", func(t *testing.T) { require.False(t, normalized.RefusalCache.DeviceBlockEnabled) })
	t.Run("inverse_score_direction", func(t *testing.T) { require.False(t, normalized.DecisionModel.BlockIfBelow) })
	t.Run("disabled_dedup", func(t *testing.T) { require.Zero(t, normalized.DecisionModel.DedupSec) })
	t.Run("zero_threshold", func(t *testing.T) { require.Zero(t, normalized.DecisionModel.SafetyThreshold) })
	t.Run("removed_hard_needles", func(t *testing.T) {
		require.Empty(t, normalized.Distill.HardNeedles, "deleting a list must not restore it on save")
	})
}

func TestRiskAuditAlignmentRetentionAndRefusalPersistence(t *testing.T) {
	h := newAlignmentHarness(t)
	view := h.call("GET", "/config", nil, 200)
	cfg := view["config"].(map[string]any)
	cfg["mode"] = "observe"
	cfg["retention_days"] = 7
	h.saveConfig(cfg, view["version"])
	store := riskgate.NewRefusalStore(h.db)
	first := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	last := first.Add(30 * time.Second)
	store.Enqueue(riskgate.RefusalRecord{PromptHash: "retention-fixture-hash", NormalizedPrompt: "synthetic evidence", CreatedAt: first})
	store.Enqueue(riskgate.RefusalRecord{PromptHash: "retention-fixture-hash", NormalizedPrompt: "synthetic evidence", CreatedAt: last})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, store.Shutdown(ctx))
	var count int
	var firstSeen, lastSeen time.Time
	require.NoError(t, h.db.QueryRow(`SELECT hit_count,first_seen_at,last_seen_at FROM risk_gate_refusals WHERE prompt_hash=$1`, "retention-fixture-hash").Scan(&count, &firstSeen, &lastSeen))
	require.Equal(t, 2, count)
	require.True(t, first.Equal(firstSeen))
	require.True(t, last.Equal(lastSeen))
	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	_, err := h.db.Exec(`INSERT INTO risk_gate_decisions(decision_key,request_id,outcome,created_at) VALUES('old-fixture','old-fixture','allowed',$1)`, old)
	require.NoError(t, err)
	_, err = h.db.Exec(`INSERT INTO risk_gate_classifier_usage(outcome,duration_ms,created_at) VALUES('success',10,$1)`, old)
	require.NoError(t, err)
	_, err = h.db.Exec(`UPDATE risk_gate_classifier_totals SET requests=42,input_tokens=1234 WHERE id=1`)
	require.NoError(t, err)
	cleanup := riskgate.NewCleanupScheduler(h.db, h.config, store)
	result, err := cleanup.RunOnce(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Decisions)
	require.EqualValues(t, 1, result.ClassifierUsage)
	var requests, tokens int
	require.NoError(t, h.db.QueryRow(`SELECT requests,input_tokens FROM risk_gate_classifier_totals WHERE id=1`).Scan(&requests, &tokens))
	require.Equal(t, 42, requests)
	require.Equal(t, 1234, tokens)
	require.NoError(t, h.db.QueryRow(`SELECT COUNT(*) FROM risk_gate_refusals WHERE prompt_hash=$1`, "retention-fixture-hash").Scan(&count))
	require.Equal(t, 1, count, "current refusal evidence must survive detail retention")
}
