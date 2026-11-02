package riskgate

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
)

// fakeConfigSource 记录读取次数，用于断言 off 模式只有一次原子读。
type fakeConfigSource struct {
	config  Config
	version int64
	ready   bool
	reads   atomic.Int64
}

func (f *fakeConfigSource) Current() (Config, int64, bool) {
	f.reads.Add(1)
	if !f.ready {
		return Config{}, 0, false
	}
	return f.config, f.version, true
}

func (f *fakeConfigSource) Reads() int64 { return f.reads.Load() }

// fakeRuleSource 记录查库次数。
type fakeRuleSource struct {
	rules []Rule
	err   error
	calls atomic.Int64
}

func (f *fakeRuleSource) Rules(context.Context) ([]Rule, error) {
	f.calls.Add(1)
	return f.rules, f.err
}

func (f *fakeRuleSource) Calls() int64 { return f.calls.Load() }

// fakeBanResolver 是内存封禁实现，遵守 expires_at 语义。
type fakeBanResolver struct {
	mu        sync.Mutex
	bans      map[string]Ban
	upserts   []Ban
	lookups   []string
	errors    error
	upsertErr error
}

func newFakeBanResolver() *fakeBanResolver {
	return &fakeBanResolver{bans: make(map[string]Ban, 4)}
}

func fakeBanKey(scope, subject string) string { return scope + "|" + subject }

func (f *fakeBanResolver) add(ban Ban) {
	if f == nil {
		return
	}
	if f.bans == nil {
		f.bans = make(map[string]Ban, 4)
	}
	f.bans[fakeBanKey(ban.Scope, ban.Subject)] = ban
}

func (f *fakeBanResolver) FindActive(_ context.Context, scope, subject string, now time.Time) (*Ban, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, fakeBanKey(scope, subject))
	if f.errors != nil {
		return nil, f.errors
	}
	ban, ok := f.bans[fakeBanKey(scope, subject)]
	if !ok {
		return nil, nil
	}
	if ban.ExpiresAt != nil && !ban.ExpiresAt.After(now) {
		return nil, nil
	}
	return &ban, nil
}

func (f *fakeBanResolver) Upsert(_ context.Context, ban Ban) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserts = append(f.upserts, ban)
	return nil
}

func (f *fakeBanResolver) CountActive(context.Context, time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.bans)), nil
}

func (f *fakeBanResolver) Upserts() []Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Ban(nil), f.upserts...)
}

func (f *fakeBanResolver) Lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lookups...)
}

// recordingSink 记录写入的事件。
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *recordingSink) Write(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *recordingSink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// fakeRefusalRepository 记录拒答语料的查询/写入次数，便于断言零行为与命中路径。
type fakeRefusalRepository struct {
	mu sync.Mutex

	hit      *RefusalHit
	err      error
	matches  []string
	enqueued []RefusalRecord
}

func (f *fakeRefusalRepository) Match(_ context.Context, promptHash string, _ []uint64, _ float64) (*RefusalHit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.matches = append(f.matches, promptHash)
	if f.err != nil {
		return nil, f.err
	}
	if f.hit == nil {
		return nil, nil
	}
	hit := *f.hit
	return &hit, nil
}

func (f *fakeRefusalRepository) Enqueue(record RefusalRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, record)
}

func (f *fakeRefusalRepository) MatchCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.matches...)
}

func (f *fakeRefusalRepository) Enqueued() []RefusalRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RefusalRecord(nil), f.enqueued...)
}

// chatBody 构造 Chat Completions 请求体。
func chatBody(system, user string) []byte {
	payload := `{"model":"gpt-4o","max_tokens":2048,"messages":[`
	if system != "" {
		payload += `{"role":"system","content":` + quote(system) + `},`
	}
	payload += `{"role":"user","content":` + quote(user) + `}]}`
	return []byte(payload)
}

func quote(value string) string {
	return `"` + escapeJSON(value) + `"`
}

func escapeJSON(value string) string {
	escaped := make([]rune, 0, len(value))
	for _, r := range value {
		switch r {
		case '"':
			escaped = append(escaped, '\\', '"')
		case '\\':
			escaped = append(escaped, '\\', '\\')
		case '\n':
			escaped = append(escaped, '\\', 'n')
		case '\r':
			escaped = append(escaped, '\\', 'r')
		case '\t':
			escaped = append(escaped, '\\', 't')
		default:
			escaped = append(escaped, r)
		}
	}
	return string(escaped)
}

// newTestRequest 构造一个带身份的 Chat 请求。
func newTestRequest(body []byte) securityaudit.Request {
	return securityaudit.Request{
		RequestID: "req-1", UserID: 7, APIKeyID: 11, Provider: "openai",
		Endpoint: "/v1/chat/completions", Protocol: "openai_chat_completions",
		Model: "gpt-4o", Body: body, Stage: "http",
	}
}

// fakeClassifier 记录调用次数与入参，便于断言闸门顺序、零行为与缓存命中。
type fakeClassifier struct {
	mu       sync.Mutex
	score    float64
	category string
	err      error
	// calls 记录每次调用的端点 ID，用于断言「只调一次」与端点顺序。
	calls []string
	// texts 记录每次调用的待判定正文。
	texts []string
}

func (f *fakeClassifier) Score(_ context.Context, endpoint ClassifierEndpoint, text string) (float64, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, endpoint.ID)
	f.texts = append(f.texts, text)
	if f.err != nil {
		return 0, "", f.err
	}
	return f.score, f.category, nil
}

func (f *fakeClassifier) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeClassifier) Endpoints() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// legacyRiskConfigForTest freezes the configuration contract of the existing
// risk-score engine tests independently of new-install schema-v2 defaults.
func legacyRiskConfigForTest() Config {
	cfg := DefaultConfig()
	cfg.SchemaVersion = 0
	cfg.DecisionModel.ScoringMode = "risk"
	cfg.DecisionModel.Provider = "openai"
	cfg.Scope.OpenAIPlatformEnabled = true
	cfg.Distill.RequireNoTools = false
	cfg.Distill.RequireSingleTurn = false
	cfg.RefusalCache.DeviceBlockEnabled = false
	return cfg
}
