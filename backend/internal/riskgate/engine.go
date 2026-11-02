package riskgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// 默认拦截文案。
const (
	defaultBlockMessage = "风险闸门拒绝了该请求：疑似抓取/蒸馏上游模型，请调整输入后重试"
	defaultBanMessage   = "该身份已被风险闸门封禁，请调整输入后重试。"
	// decisionBlockMessage 是决策模型命中时的内置拦截文案（与 regex.block_message 无关）。
	decisionBlockMessage = "风险闸门拒绝了该请求：内容被判定为高风险，请调整输入后重试"
	// decisionUnavailableMessage 是决策模型不可用且 fail_closed 时的文案。
	decisionUnavailableMessage = "风险闸门决策模型暂不可用，请稍后重试"
)

// ConfigSource 提供当前生效的配置快照。
type ConfigSource interface {
	// Current 返回配置、版本号与是否已有可信快照。
	Current() (Config, int64, bool)
}

// Engine 是风险闸门引擎，实现 securityaudit.PreGate。
//
// mode=off 时 Decide 只做一次原子读后立刻返回 nil：不查库、不查 Redis、
// 不发 HTTP、不写事件。
type Engine struct {
	audit  *AuditStore
	config ConfigSource
	rules  RuleSource
	bans   BanResolver
	events EventSink
	// refusals 是拒答语料仓库（P3）。nil 时拒答缓存闸不生效。
	refusals RefusalRepository
	// classifier 是决策模型（P4）。nil 时决策模型闸不生效。
	classifier Classifier
	clock      Clock
	regex      *regexCache
	// decisionCache 是「prompt_hash → 分数」缓存；observe 模式只读不写。
	decisionCache *decisionCache
	// decisionSemaphore 是决策模型闸的进程级并发信号量。
	// 容量由配置决定，配置变化时按「容量不同则重建」的方式安全替换。
	decisionSemaphoreMu  sync.Mutex
	decisionSemaphore    chan struct{}
	decisionSemaphoreCap int

	starters []starter
	shutters []shutter

	counters gateCounters
	lastErr  atomic.Pointer[string]
}

type starter interface {
	Start(context.Context) error
}

type shutter interface {
	Shutdown(context.Context) error
}

type gateCounters struct {
	evaluated  atomic.Int64
	allowed    atomic.Int64
	blocked    atomic.Int64
	wouldBlock atomic.Int64
	banned     atomic.Int64
	banHits    atomic.Int64
	distill    atomic.Int64
	refusal    atomic.Int64
	regex      atomic.Int64
	decision   atomic.Int64
	classifier atomic.Int64
}

// NewEngine 构造引擎；只有配置来源缺失时返回错误（此时调用方应降级为 nil preGate）。
// NewEngine 构造引擎；只有配置来源缺失时返回错误（此时调用方应降级为 nil preGate）。
// refusals / classifier 允许为 nil，表示对应闸门不生效。
// extras 是可选的后台组件（如清理调度器），实现了 starter/shutter 才会被接管生命周期。
func NewEngine(config ConfigSource, rules RuleSource, bans BanResolver, events EventSink, refusals RefusalRepository, classifier Classifier, extras ...any) (*Engine, error) {
	if config == nil {
		return nil, errors.New("risk gate requires a config source")
	}
	engine := &Engine{
		config: config, rules: rules, bans: bans, events: events, refusals: refusals,
		classifier: classifier, clock: realClock{}, regex: newRegexCache(),
		decisionCache: newDecisionCache(decisionCacheTTL, decisionCacheMaxEntries, nil),
	}
	if manager, ok := config.(*ConfigManager); ok && manager.db != nil {
		engine.audit = NewAuditStore(manager.db)
		engine.shutters = append(engine.shutters, engine.audit)
		if client, ok := classifier.(*OpenAIClassifier); ok {
			client.audit = engine.audit
		}
	}
	if component, ok := config.(starter); ok {
		engine.starters = append(engine.starters, component)
	}
	if component, ok := config.(shutter); ok {
		engine.shutters = append(engine.shutters, component)
	}
	if events != nil {
		if component, ok := events.(shutter); ok {
			engine.shutters = append(engine.shutters, component)
		}
	}
	if refusals != nil {
		if component, ok := refusals.(starter); ok {
			engine.starters = append(engine.starters, component)
		}
		if component, ok := refusals.(shutter); ok {
			engine.shutters = append(engine.shutters, component)
		}
	}
	// extras 里的可选组件：只接管实现了 starter/shutter 的实例，nil 值自动跳过。
	for _, extra := range extras {
		if component, ok := extra.(starter); ok {
			engine.starters = append(engine.starters, component)
		}
		if component, ok := extra.(shutter); ok {
			engine.shutters = append(engine.shutters, component)
		}
	}
	return engine, nil
}

// SetClock 注入测试时钟。
func (e *Engine) SetClock(clock Clock) {
	if e == nil || clock == nil {
		return
	}
	e.clock = clock
}

// Start 启动配置热加载与事件写入协程，并把本引擎注册为上游拒答记录器。
func (e *Engine) Start(ctx context.Context) error {
	if e == nil {
		return nil
	}
	var firstErr error
	for _, component := range e.starters {
		if err := component.Start(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// 即使某个子组件启动失败也注册：mode=off 时函数体第一步就返回，
	// 运行时切到 observe/blocking 后即可立即生效。
	service.SetUpstreamRefusalRecorder(e)
	return firstErr
}

// Shutdown 停止配置热加载并把事件缓冲写完。
func (e *Engine) Shutdown(ctx context.Context) error {
	if e == nil {
		return nil
	}
	var firstErr error
	for _, component := range e.shutters {
		if err := component.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// 引擎下线后 service 层不应再往这里投递上游拒答观察。
	service.SetUpstreamRefusalRecorder(nil)
	return firstErr
}

// Decide 实现 securityaudit.PreGate。
func (e *Engine) Decide(ctx context.Context, req securityaudit.Request) *securityaudit.Decision {
	if e == nil {
		return nil
	}
	cfg, version, ok := e.config.Current()
	if !ok {
		// 快照未就绪（启动中/加载失败）时一律放行：默认关闭的能力不能拖垮网关。
		return nil
	}
	if cfg.EffectiveMode() == ModeOff {
		return nil
	}
	// Scope restricted to actual upstream accounts is evaluated by the selected-
	// account hook, never guessed from the inbound group/provider.
	if cfg.hasAccountScope() && req.SelectedAccountID == 0 {
		return nil
	}
	now := e.clock.Now()
	if !cfg.inScopeRequest(req) {
		if e.audit != nil {
			e.audit.RecordDecision(req, "passed", "scope", GateResult{}, false, now)
		}
		return nil
	}
	if cfg.SchemaVersion >= 2 && !cfg.hasAccountScope() && !cfg.Scope.OpenAIPlatformEnabled && isOpenAI(req.Provider, req.Model) {
		if e.audit != nil {
			e.audit.RecordDecision(req, "passed", "platform", GateResult{}, false, now)
		}
		return nil
	}
	cfg = cfg.Clone()
	for i := range cfg.DecisionModel.Endpoints {
		cfg.DecisionModel.Endpoints[i].KeyRevision = version
	}
	ctx = context.WithValue(ctx, requestIDContextKey{}, req.RequestID)
	e.counters.evaluated.Add(1)
	result := e.evaluate(ctx, req, cfg, now)
	if !result.hit.Hit {
		e.counters.allowed.Add(1)
		if e.audit != nil {
			reason := result.passReason
			if reason == "" {
				reason = "regex"
			}
			e.audit.RecordDecision(req, "passed", reason, GateResult{}, len(result.observations) > 0, now)
		}
		return nil
	}
	return e.block(ctx, req, cfg, result, now)
}

// evaluation 汇总一次判定的结果。
type evaluation struct {
	observations []GateResult
	passReason   string
	hit          GateResult
	identity     Identity
	view         TextView
	meta         RequestMeta
}

// evaluate 按固定顺序执行闸门：ban → distill → regex → refusal_cache → decision_model，
// 命中即短路。mode=off 时不会走到这里（Decide 已提前返回）。
func (e *Engine) evaluate(ctx context.Context, req securityaudit.Request, cfg Config, now time.Time) evaluation {
	result := evaluation{}
	banResult, err := evaluateBan(ctx, cfg, req, e.bans, now)
	if err != nil {
		e.recordError(err)
	}
	if banResult.Hit {
		result.hit = banResult
		return result
	}
	// 所有文本类闸门都关闭时不再解析正文：不发 HTTP、不查库。
	if !cfg.Gates.Distill && !cfg.Gates.Regex && !cfg.RefusalCacheActive() && !e.decisionGateActive(cfg) {
		result.passReason = "unchecked"
		return result
	}
	view, meta, err := BuildTextView(req, NormalizeOptions{ExpandBase64: cfg.Regex.ExpandBase64, KeepReminders: cfg.SchemaVersion >= 2 && !cfg.Regex.StripReminders})
	if err != nil {
		// 请求体无法解析（例如空 body 的 count_tokens）时跳过文本类闸门。
		return result
	}
	result.view = view
	result.meta = meta
	result.identity = ExtractIdentity(req, view)
	var rules []Rule
	if e.rules != nil {
		if store, ok := e.rules.(*RuleStore); ok && cfg.SchemaVersion >= 2 {
			rules, err = store.PolicyRules(ctx)
		} else {
			rules, err = e.rules.Rules(ctx)
		}
		if err != nil {
			e.recordError(err)
		}
	} else if cfg.SchemaVersion >= 2 {
		rules = BuiltinRules()
	}
	openai := isOpenAI(req.Provider, req.Model)
	if cfg.Gates.Distill && (cfg.SchemaVersion < 2 || !openai) {
		hit, observations := evaluateDistillRules(cfg, view, meta, result.identity, e.regex, rules)
		for _, observation := range observations {
			e.observeRule(req, view, observation)
			result.observations = append(result.observations, observation)
		}
		if hit.Hit {
			result.hit = hit
			return result
		}
	}
	if cfg.SchemaVersion >= 2 {
		hit, observations := evaluatePolicyRules(cfg, view, rules, e.regex, openai)
		for _, observation := range observations {
			e.observeRule(req, view, observation)
			result.observations = append(result.observations, observation)
		}
		if hit.Hit {
			result.hit = hit
			return result
		}
	} else if cfg.Gates.Regex {
		if hit := evaluateRegex(cfg, view, rules, e.regex); hit.Hit {
			result.hit = hit
			return result
		}
	}
	if cfg.RefusalCacheActive() {
		if cfg.RefusalCache.DeviceBlockEnabled {
			if subject := checkBanSubject(BanScopeClientFingerprint, req); subject != "" && e.bans != nil {
				if ban, banErr := e.bans.FindActive(ctx, BanScopeClientFingerprint, subject, now); banErr != nil {
					e.recordError(banErr)
				} else if ban != nil {
					result.hit = GateResult{Hit: true, Gate: GateRefusalCache, Category: BanScopeClientFingerprint,
						Reason: "device", HTTPStatus: refusalHTTPStatus, ErrorCode: ErrorCodePolicyBlocked,
						Evidence: redactEvidence(view.LatestUser, evidenceMaxRunes)}
					return result
				}
			}
		}
		hit, err := evaluateRefusal(ctx, cfg, view, e.refusals)
		if err != nil {
			// 语料查询失败只记录，不拦（闸门自身故障不能变成误伤）。
			e.recordError(err)
		}
		if hit.Hit {
			result.hit = hit
			return result
		}
	}
	if e.decisionGateActive(cfg) {
		hit, unavailable := e.runDecisionGate(ctx, cfg, view)
		if hit.Hit {
			result.hit = hit
			return result
		}
		result.passReason = "jev"
		if unavailable {
			result.passReason = "fail-open"
			// 模型不可用但按 pass 放行：写一条漏拦观察事件（不拦、不封禁）。
			e.writeUpstreamPass(ctx, req, view, decisionUnavailable)
		}
	}
	return result
}

// decisionGateActive 报告决策模型闸是否真正生效。
//
// classifier 为 nil 时闸门不生效（规格：nil 即关闭），避免误把
// 「未装配分类器」当成端点故障写成 fail_closed 拦截。
func (e *Engine) decisionGateActive(cfg Config) bool {
	if e == nil || e.classifier == nil || !cfg.DecisionModelActive() {
		return false
	}
	if cfg.SchemaVersion >= 2 && len(usableClassifierEndpoints(cfg.DecisionModel.Endpoints)) == 0 {
		return false
	}
	return true
}

// runDecisionGate 在并发信号量与结果缓存的包裹下执行决策模型闸门。
//
// 缓存语义：prompt_hash → 分数缓存 10 分钟、上限 1 万条；mode=observe 只读不写，
// 避免观察模式的判定结果污染 blocking 模式的依据。
func (e *Engine) runDecisionGate(ctx context.Context, cfg Config, view TextView) (GateResult, bool) {
	document := view.LatestUser
	if cfg.SchemaVersion >= 2 && cfg.DecisionModel.ScoringMode == "safety_questions" {
		document = modelUserDocument(view.UserTurns, view.UserLabels, cfg.DecisionModel.MaxStateChars, cfg.Regex.StripReminders)
	}
	keyData, _ := json.Marshal(cfg.DecisionModel)
	digest := sha256.Sum256(append(keyData, []byte("\x00"+document)...))
	hash := hex.EncodeToString(digest[:])
	cacheEnabled := cfg.SchemaVersion < 2 || cfg.DecisionModel.DedupSec > 0
	if cacheEnabled {
		if score, category, ok := e.decisionCache.get(hash); ok {
			if cfg.SchemaVersion >= 2 && cfg.DecisionModel.ScoringMode == "safety_questions" {
				var scores map[string]float64
				if json.Unmarshal([]byte(category), &scores) == nil {
					return safetyDecision(cfg, document, scores), false
				}
			}
			return decisionHitFromScore(cfg, view.LatestUser, score, category), false
		}
	}
	release := e.acquireDecisionSlot(ctx, cfg.DecisionModel.MaxConcurrent)
	if release == nil {
		// 等不到信号量（请求被取消）：按不可用处理，绝不让排队失败变成拦截。
		return unavailableDecision(cfg)
	}
	defer release()
	outcome := evaluateDecisionOutcome(ctx, cfg, view, e.classifier)
	if outcome.Failures > 0 {
		e.counters.classifier.Add(int64(outcome.Failures))
	}
	if outcome.Scored && cfg.EffectiveMode() != ModeObserve && cacheEnabled {
		ttl := decisionCacheTTL
		if cfg.SchemaVersion >= 2 {
			ttl = time.Duration(cfg.DecisionModel.DedupSec) * time.Second
		}
		e.decisionCache.putTTL(hash, outcome.Score, outcome.Category, ttl)
	}
	return outcome.Hit, outcome.Unavailable
}

// acquireDecisionSlot 取得一个决策模型的并发槽位，返回释放函数；等不到返回 nil。
//
// 信号量容量跟随配置；容量变化时重建信号量（旧信号量里的在途槽位自然失效，
// 只是短暂放宽上限，不影响正确性）。
func (e *Engine) acquireDecisionSlot(ctx context.Context, maxConcurrent int) func() {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultDecisionConcurrency
	}
	e.decisionSemaphoreMu.Lock()
	if e.decisionSemaphore == nil || e.decisionSemaphoreCap != maxConcurrent {
		e.decisionSemaphore = make(chan struct{}, maxConcurrent)
		e.decisionSemaphoreCap = maxConcurrent
	}
	semaphore := e.decisionSemaphore
	e.decisionSemaphoreMu.Unlock()
	select {
	case semaphore <- struct{}{}:
		return func() { <-semaphore }
	case <-ctx.Done():
		return nil
	}
}

// block 把命中结果转换为事件与拦截决策。observe 模式只写事件并返回 nil。
func (e *Engine) block(ctx context.Context, req securityaudit.Request, cfg Config, result evaluation, now time.Time) *securityaudit.Decision {
	e.countGateHit(result.hit.Gate)
	event := e.baseEvent(req, result.view.NormalizedHash)
	event.Kind = EventKindBlocked
	event.Gate = result.hit.Gate
	event.RuleID = result.hit.RuleID
	event.Reason = result.hit.Reason
	event.Score = result.hit.Score
	event.Evidence = result.hit.Evidence
	event.Category = result.hit.Category
	event.RuleKey = result.hit.RuleKey
	event.Pattern = result.hit.Pattern
	event.ClientFingerprint = inboundFingerprint(req)
	event.UserPreview = redactEvidence(result.view.LatestUser, 2048)
	event.SubmittedText = result.hit.SubmittedText
	event.Scores = result.hit.Scores

	if cfg.EffectiveMode() == ModeObserve {
		event.Action = EventActionWouldBlock
		e.counters.wouldBlock.Add(1)
		event.TerminalOutcome = "passed"
		e.writeEvent(event)
		if e.audit != nil {
			e.audit.RecordDecision(req, "passed", "observe", result.hit, true, now)
		}
		return nil
	}

	banScope := ""
	if ban, ok := buildBan(cfg, req, result.hit, now); ok && e.bans != nil {
		if err := e.bans.Upsert(ctx, ban); err != nil {
			e.recordError(err)
		} else {
			banScope = ban.Scope
			e.counters.banned.Add(1)
		}
	}
	event.Action = EventActionNone
	if banScope != "" {
		event.Action = EventActionBanned
	}
	event.TerminalOutcome = "blocked"
	e.writeEvent(event)
	if e.audit != nil {
		e.audit.RecordDecision(req, "blocked", result.hit.Reason, result.hit, false, now)
	}
	e.counters.blocked.Add(1)

	status := result.hit.HTTPStatus
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	code := result.hit.ErrorCode
	if strings.TrimSpace(code) == "" {
		code = ErrorCodeBlocked
	}
	return &securityaudit.Decision{
		Kind: securityaudit.DecisionBlock,
		ClientErrorType: func() string {
			if cfg.SchemaVersion >= 2 && result.hit.Gate == GateDistill {
				return cfg.Distill.Error.Type
			}
			return ""
		}(),
		HTTPStatus:     status,
		ErrorCode:      code,
		ClientMessage:  e.clientMessage(cfg, result.hit, banScope),
		RiskGate:       e.riskGateDecision(result.hit, banScope),
		AllowNextStage: false,
	}
}

// clientMessage 生成回给客户端的文案；封禁命中附解除方式提示。
func (e *Engine) clientMessage(cfg Config, hit GateResult, banScope string) string {
	if cfg.SchemaVersion >= 2 && hit.Gate == GateDistill && cfg.Distill.Error.Message != "" {
		return cfg.Distill.Error.Message
	}
	if hit.Gate == GateBan {
		return defaultBanMessage + BanHint
	}
	if hit.Gate == GateRefusalCache {
		return refusalBlockMessage(hit.Reason)
	}
	if hit.Gate == GateDecisionModel {
		message := decisionBlockMessage
		if hit.HTTPStatus == http.StatusServiceUnavailable {
			message = decisionUnavailableMessage
		}
		if banScope != "" {
			return message + " " + BanHint
		}
		return message
	}
	if banScope != "" {
		return strings.TrimSpace(cfg.Regex.BlockMessage) + " " + BanHint
	}
	if message := strings.TrimSpace(cfg.Regex.BlockMessage); message != "" {
		return message
	}
	return defaultBlockMessage
}

// riskGateDecision 生成随 Decision 回传的命中摘要（不含正文）。
func (e *Engine) riskGateDecision(hit GateResult, banScope string) *securityaudit.RiskGateDecision {
	return &securityaudit.RiskGateDecision{
		Gate: hit.Gate, Category: hit.Category, Reason: hit.Reason, RuleID: hit.RuleID,
		Score: hit.Score, Evidence: hit.Evidence, BanScope: banScope, Banned: banScope != "",
	}
}

// baseEvent 生成事件模板，后续按命中结果补齐。
func (e *Engine) baseEvent(req securityaudit.Request, promptHash string) Event {
	var groupID *int64
	if req.GroupID != nil {
		value := *req.GroupID
		groupID = &value
	}
	return Event{
		RequestID: req.RequestID, UserID: req.UserID, APIKeyID: req.APIKeyID, GroupID: groupID,
		Provider: req.Provider, Endpoint: req.Endpoint, Protocol: req.Protocol, Model: req.Model,
		PromptHash: promptHash, CreatedAt: e.clock.Now(),
	}
}

func (e *Engine) writeEvent(event Event) {
	if e.events == nil {
		return
	}
	// 事件写入绝不能影响请求结果：Write 自身是非阻塞的，这里再兜一层 panic。
	defer func() { _ = recover() }()
	e.events.Write(event)
}

func (e *Engine) countGateHit(gate string) {
	switch gate {
	case GateBan:
		e.counters.banHits.Add(1)
	case GateDistill:
		e.counters.distill.Add(1)
	case GateRegex:
		e.counters.regex.Add(1)
	case GateRefusalCache:
		e.counters.refusal.Add(1)
	case GateDecisionModel:
		e.counters.decision.Add(1)
	}
}

func (e *Engine) recordError(err error) {
	if e == nil || err == nil {
		return
	}
	message := err.Error()
	e.lastErr.Store(&message)
}

// LastError 返回最近一次内部错误（status 展示）。
func (e *Engine) LastError() string {
	if e == nil {
		return ""
	}
	if value := e.lastErr.Load(); value != nil {
		return *value
	}
	return ""
}

// Counters 返回当前计数快照。
func (e *Engine) Counters() GateCounters {
	if e == nil {
		return GateCounters{}
	}
	return GateCounters{
		Evaluated: e.counters.evaluated.Load(), Allowed: e.counters.allowed.Load(),
		Blocked: e.counters.blocked.Load(), WouldBlock: e.counters.wouldBlock.Load(),
		Banned: e.counters.banned.Load(), BanHits: e.counters.banHits.Load(),
		Distill: e.counters.distill.Load(), Regex: e.counters.regex.Load(),
		RefusalCache:  e.counters.refusal.Load(),
		DecisionModel: e.counters.decision.Load(), ClassifierErrors: e.counters.classifier.Load(),
	}
}

func (e *Engine) observeRule(req securityaudit.Request, view TextView, hit GateResult) {
	event := e.baseEvent(req, view.NormalizedHash)
	event.Kind = EventKindBlocked
	event.Gate = hit.Gate
	event.RuleID = hit.RuleID
	event.RuleKey = hit.RuleKey
	event.Pattern = hit.Pattern
	event.Category = hit.Category
	event.Reason = hit.Reason
	event.Evidence = hit.Evidence
	event.Action = EventActionWouldBlock
	event.UserPreview = redactEvidence(view.LatestUser, 2048)
	event.ClientFingerprint = inboundFingerprint(req)
	e.writeEvent(event)
}
func isOpenAI(provider, model string) bool {
	return strings.EqualFold(provider, "openai") || strings.EqualFold(provider, "gpt") || strings.HasPrefix(strings.ToLower(model), "gpt") || strings.HasPrefix(strings.ToLower(model), "codex")
}
func (c Config) hasAccountScope() bool {
	return len(c.Scope.AccountIDs) > 0 || len(c.Scope.AccountPlatformPlans) > 0
}

// DecideSelected is invoked only after a real upstream account is chosen and
// before its request is dispatched. Non-account-scoped configurations are not
// evaluated twice, and the normal audit coordinator is not run a second time.
func (e *Engine) DecideSelected(ctx context.Context, req securityaudit.Request) *securityaudit.Decision {
	if e == nil {
		return nil
	}
	cfg, _, ok := e.config.Current()
	if !ok || cfg.EffectiveMode() == ModeOff || !cfg.hasAccountScope() {
		return nil
	}
	return e.Decide(ctx, req)
}
