package riskgate

import (
	"container/list"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// 决策模型闸门（第 5 道）常量。
const (
	// decisionModelCategory 是模型没给出标签时的兜底类别。
	decisionModelCategory = "decision_model"
	// decisionReasonScore 是「分数达到阈值」的命中原因。
	decisionReasonScore = "decision_score"
	// decisionUnavailable 是「端点全部不可用」的原因（fail_closed 命中 / 放行观察事件共用）。
	decisionUnavailable = "classifier_unavailable"
	// decisionHTTPStatus 是决策模型命中时的 HTTP 状态码。
	decisionHTTPStatus = 403
	// decisionUnavailableHTTPStatus 是 fail_closed 时的 HTTP 状态码。
	decisionUnavailableHTTPStatus = 503

	// decisionCacheTTL 是「prompt_hash → 分数」缓存的存活时间。
	decisionCacheTTL = 10 * time.Minute
	// decisionCacheMaxEntries 是缓存条目上限，超出按 LRU 淘汰。
	decisionCacheMaxEntries = 10000
)

// evaluateDecision 执行决策模型闸门；返回命中结果与「因不可用而放行」标记。
//
// 语义要点（design §3 第 5 道）：
//   - 只看最新一条 user 正文（view.LatestUser），空白正文直接不命中；
//   - 端点按配置顺序尝试，跳过未启用的端点，单个端点用自己的 timeout_ms；
//   - 分数 >= threshold 即命中；未达阈值不命中；
//   - 全部端点失败时按 on_unavailable 决定：fail_closed 返回 503 + risk_gate_unavailable，
//     pass 返回零值 + unavailable=true（调用方写观察事件后放行）。
func evaluateDecision(ctx context.Context, cfg Config, view TextView, classifier Classifier) (GateResult, bool) {
	outcome := evaluateDecisionOutcome(ctx, cfg, view, classifier)
	return outcome.Hit, outcome.Unavailable
}

// decisionOutcome 汇总一次决策模型判定，供引擎写缓存与计数。
type decisionOutcome struct {
	// Hit 是命中结果（未命中时为零值）。
	Hit GateResult
	// Unavailable 表示端点不可用且按 pass 放行（调用方写观察事件）。
	Unavailable bool
	// Failures 是失败的端点尝试次数。
	Failures int
	// Scored 表示拿到了可用分数（可用于缓存）。
	Scored   bool
	Score    float64
	Category string
}

// evaluateDecisionOutcome 执行决策模型闸门并返回完整的判定上下文。
func evaluateDecisionOutcome(ctx context.Context, cfg Config, view TextView, classifier Classifier) decisionOutcome {
	text := strings.TrimSpace(view.LatestUser)
	if text == "" {
		// 没有 user 正文（例如只有工具回传）时不发任何请求。
		return decisionOutcome{}
	}
	if cfg.SchemaVersion >= 2 && cfg.DecisionModel.ScoringMode == "safety_questions" {
		document := modelUserDocument(view.UserTurns, view.UserLabels, cfg.DecisionModel.MaxStateChars, cfg.Regex.StripReminders)
		if document == "" {
			document = truncateRunes(view.LatestUser, cfg.DecisionModel.MaxStateChars)
		}
		scorer, ok := classifier.(QuestionClassifier)
		if !ok {
			hit, unavailable := unavailableDecision(cfg)
			return decisionOutcome{Hit: hit, Unavailable: unavailable}
		}
		failures := 0
		for _, endpoint := range usableClassifierEndpoints(cfg.DecisionModel.Endpoints) {
			if endpoint.Provider == "" {
				endpoint.Provider = cfg.DecisionModel.Provider
			}
			callCtx, cancel := context.WithTimeout(ctx, time.Duration(classifierTimeoutMS(endpoint))*time.Millisecond)
			scores, err := scorer.ScoreQuestions(callCtx, endpoint, document, cfg.DecisionModel)
			cancel()
			if err != nil {
				failures++
				continue
			}
			hit := safetyDecision(cfg, document, scores)
			encoded, _ := json.Marshal(scores)
			return decisionOutcome{Hit: hit, Failures: failures, Scored: true, Score: hit.Score, Category: string(encoded)}
		}
		hit, unavailable := unavailableDecision(cfg)
		return decisionOutcome{Hit: hit, Unavailable: unavailable, Failures: failures}
	}
	endpoints := usableClassifierEndpoints(cfg.DecisionModel.Endpoints)
	if classifier == nil || len(endpoints) == 0 {
		// 未配置可用端点：不发 HTTP，按「不可用」处理。
		hit, unavailable := unavailableDecision(cfg)
		return decisionOutcome{Hit: hit, Unavailable: unavailable}
	}
	failures := 0
	for _, endpoint := range endpoints {
		score, category, err := scoreWithClassifier(ctx, cfg, endpoint, text, classifier)
		if err != nil {
			// 单个端点失败只记一次失败并换下一个端点，绝不因为模型故障误伤用户。
			failures++
			continue
		}
		return decisionOutcome{
			Hit:      decisionHitFromScore(cfg, view.LatestUser, score, category),
			Failures: failures, Scored: true, Score: score, Category: category,
		}
	}
	hit, unavailable := unavailableDecision(cfg)
	return decisionOutcome{Hit: hit, Unavailable: unavailable, Failures: failures}
}

// decisionHitFromScore 把分数映射成命中结果：达到阈值即命中，否则零值。
func decisionHitFromScore(cfg Config, userText string, score float64, category string) GateResult {
	if score < cfg.DecisionModel.Threshold {
		return GateResult{}
	}
	if category = strings.TrimSpace(category); category == "" {
		category = decisionModelCategory
	}
	return GateResult{
		Hit: true, Gate: GateDecisionModel, Category: category,
		Reason: decisionReasonScore, Score: score,
		HTTPStatus: decisionHTTPStatus, ErrorCode: ErrorCodeBlocked,
		Evidence:  redactEvidence(userText, evidenceMaxRunes),
		BanSignal: cfg.Ban.OnDecisionModel,
	}
}

// unavailableDecision 处理「没有可用端点 / 全部失败」：fail_closed 命中 503，pass 放行。
func unavailableDecision(cfg Config) (GateResult, bool) {
	if !strings.EqualFold(strings.TrimSpace(cfg.DecisionModel.OnUnavailable), onUnavailableFailClosed) {
		return GateResult{}, true
	}
	return GateResult{
		Hit: true, Gate: GateDecisionModel, Category: decisionModelCategory,
		Reason: decisionUnavailable, HTTPStatus: decisionUnavailableHTTPStatus,
		ErrorCode: ErrorCodeUnavailable,
	}, false
}

// usableClassifierEndpoints 过滤出真正可用的端点：已启用且地址与模型都已配置。
func usableClassifierEndpoints(endpoints []ClassifierEndpoint) []ClassifierEndpoint {
	usable := make([]ClassifierEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		if strings.TrimSpace(endpoint.BaseURL) == "" || (strings.TrimSpace(endpoint.Model) == "" && endpoint.Provider != "laya") {
			continue
		}
		usable = append(usable, endpoint)
	}
	return usable
}

// scoreWithClassifier 用端点的 timeout_ms（为 0 时用整段配置的超时）调用一次分类器。
func scoreWithClassifier(ctx context.Context, cfg Config, endpoint ClassifierEndpoint, text string, classifier Classifier) (float64, string, error) {
	timeoutMS := endpoint.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = cfg.DecisionModel.TimeoutMS
	}
	if timeoutMS <= 0 {
		timeoutMS = DefaultDecisionTimeoutMS
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()
	return classifier.Score(callCtx, endpoint, text)
}

// decisionCacheEntry 是缓存里的一条记录。
type decisionCacheEntry struct {
	hash      string
	score     float64
	category  string
	expiresAt time.Time
}

// decisionCache 是 prompt_hash → (分数, 标签) 的进程内 LRU + TTL 缓存。
//
// 目的：同一段正文反复重放时不再重复打模型端点（10 分钟内、上限 1 万条）。
type decisionCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	order      *list.List
	entries    map[string]*list.Element
}

// newDecisionCache 构造缓存；now 为 nil 时用 time.Now。
func newDecisionCache(ttl time.Duration, maxEntries int, now func() time.Time) *decisionCache {
	if ttl <= 0 {
		ttl = decisionCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = decisionCacheMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &decisionCache{
		ttl: ttl, maxEntries: maxEntries, now: now,
		order: list.New(), entries: make(map[string]*list.Element, 64),
	}
}

// get 读取缓存；过期条目会被就地删除。
func (c *decisionCache) get(hash string) (float64, string, bool) {
	if c == nil || hash == "" {
		return 0, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[hash]
	if !ok {
		return 0, "", false
	}
	entry, valid := element.Value.(*decisionCacheEntry)
	if !valid {
		c.order.Remove(element)
		delete(c.entries, hash)
		return 0, "", false
	}
	if !entry.expiresAt.After(c.now()) {
		c.order.Remove(element)
		delete(c.entries, hash)
		return 0, "", false
	}
	c.order.MoveToFront(element)
	return entry.score, entry.category, true
}

// put 写入缓存；超出上限时淘汰最久未使用的条目。
func (c *decisionCache) put(hash string, score float64, category string) {
	if c != nil {
		c.putTTL(hash, score, category, c.ttl)
	}
}
func (c *decisionCache) putTTL(hash string, score float64, category string, ttl time.Duration) {
	if c == nil || hash == "" {
		return
	}
	expiresAt := c.now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[hash]; ok {
		if entry, valid := element.Value.(*decisionCacheEntry); valid {
			entry.score, entry.category, entry.expiresAt = score, category, expiresAt
		}
		c.order.MoveToFront(element)
		return
	}
	c.entries[hash] = c.order.PushFront(&decisionCacheEntry{
		hash: hash, score: score, category: category, expiresAt: expiresAt,
	})
	for len(c.entries) > c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		if entry, valid := oldest.Value.(*decisionCacheEntry); valid {
			delete(c.entries, entry.hash)
		}
	}
}

// len 返回当前条目数（测试用）。
func (c *decisionCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
