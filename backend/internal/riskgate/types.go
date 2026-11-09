// Package riskgate 实现「风险闸门」：在账号选择、计费与任何上游调用之前，
// 用一串由便宜到贵的闸门拦下试图薅上游模型的请求（蒸馏/破限/重放已被上游
// 拒答的正文），并可按身份封禁。
//
// 该模块与内容审核、提示词审计并列且相互独立：默认 mode=off，关闭时每个请求
// 只做一次原子读，不查库、不查 Redis、不发 HTTP、不写任何表。
package riskgate

import (
	"time"
)

// Mode 是风险闸门的运行模式。
type Mode string

const (
	// ModeOff 完全关闭：零行为，不查库、不查 Redis、不发 HTTP、不写事件。
	ModeOff Mode = "off"
	// ModeObserve 只记录不拦截：命中写 kind=blocked、action=would_block 事件。
	ModeObserve Mode = "observe"
	// ModeBlocking 命中即拦截。
	ModeBlocking Mode = "blocking"
)

// Gate 名称。顺序即执行顺序（前一道命中即短路）。
const (
	GateBan           = "ban"
	GateDistill       = "distill"
	GateRegex         = "regex"
	GateRefusalCache  = "refusal_cache"
	GateDecisionModel = "decision_model"
)

// 事件 kind / action 取值，与 risk_gate_events 注释保持一致。
const (
	EventKindBlocked         = "blocked"
	EventKindAllowed         = "allowed"
	EventKindObservation     = "observation"
	EventKindUpstreamPass    = "upstream_pass"
	EventKindUpstreamRefusal = "upstream_refusal"

	EventActionNone       = "none"
	EventActionBanned     = "banned"
	EventActionWouldBlock = "would_block"
	EventActionObserve    = "observe"
)

// 封禁作用域。client_fingerprint 默认只记录不封禁。
const (
	BanScopeAPIKey            = "api_key"
	BanScopeUser              = "user"
	BanScopeClientFingerprint = "client_fingerprint"
)

// 内置正则类别。
const (
	CategoryDistill   = "distill"
	CategorySexual    = "sexual"
	CategoryJailbreak = "jailbreak"
	CategoryBypass    = "bypass"
	CategoryCustom    = "custom"
)

// 错误码与提示文案。
const (
	// ErrorCodeBlocked 蒸馏/硬正则/决策模型命中。
	ErrorCodeBlocked = "risk_gate_blocked"
	// ErrorCodeBanned 身份封禁命中。
	ErrorCodeBanned = "risk_gate_banned"
	// ErrorCodeUnavailable 决策模型不可用且 fail-closed（P4 阶段使用）。
	ErrorCodeUnavailable = "risk_gate_unavailable"
	// ErrorCodePolicyBlocked 拒答缓存闸门命中（HTTP 400）：不可重试，也不是鉴权失败。
	ErrorCodePolicyBlocked = "policy_blocked"

	// ErrorCodeConfigConflict 配置版本冲突（HTTP 409）。
	ErrorCodeConfigConflict = "risk_gate_config_conflict"
	// ErrorCodeConfigUnavailable 配置尚不可用。
	ErrorCodeConfigUnavailable = "risk_gate_config_unavailable"
	// ErrorCodeInvalidConfig 配置校验失败（HTTP 400）。
	ErrorCodeInvalidConfig = "risk_gate_invalid_config"
	// ErrorCodeInvalidRule 自定义规则校验失败（HTTP 400）。
	ErrorCodeInvalidRule = "risk_gate_invalid_rule"
	// ErrorCodeInvalidBan 封禁参数校验失败（HTTP 400）。
	ErrorCodeInvalidBan = "risk_gate_invalid_ban"
	// ErrorCodeFilterRequired 批量删除必须至少提供一个过滤条件（HTTP 400）。
	ErrorCodeFilterRequired = "risk_gate_filter_required"
	// ConfigInvalidationChannel 是多实例配置失效广播频道。
	ConfigInvalidationChannel = "sub2api:risk_gate:config:invalidate"
	// banCacheKeyPrefix 是封禁的 Redis 缓存前缀。
	banCacheKeyPrefix = "sub2api:risk_gate:ban:"
)

// BanHint 是封禁命中时回给客户端的解除方式提示。
const BanHint = "如需解除请联系管理员，或在管理后台 /admin/risk-gate 解封"

// Clock 抽象时间，便于单测控制封禁过期与本地缓存 TTL。
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ClockFunc 让测试可以直接注入函数式时钟。
type ClockFunc func() time.Time

func (fn ClockFunc) Now() time.Time {
	if fn == nil {
		return time.Now()
	}
	return fn()
}

// Config 是 risk_gate_config.config 的 JSONB 结构，也是 API 的读写结构。
type Config struct {
	SchemaVersion int                 `json:"schema_version"`
	Mode          string              `json:"mode"`
	Gates         GateToggles         `json:"gates"`
	Distill       DistillConfig       `json:"distill"`
	Regex         RegexConfig         `json:"regex"`
	RefusalCache  RefusalCacheConfig  `json:"refusal_cache"`
	DecisionModel DecisionModelConfig `json:"decision_model"`
	Ban           BanConfig           `json:"ban"`
	Scope         ScopeConfig         `json:"scope"`
	RetentionDays int                 `json:"retention_days"`
}

// GateToggles 逐闸开关。ban 闸不可关闭（封禁始终有效），其余四道可独立开关。
type GateToggles struct {
	Distill       bool `json:"distill"`
	Regex         bool `json:"regex"`
	RefusalCache  bool `json:"refusal_cache"`
	DecisionModel bool `json:"decision_model"`
}

// DistillConfig 是蒸馏/赛题指纹闸门的配置。
type DistillConfig struct {
	// HardNeedles 收割包装词，始终扫描，不受 skip_official/skip_zero 影响。
	HardNeedles []string `json:"hard_needles"`
	// Needles 普通针，按 skip 开关跳过官方客户端/零注入请求。
	Needles []string `json:"needles"`
	// Fingerprints 题目指纹（区分大小写的原文匹配前会统一小写）。
	Fingerprints []string `json:"fingerprints"`
	Patterns     []string `json:"patterns"`
	// SkipOfficial 是否跳过官方 Claude Code 客户端。
	SkipOfficial bool `json:"skip_official"`
	// SkipZero 是否跳过零注入（无 system 正文）的请求。
	SkipZero bool `json:"skip_zero"`
	// MinMaxTokens 是结构收割闸的下限：max_tokens 与思考预算都必须 >= 该值。
	MinMaxTokens int `json:"min_max_tokens"`
	// ContestPattern 是赛题正文特征。为空表示结构收割闸不启用。
	ContestPattern    string              `json:"contest_pattern"`
	RequireNoTools    bool                `json:"require_no_tools"`
	RequireSingleTurn bool                `json:"require_single_turn"`
	Error             ResponseErrorConfig `json:"error"`
}

type ResponseErrorConfig struct {
	Status  int    `json:"status"`
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// RegexConfig 是硬正则闸门的配置。
type RegexConfig struct {
	// Categories 启用的内置类别（sexual/distill/jailbreak/bypass）。
	Categories []string `json:"categories"`
	// CustomRules 是否加载 risk_gate_rules 中 gate=regex 的自定义规则。
	CustomRules bool `json:"custom_rules"`
	// MaxInputBytes 单次扫描的最大字节数，超出部分截断（默认 1 MiB）。
	MaxInputBytes int `json:"max_input_bytes"`
	// ExpandBase64 是否展开 base64 块后再扫描。
	ExpandBase64   bool     `json:"expand_base64"`
	StripReminders bool     `json:"strip_reminders"`
	Patterns       []string `json:"patterns"`
	// BlockMessage 可按类别给不同文案，未配置时用默认文案。
	BlockMessage string `json:"block_message"`
}

// RefusalCacheConfig 是拒答缓存闸门配置（P3 阶段才生效，本阶段保持惰性）。
type RefusalCacheConfig struct {
	Enabled             bool    `json:"enabled"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
	MinShingleRunes     int     `json:"min_shingle_runes"`
	SimilarityEnabled   bool    `json:"similarity_enabled"`
	DeviceBlockEnabled  bool    `json:"device_block_enabled"`
}

// ClassifierEndpoint 是决策模型端点（OpenAI 兼容 Chat Completions）。
type ClassifierEndpoint struct {
	KeyRevision int64  `json:"key_revision,omitempty"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	TimeoutMS   int    `json:"timeout_ms"`
	Enabled     bool   `json:"enabled"`
	// APIKey 只在写入请求里出现（明文），保存时立即加密为 APIKeyCiphertext；
	// 读取接口永不回传明文或密文，只回传 HasAPIKey。
	APIKey    string `json:"api_key,omitempty"`
	HasAPIKey bool   `json:"has_api_key,omitempty"`
	// APIKeyCiphertext 是落库字段（SecretEncryptor 加密），运行时解密成内存里的 APIKey。
	APIKeyCiphertext  string   `json:"api_key_ciphertext,omitempty"`
	APIKeys           []string `json:"api_keys,omitempty"`
	APIKeyCiphertexts []string `json:"api_key_ciphertexts,omitempty"`
	ClearAPIKeys      bool     `json:"clear_api_keys,omitempty"`
	APIKeyCount       int      `json:"api_key_count"`
	Provider          string   `json:"provider,omitempty"`
}

type PolicyQuestion struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Summary      string `json:"summary"`
	Instructions string `json:"instructions"`
	Enabled      bool   `json:"enabled"`
	Builtin      bool   `json:"builtin,omitempty"`
}

// DecisionModelConfig 是决策模型配置（第 5 道闸门）。
type DecisionModelConfig struct {
	Enabled           bool                 `json:"enabled"`
	Threshold         float64              `json:"threshold"`
	TimeoutMS         int                  `json:"timeout_ms"`
	MaxConcurrent     int                  `json:"max_concurrent"`
	OnUnavailable     string               `json:"on_unavailable"`
	Endpoints         []ClassifierEndpoint `json:"endpoints"`
	ScoringMode       string               `json:"scoring_mode,omitempty"`
	Provider          string               `json:"provider,omitempty"`
	SafetyThreshold   float64              `json:"safety_threshold"`
	BlockIfBelow      bool                 `json:"block_if_below"`
	DedupSec          int                  `json:"dedup_sec"`
	MaxStateChars     int                  `json:"max_state_chars"`
	SafetyInstruction string               `json:"safety_instruction,omitempty"`
	Questions         []PolicyQuestion     `json:"questions"`
	FailOpen          bool                 `json:"fail_open,omitempty"`
	CacheVersion      string               `json:"cache_version,omitempty"`
}

// BanConfig 是自动封禁配置。
type BanConfig struct {
	// Scope 是自动封禁作用域：api_key（默认）/ user / client_fingerprint。
	Scope string `json:"scope"`
	// OnDistill 蒸馏/指纹命中是否自动封禁。
	OnDistill bool `json:"on_distill"`
	// OnRegex 硬正则命中是否自动封禁。
	OnRegex bool `json:"on_regex"`
	// OnDecisionModel 决策模型命中是否自动封禁。默认 false：模型判定有误伤风险。
	OnDecisionModel bool `json:"on_decision_model"`
	// DurationHours 封禁时长（小时），0 表示永久。
	DurationHours int `json:"duration_hours"`
}

// ScopeConfig 是闸门生效范围。
type ScopeConfig struct {
	AllGroups             bool     `json:"all_groups"`
	GroupIDs              []int64  `json:"group_ids"`
	AllProviders          bool     `json:"all_providers"`
	Providers             []string `json:"providers"`
	OpenAIPlatformEnabled bool     `json:"openai_platform_enabled"`
	AccountPlatformPlans  []string `json:"account_platform_plans"`
	AccountIDs            []string `json:"account_ids"`
	ExemptAPIKeys         []string `json:"exempt_api_keys"`
	CoverageSupported     bool     `json:"coverage_supported"`
}

// Event 对应 risk_gate_events 的一行。evidence 只允许存放已脱敏片段。
type Event struct {
	RequestID         string
	UserID            int64
	APIKeyID          int64
	GroupID           *int64
	Provider          string
	Endpoint          string
	Protocol          string
	Model             string
	Kind              string
	Gate              string
	RuleID            int64
	Reason            string
	Score             float64
	PromptHash        string
	Evidence          string
	Action            string
	RuleKey           string
	Pattern           string
	ClientFingerprint string
	UserPreview       string
	SubmittedText     string
	Scores            map[string]float64
	TerminalOutcome   string
	Category          string
	CreatedAt         time.Time
}

// Rule 对应 risk_gate_rules 的一行。
// json tag 供管理端接口返回稳定的 snake_case 字段名。
type Rule struct {
	ID          int64  `json:"id"`
	Gate        string `json:"gate"`
	Category    string `json:"category"`
	Pattern     string `json:"pattern"`
	IsRegex     bool   `json:"is_regex"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	SortOrder   int    `json:"sort_order"`
	Description string `json:"description"`
	RuleKey     string `json:"rule_key,omitempty"`
	Builtin     bool   `json:"builtin,omitempty"`
}

// Ban 对应 risk_gate_bans 的一行。json tag 供管理端接口使用。
type Ban struct {
	ID        int64      `json:"id"`
	Scope     string     `json:"scope"`
	Subject   string     `json:"subject"`
	Reason    string     `json:"reason"`
	Gate      string     `json:"gate"`
	HitCount  int        `json:"hit_count"`
	BannedAt  time.Time  `json:"banned_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
}

// GateResult 是单次闸门判定的结果。Hit 为 false 时可忽略其余字段。
type GateResult struct {
	Hit        bool
	Gate       string
	Category   string
	Reason     string
	RuleID     int64
	Score      float64
	Evidence   string
	HTTPStatus int
	ErrorCode  string
	// BanSignal 表示该闸配置了自动封禁（真正是否封禁还取决于封禁作用域）。
	BanSignal     bool
	Action        string
	RuleKey       string
	Pattern       string
	Scores        map[string]float64
	SubmittedText string
}

// GateCounters 是进程内闸门计数，供 /risk-gate/status 展示。
type GateCounters struct {
	Evaluated  int64 `json:"evaluated"`
	Allowed    int64 `json:"allowed"`
	Blocked    int64 `json:"blocked"`
	WouldBlock int64 `json:"would_block"`
	Banned     int64 `json:"banned"`
	BanHits    int64 `json:"ban_hits"`
	Distill    int64 `json:"distill_hits"`
	Regex      int64 `json:"regex_hits"`
	// RefusalCache 是拒答缓存闸门命中次数。
	RefusalCache int64 `json:"refusal_cache_hits"`
	// DecisionModel 是决策模型闸门命中次数。
	DecisionModel int64 `json:"decision_model_hits"`
	// ClassifierErrors 是决策模型端点失败/不可用次数（每次尝试 +1）。
	ClassifierErrors int64 `json:"classifier_errors"`
}

// ConfigView 是 GET /risk-gate/config 的响应体。
type ConfigView struct {
	Config    Config     `json:"config"`
	Version   int64      `json:"version"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// UpdateConfigRequest 是 PUT /risk-gate/config 的请求体。
// Config 内嵌，因此 JSON 中配置字段与 expected_version 平级。
type UpdateConfigRequest struct {
	ExpectedVersion int64 `json:"expected_version"`
	Config
}

// StatusSnapshot 是 GET /risk-gate/status 的响应体。
type StatusSnapshot struct {
	Mode           Mode         `json:"mode"`
	ConfigVersion  int64        `json:"config_version"`
	EffectiveGates []string     `json:"effective_gates"`
	Counters       GateCounters `json:"counters"`
	BanCount       int64        `json:"ban_count"`
	RulesCount     int64        `json:"rules_count"`
	LastError      string       `json:"last_error,omitempty"`
	CheckedAt      time.Time    `json:"checked_at"`
}

// ProbeRequest 是 POST /risk-gate/classifier/probe 的请求体。
type ProbeRequest struct {
	// EndpointIndex 指向当前配置里的第 N 个端点（默认 0）；Endpoint 非空时直接用它探测（不落库）。
	EndpointIndex int                  `json:"endpoint_index"`
	Endpoint      *ClassifierEndpoint  `json:"endpoint"`
	Text          string               `json:"text"`
	DecisionModel *DecisionModelConfig `json:"decision_model,omitempty"`
}

// ProbeResult 是探测结果。探测失败不是接口失败，错误写在 Error 里。
type ProbeResult struct {
	OK         bool               `json:"ok"`
	Score      float64            `json:"score"`
	Category   string             `json:"category"`
	LatencyMS  int64              `json:"latency_ms"`
	EndpointID string             `json:"endpoint_id"`
	Error      string             `json:"error,omitempty"`
	Scores     map[string]float64 `json:"scores,omitempty"`
}
