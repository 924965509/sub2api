// 风险闸门（Risk Gate）前端类型定义。
// 字段名以后端真实 JSON 为准：除 Ban / RefusalRow 早期注释提到过 PascalCase 外，
// 后端 riskgate 包已统一补上 snake_case json tag，这里全部按 snake_case 解析。

export type RiskGateMode = "off" | "observe" | "blocking";
export type RiskGateView =
  "all" | "distill" | "hard-regex" | "refusal" | "jev" | "pass";
export type DecisionScoringMode = "risk" | "safety_questions";
export type DecisionProvider = "openai" | "jev" | "laya" | "modernbert";
export type RiskState = "on" | "off" | "unset" | "loading" | "observe";
// 四道可独立开关的闸门；ban（身份封禁）恒定生效，不在 gates 里。
export type RiskGateId =
  "distill" | "regex" | "refusal_cache" | "decision_model";
export type RuleGate = "regex" | "distill";
export type RuleCategory =
  "distill" | "sexual" | "jailbreak" | "bypass" | "custom" | "nsfw" | "crack";
export type RuleAction = "block" | "observe";
export type BanScope = "api_key" | "user" | "client_fingerprint";
export type OnUnavailable = "pass" | "fail_closed";
export type EventKind =
  "blocked" | "allowed" | "upstream_pass" | "upstream_refusal";
export type EventAction = "none" | "banned" | "would_block" | "";

export interface ClassifierEndpoint {
  id: string;
  name: string;
  base_url: string;
  model: string;
  timeout_ms: number;
  enabled: boolean;
  // 只在写入请求里出现的明文密钥；读取接口永不回传，只回传 has_api_key。
  api_key?: string;
  api_keys?: string[];
  has_api_key?: boolean;
  provider?: DecisionProvider;
  api_key_count?: number;
  clear_api_keys?: boolean;
}

export interface DistillConfig {
  hard_needles: string[] | null;
  needles: string[] | null;
  fingerprints: string[] | null;
  skip_official: boolean;
  skip_zero: boolean;
  min_max_tokens: number;
  contest_pattern: string;
  patterns?: string[] | null;
  require_no_tools?: boolean;
  require_single_turn?: boolean;
  error?: DistillErrorConfig;
}

export interface DistillErrorConfig {
  status: number;
  type: string;
  code: string;
  message: string;
}

export interface RegexConfig {
  categories: string[] | null;
  custom_rules: boolean;
  max_input_bytes: number;
  expand_base64: boolean;
  block_message: string;
  strip_reminders?: boolean;
  patterns?: string[] | null;
}

export interface RefusalCacheConfig {
  enabled: boolean;
  similarity_threshold: number;
  min_shingle_runes: number;
  similarity_enabled?: boolean;
  device_block_enabled?: boolean;
}

export interface DecisionModelConfig {
  enabled: boolean;
  threshold: number;
  timeout_ms: number;
  max_concurrent: number;
  on_unavailable: OnUnavailable;
  endpoints: ClassifierEndpoint[];
  scoring_mode?: DecisionScoringMode;
  provider?: DecisionProvider;
  safety_threshold?: number;
  block_if_below?: boolean;
  dedup_sec?: number;
  max_state_chars?: number;
  safety_instruction?: string;
  questions?: PolicyQuestion[];
}

export interface PolicyQuestion {
  id: string;
  label: string;
  summary: string;
  instructions: string;
  enabled: boolean;
  builtin?: boolean;
}

export interface GateToggles {
  distill: boolean;
  regex: boolean;
  refusal_cache: boolean;
  decision_model: boolean;
}

export interface BanConfig {
  scope: BanScope;
  on_distill: boolean;
  on_regex: boolean;
  on_decision_model: boolean;
  duration_hours: number;
}

export interface ScopeConfig {
  all_groups: boolean;
  group_ids: number[] | null;
  all_providers: boolean;
  providers: string[] | null;
  openai_platform_enabled?: boolean;
  account_platform_plans?: string[] | null;
  account_ids?: string[] | null;
}

export interface RiskGateConfig {
  schema_version?: number;
  mode: RiskGateMode;
  gates: GateToggles;
  distill: DistillConfig;
  regex: RegexConfig;
  refusal_cache: RefusalCacheConfig;
  decision_model: DecisionModelConfig;
  ban: BanConfig;
  scope: ScopeConfig;
  retention_days: number;
}

// GET / PUT /config 的响应体；PUT 请求体是 { expected_version, ...RiskGateConfig }。
export interface ConfigView {
  config: RiskGateConfig;
  version: number;
  updated_at?: string;
}

export interface UpdateConfigRequest extends RiskGateConfig {
  expected_version: number;
}

export interface GateCounters {
  evaluated: number;
  allowed: number;
  blocked: number;
  would_block: number;
  banned: number;
  ban_hits: number;
  distill_hits: number;
  regex_hits: number;
  refusal_cache_hits: number;
  decision_model_hits: number;
  classifier_errors: number;
}

export interface StatusSnapshot {
  mode: RiskGateMode;
  config_version: number;
  effective_gates: string[] | null;
  counters: GateCounters;
  ban_count: number;
  rules_count: number;
  last_error?: string;
  checked_at: string;
  effective_state?: Partial<Record<RiskGateId, RiskState>>;
  window_counts?: Partial<Record<RiskGateView | RiskGateId, number | null>>;
}

export interface ProbeResult {
  ok: boolean;
  score: number;
  category: string;
  latency_ms: number;
  endpoint_id: string;
  error?: string;
  scores?: Record<string, number>;
}

export interface ProbeRequest {
  endpoint_index?: number;
  endpoint?: ClassifierEndpoint;
  text?: string;
  decision_model?: DecisionModelConfig;
}

export interface Rule {
  id?: number;
  gate: RuleGate;
  category: RuleCategory;
  pattern: string;
  is_regex: boolean;
  action: RuleAction;
  enabled: boolean;
  sort_order: number;
  description: string;
  rule_key?: string;
  builtin?: boolean;
}

export interface RuleSetView {
  version: number;
  rules: Rule[];
  builtin_rules: Rule[];
  customized: boolean;
}

export interface RuleValidationResult {
  valid: boolean;
  errors: Array<{ index: number; message: string }>;
  matches: Array<{ index: number; rule_id?: number; matched_text: string }>;
}

export interface ScopeAccount {
  id: string;
  name: string;
  email?: string;
  platform: string;
  account_type?: string;
  base_url?: string;
  plan_type: string;
  scope_key: string;
  schedulable: boolean;
}

export interface ScopeOption {
  id: string;
  label: string;
  count: number;
}

export interface ScopeInventory {
  accounts_total: number;
  accounts: ScopeAccount[];
  account_platform_plan_options: ScopeOption[];
}

export interface GateHitRow {
  gate: string;
  rule_id?: number;
  rule_key?: string;
  category: string;
  keyword: string;
  pattern: string;
  count: number;
  action?: EventAction | string;
}

export interface PassReasonRow {
  reason: string;
  count: number;
}

export interface RiskStats {
  since: string;
  until?: string;
  timezone?: string;
  total: number | null;
  blocked: number | null;
  passed: number | null;
  would_block: number | null;
  blocks: GateHitRow[];
  passes: PassReasonRow[];
  coverage_start?: string;
  storage_errors?: number;
}

export interface ClassifierUsageRow {
  id: string | number;
  created_at: string;
  request_id?: string;
  model?: string;
  key_fingerprint?: string;
  http_status?: number | null;
  outcome?: string;
  duration_ms?: number | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  estimated_cost_nano_usd?: number | null;
}

export interface ClassifierUsageSummary {
  requests: number;
  successful: number;
  input_tokens: number;
  output_tokens: number;
  unknown_usage_requests: number;
  estimated_cost_nano_usd: number | null;
  unknown_cost_requests: number;
}

export interface ClassifierUsagePage {
  items: ClassifierUsageRow[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  summary: ClassifierUsageSummary;
  today: ClassifierUsageSummary;
  started_at: string | null;
  storage_errors_since_start: number;
}

export interface Ban {
  id: number;
  scope: string;
  subject: string;
  reason: string;
  gate: string;
  hit_count: number;
  banned_at: string;
  expires_at: string | null;
  created_by: string;
}

export interface EventRow {
  id: number;
  request_id: string;
  user_id: number;
  api_key_id: number;
  group_id?: number | null;
  provider: string;
  endpoint: string;
  protocol: string;
  model: string;
  kind: EventKind;
  gate: string;
  rule_id: number;
  reason: string;
  score: number;
  prompt_hash: string;
  evidence: string;
  action: EventAction;
  created_at: string;
  user_name?: string;
  user_email?: string;
  api_key_name?: string;
  rule_key?: string;
  category?: string;
  pattern?: string;
  client_fingerprint?: string;
  user_preview?: string;
  submitted_text?: string;
  scores?: Record<string, number>;
  terminal_outcome?: string;
  upstream_code?: string;
  upstream_status?: number;
  source_request_id?: string;
}

export interface RefusalRow {
  id: number;
  provider: string;
  model: string;
  prompt_hash: string;
  normalized_prompt: string;
  source: string;
  created_at: string;
  hit_count?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  source_request_id?: string;
  error_message?: string;
  client_fingerprint?: string;
}

// 分页响应体：{ items, total, page, page_size, pages }
export interface PageResult<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// 事件过滤条件：全部存字符串（前端输入框原样），出参由 viewModel 归一化。
export interface EventFilter {
  kind: string;
  gate: string;
  provider: string;
  request_id: string;
  prompt_hash: string;
  user_id: string;
  api_key_id: string;
  group_id: string;
  from: string;
  to: string;
  reason?: string;
  action?: string;
  rule_id?: string;
  view?: RiskGateView;
}

export interface BanFilter {
  scope: string;
  subject: string;
  active_only: boolean;
}

export interface RefusalFilter {
  provider: string;
  source: string;
  prompt_hash: string;
}

export interface CreateBanRequest {
  scope: BanScope;
  subject: string;
  reason: string;
  duration_hours: number;
  gate: string;
}

// 保存失败 / 加载失败的集中错误位。
export interface RiskGateLoadErrors {
  config: string;
  status: string;
  rules: string;
  bans: string;
  events: string;
  refusals: string;
  stats?: string;
  scope?: string;
  usage?: string;
}
