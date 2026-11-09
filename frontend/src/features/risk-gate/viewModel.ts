import type {
  Ban,
  ClassifierEndpoint,
  ConfigView,
  DecisionModelConfig,
  EventFilter,
  EventRow,
  GateCounters,
  ProbeResult,
  RiskGateConfig,
  RiskGateMode,
  Rule,
  StatusSnapshot,
  RiskGateView,
  ScopeAccount,
  ScopeConfig,
  UpdateConfigRequest,
} from "./types";

// 视图层需要的文案 key 全部集中在 viewModel 里，组件只负责 t(key)。
// 动态拼接的 key（如 admin.riskGate.mode.${mode}）不被 i18n 完整性扫描覆盖，
// 因此这里的 key 必须与 locales/en|zh/admin/riskGate.ts 手工保持一致。

const MODE_META: Record<
  RiskGateMode,
  { labelKey: string; tone: "muted" | "warn" | "danger" }
> = {
  off: { labelKey: "admin.riskGate.mode.off", tone: "muted" },
  observe: { labelKey: "admin.riskGate.mode.observe", tone: "warn" },
  blocking: { labelKey: "admin.riskGate.mode.blocking", tone: "danger" },
};

// modeMeta 把三态模式映射成徽标文案与颜色；未知值退回 off，避免页面炸掉。
export function modeMeta(mode: string | null | undefined): {
  labelKey: string;
  tone: "muted" | "warn" | "danger";
} {
  if (mode === "observe" || mode === "blocking") return MODE_META[mode];
  return MODE_META.off;
}

export const GATE_ORDER = [
  "ban",
  "distill",
  "regex",
  "refusal_cache",
  "decision_model",
] as const;
export type GateKey = (typeof GATE_ORDER)[number];

export interface GateSummaryItem {
  id: GateKey;
  labelKey: string;
  enabled: boolean;
  // ban 闸恒定生效，不允许关闭，UI 上单独标注。
  always: boolean;
}

// gateSummary 返回每道闸门的开关状态；ban 恒为 true 且标记 always。
export function gateSummary(
  config: RiskGateConfig | null | undefined,
): GateSummaryItem[] {
  const gates = config?.gates;
  return GATE_ORDER.map((id) => ({
    id,
    labelKey: `admin.riskGate.gates.${id}`,
    enabled: id === "ban" ? true : Boolean(gates?.[id]),
    always: id === "ban",
  }));
}

export interface StatusCard {
  key: string;
  labelKey: string;
  value: string | number;
  tone: "neutral" | "warn" | "danger";
}

// statusCards 把运行态快照压成卡片数据：模式、生效闸门、计数、封禁数、规则数、最后错误。
export function statusCards(
  status: StatusSnapshot | null | undefined,
): StatusCard[] {
  if (!status) return [];
  const gates = (status.effective_gates ?? []).join(", ");
  const counters = status.counters ?? ({} as GateCounters);
  return [
    {
      key: "mode",
      labelKey: "admin.riskGate.runtime.mode",
      value: modeMeta(status.mode).labelKey,
      tone: "neutral",
    },
    {
      key: "gates",
      labelKey: "admin.riskGate.runtime.effectiveGates",
      value: gates || "admin.riskGate.runtime.none",
      tone: "neutral",
    },
    {
      key: "evaluated",
      labelKey: "admin.riskGate.runtime.evaluated",
      value: counters.evaluated ?? 0,
      tone: "neutral",
    },
    {
      key: "blocked",
      labelKey: "admin.riskGate.runtime.blocked",
      value: counters.blocked ?? 0,
      tone: (counters.blocked ?? 0) > 0 ? "danger" : "neutral",
    },
    {
      key: "would_block",
      labelKey: "admin.riskGate.runtime.wouldBlock",
      value: counters.would_block ?? 0,
      tone: (counters.would_block ?? 0) > 0 ? "warn" : "neutral",
    },
    {
      key: "ban_count",
      labelKey: "admin.riskGate.runtime.banCount",
      value: status.ban_count ?? 0,
      tone: "neutral",
    },
    {
      key: "rules_count",
      labelKey: "admin.riskGate.runtime.rulesCount",
      value: status.rules_count ?? 0,
      tone: "neutral",
    },
    {
      key: "config_version",
      labelKey: "admin.riskGate.runtime.configVersion",
      value: status.config_version ?? 0,
      tone: "neutral",
    },
    {
      key: "last_error",
      labelKey: "admin.riskGate.runtime.lastError",
      value: status.last_error || "admin.riskGate.runtime.noError",
      tone: status.last_error ? "danger" : "neutral",
    },
  ];
}

// counterLabels 给出计数明细表的顺序，组件据此渲染。
export const COUNTER_KEYS: Array<keyof GateCounters> = [
  "evaluated",
  "allowed",
  "blocked",
  "would_block",
  "banned",
  "ban_hits",
  "distill_hits",
  "regex_hits",
  "refusal_cache_hits",
  "decision_model_hits",
  "classifier_errors",
];

export function counterItems(
  status: StatusSnapshot | null | undefined,
): Array<{ key: string; labelKey: string; value: number }> {
  const counters = status?.counters;
  return COUNTER_KEYS.map((key) => ({
    key,
    labelKey: `admin.riskGate.counters.${key}`,
    value: counters?.[key] ?? 0,
  }));
}

// Vue props/refs 不能直接 structuredClone，这里统一走 JSON 深拷贝。
export function cloneData<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

// parseStringList 把多行/逗号分隔文本解析成字符串数组，忽略空行。
export function parseStringList(text: string | null | undefined): string[] {
  if (!text) return [];
  return text
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

// parseNumberList 解析正整数列表，非法项直接丢弃。
export function parseNumberList(text: string | null | undefined): number[] {
  return parseStringList(text)
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0);
}

// formatStringList 把数组还原成多行文本，供 textarea 编辑。
export function formatStringList(list: string[] | null | undefined): string {
  return (list ?? []).join("\n");
}

export function formatNumberList(list: number[] | null | undefined): string {
  return (list ?? []).join("\n");
}

// configToDraft 归一化后端返回的配置：null 集合变空数组，端点明文密钥恒为空。
export function configToDraft(config: RiskGateConfig): RiskGateConfig {
  const cloned = cloneData(config);
  return {
    ...cloned,
    gates: {
      ...cloned.gates,
      refusal_cache:
        (cloned.schema_version ?? 0) < 2
          ? Boolean(cloned.gates.refusal_cache || cloned.refusal_cache.enabled)
          : Boolean(cloned.gates.refusal_cache),
      decision_model:
        (cloned.schema_version ?? 0) < 2
          ? Boolean(
              cloned.gates.decision_model || cloned.decision_model.enabled,
            )
          : Boolean(cloned.gates.decision_model),
    },
    distill: {
      ...cloned.distill,
      hard_needles: cloned.distill?.hard_needles ?? [],
      needles: cloned.distill?.needles ?? [],
      fingerprints: cloned.distill?.fingerprints ?? [],
      patterns: cloned.distill?.patterns ?? [],
      require_no_tools: cloned.distill?.require_no_tools ?? false,
      require_single_turn: cloned.distill?.require_single_turn ?? false,
      error: cloned.distill?.error ?? {
        status: 403,
        type: "invalid_request_error",
        code: "risk_gate_blocked",
        message: "",
      },
    },
    regex: {
      ...cloned.regex,
      categories: cloned.regex?.categories ?? [],
      patterns: cloned.regex?.patterns ?? [],
      strip_reminders: cloned.regex?.strip_reminders ?? true,
    },
    refusal_cache: {
      ...cloned.refusal_cache,
      similarity_enabled: cloned.refusal_cache?.similarity_enabled ?? true,
      device_block_enabled: cloned.refusal_cache?.device_block_enabled ?? true,
    },
    decision_model: {
      ...cloned.decision_model,
      scoring_mode: cloned.decision_model?.scoring_mode ?? "risk",
      provider: cloned.decision_model?.provider ?? "openai",
      safety_threshold:
        cloned.decision_model?.safety_threshold ??
        cloned.decision_model?.threshold ??
        0.5,
      block_if_below: cloned.decision_model?.block_if_below ?? true,
      dedup_sec: cloned.decision_model?.dedup_sec ?? 60,
      max_state_chars: cloned.decision_model?.max_state_chars ?? 64000,
      safety_instruction: cloned.decision_model?.safety_instruction ?? "",
      questions: cloned.decision_model?.questions ?? defaultPolicyQuestions(),
      endpoints: (cloned.decision_model?.endpoints ?? []).map((endpoint) => ({
        ...endpoint,
        name: endpoint.name ?? "",
        timeout_ms:
          endpoint.timeout_ms ?? cloned.decision_model?.timeout_ms ?? 3000,
        api_key: "",
        api_keys: [],
        clear_api_keys: false,
        has_api_key: Boolean(endpoint.has_api_key),
        api_key_count: endpoint.api_key_count,
        provider: endpoint.provider,
      })),
    },
    ban: { ...cloned.ban },
    scope: {
      ...cloned.scope,
      group_ids: cloned.scope?.group_ids ?? [],
      providers: cloned.scope?.providers ?? [],
      openai_platform_enabled: cloned.scope?.openai_platform_enabled ?? true,
      account_platform_plans: cloned.scope?.account_platform_plans ?? [],
      account_ids: cloned.scope?.account_ids ?? [],
      exempt_api_keys: cloned.scope?.exempt_api_keys ?? [],
    },
  };
}

export function draftFromView(view: ConfigView): {
  draft: RiskGateConfig;
  version: number;
  updatedAt: string;
} {
  return {
    draft: configToDraft(view.config),
    version: view.version ?? 0,
    updatedAt: view.updated_at ?? "",
  };
}

// buildUpdateRequest 生成 PUT /config 的请求体：expected_version 与配置字段平级；
// 端点的 api_key 只在用户输入后出现，留空即表示不修改已保存密钥。
export function buildUpdateRequest(
  draft: RiskGateConfig,
  expectedVersion: number,
): UpdateConfigRequest {
  const cloned = cloneData(draft);
  return {
    expected_version: expectedVersion,
    mode: cloned.mode,
    gates: { ...cloned.gates },
    distill: {
      ...cloned.distill,
      hard_needles: cloned.distill.hard_needles ?? [],
      needles: cloned.distill.needles ?? [],
      fingerprints: cloned.distill.fingerprints ?? [],
      min_max_tokens: Number(cloned.distill.min_max_tokens),
      contest_pattern: String(cloned.distill.contest_pattern ?? ""),
      patterns: cloned.distill.patterns ?? [],
      require_no_tools: Boolean(cloned.distill.require_no_tools),
      require_single_turn: Boolean(cloned.distill.require_single_turn),
      error: cloned.distill.error,
    },
    regex: {
      ...cloned.regex,
      categories: cloned.regex.categories ?? [],
      max_input_bytes: Number(cloned.regex.max_input_bytes),
      block_message: String(cloned.regex.block_message ?? ""),
      strip_reminders: cloned.regex.strip_reminders ?? true,
      patterns: cloned.regex.patterns ?? [],
    },
    refusal_cache: {
      enabled: Boolean(cloned.gates.refusal_cache),
      similarity_threshold: Number(cloned.refusal_cache.similarity_threshold),
      min_shingle_runes: Number(cloned.refusal_cache.min_shingle_runes),
      similarity_enabled: cloned.refusal_cache.similarity_enabled ?? true,
      device_block_enabled: cloned.refusal_cache.device_block_enabled ?? true,
    },
    decision_model: {
      enabled: Boolean(cloned.gates.decision_model),
      threshold: Number(cloned.decision_model.threshold),
      timeout_ms: Number(cloned.decision_model.timeout_ms),
      max_concurrent: Number(cloned.decision_model.max_concurrent),
      on_unavailable: cloned.decision_model.on_unavailable,
      scoring_mode: cloned.decision_model.scoring_mode ?? "risk",
      provider: cloned.decision_model.provider ?? "openai",
      safety_threshold: Number(
        cloned.decision_model.safety_threshold ??
          cloned.decision_model.threshold,
      ),
      block_if_below: cloned.decision_model.block_if_below ?? true,
      dedup_sec: Number(cloned.decision_model.dedup_sec ?? 60),
      max_state_chars: Number(cloned.decision_model.max_state_chars ?? 64000),
      safety_instruction: String(
        cloned.decision_model.safety_instruction ?? "",
      ),
      questions: cloneData(
        cloned.decision_model.questions ?? defaultPolicyQuestions(),
      ),
      endpoints: (cloned.decision_model.endpoints ?? []).map((endpoint) => ({
        id: endpoint.id.trim(),
        name: endpoint.name.trim(),
        base_url: endpoint.base_url.trim(),
        model: endpoint.model.trim(),
        timeout_ms: Number(endpoint.timeout_ms),
        enabled: Boolean(endpoint.enabled),
        provider: endpoint.provider,
        clear_api_keys: Boolean(endpoint.clear_api_keys),
        api_keys: endpoint.api_keys?.map((key) => key.trim()).filter(Boolean),
        api_key: endpoint.api_key?.trim() ? endpoint.api_key.trim() : undefined,
        has_api_key: undefined,
      })),
    },
    ban: {
      scope: cloned.ban.scope,
      on_distill: cloned.ban.on_distill,
      on_regex: cloned.ban.on_regex,
      on_decision_model: cloned.ban.on_decision_model,
      duration_hours: Number(cloned.ban.duration_hours),
    },
    scope: {
      all_groups: cloned.scope.all_groups,
      group_ids: cloned.scope.all_groups
        ? []
        : [...(cloned.scope.group_ids ?? [])].sort((a, b) => a - b),
      all_providers: cloned.scope.all_providers,
      providers: cloned.scope.all_providers
        ? []
        : [...(cloned.scope.providers ?? [])],
      openai_platform_enabled: cloned.scope.openai_platform_enabled ?? true,
      account_platform_plans: [...(cloned.scope.account_platform_plans ?? [])],
      account_ids: [...(cloned.scope.account_ids ?? [])],
      exempt_api_keys: [...(cloned.scope.exempt_api_keys ?? [])],
    },
    schema_version: cloned.schema_version ?? 0,
    retention_days: Number(cloned.retention_days),
  };
}

export function draftFingerprint(
  draft: RiskGateConfig | null,
  version: number,
): string {
  if (!draft) return "";
  return JSON.stringify(buildUpdateRequest(draft, version));
}

// configBlockReason 在保存前把关：返回 i18n key 表示禁止保存及原因，返回 '' 表示可保存。
export function configBlockReason(
  draft: RiskGateConfig | null | undefined,
): string {
  if (!draft) return "";
  const model = draft.decision_model;
  if (
    model?.enabled &&
    !(model.endpoints ?? []).some((endpoint) => endpoint.enabled)
  ) {
    return "admin.riskGate.errors.decisionModelEndpointRequired";
  }
  if (draft.mode !== "off" && !Object.values(draft.gates ?? {}).some(Boolean)) {
    return "admin.riskGate.errors.gateRequired";
  }
  if (!draft.scope?.all_groups && (draft.scope?.group_ids ?? []).length === 0) {
    return "admin.riskGate.errors.groupRequired";
  }
  return "";
}

export const RULE_GATES: Rule["gate"][] = ["regex", "distill"];
export const RULE_CATEGORIES: Rule["category"][] = [
  "distill",
  "nsfw",
  "crack",
  "jailbreak",
  "custom",
  "sexual",
  "bypass",
];
export const RULE_ACTIONS: Rule["action"][] = ["block", "observe"];
export const MAX_PATTERN_BYTES = 2048;

export function utf8Bytes(value: string): number {
  if (typeof TextEncoder !== "undefined")
    return new TextEncoder().encode(value).length;
  return encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, "x").length;
}

// validateRuleDraft 返回错误 key 列表；空数组表示该行合法。
export function validateRuleDraft(rule: Rule): string[] {
  const errors: string[] = [];
  const pattern = rule.pattern.trim();
  if (!pattern) {
    errors.push("admin.riskGate.rules.errors.patternRequired");
  } else if (utf8Bytes(pattern) > MAX_PATTERN_BYTES) {
    errors.push("admin.riskGate.rules.errors.patternTooLong");
  } else if (rule.is_regex && !looksLikeInvalidGoRegexp(pattern)) {
    // Syntax is validated by the backend's Go regexp engine. The browser must
    // not use JavaScript RegExp here because RE2 accepts syntax JS rejects.
  } else if (rule.is_regex) {
    errors.push("admin.riskGate.rules.errors.regexInvalid");
  }
  if (!RULE_GATES.includes(rule.gate))
    errors.push("admin.riskGate.rules.errors.gateInvalid");
  if (!RULE_CATEGORIES.includes(rule.category))
    errors.push("admin.riskGate.rules.errors.categoryInvalid");
  if (!RULE_ACTIONS.includes(rule.action))
    errors.push("admin.riskGate.rules.errors.actionInvalid");
  return errors;
}

function looksLikeInvalidGoRegexp(pattern: string): boolean {
  let escaped = false;
  let parentheses = 0;
  let brackets = 0;
  for (const char of pattern) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "(") parentheses += 1;
    if (char === ")") parentheses -= 1;
    if (char === "[") brackets += 1;
    if (char === "]") brackets -= 1;
    if (parentheses < 0 || brackets < 0) return true;
  }
  return escaped || parentheses !== 0 || brackets !== 0;
}

export function defaultPolicyQuestions(): DecisionModelConfig["questions"] {
  return [
    {
      id: "usage_policy",
      label: "使用政策",
      summary: "违法协助、武器、诈骗与儿童保护",
      instructions:
        "Is this request safe to process under the usage policy? Ordinary legal and educational requests are true; assistance enabling serious harm is false.",
      enabled: true,
      builtin: true,
    },
    {
      id: "nsfw",
      label: "色情",
      summary: "不当色情与性剥削内容",
      instructions:
        "Is this request safe to process without generating prohibited sexual content or sexual content involving minors? A safe or non-sexual request is true; prohibited sexual content is false.",
      enabled: true,
      builtin: true,
    },
    {
      id: "abuse",
      label: "破限与攻击",
      summary: "恶意越狱、盗取与攻击",
      instructions:
        "Is this request safe to process without malicious safeguard bypass, credential or prompt theft, or harmful attacks? Ordinary programming and defensive explanations are true; malicious assistance is false.",
      enabled: true,
      builtin: true,
    },
  ];
}

export const RISK_VIEWS: RiskGateView[] = [
  "all",
  "distill",
  "hard-regex",
  "refusal",
  "jev",
  "pass",
];

export function isRiskGateView(value: unknown): value is RiskGateView {
  return (
    typeof value === "string" && RISK_VIEWS.includes(value as RiskGateView)
  );
}

export function scopeConfigured(
  scope:
    | Pick<ScopeConfig, "account_platform_plans" | "account_ids">
    | null
    | undefined,
): boolean {
  return Boolean(
    scope?.account_platform_plans?.length || scope?.account_ids?.length,
  );
}

export function extractBaseURLHost(raw?: string | null): string {
  const trimmed = (raw ?? "").trim().replace(/\/+$/, "");
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed);
    return parsed.host.toLowerCase();
  } catch {
    return trimmed.toLowerCase();
  }
}

export function accountInScope(
  scope: Pick<ScopeConfig, "account_platform_plans" | "account_ids">,
  account: ScopeAccount,
): boolean {
  if (!scopeConfigured(scope)) return true;
  const wanted = (scope.account_ids ?? [])
    .map((value) => value.trim().toLowerCase().replace(/\/+$/, ""))
    .filter(Boolean);
  const baseTrimmed = (account.base_url ?? "").trim().toLowerCase().replace(/\/+$/, "");
  const baseHost = extractBaseURLHost(account.base_url);
  const identity = [
    account.id,
    account.email,
    account.name,
    baseTrimmed,
    baseHost,
  ]
    .filter(Boolean)
    .map((value) => String(value).trim().toLowerCase());
  const selectedPlans = (scope.account_platform_plans ?? []).map((value) =>
    value.trim().toLowerCase(),
  );
  const isApiKey =
    account.account_type?.toLowerCase() === "apikey" ||
    account.plan_type?.toLowerCase() === "apikey";
  const platform = (account.platform ?? "").trim().toLowerCase();
  const planMatch =
    Boolean(
      account.scope_key &&
        selectedPlans.includes(account.scope_key.toLowerCase()),
    ) ||
    (isApiKey &&
      Boolean(
        platform &&
          (selectedPlans.includes(`${platform}:apikey`) ||
            selectedPlans.includes(`${platform}:unknown`)),
      ));
  return wanted.some((value) => identity.includes(value)) || planMatch;
}

export function scopeMatches(
  scope: Pick<ScopeConfig, "account_platform_plans" | "account_ids">,
  accounts: ScopeAccount[],
): ScopeAccount[] {
  return accounts.filter((account) => accountInScope(scope, account));
}

export function parseFingerprintList(text: string): string[] {
  return text
    .split(/\n\s*---\s*\n/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function formatFingerprintList(
  items: string[] | null | undefined,
): string {
  return (items ?? []).join("\n---\n");
}

export function share(
  part: number | null | undefined,
  whole: number | null | undefined,
): string {
  if (!whole || !part) return "0%";
  const percentage = (part / whole) * 100;
  return percentage < 0.1
    ? "<0.1%"
    : `${percentage < 10 ? percentage.toFixed(1) : Math.round(percentage)}%`;
}

export function riskEventViewQuery(
  view: RiskGateView,
): Pick<EventFilter, "view" | "gate"> {
  if (view === "all") return { view: "all", gate: "" };
  if (view === "pass") return { view: "pass", gate: "" };
  if (view === "hard-regex") return { view, gate: "regex" };
  if (view === "refusal") return { view, gate: "refusal_cache" };
  if (view === "jev") return { view, gate: "decision_model" };
  return { view, gate: "distill" };
}

export function createDefaultRule(sortOrder: number): Rule {
  return {
    gate: "regex",
    category: "custom",
    pattern: "",
    is_regex: false,
    action: "block",
    enabled: true,
    sort_order: sortOrder,
    description: "",
  };
}

export function createDefaultEndpoint(index: number): ClassifierEndpoint {
  return {
    id: `classifier-${Date.now()}-${index}`,
    name: `Classifier ${index}`,
    base_url: "http://127.0.0.1:8000/v1",
    model: "classifier",
    timeout_ms: 3000,
    enabled: true,
    api_key: "",
    has_api_key: false,
  };
}

// expiresAtFromHours 把封禁时长换算成过期时间；0 表示永久，返回 null。
export function expiresAtFromHours(
  hours: number,
  now: number = Date.now(),
): string | null {
  const value = Number(hours);
  if (!Number.isFinite(value) || value <= 0) return null;
  return new Date(now + value * 60 * 60 * 1000).toISOString();
}

// banDurationLabel 计算封禁剩余时长的文案 key + 参数，供模板 t(key, params) 使用。
export function banDurationLabel(
  ban: Pick<Ban, "expires_at">,
  now: number = Date.now(),
): { key: string; params: Record<string, number> } {
  if (!ban.expires_at)
    return { key: "admin.riskGate.bans.durationPermanent", params: {} };
  const expiresAt = new Date(ban.expires_at).getTime();
  if (Number.isNaN(expiresAt) || expiresAt <= now)
    return { key: "admin.riskGate.bans.durationExpired", params: {} };
  const hours = Math.ceil((expiresAt - now) / (60 * 60 * 1000));
  if (hours < 48)
    return { key: "admin.riskGate.bans.durationHours", params: { hours } };
  return {
    key: "admin.riskGate.bans.durationDays",
    params: { days: Math.ceil(hours / 24) },
  };
}

// probeResultLabel 生成探测结果文案：成功展示分数/类别/延迟，失败展示错误文本。
export function probeResultLabel(result: ProbeResult): {
  key: string;
  params: Record<string, string | number>;
} {
  if (result.ok) {
    return {
      key: "admin.riskGate.classifier.probeOk",
      params: {
        score: result.score,
        category: result.category || "—",
        latency: result.latency_ms,
      },
    };
  }
  return {
    key: "admin.riskGate.classifier.probeFailed",
    params: { error: result.error || "—" },
  };
}

function pad(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

// csvFilename 复刻后端导出文件名格式：<prefix>-YYYYMMDDTHHMMSSZ.csv
export function csvFilename(
  prefix: string,
  now: number | Date = Date.now(),
): string {
  const date = now instanceof Date ? now : new Date(now);
  const stamp =
    `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  const base = prefix.trim() || "risk-gate-events";
  return `${base}-${stamp}.csv`;
}

export function emptyEventFilter(): EventFilter {
  return {
    kind: "",
    gate: "",
    provider: "",
    request_id: "",
    prompt_hash: "",
    user_id: "",
    api_key_id: "",
    group_id: "",
    from: "",
    to: "",
  };
}

// toRFC3339 把 datetime-local 的值转成 UTC RFC3339；非法或空值返回 undefined。
export function toRFC3339(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const date = new Date(trimmed);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString();
}

const TEXT_FILTER_KEYS = [
  "kind",
  "gate",
  "provider",
  "request_id",
  "prompt_hash",
  "reason",
  "action",
  "rule_id",
  "view",
] as const;
const NUMBER_FILTER_KEYS = ["user_id", "api_key_id", "group_id"] as const;

// eventQuery 去掉空值，产出可直接作为查询参数/请求体的对象。
export function eventQuery(
  filter: EventFilter,
): Record<string, string | number> {
  const params: Record<string, string | number> = {};
  for (const key of TEXT_FILTER_KEYS) {
    const value = (filter[key] ?? "").trim();
    if (value) params[key] = value;
  }
  for (const key of NUMBER_FILTER_KEYS) {
    const value = Number((filter[key] ?? "").trim());
    if (Number.isInteger(value) && value > 0) params[key] = value;
  }
  const from = toRFC3339(filter.from ?? "");
  const to = toRFC3339(filter.to ?? "");
  if (from) params.from = from;
  if (to) params.to = to;
  return params;
}

// hasEventFilter 判断是否至少有一个过滤条件；后端在没有条件时返回 400。
export function hasEventFilter(filter: EventFilter): boolean {
  return Object.keys(eventQuery(filter)).length > 0;
}

/** Rebase local rule edits without dropping rules added remotely or resurrecting
 * remotely deleted rules that the local operator never edited. */
export function rebaseRuleDraft(base: Rule[], local: Rule[], remote: Rule[]): Rule[] {
  const key = (rule: Rule) => rule.rule_key || (rule.id ? `id:${rule.id}` : '')
  const original = new Map(base.map(rule => [key(rule), rule]))
  const edited = new Map(local.filter(rule => key(rule)).map(rule => [key(rule), rule]))
  const remoteKeys = new Set(remote.map(key))
  const result: Rule[] = []
  for (const latest of remote) {
    const id = key(latest)
    const previous = original.get(id)
    const draft = edited.get(id)
    if (previous && !draft) continue // Deliberate local deletion.
    if (!previous || !draft) { result.push(cloneData(latest)); continue }
    const merged = cloneData(latest)
    for (const field of Object.keys(draft) as Array<keyof Rule>) {
      if (field === 'id' || field === 'rule_key') continue
      if (JSON.stringify(previous[field]) !== JSON.stringify(draft[field])) {
        Object.assign(merged, { [field]: draft[field] === undefined ? undefined : cloneData(draft[field]) })
      }
    }
    result.push(merged)
  }
  for (const draft of local) {
    const id = key(draft)
    if (remoteKeys.has(id)) continue
    const previous = original.get(id)
    if (!previous || JSON.stringify(previous) !== JSON.stringify(draft)) {
      // A locally edited rule deleted remotely becomes an explicit new draft.
      result.push({ ...cloneData(draft), id: undefined })
    }
  }
  return result
}


/** Shared outcome semantics for historical rows, compact feed and details.
 * Older upstream refusals used kind=upstream_pass plus reason=upstream_refusal.
 * An observation match is never presented as an actual blocked request.
 */
export function eventOutcome(
  row: Pick<EventRow, "kind" | "action" | "reason">,
): "observe" | "blocked" | "upstreamRefusal" | "upstreamPass" | "passed" {
  if (row.action === "would_block") return "observe";
  if (row.kind === "upstream_refusal" || row.reason === "upstream_refusal")
    return "upstreamRefusal";
  if (row.kind === "blocked") return "blocked";
  if (row.kind === "upstream_pass") return "upstreamPass";
  return "passed";
}
