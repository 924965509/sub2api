import { describe, expect, it } from "vitest";
import type { RiskGateConfig, StatusSnapshot } from "../types";
import {
  banDurationLabel,
  buildUpdateRequest,
  configBlockReason,
  configToDraft,
  csvFilename,
  emptyEventFilter,
  eventQuery,
  eventOutcome,
  expiresAtFromHours,
  gateSummary,
  hasEventFilter,
  modeMeta,
  probeResultLabel,
  statusCards,
  validateRuleDraft,
} from "../viewModel";

const HOUR = 60 * 60 * 1000;

const config = (): RiskGateConfig => ({
  mode: "observe",
  gates: {
    distill: true,
    regex: true,
    refusal_cache: false,
    decision_model: false,
  },
  distill: {
    hard_needles: ["hard"],
    needles: ["needle"],
    fingerprints: [],
    skip_official: true,
    skip_zero: true,
    min_max_tokens: 8192,
    contest_pattern: "",
  },
  regex: {
    categories: ["sexual"],
    custom_rules: true,
    max_input_bytes: 1048576,
    expand_base64: false,
    block_message: "",
  },
  refusal_cache: {
    enabled: false,
    similarity_threshold: 0.9,
    min_shingle_runes: 5,
  },
  decision_model: {
    enabled: false,
    threshold: 0.5,
    timeout_ms: 3000,
    max_concurrent: 4,
    on_unavailable: "pass",
    endpoints: [
      {
        id: "c-1",
        name: "C1",
        base_url: "http://127.0.0.1:8000/v1",
        model: "classifier",
        timeout_ms: 2000,
        enabled: true,
        has_api_key: true,
      },
    ],
  },
  ban: {
    scope: "api_key",
    on_distill: true,
    on_regex: false,
    on_decision_model: false,
    duration_hours: 24,
  },
  scope: {
    all_groups: true,
    group_ids: [],
    all_providers: true,
    providers: [],
  },
  retention_days: 30,
});

const status = (): StatusSnapshot => ({
  mode: "blocking",
  config_version: 5,
  effective_gates: ["ban", "distill"],
  counters: {
    evaluated: 10,
    allowed: 8,
    blocked: 2,
    would_block: 0,
    banned: 1,
    ban_hits: 1,
    distill_hits: 1,
    regex_hits: 0,
    refusal_cache_hits: 0,
    decision_model_hits: 0,
    classifier_errors: 0,
  },
  ban_count: 3,
  rules_count: 2,
  last_error: "endpoint timeout",
  checked_at: "2026-07-16T00:00:00Z",
});

describe("risk gate view model", () => {
  it("maps the three run modes to badge copy and tone", () => {
    expect(modeMeta("off")).toEqual({
      labelKey: "admin.riskGate.mode.off",
      tone: "muted",
    });
    expect(modeMeta("observe").labelKey).toBe("admin.riskGate.mode.observe");
    expect(modeMeta("observe").tone).toBe("warn");
    expect(modeMeta("blocking")).toEqual({
      labelKey: "admin.riskGate.mode.blocking",
      tone: "danger",
    });
    // 未知值退回 off，页面不能因为后端新增枚举而崩。
    expect(modeMeta("unexpected").labelKey).toBe("admin.riskGate.mode.off");
  });

  it("marks the ban gate as always on and reflects the other four toggles", () => {
    const summary = gateSummary(config());
    expect(summary.map((item) => item.id)).toEqual([
      "ban",
      "distill",
      "regex",
      "refusal_cache",
      "decision_model",
    ]);
    expect(summary[0]).toMatchObject({ enabled: true, always: true });
    expect(summary[1]).toMatchObject({ enabled: true, always: false });
    expect(summary[3]).toMatchObject({ enabled: false });
    expect(summary[4]).toMatchObject({ enabled: false });
  });

  it("builds runtime cards including counters, ban count and the last error", () => {
    const cards = statusCards(status());
    const byKey = Object.fromEntries(cards.map((card) => [card.key, card]));
    expect(byKey.mode.value).toBe("admin.riskGate.mode.blocking");
    expect(byKey.gates.value).toBe("ban, distill");
    expect(byKey.evaluated.value).toBe(10);
    expect(byKey.blocked).toMatchObject({ value: 2, tone: "danger" });
    expect(byKey.ban_count.value).toBe(3);
    expect(byKey.rules_count.value).toBe(2);
    expect(byKey.last_error).toMatchObject({
      value: "endpoint timeout",
      tone: "danger",
    });
    // 没有错误时给出「无错误」的文案 key，而不是空字符串。
    expect(
      statusCards({ ...status(), last_error: "" }).find(
        (card) => card.key === "last_error",
      )?.value,
    ).toBe("admin.riskGate.runtime.noError");
    expect(statusCards(null)).toEqual([]);
  });

  it("drops empty event filters and converts times to RFC3339", () => {
    const filter = emptyEventFilter();
    expect(eventQuery(filter)).toEqual({});
    expect(hasEventFilter(filter)).toBe(false);

    filter.kind = "blocked";
    filter.gate = "distill";
    filter.provider = " claude ";
    filter.user_id = "7";
    filter.api_key_id = "0";
    filter.group_id = "abc";
    filter.from = "2026-07-15T10:00";
    filter.to = "2026-07-16T10:00";

    expect(eventQuery(filter)).toEqual({
      kind: "blocked",
      gate: "distill",
      provider: "claude",
      user_id: 7,
      from: new Date("2026-07-15T10:00").toISOString(),
      to: new Date("2026-07-16T10:00").toISOString(),
    });
    expect(hasEventFilter(filter)).toBe(true);

    // 单个时间条件也满足后端「至少一个条件」的要求。
    const timeOnly = emptyEventFilter();
    timeOnly.from = "2026-07-15T10:00";
    expect(hasEventFilter(timeOnly)).toBe(true);
  });

  it("validates rule drafts including regex compilation", () => {
    const base = {
      gate: "regex" as const,
      category: "custom" as const,
      pattern: "abc",
      is_regex: false,
      action: "block" as const,
      enabled: true,
      sort_order: 1,
      description: "",
    };
    expect(validateRuleDraft(base)).toEqual([]);
    expect(validateRuleDraft({ ...base, pattern: "   " })).toContain(
      "admin.riskGate.rules.errors.patternRequired",
    );
    expect(validateRuleDraft({ ...base, pattern: "a".repeat(2049) })).toContain(
      "admin.riskGate.rules.errors.patternTooLong",
    );
    // 2048 字节以内、但多字节字符也不能误判。
    expect(validateRuleDraft({ ...base, pattern: "中".repeat(682) })).toEqual(
      [],
    );
    expect(
      validateRuleDraft({ ...base, pattern: "(unclosed", is_regex: true }),
    ).toContain("admin.riskGate.rules.errors.regexInvalid");
    expect(
      validateRuleDraft({ ...base, pattern: "^harvest.*$", is_regex: true }),
    ).toEqual([]);
    expect(validateRuleDraft({ ...base, gate: "ban" as never })).toContain(
      "admin.riskGate.rules.errors.gateInvalid",
    );
    expect(
      validateRuleDraft({ ...base, category: "unknown" as never }),
    ).toContain("admin.riskGate.rules.errors.categoryInvalid");
    expect(validateRuleDraft({ ...base, action: "warn" as never })).toContain(
      "admin.riskGate.rules.errors.actionInvalid",
    );
  });

  it("converts ban hours to expiry and labels the remaining duration", () => {
    const now = new Date("2026-07-16T00:00:00Z").getTime();
    expect(expiresAtFromHours(0, now)).toBeNull();
    expect(expiresAtFromHours(24, now)).toBe("2026-07-17T00:00:00.000Z");

    expect(banDurationLabel({ expires_at: null }, now)).toEqual({
      key: "admin.riskGate.bans.durationPermanent",
      params: {},
    });
    expect(
      banDurationLabel({ expires_at: "2026-07-15T00:00:00Z" }, now).key,
    ).toBe("admin.riskGate.bans.durationExpired");
    expect(
      banDurationLabel(
        { expires_at: new Date(now + 5 * HOUR).toISOString() },
        now,
      ),
    ).toEqual({
      key: "admin.riskGate.bans.durationHours",
      params: { hours: 5 },
    });
    expect(
      banDurationLabel(
        { expires_at: new Date(now + 72 * HOUR).toISOString() },
        now,
      ),
    ).toEqual({
      key: "admin.riskGate.bans.durationDays",
      params: { days: 3 },
    });
  });

  it("describes probe results and export file names", () => {
    expect(
      probeResultLabel({
        ok: true,
        score: 0.91,
        category: "distill",
        latency_ms: 12,
        endpoint_id: "c-1",
      }),
    ).toEqual({
      key: "admin.riskGate.classifier.probeOk",
      params: { score: 0.91, category: "distill", latency: 12 },
    });
    expect(
      probeResultLabel({
        ok: false,
        score: 0,
        category: "",
        latency_ms: 5,
        endpoint_id: "c-1",
        error: "boom",
      }),
    ).toEqual({
      key: "admin.riskGate.classifier.probeFailed",
      params: { error: "boom" },
    });

    const now = new Date("2026-07-16T08:09:10Z").getTime();
    expect(csvFilename("risk-gate-events", now)).toBe(
      "risk-gate-events-20260716T080910Z.csv",
    );
    expect(csvFilename("  ", now)).toBe(
      "risk-gate-events-20260716T080910Z.csv",
    );
  });

  it("normalizes null collections and never echoes a stored classifier key", () => {
    const legacy = {
      ...config(),
      distill: {
        ...config().distill,
        hard_needles: null,
        needles: null,
        fingerprints: null,
      },
      regex: { ...config().regex, categories: null },
      scope: {
        all_groups: false,
        group_ids: null,
        all_providers: false,
        providers: null,
      },
    } as unknown as RiskGateConfig;
    const draft = configToDraft(legacy);
    expect(draft.distill.hard_needles).toEqual([]);
    expect(draft.regex.categories).toEqual([]);
    expect(draft.scope.group_ids).toEqual([]);
    expect(draft.scope.providers).toEqual([]);
    expect(draft.decision_model.endpoints[0]).toMatchObject({
      api_key: "",
      has_api_key: true,
    });

    const payload = buildUpdateRequest(draft, 9);
    expect(payload.expected_version).toBe(9);
    expect(payload.decision_model.endpoints[0]).toMatchObject({
      api_key: undefined,
    });
    expect(JSON.stringify(payload)).not.toContain('"has_api_key"');
  });

  it("sends plaintext keys only when the operator typed one", () => {
    const draft = configToDraft(config());
    draft.decision_model.endpoints[0].api_key = "temp-canary-key";
    const payload = buildUpdateRequest(draft, 1);
    expect(payload.decision_model.endpoints[0].api_key).toBe("temp-canary-key");
    expect(
      buildUpdateRequest(configToDraft(config()), 1).decision_model.endpoints[0]
        .api_key,
    ).toBeUndefined();
  });

  it("blocks saves that would leave the decision model without an enabled endpoint", () => {
    const draft = configToDraft(config());
    expect(configBlockReason(draft)).toBe("");

    draft.decision_model.enabled = true;
    expect(configBlockReason(draft)).toBe("");
    draft.decision_model.endpoints[0].enabled = false;
    expect(configBlockReason(draft)).toBe(
      "admin.riskGate.errors.decisionModelEndpointRequired",
    );

    const noGate = configToDraft(config());
    noGate.gates = {
      distill: false,
      regex: false,
      refusal_cache: false,
      decision_model: false,
    };
    expect(configBlockReason(noGate)).toBe(
      "admin.riskGate.errors.gateRequired",
    );

    const noGroup = configToDraft(config());
    noGroup.scope = {
      all_groups: false,
      group_ids: [],
      all_providers: true,
      providers: [],
    };
    expect(configBlockReason(noGroup)).toBe(
      "admin.riskGate.errors.groupRequired",
    );
  });
});


describe("event outcome compatibility", () => {
  it("never presents observe hits as actual blocks", () => {
    expect(eventOutcome({ kind: "blocked", action: "would_block", reason: "rule" })).toBe("observe");
  });
  it("recognizes old and new upstream refusal rows", () => {
    expect(eventOutcome({ kind: "upstream_pass", action: "none", reason: "upstream_refusal" })).toBe("upstreamRefusal");
    expect(eventOutcome({ kind: "upstream_refusal", action: "none", reason: "policy" })).toBe("upstreamRefusal");
  });
  it("distinguishes model fail-open from fail-closed", () => {
    expect(eventOutcome({ kind: "upstream_pass", action: "none", reason: "classifier_unavailable" })).toBe("upstreamPass");
    expect(eventOutcome({ kind: "blocked", action: "none", reason: "classifier_unavailable" })).toBe("blocked");
  });
  it("keeps allowed requests and real blocks distinct", () => {
    expect(eventOutcome({ kind: "allowed", action: "none", reason: "model_safe" })).toBe("passed");
    expect(eventOutcome({ kind: "blocked", action: "banned", reason: "rule" })).toBe("blocked");
  });
});
