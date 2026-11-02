import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent } from "vue";
import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { createI18n } from "vue-i18n";
import { createMemoryHistory, createRouter, type Router } from "vue-router";
import zh from "@/i18n/locales/zh";
import RiskGateView from "../RiskGateView.vue";
import DistillSettings from "../components/DistillSettings.vue";
import HardRegexSettings from "../components/HardRegexSettings.vue";
import ModelSettings from "../components/ModelSettings.vue";
import RefusalSettings from "../components/RefusalSettings.vue";
import AccountScopePanel from "../components/AccountScopePanel.vue";
import EventWorkspace from "../components/EventWorkspace.vue";
import EventDetailDialog from "../components/EventDetailDialog.vue";
import FilterDeleteDialog from "../components/FilterDeleteDialog.vue";
import BanPanel from "../components/BanPanel.vue";
import RefusalPanel from "../components/RefusalPanel.vue";
import GateRail from "../components/GateRail.vue";
import RiskFeed from "../components/RiskFeed.vue";
import {
  cloneData,
  defaultPolicyQuestions,
  emptyEventFilter,
} from "../viewModel";
import type { ConfigView, EventRow, RiskGateConfig, Rule } from "../types";

const { api, showSuccess, showError } = vi.hoisted(() => ({
  api: Object.fromEntries(
    [
      "getConfig",
      "updateConfig",
      "getStatus",
      "getStats",
      "getRuleset",
      "saveRuleset",
      "validateRules",
      "getScopeInventory",
      "getClassifierUsage",
      "getClassifierModels",
      "probeClassifier",
      "getRules",
      "saveRules",
      "getBans",
      "createBan",
      "deleteBan",
      "clearBans",
      "getEvents",
      "getEvent",
      "previewDeleteEvents",
      "deleteEventsByFilter",
      "exportEvents",
      "getRefusals",
      "deleteRefusal",
      "deleteAllRefusals",
    ].map((key) => [key, vi.fn()]),
  ),
  showSuccess: vi.fn(),
  showError: vi.fn(),
}));
vi.mock("../api", () => ({ default: api }));
vi.mock("@/stores/app", () => ({
  useAppStore: () => ({ showSuccess, showError }),
}));
const rule: Rule = {
  id: 11,
  rule_key: "custom-11",
  gate: "regex",
  category: "custom",
  pattern: "fixture",
  is_regex: false,
  action: "block",
  enabled: true,
  sort_order: 1,
  description: "",
};
function config(): RiskGateConfig {
  return {
    schema_version: 2,
    mode: "observe",
    gates: {
      distill: true,
      regex: true,
      refusal_cache: false,
      decision_model: false,
    },
    distill: {
      hard_needles: ["fixture_harvest"],
      needles: [],
      fingerprints: [],
      patterns: [],
      skip_official: true,
      skip_zero: true,
      min_max_tokens: 8192,
      contest_pattern: "",
      require_no_tools: true,
      require_single_turn: true,
      error: {
        status: 403,
        type: "permission_error",
        code: "distill_blocked",
        message: "blocked",
      },
    },
    regex: {
      categories: ["custom"],
      custom_rules: true,
      max_input_bytes: 262144,
      expand_base64: true,
      strip_reminders: true,
      block_message: "",
      patterns: [],
    },
    refusal_cache: {
      enabled: false,
      similarity_threshold: 0.9,
      min_shingle_runes: 512,
      similarity_enabled: true,
      device_block_enabled: true,
    },
    decision_model: {
      enabled: false,
      threshold: 0.8,
      timeout_ms: 3000,
      max_concurrent: 32,
      on_unavailable: "pass",
      scoring_mode: "safety_questions",
      provider: "jev",
      safety_threshold: 0.5,
      block_if_below: true,
      dedup_sec: 60,
      max_state_chars: 16000,
      safety_instruction: "",
      questions: defaultPolicyQuestions(),
      endpoints: [
        {
          id: "primary",
          name: "Primary",
          base_url: "https://classifier.example.test",
          model: "test-model",
          timeout_ms: 3000,
          enabled: true,
          has_api_key: true,
          api_key_count: 2,
          provider: "jev",
        },
      ],
    },
    ban: {
      scope: "api_key",
      duration_hours: 24,
      on_distill: true,
      on_regex: false,
      on_decision_model: false,
    },
    scope: {
      all_groups: true,
      group_ids: [],
      all_providers: true,
      providers: [],
      openai_platform_enabled: true,
      account_ids: [],
      account_platform_plans: [],
    },
    retention_days: 30,
  };
}
const page = <T>(items: T[] = [], total = items.length) => ({
  items,
  total,
  page: 1,
  page_size: 20,
  pages: Math.ceil(total / 20),
});
const event: EventRow = {
  id: 1,
  request_id: "request-fixture",
  user_id: 1,
  api_key_id: 2,
  group_id: 3,
  provider: "anthropic",
  endpoint: "/v1/messages",
  protocol: "anthropic",
  model: "claude-test",
  kind: "blocked",
  gate: "regex",
  rule_id: 11,
  reason: "custom",
  score: 0,
  prompt_hash: "hash-fixture",
  evidence: "fixture evidence",
  action: "would_block",
  created_at: "2026-11-01T10:00:00Z",
};
let wrapper: VueWrapper | undefined;
let router: Router;
let server: ConfigView;
async function render(view = "all") {
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/risk-gate", component: RiskGateView },
      { path: "/elsewhere", component: { template: "<p>Elsewhere</p>" } },
    ],
  });
  await router.push(`/admin/risk-gate?view=${view}`);
  await router.isReady();
  wrapper = mount(defineComponent({ template: "<RouterView />" }), {
    global: {
      plugins: [
        router,
        createI18n({ legacy: false, locale: "zh", messages: { zh } }),
      ],
      stubs: {
        AppLayout: { template: "<div><slot /></div>" },
        teleport: true,
        transition: false,
      },
    },
  });
  await flushPromises();
  return wrapper;
}
async function stage(view: string) {
  await router.replace({ query: { view } });
  await flushPromises();
}
async function openTools(id: string) {
  const toggle = wrapper!
    .findAll("button")
    .find((item) => item.text() === "历史与管理工具");
  await toggle!.trigger("click");
  await flushPromises();
  const buttons = wrapper!
    .findAll("button")
    .filter((item) => item.text() === id);
  await buttons[buttons.length - 1].trigger("click");
  await flushPromises();
}
beforeEach(() => {
  vi.resetAllMocks();
  server = { config: config(), version: 7, updated_at: "2026-11-01T10:00:00Z" };
  vi.spyOn(window, "confirm").mockReturnValue(true);
  api.getConfig.mockImplementation(async () => cloneData(server));
  api.updateConfig.mockImplementation(async (payload) => {
    server = {
      config: { ...payload, expected_version: undefined },
      version: payload.expected_version + 1,
      updated_at: server.updated_at,
    } as ConfigView;
    return cloneData(server);
  });
  api.getStatus.mockResolvedValue({
    mode: "observe",
    config_version: 7,
    effective_gates: ["ban", "distill", "regex"],
    counters: {},
    ban_count: 0,
    rules_count: 1,
    last_error: "",
    checked_at: "2026-11-01T10:00:00Z",
  });
  api.getStats.mockResolvedValue({
    since: "2026-11-01T00:00:00Z",
    until: "2026-11-01T10:00:00Z",
    timezone: "UTC",
    total: 20,
    blocked: 2,
    passed: 18,
    would_block: 1,
    blocks: [
      {
        gate: "regex",
        rule_id: 11,
        rule_key: "custom-11",
        category: "custom",
        keyword: "fixture",
        pattern: "fixture",
        action: "none",
        count: 2,
      },
    ],
    passes: [{ reason: "regex", count: 18 }],
  });
  api.getRuleset.mockResolvedValue({
    version: 3,
    rules: [cloneData(rule)],
    builtin_rules: [cloneData(rule)],
    customized: true,
  });
  api.saveRuleset.mockImplementation(async (version, rules) => ({
    version: version + 1,
    rules: cloneData(rules),
    builtin_rules: [rule],
    customized: true,
  }));
  api.validateRules.mockResolvedValue({ valid: true, errors: [], matches: [] });
  api.getScopeInventory.mockResolvedValue({
    accounts_total: 1,
    accounts: [
      {
        id: "1",
        name: "Fixture",
        platform: "claude",
        plan_type: "max",
        scope_key: "claude:max",
        schedulable: true,
      },
    ],
    account_platform_plan_options: [
      { id: "claude:max", label: "Claude Max", count: 1 },
    ],
  });
  const counts = {
    requests: 0,
    successful: 0,
    input_tokens: 0,
    output_tokens: 0,
    unknown_usage_requests: 0,
    estimated_cost_nano_usd: null,
    unknown_cost_requests: 0,
  };
  api.getClassifierUsage.mockResolvedValue({
    ...page(),
    summary: counts,
    today: counts,
    started_at: null,
    storage_errors_since_start: 0,
  });
  api.getEvents.mockResolvedValue(page([cloneData(event)]));
  api.getEvent.mockResolvedValue(cloneData(event));
  api.getBans.mockResolvedValue(page());
  api.getRefusals.mockResolvedValue(page());
  api.getRules.mockResolvedValue([cloneData(rule)]);
  api.previewDeleteEvents.mockResolvedValue({ total: 2 });
  api.deleteEventsByFilter.mockResolvedValue({ deleted: 2 });
  api.exportEvents.mockResolvedValue("fixture.csv");
  api.deleteAllRefusals.mockResolvedValue({ deleted: 1 });
  api.clearBans.mockResolvedValue({ deleted: 1 });
  api.probeClassifier.mockResolvedValue({
    ok: true,
    score: 0.9,
    category: "safe",
    latency_ms: 25,
    endpoint_id: "primary",
    scores: { usage_policy: 0.9, nsfw: 0.99, abuse: 0.98 },
  });
  api.getClassifierModels.mockResolvedValue({
    models: [{ id: "fixture-model" }],
  });
});
afterEach(() => {
  wrapper?.unmount();
  wrapper = undefined;
  vi.restoreAllMocks();
});

describe("Risk audit reference workspace", () => {
  it("loads saved state, persisted stats, rules and inventory, but lazy-loads management tables", async () => {
    await render();
    for (const key of [
      "getConfig",
      "getStatus",
      "getStats",
      "getRuleset",
      "getScopeInventory",
      "getClassifierUsage",
      "getEvents",
    ])
      expect(api[key]).toHaveBeenCalled();
    expect(api.getBans).not.toHaveBeenCalled();
    expect(api.getRefusals).not.toHaveBeenCalled();
    expect(wrapper!.findAll('[role="tab"]')).toHaveLength(6);
  });
  it("restores the requested stage from URL and changes it through the rail", async () => {
    await render("distill");
    expect(wrapper!.findComponent(DistillSettings).exists()).toBe(true);
    wrapper!.findComponent(GateRail).vm.$emit("view", "jev");
    await flushPromises();
    expect(router.currentRoute.value.query.view).toBe("jev");
    expect(wrapper!.findComponent(ModelSettings).exists()).toBe(true);
  });
  it("keeps effective states independent of unsaved gate toggles", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.gates.distill = false;
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    await flushPromises();
    expect(wrapper!.findComponent(GateRail).props("states").distill).toBe(
      "observe",
    );
    expect(wrapper!.find('[data-test="save-config"]').exists()).toBe(true);
  });
  it("saves edited configuration with the expected version and then hides the save bar", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.distill.hard_needles = ["new fixture"];
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    await flushPromises();
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(api.updateConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        expected_version: 7,
        distill: expect.objectContaining({ hard_needles: ["new fixture"] }),
      }),
    );
    expect(wrapper!.find('[data-test="save-config"]').exists()).toBe(false);
  });
  it("preserves drafts across stage changes and protects page departure", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.distill.needles = ["keep this"];
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    await stage("jev");
    await stage("distill");
    expect(
      wrapper!.findComponent(DistillSettings).props("config").distill.needles,
    ).toEqual(["keep this"]);
    vi.mocked(window.confirm).mockReturnValue(false);
    await router.push("/elsewhere");
    expect(router.currentRoute.value.path).toBe("/admin/risk-gate");
  });
  it("retains a conflict draft instead of automatically overwriting it", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.distill.needles = ["local draft"];
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    api.updateConfig.mockRejectedValueOnce({
      response: { status: 409, data: { reason: "risk_gate_config_conflict" } },
    });
    await flushPromises();
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(wrapper!.find('[data-test="config-conflict"]').exists()).toBe(true);
    expect(api.getConfig).toHaveBeenCalledTimes(1);
    expect(
      wrapper!.findComponent(DistillSettings).props("config").distill.needles,
    ).toEqual(["local draft"]);
  });
  it("rebases only locally edited fields onto the latest server version", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.distill.needles = ["local draft"];
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    api.updateConfig.mockRejectedValueOnce({ response: { status: 409 } });
    await flushPromises();
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    server.version = 9;
    server.config.retention_days = 45;
    const rebase = wrapper!
      .findAll("button")
      .find((item) => item.text().includes("合并到最新"));
    await rebase!.trigger("click");
    await flushPromises();
    const next = wrapper!.findComponent(DistillSettings).props("config");
    expect(next.distill.needles).toEqual(["local draft"]);
    expect(next.retention_days).toBe(45);
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(api.updateConfig).toHaveBeenLastCalledWith(
      expect.objectContaining({ expected_version: 9 }),
    );
  });
  it("discards local changes only after the explicit discard action", async () => {
    await render("distill");
    const draft = cloneData(
      wrapper!.findComponent(DistillSettings).props("config"),
    );
    draft.distill.needles = ["discard"];
    wrapper!.findComponent(DistillSettings).vm.$emit("update", draft);
    await flushPromises();
    await wrapper!.find('[data-test="reset-config"]').trigger("click");
    expect(
      wrapper!.findComponent(DistillSettings).props("config").distill.needles,
    ).toEqual([]);
  });
  it("retries a failed initial configuration load", async () => {
    api.getConfig.mockRejectedValueOnce(new Error("fixture outage"));
    await render();
    expect(wrapper!.text()).toContain("fixture outage");
    const retry = wrapper!
      .findAll("button")
      .find((item) => item.text() === "重试");
    await retry!.trigger("click");
    await flushPromises();
    expect(api.getConfig).toHaveBeenCalledTimes(2);
    expect(wrapper!.findComponent(AccountScopePanel).exists()).toBe(true);
  });
  it("does not reset a disabled or unknown rail state to an enabled draft state", async () => {
    server.config.mode = "off";
    await render();
    expect(wrapper!.findComponent(GateRail).props("states")).toMatchObject({
      distill: "off",
      "hard-regex": "off",
      refusal: "off",
      jev: "off",
    });
  });
  it("shows observation-only matches without calling them real interceptions", async () => {
    await render("hard-regex");
    expect(wrapper!.findComponent(RiskFeed).text()).toContain("观察命中");
    expect(wrapper!.findComponent(RiskFeed).text()).toContain("未拦截");
  });
  it("saves rules against their own optimistic version", async () => {
    await render("hard-regex");
    const next = [{ ...rule, pattern: "(?i)new_fixture", is_regex: true }];
    wrapper!.findComponent(HardRegexSettings).vm.$emit("update:rules", next);
    await flushPromises();
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(api.saveRuleset).toHaveBeenCalledWith(3, next);
    expect(api.updateConfig).not.toHaveBeenCalled();
  });
  it("uses the backend validator rather than a JavaScript regex engine", async () => {
    await render("hard-regex");
    wrapper!
      .findComponent(HardRegexSettings)
      .vm.$emit("validate", "fixture text");
    await flushPromises();
    expect(api.validateRules).toHaveBeenCalledWith([rule], "fixture text");
    expect(
      wrapper!.findComponent(HardRegexSettings).props("validation")?.valid,
    ).toBe(true);
  });
  it("keeps rules dirty when rule persistence fails after a configuration save", async () => {
    await render("hard-regex");
    const panel = wrapper!.findComponent(HardRegexSettings);
    const cfg = cloneData(panel.props("config"));
    cfg.regex.expand_base64 = false;
    panel.vm.$emit("update", cfg);
    panel.vm.$emit("update:rules", [{ ...rule, enabled: false }]);
    api.saveRuleset.mockRejectedValueOnce(new Error("rules failed"));
    await flushPromises();
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(api.updateConfig).toHaveBeenCalledTimes(1);
    expect(wrapper!.find('[data-test="save-config"]').exists()).toBe(true);
    expect(wrapper!.find('[data-test="dirty-state"]').text()).toContain(
      "规则列表",
    );
  });
  it("preserves typed secret drafts across unrelated field edits", async () => {
    await render("jev");
    await wrapper!
      .find('[data-test="model-api-key"]')
      .setValue("synthetic-secret");
    await wrapper!.find('[data-test="model-name"]').setValue("another-model");
    expect(
      wrapper!.findComponent(ModelSettings).props("config").decision_model
        .endpoints[0].api_key,
    ).toBe("synthetic-secret");
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(
      api.updateConfig.mock.calls[0][0].decision_model.endpoints[0].api_key,
    ).toBe("synthetic-secret");
  });
  it("submits multiple keys without erasing them during draft updates", async () => {
    await render("jev");
    await wrapper!
      .find('[data-test="model-api-keys"]')
      .setValue("fixture-key-a\nfixture-key-b");
    await wrapper!.find('[data-test="model-name"]').setValue("multi-key-model");
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(
      api.updateConfig.mock.calls[0][0].decision_model.endpoints[0].api_keys,
    ).toEqual(["fixture-key-a", "fixture-key-b"]);
  });
  it("probes the displayed question draft and refreshes actual model usage", async () => {
    await render("jev");
    await wrapper!
      .find('[data-test="model-custom-instruction"]')
      .setValue("Custom safe requirement");
    await wrapper!.find('[data-test="probe-model"]').trigger("click");
    await flushPromises();
    expect(api.probeClassifier).toHaveBeenCalledWith(
      expect.objectContaining({
        decision_model: expect.objectContaining({
          safety_instruction: "Custom safe requirement",
        }),
      }),
    );
    expect(wrapper!.findComponent(ModelSettings).text()).toContain("探测成功");
    expect(api.getClassifierUsage).toHaveBeenCalledTimes(2);
  });
  it("fetches model IDs and lets the operator select one", async () => {
    await render("jev");
    await wrapper!.find('[data-test="fetch-models"]').trigger("click");
    await flushPromises();
    await wrapper!
      .find('[data-test="available-models"]')
      .setValue("fixture-model");
    expect(
      wrapper!.findComponent(ModelSettings).props("config").decision_model
        .endpoints[0].model,
    ).toBe("fixture-model");
  });
  it("edits question instructions and restores executable built-in questions", async () => {
    await render("jev");
    await wrapper!
      .find('[data-test="question-instructions-0"]')
      .setValue("Is this safe?");
    expect(
      wrapper!.findComponent(ModelSettings).props("config").decision_model
        .questions?.[0].instructions,
    ).toBe("Is this safe?");
    await wrapper!.find('[data-test="reset-questions"]').trigger("click");
    expect(
      wrapper!
        .findComponent(ModelSettings)
        .props("config")
        .decision_model.questions?.every((q) => q.instructions.length > 10),
    ).toBe(true);
  });
  it("immediate refusal changes do not save unrelated model drafts", async () => {
    await render("jev");
    await wrapper!.find('[data-test="model-name"]').setValue("unsaved-model");
    await stage("refusal");
    await wrapper!.find('[data-test="refusal-enabled"]').setValue(true);
    await flushPromises();
    expect(
      api.updateConfig.mock.calls[0][0].decision_model.endpoints[0].model,
    ).toBe("test-model");
    await stage("jev");
    expect(
      wrapper!.findComponent(ModelSettings).props("config").decision_model
        .endpoints[0].model,
    ).toBe("unsaved-model");
    expect(wrapper!.find('[data-test="save-config"]').exists()).toBe(true);
  });
  it("rolls back a failed immediate refusal toggle and shows the failure", async () => {
    await render("refusal");
    api.updateConfig.mockRejectedValueOnce(new Error("immediate write failed"));
    await wrapper!.find('[data-test="refusal-enabled"]').setValue(true);
    await flushPromises();
    expect(
      wrapper!.findComponent(RefusalSettings).props("config").gates
        .refusal_cache,
    ).toBe(false);
    expect(wrapper!.text()).toContain("immediate write failed");
  });
  it("clears only device bans from the refusal stage, not users and keys", async () => {
    await render("refusal");
    wrapper!.findComponent(RefusalSettings).vm.$emit("clear-bans");
    await flushPromises();
    expect(api.clearBans).toHaveBeenCalledWith("client_fingerprint");
  });
  it("retains manual ban creation and individual release", async () => {
    await render();
    await openTools("封禁");
    const panel = wrapper!.findComponent(BanPanel);
    panel.vm.$emit("create", {
      scope: "api_key",
      subject: "20",
      reason: "fixture",
      duration_hours: 24,
    });
    await flushPromises();
    expect(api.createBan).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "api_key", subject: "20" }),
    );
    panel.vm.$emit("release", 5);
    await flushPromises();
    expect(api.deleteBan).toHaveBeenCalledWith(5);
  });
  it("queries event history using applied filters and supports pagination", async () => {
    await render();
    await openTools("事件工作台");
    const panel = wrapper!.findComponent(EventWorkspace);
    const filter = { ...emptyEventFilter(), kind: "blocked", user_id: "10" };
    panel.vm.$emit("search", filter);
    await flushPromises();
    expect(api.getEvents).toHaveBeenLastCalledWith(filter, 1, 20);
    panel.vm.$emit("page", 2);
    await flushPromises();
    expect(api.getEvents).toHaveBeenLastCalledWith(filter, 2, 20);
  });
  it("exports the applied filter, not an unsubmitted form edit", async () => {
    await render();
    await openTools("事件工作台");
    const panel = wrapper!.findComponent(EventWorkspace);
    const applied = { ...emptyEventFilter(), user_id: "10" };
    panel.vm.$emit("search", applied);
    await flushPromises();
    panel.vm.$emit("filters-change", { ...applied, user_id: "20" });
    panel.vm.$emit("export", { ...applied, user_id: "20" });
    await flushPromises();
    expect(api.exportEvents).toHaveBeenCalledWith(applied);
    expect(showSuccess).toHaveBeenCalled();
  });
  it("previews and deletes history using the same applied criteria", async () => {
    await render();
    await openTools("事件工作台");
    const panel = wrapper!.findComponent(EventWorkspace);
    const filter = { ...emptyEventFilter(), kind: "blocked" };
    panel.vm.$emit("search", filter);
    await flushPromises();
    panel.vm.$emit("delete-preview", filter);
    await flushPromises();
    const dialog = wrapper!.findComponent(FilterDeleteDialog);
    expect(dialog.props("initialFilter")).toEqual(filter);
    dialog.vm.$emit("preview", filter);
    await flushPromises();
    expect(api.previewDeleteEvents).toHaveBeenCalledWith(filter);
    dialog.vm.$emit("confirm", filter);
    await flushPromises();
    expect(api.deleteEventsByFilter).toHaveBeenCalledWith(filter);
  });
  it("loads detail through the API and refuses a stale detail response after close", async () => {
    await render();
    let resolve!: (value: EventRow) => void;
    api.getEvent.mockReturnValueOnce(
      new Promise<EventRow>((done) => {
        resolve = done;
      }),
    );
    wrapper!.findComponent(RiskFeed).vm.$emit("open", 1);
    await flushPromises();
    const dialog = wrapper!.findComponent(EventDetailDialog);
    dialog.vm.$emit("close");
    resolve(event);
    await flushPromises();
    expect(dialog.props("show")).toBe(false);
    expect(dialog.props("event")).toBeNull();
  });
  it("retains per-refusal deletion and corpus clearing in management tools", async () => {
    await render();
    await openTools("拒答语料");
    const panel = wrapper!.findComponent(RefusalPanel);
    panel.vm.$emit("delete", 3);
    await flushPromises();
    expect(api.deleteRefusal).toHaveBeenCalledWith(3);
    panel.vm.$emit("clear-all");
    await flushPromises();
    expect(api.deleteAllRefusals).toHaveBeenCalled();
  });
  it("does not show classifier failures as upstream-refusal rows", async () => {
    api.getEvents.mockResolvedValue(
      page([
        {
          ...event,
          kind: "upstream_pass",
          reason: "classifier_unavailable",
          evidence: "only fail-open",
        },
        {
          ...event,
          id: 2,
          kind: "upstream_pass",
          reason: "upstream_refusal",
          evidence: "upstream evidence",
        },
      ]),
    );
    await render("pass");
    const rows = wrapper!.findComponent(RiskFeed).props("rows");
    expect(rows).toHaveLength(1);
    expect(rows[0].reason).toBe("upstream_refusal");
  });
  it("keeps a legacy configuration in legacy mode until explicitly changed", async () => {
    server.config.schema_version = 0;
    server.config.decision_model.scoring_mode = "risk";
    await render("jev");
    expect(wrapper!.find('[data-test="legacy-scoring-notice"]').exists()).toBe(
      true,
    );
    await wrapper!.find('[data-test="model-name"]').setValue("legacy-edited");
    await wrapper!.find('[data-test="save-config"]').trigger("click");
    await flushPromises();
    expect(api.updateConfig.mock.calls[0][0].schema_version).toBe(0);
    expect(api.updateConfig.mock.calls[0][0].decision_model.scoring_mode).toBe(
      "risk",
    );
  });
});
