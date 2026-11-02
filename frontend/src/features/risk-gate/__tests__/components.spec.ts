import { afterEach, describe, expect, it, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import RuleTable from "../components/RuleTable.vue";
import DistillSettings from "../components/DistillSettings.vue";
import HardRegexSettings from "../components/HardRegexSettings.vue";
import HitSummary from "../components/HitSummary.vue";
import GateConfigPanel from "../components/GateConfigPanel.vue";
import ClassifierEndpointEditor from "../components/ClassifierEndpointEditor.vue";
import FilterDeleteDialog from "../components/FilterDeleteDialog.vue";
import BanPanel from "../components/BanPanel.vue";
import EventWorkspace from "../components/EventWorkspace.vue";
import RefusalPanel from "../components/RefusalPanel.vue";
import type {
  Ban,
  ClassifierEndpoint,
  EventFilter,
  RefusalRow,
  RiskGateConfig,
  Rule,
} from "../types";
import { emptyEventFilter } from "../viewModel";

vi.mock("vue-i18n", async () => {
  const actual = await vi.importActual<typeof import("vue-i18n")>("vue-i18n");
  return {
    ...actual,
    useI18n: () => ({
      locale: { value: "en" },
      t: (key: string, params?: Record<string, unknown>) =>
        key.replace(/\{(\w+)\}/g, (_, token) =>
          String(params?.[token] ?? `{${token}}`),
        ),
    }),
  };
});

const DialogStub = defineComponent({
  props: ["show", "title"],
  emits: ["close"],
  template:
    '<div v-if="show" data-test="dialog"><slot /><slot name="footer" /></div>',
});
const ConfirmStub = defineComponent({
  props: ["show", "title", "message", "confirmText"],
  emits: ["confirm", "cancel"],
  template:
    '<div v-if="show" data-test="confirm-dialog"><button data-test="confirm-action" @click="$emit(\'confirm\')">ok</button></div>',
});
const PaginationStub = defineComponent({
  props: ["total", "page", "pageSize"],
  emits: ["update:page", "update:pageSize"],
  template: '<div data-test="pagination" />',
});

const rule = (patch: Partial<Rule> = {}): Rule => ({
  id: 1,
  gate: "regex",
  category: "custom",
  pattern: "^harvest",
  is_regex: true,
  action: "block",
  enabled: true,
  sort_order: 1,
  description: "",
  ...patch,
});

const endpoint = (
  patch: Partial<ClassifierEndpoint> = {},
): ClassifierEndpoint => ({
  id: "c-1",
  name: "Classifier One",
  base_url: "http://127.0.0.1:8000/v1",
  model: "classifier",
  timeout_ms: 2000,
  enabled: true,
  api_key: "",
  has_api_key: true,
  ...patch,
});

const ban = (): Ban => ({
  id: 2,
  scope: "api_key",
  subject: "key-abc",
  reason: "harvest",
  gate: "regex",
  hit_count: 3,
  banned_at: "2026-07-16T00:00:00Z",
  expires_at: null,
  created_by: "admin",
});

const refusal = (): RefusalRow => ({
  id: 5,
  provider: "claude",
  model: "claude-3",
  prompt_hash: "a".repeat(64),
  normalized_prompt: "hello",
  source: "upstream_refusal",
  created_at: "2026-07-16T00:00:00Z",
});

const noFilter = (): EventFilter => emptyEventFilter();

// GateConfigPanel 需要一个完整草稿：observe 模式、只开蒸馏闸门、端点已配置密钥。
const config = (): RiskGateConfig => ({
  mode: "observe",
  gates: {
    distill: true,
    regex: false,
    refusal_cache: false,
    decision_model: false,
  },
  distill: {
    hard_needles: ["needle"],
    needles: [],
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
    endpoints: [endpoint()],
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

describe("Risk Gate components", () => {
  afterEach(() => vi.restoreAllMocks());

  it("refuses to save a rule table that contains an uncompilable regex", async () => {
    const broken = rule({ pattern: "(unclosed" });
    const wrapper = mount(RuleTable, {
      props: { rules: [broken], saving: false, error: "" },
    });

    expect(wrapper.find('[data-test="rules-invalid-notice"]').exists()).toBe(
      true,
    );
    expect(wrapper.get('[data-test="rule-error-0"]').text()).toBe(
      "admin.riskGate.rules.errors.regexInvalid",
    );
    expect(wrapper.get('[data-test="save-rules"]').attributes()).toHaveProperty(
      "disabled",
    );

    await wrapper.get('[data-test="save-rules"]').trigger("click");
    expect(wrapper.emitted("save")).toBeUndefined();

    // 修好后同步 groundwork：输入合法正则，报错消失、保存可用。
    await wrapper.get('[data-test="rule-pattern-0"]').setValue("^harvest.*$");
    expect(wrapper.emitted("update:rules")?.[0]?.[0]).toMatchObject([
      { pattern: "^harvest.*$" },
    ]);
  });

  it("keeps a rule table saveable when every row is valid", async () => {
    const wrapper = mount(RuleTable, {
      props: { rules: [rule()], saving: false, error: "" },
    });
    expect(wrapper.find('[data-test="rules-invalid-notice"]').exists()).toBe(
      false,
    );
    expect(
      wrapper.get('[data-test="save-rules"]').attributes(),
    ).not.toHaveProperty("disabled");

    await wrapper.get('[data-test="save-rules"]').trigger("click");
    expect(wrapper.emitted("save")?.[0]?.[0]).toEqual([rule()]);

    await wrapper.get('[data-test="add-rule"]').trigger("click");
    const added = wrapper.emitted("update:rules")?.at(-1)?.[0] as Rule[];
    expect(added).toHaveLength(2);
    expect(added[1]).toMatchObject({
      gate: "regex",
      category: "custom",
      pattern: "",
      sort_order: 2,
    });
  });
  it("shows probe results per endpoint and never echoes a stored classifier key", async () => {
    const wrapper = mount(ClassifierEndpointEditor, {
      props: {
        endpoints: [
          endpoint(),
          endpoint({ id: "c-2", name: "Classifier Two", has_api_key: false }),
        ],
        probeResults: {
          "c-1": {
            ok: true,
            score: 0.87,
            category: "distill",
            latency_ms: 12,
            endpoint_id: "c-1",
          },
          "c-2": {
            ok: false,
            score: 0,
            category: "",
            latency_ms: 5,
            endpoint_id: "c-2",
            error: "timeout",
          },
        },
        probingIds: ["c-2"],
      },
      global: { stubs: { BaseDialog: DialogStub } },
    });

    expect(wrapper.get('[data-test="probe-result-c-1"]').text()).toBe(
      "admin.riskGate.classifier.probeOk",
    );
    expect(wrapper.get('[data-test="probe-result-c-2"]').text()).toBe(
      "admin.riskGate.classifier.probeFailed",
    );
    // 已配置/未配置密钥用不同徽标区分，界面不出现任何明文。
    expect(wrapper.get('[data-test="endpoint-key-c-1"]').text()).toBe(
      "admin.riskGate.classifier.keyConfigured",
    );
    expect(wrapper.get('[data-test="endpoint-key-c-2"]').text()).toBe(
      "admin.riskGate.classifier.keyMissing",
    );
    expect(wrapper.get('[data-test="probe-c-2"]').attributes()).toHaveProperty(
      "disabled",
    );

    await wrapper.get('[data-test="probe-c-1"]').trigger("click");
    expect(wrapper.emitted("probe")?.[0]?.[0]).toMatchObject({ id: "c-1" });

    // 编辑已保存的端点时密钥输入恒为空，只以 placeholder 提示「已配置」。
    const edit = wrapper
      .findAll("button")
      .find((button) => button.text().includes("common.edit"));
    await edit!.trigger("click");
    const key = wrapper.get<HTMLInputElement>('[data-test="endpoint-api-key"]');
    expect(key.element.value).toBe("");
    expect(key.attributes("type")).toBe("password");
    expect(key.attributes("placeholder")).toBe(
      "admin.riskGate.classifier.keyConfigured",
    );
  });

  it("emits a sanitized endpoint payload when the operator types a new key", async () => {
    const wrapper = mount(ClassifierEndpointEditor, {
      props: { endpoints: [endpoint()], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    });
    const edit = wrapper
      .findAll("button")
      .find((button) => button.text().includes("common.edit"));
    await edit!.trigger("click");
    await wrapper
      .get('[data-test="endpoint-api-key"]')
      .setValue("temp-canary-key");
    await wrapper.get('[data-test="save-endpoint"]').trigger("click");

    const updated = wrapper
      .emitted("update:endpoints")
      ?.at(-1)?.[0] as ClassifierEndpoint[];
    expect(updated[0]).toMatchObject({ id: "c-1", api_key: "temp-canary-key" });
  });

  it("disables filter deletion until a criterion exists and warns on a zero-match preview", async () => {
    const wrapper = mount(FilterDeleteDialog, {
      props: {
        show: true,
        initialFilter: noFilter(),
        preview: null,
        previewing: false,
        deleting: false,
      },
      global: { stubs: { BaseDialog: DialogStub } },
    });

    expect(wrapper.find('[data-test="delete-filter-required"]').exists()).toBe(
      true,
    );
    expect(
      wrapper.get('[data-test="confirm-filter-delete"]').attributes(),
    ).toHaveProperty("disabled");
    expect(wrapper.get('[data-test="delete-confirm-reason"]').text()).toBe(
      "admin.riskGate.events.filterDeleteNoFilter",
    );

    // 没有条件时连预览都不发请求，避免拿 400。
    await wrapper.get('[data-test="run-delete-preview"]').trigger("click");
    expect(wrapper.emitted("preview")).toBeUndefined();

    await wrapper.get('[data-test="delete-provider"]').setValue("claude");
    expect(wrapper.emitted("criteria-change")).toBeTruthy();
    expect(wrapper.find('[data-test="delete-filter-required"]').exists()).toBe(
      false,
    );
    await wrapper.get('[data-test="run-delete-preview"]').trigger("click");
    expect(wrapper.emitted("preview")?.[0]?.[0]).toMatchObject({
      provider: "claude",
    });
  });

  it("blocks confirmation when the preview matched nothing and allows it afterwards", async () => {
    const filter = noFilter();
    filter.provider = "claude";
    const wrapper = mount(FilterDeleteDialog, {
      props: {
        show: true,
        initialFilter: filter,
        preview: { total: 0 },
        previewing: false,
        deleting: false,
      },
      global: { stubs: { BaseDialog: DialogStub } },
    });
    expect(wrapper.get('[data-test="delete-preview-result"]').text()).toContain(
      "admin.riskGate.events.filterDeleteCount",
    );
    expect(
      wrapper.get('[data-test="confirm-filter-delete"]').attributes(),
    ).toHaveProperty("disabled");
    expect(wrapper.get('[data-test="delete-confirm-reason"]').text()).toBe(
      "admin.riskGate.events.filterDeleteNoMatch",
    );

    await wrapper.setProps({ preview: { total: 3 } });
    expect(
      wrapper.get('[data-test="confirm-filter-delete"]').attributes(),
    ).not.toHaveProperty("disabled");
    expect(wrapper.find('[data-test="delete-confirm-reason"]').exists()).toBe(
      false,
    );
    await wrapper.get('[data-test="confirm-filter-delete"]').trigger("click");
    expect(wrapper.emitted("confirm")?.[0]?.[0]).toMatchObject({
      provider: "claude",
    });
  });

  it("disables the events delete-by-filter button while every filter is empty", async () => {
    const base = {
      events: [],
      total: 0,
      page: 1,
      pageSize: 20,
      filter: noFilter(),
      loading: false,
      error: "",
      exporting: false,
    };
    const wrapper = mount(EventWorkspace, {
      props: base,
      global: { stubs: { Pagination: PaginationStub } },
    });
    expect(
      wrapper.get('[data-test="delete-by-filter"]').attributes(),
    ).toHaveProperty("disabled");
    expect(wrapper.find('[data-test="events-empty"]').exists()).toBe(true);

    await wrapper.get('[data-test="filter-provider"]').setValue("claude");
    expect(
      wrapper.get('[data-test="delete-by-filter"]').attributes(),
    ).not.toHaveProperty("disabled");
    await wrapper.get('[data-test="delete-by-filter"]').trigger("click");
    expect(wrapper.emitted("delete-preview")?.[0]?.[0]).toMatchObject({
      provider: "claude",
    });

    // 导出把当前（含未提交的）过滤条件一并带出去。
    await wrapper.get('[data-test="export-events"]').trigger("click");
    expect(wrapper.emitted("export")?.[0]?.[0]).toMatchObject({
      provider: "claude",
    });

    await wrapper.get('[data-test="reset-filters"]').trigger("click");
    expect(wrapper.emitted("delete-preview")).toHaveLength(1);
  });

  it("requires a subject before creating a ban and confirms before releasing one", async () => {
    const wrapper = mount(BanPanel, {
      props: {
        bans: [ban()],
        total: 1,
        page: 1,
        pageSize: 20,
        filter: { scope: "", subject: "", active_only: false },
        loading: false,
        error: "",
        creating: false,
      },
      global: {
        stubs: { Pagination: PaginationStub, ConfirmDialog: ConfirmStub },
      },
    });

    expect(wrapper.get('[data-test="create-ban"]').attributes()).toHaveProperty(
      "disabled",
    );
    await wrapper.get('[data-test="ban-form-subject"]').setValue(" key-abc ");
    expect(
      wrapper.get('[data-test="create-ban"]').attributes(),
    ).not.toHaveProperty("disabled");
    await wrapper.get('[data-test="ban-form"]').trigger("submit");
    expect(wrapper.emitted("create")?.[0]?.[0]).toMatchObject({
      subject: "key-abc",
      scope: "api_key",
      duration_hours: 24,
    });

    // 时长 0 表示永久封禁，表单要给出提示。
    await wrapper.get('[data-test="ban-form-duration"]').setValue("0");
    expect(wrapper.text()).toContain("admin.riskGate.bans.durationPermanent");

    await wrapper.get('[data-test="active-only"]').setValue(true);
    expect(wrapper.emitted("filter-change")?.[0]?.[0]).toMatchObject({
      active_only: true,
    });

    await wrapper.get('[data-test="release-ban-2"]').trigger("click");
    expect(wrapper.find('[data-test="confirm-dialog"]').exists()).toBe(true);
    expect(wrapper.emitted("release")).toBeUndefined();
    await wrapper.get('[data-test="confirm-action"]').trigger("click");
    expect(wrapper.emitted("release")?.[0]).toEqual([2]);
  });

  it("confirms single and bulk refusal deletion through dialogs", async () => {
    const wrapper = mount(RefusalPanel, {
      props: {
        refusals: [refusal()],
        total: 1,
        page: 1,
        pageSize: 20,
        filter: { provider: "", source: "", prompt_hash: "" },
        loading: false,
        error: "",
      },
      global: {
        stubs: { Pagination: PaginationStub, ConfirmDialog: ConfirmStub },
      },
    });

    expect(
      wrapper.get('[data-test="clear-refusals"]').attributes(),
    ).not.toHaveProperty("disabled");
    await wrapper.get('[data-test="delete-refusal-5"]').trigger("click");
    expect(wrapper.emitted("delete")).toBeUndefined();
    await wrapper.get('[data-test="confirm-action"]').trigger("click");
    expect(wrapper.emitted("delete")?.[0]).toEqual([5]);

    await wrapper.get('[data-test="clear-refusals"]').trigger("click");
    await wrapper.get('[data-test="confirm-action"]').trigger("click");
    expect(wrapper.emitted("clear-all")).toBeTruthy();
  });

  it("keeps bulk refusal clearing disabled when the corpus is empty", () => {
    const wrapper = mount(RefusalPanel, {
      props: {
        refusals: [],
        total: 0,
        page: 1,
        pageSize: 20,
        filter: { provider: "", source: "", prompt_hash: "" },
        loading: false,
        error: "",
      },
      global: {
        stubs: { Pagination: PaginationStub, ConfirmDialog: ConfirmStub },
      },
    });
    expect(
      wrapper.get('[data-test="clear-refusals"]').attributes(),
    ).toHaveProperty("disabled");
    expect(wrapper.find('[data-test="refusals-empty"]').exists()).toBe(true);
  });

  it("mirrors mode, gate and decision-model edits back through the draft event", async () => {
    const EndpointEditorStub = defineComponent({
      props: ["endpoints", "probeResults", "probingIds"],
      emits: ["update:endpoints", "probe"],
      template: '<div data-test="endpoint-editor" />',
    });
    const wrapper = mount(GateConfigPanel, {
      props: { draft: config(), probeResults: {}, probingIds: [] },
      global: { stubs: { ClassifierEndpointEditor: EndpointEditorStub } },
    });

    // observe 模式必须给出「只记录不拦截」的提示。
    expect(wrapper.get('[data-test="mode-hint"]').text()).toBe(
      "admin.riskGate.modeHints.observe",
    );
    await wrapper.get('[data-test="mode-select"]').setValue("blocking");
    expect(wrapper.emitted("update:draft")?.at(-1)?.[0]).toMatchObject({
      mode: "blocking",
    });
    expect(wrapper.get('[data-test="mode-hint"]').text()).toBe(
      "admin.riskGate.modeHints.blocking",
    );

    // ban 闸门不可关闭，只暴露其余四道闸门的开关。
    expect(wrapper.find('[data-test="gate-toggle-ban"]').exists()).toBe(false);
    expect(
      wrapper.get('[data-test="gate-toggle-regex"]').attributes("aria-checked"),
    ).toBe("false");
    await wrapper.get('[data-test="gate-toggle-regex"]').trigger("click");
    expect(
      wrapper.get('[data-test="gate-toggle-regex"]').attributes("aria-checked"),
    ).toBe("true");
    expect(wrapper.emitted("update:draft")?.at(-1)?.[0]).toMatchObject({
      gates: { regex: true },
    });

    await wrapper.get('[data-test="decision-model-enabled"]').setValue(true);
    expect(wrapper.emitted("update:draft")?.at(-1)?.[0]).toMatchObject({
      decision_model: { enabled: true },
    });
    // on_unavailable=pass 时必须说明「不可用时放行并记录漏拦」。
    expect(wrapper.get('[data-test="on-unavailable-hint"]').text()).toBe(
      "admin.riskGate.config.decisionModel.onUnavailablePassHint",
    );
    await wrapper.get('[data-test="on-unavailable"]').setValue("fail_closed");
    expect(wrapper.get('[data-test="on-unavailable-hint"]').text()).toBe(
      "admin.riskGate.config.decisionModel.onUnavailableFailClosedHint",
    );
    expect(wrapper.emitted("update:draft")?.at(-1)?.[0]).toMatchObject({
      decision_model: { on_unavailable: "fail_closed" },
    });

    // 关闭「全部分组」后才展开分组 ID 输入框，交给管理员补 ID，否则保存会被拦。
    expect(wrapper.find('[data-test="group-ids"]').exists()).toBe(false);
    await wrapper.get('[data-test="all-groups"]').setValue(false);
    expect(wrapper.find('[data-test="group-ids"]').exists()).toBe(true);
    expect(wrapper.emitted("update:draft")?.at(-1)?.[0]).toMatchObject({
      scope: { all_groups: false },
    });
  });
});


describe("aligned workspace integration contracts", () => {
  it("wires additional regex and platform controls into the config draft", async () => {
    const original = config();
    const wrapper = mount(HardRegexSettings, { props: {
      config: original, rules: [], focusRule: null, sample: "", validating: false, validation: null,
    } });
    await wrapper.get('[data-test="regex-extra-patterns"]').setValue("foo,bar\n^other$");
    const regexDraft = wrapper.emitted("update")!.at(-1)![0] as RiskGateConfig;
    expect(regexDraft.regex.patterns).toEqual(["foo,bar", "^other$"]);
    expect(original.regex.patterns).toBeUndefined();
    await wrapper.get('[data-test="regex-openai-enabled"]').setValue(true);
    const platformDraft = wrapper.emitted("update")!.at(-1)![0] as RiskGateConfig;
    expect(platformDraft.scope.openai_platform_enabled).toBe(true);
    expect(original.scope.openai_platform_enabled).toBeUndefined();
    wrapper.unmount();
  });
  it("shows hit-summary fetch errors rather than a misleading empty table", () => {
    const wrapper = mount(HitSummary, { props: {
      rows: [], title: "Hits", hint: "Rule aggregation", empty: "None", error: "Stats unavailable", loading: false, showSource: true,
    } });
    expect(wrapper.get("h3").text()).toBe("Hits");
    expect(wrapper.get('[role="alert"]').text()).toBe("Stats unavailable");
    expect(wrapper.text()).not.toContain("None");
    wrapper.unmount();
  });
});


describe("canonical rule categories", () => {
  it("shows canonical builtin categories and does not offer ignored v2 category switches", () => {
    const original = { ...config(), schema_version: 2 };
    const wrapper = mount(HardRegexSettings, { props: {
      config: original, rules: [rule({ category: "nsfw" }), rule({ id: 2, category: "crack" })], focusRule: null, sample: "", validating: false, validation: null,
    } });
    expect((wrapper.get('[data-test="rule-category-0"]').element as HTMLSelectElement).value).toBe("nsfw");
    expect((wrapper.get('[data-test="rule-category-1"]').element as HTMLSelectElement).value).toBe("crack");
    expect(wrapper.find('[data-test="legacy-regex-categories"]').exists()).toBe(false);
    expect(wrapper.find('[data-test="regex-distill-link"]').exists()).toBe(true);
    expect(wrapper.get('[data-test="hard-rule-0"]').attributes("data-rule-key")).toBe("1");
    expect(wrapper.emitted("update:rules")).toBeUndefined();
    wrapper.unmount();
  });
  it("displays legacy aliases without silently rewriting the stored rules", async () => {
    const original = rule({ category: "sexual" });
    const wrapper = mount(HardRegexSettings, { props: {
      config: config(), rules: [original], focusRule: null, sample: "", validating: false, validation: null,
    } });
    expect((wrapper.get('[data-test="rule-category-0"]').element as HTMLSelectElement).value).toBe("nsfw");
    expect(wrapper.emitted("update:rules")).toBeUndefined();
    await wrapper.get('[data-test="rule-category-0"]').setValue("crack");
    const updated = wrapper.emitted("update:rules")!.at(-1)![0] as Rule[];
    expect(updated[0].category).toBe("bypass");
    expect(original.category).toBe("sexual");
    wrapper.unmount();
  });
});


describe("distillation rule editor", () => {
  it("preserves commas, regex quantifiers and an in-progress trailing newline", async () => {
    const original = config();
    const wrapper = mount(DistillSettings, { props: { config: original } });
    const editor = wrapper.get('[data-test="distill-hard_needles"]');
    await editor.setValue("fixture, keep together\n");
    const next = wrapper.emitted("update")!.at(-1)![0] as RiskGateConfig;
    expect(next.distill.hard_needles).toEqual(["fixture, keep together"]);
    await wrapper.setProps({ config: next });
    expect((editor.element as HTMLTextAreaElement).value).toBe("fixture, keep together\n");
    await wrapper.get('[data-test="distill-patterns"]').setValue("^a{1,3}$\nfoo,bar");
    expect((wrapper.emitted("update")!.at(-1)![0] as RiskGateConfig).distill.patterns).toEqual(["^a{1,3}$", "foo,bar"]);
    expect(original.distill.hard_needles).toEqual(["needle"]);
    wrapper.unmount();
  });
  it("keeps long rule editors collapsed until requested", () => {
    const wrapper = mount(DistillSettings, { props: { config: config() } });
    expect(wrapper.findAll("details")).toHaveLength(4);
    expect(wrapper.findAll("details").every(item => !(item.element as HTMLDetailsElement).open)).toBe(true);
    wrapper.unmount();
  });
});
