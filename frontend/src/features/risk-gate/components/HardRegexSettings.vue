<template>
  <section class="space-y-4" data-test="hard-regex-settings">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h3 class="text-sm font-semibold">
          {{ t("admin.riskGate.stages.hardRegex.title") }}
        </h3>
        <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.stages.hardRegex.description") }}
        </p>
      </div>
      <input
        type="checkbox"
        :checked="config.gates.regex"
        :aria-label="t('admin.riskGate.stages.hardRegex.enabled')"
        data-test="hard-regex-enabled"
        @change="update({ gates: { ...config.gates, regex: checked($event) } })"
      />
    </div>
    <div v-if="(config.schema_version ?? 1) < 2" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" data-test="legacy-regex-categories">
      <label
        v-for="category in legacyCategories"
        :key="category"
        class="flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2 text-xs dark:border-dark-700/60"
        ><input
          type="checkbox"
          :checked="config.regex.categories?.includes(category)"
          @change="toggleCategory(category, $event)"
        />{{ t(`admin.riskGate.categories.${category}`) }}</label
      >
    </div>
    <p v-if="(config.schema_version ?? 1) >= 2" class="text-xs leading-5 text-gray-500 dark:text-dark-400" data-test="regex-distill-link">
      {{ t("admin.riskGate.stages.hardRegex.distillFollowsGate") }}
    </p>
    <div class="grid gap-4 lg:grid-cols-2">
      <label class="flex items-center gap-2 text-xs"><input type="checkbox" :checked="config.scope.openai_platform_enabled" data-test="regex-openai-enabled" @change="setOpenAI(checked($event))" />{{ t("admin.riskGate.scope.openaiPlatform") }}</label>
      <label class="flex items-center gap-2 text-xs"
        ><input
          type="checkbox"
          :checked="config.regex.strip_reminders"
          @change="updateRegex({ strip_reminders: checked($event) })"
        />{{ t("admin.riskGate.stages.hardRegex.stripReminders") }}</label
      ><label class="flex items-center gap-2 text-xs"
        ><input
          type="checkbox"
          :checked="config.regex.expand_base64"
          @change="updateRegex({ expand_base64: checked($event) })"
        />{{ t("admin.riskGate.stages.hardRegex.expandBase64") }}</label
      >
    </div>
    <div
      class="overflow-hidden rounded-lg border border-gray-200 dark:border-dark-700/60"
    >
      <div
        class="flex items-center justify-between gap-3 border-b border-gray-200 px-3 py-2 text-xs font-medium dark:border-dark-700/60"
      >
        <span>{{ t("admin.riskGate.stages.hardRegex.rules") }}</span>
        <div class="flex gap-2">
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            @click="$emit('reset-builtin')"
          >
            {{ t("admin.riskGate.stages.hardRegex.resetBuiltin") }}</button
          ><button
            type="button"
            class="btn btn-secondary btn-sm"
            @click="addRule"
          >
            {{ t("admin.riskGate.actions.add") }}
          </button>
        </div>
      </div>
      <div v-if="!rules.length" class="px-3 py-5 text-xs text-gray-500">
        {{ t("admin.riskGate.stages.hardRegex.empty") }}
      </div>
      <div
        v-for="(rule, index) in rules"
        :key="rule.rule_key || rule.id || index"
        class="grid gap-2 border-b border-gray-100 px-3 py-3 last:border-b-0 dark:border-dark-800 sm:grid-cols-[auto_7rem_minmax(0,1fr)_auto_auto]"
        :class="{
          'bg-primary-50/50 dark:bg-primary-950/20':
            focusRule &&
            (rule.rule_key === focusRule || String(rule.id) === focusRule),
        }"
        :data-test="`hard-rule-${index}`"
        :data-rule-key="rule.rule_key || String(rule.id)"
      >
        <input
          type="checkbox"
          :checked="rule.enabled"
          :aria-label="t('admin.riskGate.stages.hardRegex.ruleEnabled')"
          @change="patchRule(index, { enabled: checked($event) })"
        /><select
          class="input"
          :value="displayCategory(rule.category)"
          :aria-label="t('admin.riskGate.rules.category')"
          :data-test="`rule-category-${index}`"
          @change="setRuleCategory(index, text($event) as Rule['category'])"
        >
          <option
            v-for="category in categories"
            :key="category"
            :value="category"
          >
            {{ t(`admin.riskGate.categories.${category}`) }}
          </option></select
        ><input
          class="input font-mono text-xs"
          :value="rule.pattern"
          :placeholder="t('admin.riskGate.stages.hardRegex.pattern')"
          @input="patchRule(index, { pattern: text($event) })"
        /><label class="flex items-center gap-1 text-xs"
          ><input
            type="checkbox"
            :checked="rule.is_regex"
            @change="patchRule(index, { is_regex: checked($event) })"
          />RE2</label
        ><button
          type="button"
          class="btn btn-ghost btn-sm text-red-600"
          @click="removeRule(index)"
        >
          {{ t("admin.riskGate.actions.remove") }}
        </button>
        <p
          v-if="validationErrors[index]"
          class="sm:col-span-5 text-xs text-red-600"
        >
          {{ validationErrors[index] }}
        </p>
      </div>
    </div>
    <label class="block space-y-2 text-xs">
      <span>{{ t("admin.riskGate.stages.hardRegex.extraPatterns") }}</span>
      <textarea :value="extraText" class="input min-h-28 w-full font-mono text-xs" rows="5" data-test="regex-extra-patterns" @input="updateExtra(text($event))" />
    </label>
    <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t("admin.riskGate.stages.hardRegex.engineHint") }}</p>
    <div class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
      <input
        class="input font-mono text-xs"
        :value="sample"
        :placeholder="t('admin.riskGate.stages.hardRegex.samplePlaceholder')"
        @input="$emit('update:sample', text($event))"
      /><button
        type="button"
        class="btn btn-secondary"
        :disabled="validating"
        @click="$emit('validate', sample)"
      >
        {{
          validating
            ? t("admin.riskGate.actions.loading")
            : t("admin.riskGate.stages.hardRegex.test")
        }}
      </button>
    </div>
    <p
      v-if="validationSummary"
      class="text-xs"
      :class="validationSummary.valid ? 'text-emerald-700' : 'text-red-700'"
    >
      {{
        validationSummary.valid
          ? t("admin.riskGate.stages.hardRegex.valid")
          : t("admin.riskGate.stages.hardRegex.invalid")
      }}
      <span v-if="validationSummary.matches.length"
        >·
        {{
          t("admin.riskGate.stages.hardRegex.matches", {
            count: validationSummary.matches.length,
          })
        }}</span
      >
    </p>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { RiskGateConfig, Rule, RuleValidationResult } from "../types";
import { cloneData, createDefaultRule } from "../viewModel";
const props = defineProps<{
  config: RiskGateConfig;
  rules: Rule[];
  focusRule: string | null;
  sample: string;
  validating: boolean;
  validation: RuleValidationResult | null;
}>();
const emit = defineEmits<{
  (event: "update", value: RiskGateConfig): void;
  (event: "update:rules", value: Rule[]): void;
  (event: "update:sample", value: string): void;
  (event: "validate", sample: string): void;
  (event: "reset-builtin"): void;
}>();
const { t } = useI18n();
const extraText = ref("");
watch(
  () => props.config.regex.patterns,
  (patterns) => {
    if (
      JSON.stringify(
        extraText.value
          .split("\n")
          .map((x) => x.trim())
          .filter(Boolean),
      ) !== JSON.stringify(patterns ?? [])
    )
      extraText.value = (patterns ?? []).join("\n");
  },
  { immediate: true, deep: true },
);
function updateExtra(text: string) {
  extraText.value = text;
  updateRegex({
    patterns: text
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean),
  });
}
function setOpenAI(enabled: boolean) {
  const next = cloneData(props.config);
  next.scope.openai_platform_enabled = enabled;
  emit("update", next);
}
const categories: Rule["category"][] = ["nsfw", "distill", "crack", "jailbreak", "custom"];
const legacyCategories: Rule["category"][] = ["sexual", "distill", "jailbreak", "bypass"];
function displayCategory(category: Rule["category"]): Rule["category"] {
  return category === "sexual" ? "nsfw" : category === "bypass" ? "crack" : category;
}
function setRuleCategory(index: number, selected: Rule["category"]) {
  const category = (props.config.schema_version ?? 1) < 2
    ? selected === "nsfw" ? "sexual" : selected === "crack" ? "bypass" : selected
    : selected;
  patchRule(index, { category });
}
const validationSummary = computed(() => props.validation);
const validationErrors = computed(
  () =>
    Object.fromEntries(
      (props.validation?.errors ?? []).map((error) => [
        error.index,
        error.message,
      ]),
    ) as Record<number, string>,
);
function checked(event: Event) {
  return (event.target as HTMLInputElement).checked;
}
function text(event: Event) {
  return (event.target as HTMLInputElement | HTMLSelectElement).value;
}
function update(partial: Partial<RiskGateConfig>) {
  emit("update", { ...props.config, ...partial });
}
function updateRegex(partial: Partial<RiskGateConfig["regex"]>) {
  update({ regex: { ...props.config.regex, ...partial } });
}
function toggleCategory(category: Rule["category"], event: Event) {
  const categories = props.config.regex.categories ?? [];
  updateRegex({
    categories: checked(event)
      ? [...categories, category]
      : categories.filter((item) => item !== category),
  });
}
function patchRule(index: number, partial: Partial<Rule>) {
  emit(
    "update:rules",
    props.rules.map((rule, position) =>
      position === index ? { ...rule, ...partial } : { ...rule },
    ),
  );
}
function addRule() {
  emit("update:rules", [
    ...props.rules,
    createDefaultRule(props.rules.length + 1),
  ]);
}
function removeRule(index: number) {
  emit(
    "update:rules",
    props.rules.filter((_, position) => position !== index),
  );
}
</script>
