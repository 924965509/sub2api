<template>
  <section class="space-y-8" data-test="distill-settings">
    <section class="space-y-3">
      <div>
        <h3 class="text-sm font-medium">{{ t("admin.riskGate.stages.distill.title") }}</h3>
        <p class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t("admin.riskGate.stages.distill.description") }}</p>
      </div>
      <div class="grid overflow-hidden rounded-xl border border-gray-200 dark:border-dark-700/60 md:grid-cols-2">
        <label class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700/60 md:border-r">
          <span>{{ t("admin.riskGate.stages.distill.enabled") }}</span>
          <input type="checkbox" :checked="config.gates.distill" :aria-label="t('admin.riskGate.stages.distill.enabled')" data-test="distill-enabled" @change="toggleGate" />
        </label>
        <label v-for="(field, index) in toggleFields" :key="field.key" class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700/60" :class="{ 'md:border-r': index % 2 === 1 }">
          <span>{{ t(`admin.riskGate.stages.distill.${field.label}`) }}</span>
          <input type="checkbox" :checked="config.distill[field.key]" :aria-label="t(`admin.riskGate.stages.distill.${field.label}`)" @change="setDistill({ [field.key]: checked($event) })" />
        </label>
        <label class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700/60">
          <span>{{ t("admin.riskGate.stages.distill.minMaxTokens") }}</span>
          <input class="input w-24 text-right tabular-nums" type="number" min="0" :aria-label="t('admin.riskGate.stages.distill.minMaxTokens')" :value="config.distill.min_max_tokens" @input="setDistill({ min_max_tokens: number($event) })" />
        </label>
        <label class="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm md:col-span-2">
          <span>{{ t("admin.riskGate.stages.distill.contestPattern") }}</span>
          <input class="input w-full font-mono text-xs sm:w-72" :aria-label="t('admin.riskGate.stages.distill.contestPattern')" :value="config.distill.contest_pattern" @input="setDistill({ contest_pattern: text($event) })" />
        </label>
      </div>
    </section>
    <section class="space-y-3">
      <h3 class="text-sm font-medium">{{ t("admin.riskGate.stages.distill.rulesTitle") }}</h3>
      <div class="divide-y divide-gray-200 overflow-hidden rounded-xl border border-gray-200 dark:divide-dark-700/60 dark:border-dark-700/60">
        <details v-for="field in listFields" :key="field.key" :data-test="`distill-fold-${field.key}`">
          <summary class="cursor-pointer px-4 py-3 text-sm hover:bg-gray-50 dark:hover:bg-dark-800/50">
            {{ t(`admin.riskGate.stages.distill.${field.label}`) }}
            <span class="ml-3 text-xs text-gray-500 dark:text-dark-400">{{ t("admin.riskGate.stages.distill.ruleCount", { count: parsed(field.key, listText[field.key]).length }) }}</span>
          </summary>
          <div class="space-y-2 border-t border-gray-200 px-4 py-3 dark:border-dark-700/60">
            <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">{{ t(field.key === 'fingerprints' ? 'admin.riskGate.stages.distill.fingerprintHint' : 'admin.riskGate.stages.distill.lineHint') }}</p>
            <textarea class="input min-h-36 w-full font-mono text-xs" :value="listText[field.key]" :data-test="`distill-${field.key}`" :aria-label="t(`admin.riskGate.stages.distill.${field.label}`)" @input="setList(field.key, $event)" />
          </div>
        </details>
      </div>
    </section>
    <section class="space-y-3">
      <h3 class="text-sm font-medium">{{ t("admin.riskGate.stages.distill.responseFold") }}</h3>
      <div class="grid gap-3 sm:grid-cols-[8rem_minmax(0,1fr)_minmax(0,1fr)]">
        <label v-for="field in errorFields" :key="field" class="space-y-1.5 text-xs" :class="{ 'sm:col-span-3': field === 'message' }">
          <span class="block">{{ t(`admin.riskGate.stages.distill.error.${field}`) }}</span>
          <input class="input w-full" :class="{ 'font-mono': field !== 'message' }" :type="field === 'status' ? 'number' : 'text'" :min="field === 'status' ? 400 : undefined" :max="field === 'status' ? 599 : undefined" :value="config.distill.error?.[field]" @input="setError(field, $event)" />
        </label>
      </div>
    </section>
  </section>
</template>

<script setup lang="ts">
import { reactive, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { DistillConfig, RiskGateConfig } from "../types";
import { formatFingerprintList, parseFingerprintList } from "../viewModel";
const props = defineProps<{ config: RiskGateConfig }>();
const emit = defineEmits<{ (event: "update", value: RiskGateConfig): void }>();
const { t } = useI18n();
const errorFields = ["status", "code", "type", "message"] as const;
const toggleFields = [
  { key: "skip_official", label: "skipOfficial" },
  { key: "skip_zero", label: "skipZero" },
  { key: "require_no_tools", label: "requireNoTools" },
  { key: "require_single_turn", label: "requireSingleTurn" },
] as const;
const listFields = [
  { key: "hard_needles", label: "hardNeedles" },
  { key: "needles", label: "needles" },
  { key: "patterns", label: "patterns" },
  { key: "fingerprints", label: "fingerprints" },
] as const;
type ListField = (typeof listFields)[number]["key"];
// Keep the editor's raw newlines locally. Parent draft normalization must not
// remove the newline the user just typed or split regex quantifiers on commas.
const listText = reactive<Record<ListField, string>>({ hard_needles: "", needles: "", patterns: "", fingerprints: "" });
function parsed(field: ListField, value: string): string[] {
  return field === "fingerprints" ? parseFingerprintList(value) : value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}
watch(() => props.config.distill, (value) => {
  for (const { key } of listFields) {
    const entries = value[key] ?? [];
    if (JSON.stringify(parsed(key, listText[key])) !== JSON.stringify(entries))
      listText[key] = key === "fingerprints" ? formatFingerprintList(entries) : entries.join("\n");
  }
}, { immediate: true, deep: true });
function update(partial: Partial<RiskGateConfig>) { emit("update", { ...props.config, ...partial }); }
function setDistill(partial: Partial<DistillConfig>) { update({ distill: { ...props.config.distill, ...partial } }); }
function setList(field: ListField, event: Event) {
  listText[field] = text(event);
  setDistill({ [field]: parsed(field, listText[field]) });
}
function setError(field: (typeof errorFields)[number], event: Event) {
  setDistill({ error: {
    status: props.config.distill.error?.status ?? 403,
    type: props.config.distill.error?.type ?? "",
    code: props.config.distill.error?.code ?? "",
    message: props.config.distill.error?.message ?? "",
    [field]: field === "status" ? number(event) : text(event),
  } });
}
function toggleGate(event: Event) { update({ gates: { ...props.config.gates, distill: checked(event) } }); }
function checked(event: Event) { return (event.target as HTMLInputElement).checked; }
function text(event: Event) { return (event.target as HTMLInputElement | HTMLTextAreaElement).value; }
function number(event: Event) { return Number(text(event)); }
</script>
