<template>
  <section class="overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20" data-test="hit-summary">
    <header class="border-b border-gray-200 px-4 py-3 dark:border-dark-700/60">
      <h3 class="text-sm font-semibold">{{ title }}</h3>
      <p v-if="hint" class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ hint }}</p>
    </header>
    <div class="max-h-[34rem] overflow-y-auto">
    <p v-if="loading" class="p-4 text-sm text-gray-500" aria-busy="true">
      {{ t("common.loading") }}
    </p>
    <p v-else-if="error" role="alert" class="p-4 text-sm text-red-700 dark:text-red-300">{{ error }}</p>
    <p v-else-if="!rows.length" class="p-4 text-sm text-gray-500">
      {{ empty }}
    </p>
    <ul v-else class="divide-y divide-gray-100 dark:divide-dark-700">
      <li
        v-for="(row, index) in rows"
        :key="`${row.gate}:${row.rule_key || row.rule_id}:${index}`"
        class="relative isolate flex items-center gap-3 px-4 py-2.5"
      >
        <span
          aria-hidden="true"
          class="absolute inset-y-1 left-0 -z-10 rounded-r-md bg-gray-50 dark:bg-dark-800/70"
          :style="{ width: `${Math.max(2, (row.count / maximum) * 100)}%` }"
        />
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm">
            <span v-if="showSource" class="mr-2 text-xs text-gray-500">{{
              gateLabel(row.gate)
            }}</span
            ><span class="font-mono text-xs">{{
              keywordLabel(row)
            }}</span
            ><span
              v-if="row.action === 'would_block'"
              class="ml-2 rounded bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950/50 dark:text-amber-300"
              >{{ t("admin.riskGate.feed.observe") }}</span
            >
          </p>
          <p
            v-if="row.pattern"
            class="mt-0.5 truncate font-mono text-xs text-gray-500"
            :title="row.pattern"
          >
            {{ row.pattern }}
          </p>
        </div>
        <span class="text-sm font-medium tabular-nums">{{
          row.count.toLocaleString()
        }}</span>
        <button
          v-if="row.rule_key || row.rule_id"
          type="button"
          class="btn btn-ghost btn-sm shrink-0 text-xs"
          :data-test="`focus-rule-${row.rule_key || row.rule_id}`"
          @click="$emit('focus-rule', row.rule_key || String(row.rule_id))"
        >
          {{ t("admin.riskGate.feed.focusRule") }}</button
        ><button
          v-else-if="showSource"
          type="button"
          class="btn btn-ghost btn-sm"
          :aria-label="gateLabel(row.gate)"
          @click="$emit('stage', stageOf(row.gate))"
        >
          ↗
        </button>
      </li>
    </ul>
    </div>
  </section>
</template>
<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { GateHitRow, RiskGateView } from "../types";
const props = defineProps<{
  rows: GateHitRow[];
  title: string;
  hint: string;
  empty: string;
  error: string;
  loading: boolean;
  showSource: boolean;
}>();
defineEmits<{
  (event: "focus-rule", rule: string): void;
  (event: "stage", view: RiskGateView): void;
}>();
const { t } = useI18n();
const maximum = computed(() =>
  Math.max(1, ...props.rows.map((row) => row.count)),
);
function keywordLabel(row: GateHitRow): string {
  if (row.gate === "refusal_cache" && ["exact", "similar", "device"].includes(row.keyword))
    return t(`admin.riskGate.hits.refusal.${row.keyword}`);
  return row.keyword || row.category || "—";
}
function stageOf(gate: string): RiskGateView {
  return (
    (
      {
        distill: "distill",
        regex: "hard-regex",
        refusal_cache: "refusal",
        decision_model: "jev",
      } as Record<string, RiskGateView>
    )[gate] ?? "all"
  );
}
function gateLabel(gate: string) {
  return gate === "ban"
    ? t("admin.riskGate.gates.ban")
    : t(`admin.riskGate.rail.${stageOf(gate)}`);
}
</script>
