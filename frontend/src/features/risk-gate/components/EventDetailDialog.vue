<template>
  <BaseDialog
    :show="show"
    :title="t('admin.riskGate.events.detailTitle')"
    width="wide"
    @close="$emit('close')"
  >
    <div
      v-if="loading"
      class="py-10 text-center text-sm text-gray-500"
      aria-busy="true"
    >
      {{ t("common.loading") }}
    </div>
    <div v-else-if="event" class="space-y-5">
      <div
        class="flex flex-wrap items-start justify-between gap-3 rounded-xl border p-4"
        :class="outcomeClass"
      >
        <div>
          <p class="text-base font-semibold">{{ outcomeLabel }}</p>
          <p class="mt-1 text-sm">
            {{ gateLabel(event.gate)
            }}<span v-if="event.category"> · {{ event.category }}</span>
          </p>
          <p class="mt-2 break-words text-xs leading-5">
            {{ event.reason || "—" }}
          </p>
        </div>
        <span class="text-xs">{{ formatDate(event.created_at) }}</span>
      </div>
      <section class="space-y-2">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold">
            {{ t("admin.riskGate.events.detail.evidence") }}
          </h3>
          <button
            v-if="event.rule_key || event.rule_id"
            type="button"
            class="btn btn-secondary btn-sm"
            data-test="detail-locate-rule"
            @click="locateRule"
          >
            {{ t("admin.riskGate.feed.focusRule") }}
          </button>
        </div>
        <pre
          class="max-h-64 overflow-y-auto whitespace-pre-wrap break-words rounded-xl border border-gray-200 bg-gray-50 p-4 font-mono text-xs leading-6 text-gray-800 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-100"
          data-test="event-evidence"
          >{{ event.evidence || "—" }}</pre>
        <p class="text-xs leading-5 text-gray-500">
          {{ t("admin.riskGate.events.detail.evidenceHint") }}
        </p>
      </section>
      <section v-if="event.pattern" class="space-y-2">
        <h3 class="text-sm font-semibold">
          {{ t("admin.riskGate.detailExtras.ruleSnapshot") }}
        </h3>
        <pre
          class="whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-3 font-mono text-xs dark:bg-dark-900"
          >{{ event.pattern }}</pre>
        <p class="text-xs text-gray-500">
          {{ t("admin.riskGate.detailExtras.ruleSnapshotHint") }}
        </p>
      </section>
      <section
        v-if="event.scores && Object.keys(event.scores).length"
        class="space-y-2"
      >
        <h3 class="text-sm font-semibold">
          {{ t("admin.riskGate.detailExtras.questionScores") }}
        </h3>
        <dl class="grid gap-2 sm:grid-cols-3">
          <div
            v-for="(score, question) in event.scores"
            :key="question"
            class="rounded-lg border border-gray-200 px-3 py-2 dark:border-dark-700"
          >
            <dt class="break-all font-mono text-xs text-gray-500">
              {{ question }}
            </dt>
            <dd class="mt-1 text-lg font-semibold tabular-nums">{{ score }}</dd>
          </div>
        </dl>
      </section>
      <details
        v-if="event.user_preview || event.submitted_text"
        class="rounded-xl border border-gray-200 dark:border-dark-700"
      >
        <summary class="cursor-pointer px-4 py-3 text-sm font-medium">
          {{ t("admin.riskGate.detailExtras.redactedContext") }}
        </summary>
        <div
          class="space-y-3 border-t border-gray-200 p-4 dark:border-dark-700"
        >
          <p class="text-xs leading-5 text-gray-500">
            {{ t("admin.riskGate.detailExtras.contextHint") }}
          </p>
          <pre
            class="max-h-80 overflow-y-auto whitespace-pre-wrap break-words font-mono text-xs leading-6"
            >{{ event.submitted_text || event.user_preview }}</pre>
        </div>
      </details>
      <details class="rounded-xl border border-gray-200 dark:border-dark-700">
        <summary class="cursor-pointer px-4 py-3 text-sm font-medium">
          {{ t("admin.riskGate.detailExtras.requestMetadata") }}
        </summary>
        <dl
          class="grid gap-4 border-t border-gray-200 p-4 text-xs dark:border-dark-700 sm:grid-cols-2"
        >
          <div
            v-for="item in metadata"
            :key="item.label"
            :class="{ 'sm:col-span-2': item.wide }"
          >
            <dt class="text-gray-500">{{ item.label }}</dt>
            <dd class="mt-1 break-all font-mono leading-5">{{ item.value }}</dd>
          </div>
        </dl>
      </details>
    </div>
    <template #footer
      ><div class="flex justify-end">
        <button
          type="button"
          class="btn btn-secondary"
          data-test="close-event-detail"
          @click="$emit('close')"
        >
          {{ t("admin.riskGate.events.detail.close") }}
        </button>
      </div></template
    >
  </BaseDialog>
</template>
<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import BaseDialog from "@/components/common/BaseDialog.vue";
import type { EventRow } from "../types";
import { eventOutcome } from "../viewModel";
const props = defineProps<{
  show: boolean;
  event: EventRow | null;
  loading: boolean;
}>();
const emit = defineEmits<{
  (event: "close"): void;
  (event: "focus-rule", key: string): void;
}>();
const { t, locale } = useI18n();
const outcome = computed(() =>
  props.event ? eventOutcome(props.event) : "passed",
);
const outcomeLabel = computed(() => t(`admin.riskGate.feed.${outcome.value}`));
const outcomeClass = computed(() =>
  outcome.value === "blocked"
    ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/30 dark:text-red-200"
    : outcome.value === "passed"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200"
      : "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200",
);
const metadata = computed(() => {
  const row = props.event;
  if (!row) return [];
  return [
    {
      label: t("admin.riskGate.events.detail.requestId"),
      value: row.request_id,
      wide: true,
    },
    {
      label: t("admin.riskGate.events.detail.promptHash"),
      value: row.prompt_hash,
      wide: true,
    },
    {
      label: t("admin.riskGate.events.detail.identity"),
      value: `user ${row.user_id} · key ${row.api_key_id} · group ${row.group_id ?? "—"}`,
    },
    {
      label: t("admin.riskGate.events.detail.route"),
      value: `${row.provider} · ${row.endpoint} · ${row.model} · ${row.protocol}`,
    },
    {
      label: t("admin.riskGate.events.detail.ruleId"),
      value: row.rule_key || row.rule_id || "—",
    },
    {
      label: t("admin.riskGate.events.detail.action"),
      value: ["none", "banned", "would_block"].includes(row.action)
        ? t(`admin.riskGate.events.actions.${row.action}`)
        : row.action || "—",
    },
    {
      label: t("admin.riskGate.config.ban.scopeClientFingerprint"),
      value: row.client_fingerprint || "—",
      wide: true,
    },
  ];
});
function gateLabel(gate: string) {
  const key = `admin.riskGate.gates.${gate}`;
  const value = t(key);
  return value === key ? gate || "—" : value;
}
function locateRule() {
  const row = props.event;
  if (!row) return;
  emit("close");
  emit("focus-rule", row.rule_key || String(row.rule_id));
}
function formatDate(value: string) {
  return value
    ? new Intl.DateTimeFormat(locale.value, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(new Date(value))
    : "—";
}
</script>
