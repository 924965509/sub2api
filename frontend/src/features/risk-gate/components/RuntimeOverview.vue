<template>
  <section
    aria-labelledby="risk-gate-runtime-title"
    class="border-b border-gray-200 py-6 dark:border-dark-700/60"
  >
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-runtime-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.runtime.title") }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.runtime.description") }}
        </p>
      </div>
      <button
        type="button"
        class="btn btn-secondary btn-sm"
        :disabled="loading"
        data-test="refresh-status"
        @click="$emit('refresh')"
      >
        {{ t("admin.riskGate.actions.refresh") }}
      </button>
    </div>

    <div
      v-if="error"
      role="alert"
      class="mt-5 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300"
    >
      {{ error }}
    </div>
    <div
      v-else-if="loading && !status"
      class="mt-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5"
      aria-busy="true"
    >
      <div
        v-for="index in 9"
        :key="index"
        class="h-16 animate-pulse rounded-xl bg-gray-100 dark:bg-dark-800"
      />
    </div>
    <template v-else-if="status">
      <dl class="mt-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <div
          v-for="card in cards"
          :key="card.key"
          :data-test="`status-card-${card.key}`"
          class="rounded-xl border border-gray-100 bg-gray-50/80 px-3 py-3 dark:border-dark-700/60 dark:bg-dark-900/40"
        >
          <dt class="text-xs text-gray-500 dark:text-dark-400">
            {{ t(card.labelKey) }}
          </dt>
          <dd
            class="mt-1.5 truncate text-sm font-semibold"
            :class="toneClass(card.tone)"
            :title="display(card.value)"
          >
            {{ display(card.value) }}
          </dd>
        </div>
      </dl>

      <div
        class="mt-4 rounded-xl border border-gray-100 px-4 py-3 dark:border-dark-700/60 dark:bg-dark-900/20"
      >
        <h3 class="text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.runtime.counters") }}
        </h3>
        <div class="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-6">
          <div
            v-for="item in counters"
            :key="item.key"
            class="rounded-lg bg-gray-50 px-2.5 py-2 dark:bg-dark-900/60"
          >
            <p class="text-[11px] text-gray-500 dark:text-dark-400">
              {{ t(item.labelKey) }}
            </p>
            <p
              class="mt-0.5 text-sm font-semibold tabular-nums text-gray-900 dark:text-white"
            >
              {{ item.value }}
            </p>
          </div>
        </div>
        <p class="mt-3 text-xs text-gray-500 dark:text-dark-400">
          {{
            t("admin.riskGate.runtime.checkedAt", {
              time: formatDate(status.checked_at),
            })
          }}
        </p>
      </div>
    </template>
    <p
      v-else
      class="mt-5 rounded-xl border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500 dark:border-dark-600 dark:text-dark-400"
    >
      {{ t("admin.riskGate.runtime.none") }}
    </p>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { StatusSnapshot } from "../types";
import { counterItems, statusCards } from "../viewModel";

const props = defineProps<{
  status: StatusSnapshot | null;
  loading: boolean;
  error: string;
}>();
defineEmits<{ (event: "refresh"): void }>();
const { t, locale } = useI18n();

const cards = computed(() => statusCards(props.status));
const counters = computed(() => counterItems(props.status));

// 卡片值里可能塞的是 i18n key（模式、无错误文案），统一在这里翻译。
function display(value: string | number): string {
  return typeof value === "string" && value.startsWith("admin.")
    ? t(value)
    : String(value);
}

function toneClass(tone: "neutral" | "warn" | "danger"): string {
  if (tone === "danger") return "text-red-600 dark:text-red-300";
  if (tone === "warn") return "text-amber-600 dark:text-amber-300";
  return "text-gray-900 dark:text-white";
}

function formatDate(value: string): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}
</script>
