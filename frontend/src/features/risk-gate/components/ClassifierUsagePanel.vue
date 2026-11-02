<template>
  <section
    class="rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20"
    data-test="classifier-usage"
  >
    <button
      type="button"
      class="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      :aria-expanded="open"
      @click="open = !open"
    >
      <span
        ><span class="text-sm font-semibold">{{
          t("admin.riskGate.usage.title")
        }}</span
        ><span class="ml-2 text-xs text-gray-500 dark:text-dark-400">{{
          t("admin.riskGate.usage.foldHint")
        }}</span></span
      ><span aria-hidden="true">{{ open ? "−" : "+" }}</span>
    </button>
    <div
      v-if="open"
      class="space-y-4 border-t border-gray-200 px-4 py-4 dark:border-dark-700/60"
    >
      <p
        v-if="error"
        role="alert"
        class="text-sm text-red-700 dark:text-red-300"
      >
        {{ t("admin.riskGate.usage.loadError") }}
      </p>
      <p v-else-if="loading" class="text-sm text-gray-500">
        {{ t("admin.riskGate.usage.loading") }}
      </p>
      <template v-else-if="usage">
        <div class="grid gap-3 text-xs sm:grid-cols-4">
          <div>
            <span class="block text-gray-500">{{
              t("admin.riskGate.usage.todayCalls")
            }}</span
            ><strong>{{ usage.today.requests.toLocaleString() }}</strong>
          </div>
          <div>
            <span class="block text-gray-500">{{
              t("admin.riskGate.usage.lifetimeCalls")
            }}</span
            ><strong>{{ usage.summary.requests.toLocaleString() }}</strong>
          </div>
          <div>
            <span class="block text-gray-500">{{
              t("admin.riskGate.usage.tokens")
            }}</span
            ><strong
              >{{ usage.summary.input_tokens.toLocaleString() }} /
              {{ usage.summary.output_tokens.toLocaleString() }}</strong
            >
          </div>
          <div>
            <span class="block text-gray-500">{{
              t("admin.riskGate.usage.cost")
            }}</span
            ><strong>{{ money(usage.summary.estimated_cost_nano_usd) }}</strong>
          </div>
        </div>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{
            t("admin.riskGate.usage.unknown", {
              calls: usage.summary.unknown_usage_requests,
              costs: usage.summary.unknown_cost_requests,
            })
          }}
        </p>
        <div class="max-h-80 overflow-auto">
          <table class="min-w-full text-left text-xs">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-700/60">
                <th class="px-2 py-2">{{ t("admin.riskGate.usage.time") }}</th>
                <th class="px-2 py-2">{{ t("admin.riskGate.usage.key") }}</th>
                <th class="px-2 py-2">{{ t("admin.riskGate.usage.model") }}</th>
                <th class="px-2 py-2">
                  {{ t("admin.riskGate.usage.outcome") }}
                </th>
                <th class="px-2 py-2">{{ t("admin.riskGate.usage.cost") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in usage.items"
                :key="row.id"
                class="border-b border-gray-100 dark:border-dark-800"
              >
                <td class="whitespace-nowrap px-2 py-2">
                  {{ formatDate(row.created_at) }}
                </td>
                <td class="px-2 py-2 font-mono">
                  {{ row.key_fingerprint || t("admin.riskGate.usage.noKey") }}
                </td>
                <td class="px-2 py-2">{{ row.model || "—" }}</td>
                <td class="px-2 py-2">
                  {{
                    row.http_status ?? t("admin.riskGate.usage.networkFailure")
                  }}
                  · {{ row.outcome || "—" }}
                </td>
                <td class="px-2 py-2">
                  {{ money(row.estimated_cost_nano_usd) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="!usage.items.length" class="text-sm text-gray-500">
          {{ t("admin.riskGate.usage.empty") }}
        </p>
        <button
          v-if="usage.page < usage.pages"
          type="button"
          class="btn btn-secondary btn-sm"
          @click="$emit('next-page')"
        >
          {{ t("admin.riskGate.usage.more") }}
        </button>
      </template>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import type { ClassifierUsagePage } from "../types";
defineProps<{
  usage: ClassifierUsagePage | null;
  loading: boolean;
  error: string;
}>();
defineEmits<{ (event: "next-page"): void }>();
const { t, locale } = useI18n();
const open = ref(false);
function money(value: number | null | undefined) {
  return value === null || value === undefined
    ? t("admin.riskGate.usage.unknownCost")
    : `$${(value / 1_000_000_000).toFixed(8)}`;
}
function formatDate(value: string) {
  return value
    ? new Intl.DateTimeFormat(locale.value, {
        dateStyle: "short",
        timeStyle: "medium",
      }).format(new Date(value))
    : "—";
}
</script>
