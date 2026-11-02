<template>
  <section aria-labelledby="risk-gate-events-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-events-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.events.title") }}
        </h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.events.description") }}
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="btn btn-secondary btn-sm"
          :disabled="exporting"
          data-test="export-events"
          @click="$emit('export', cloneData(localFilters))"
        >
          {{
            exporting
              ? t("admin.riskGate.actions.exporting")
              : t("admin.riskGate.actions.exportCsv")
          }}
        </button>
        <button
          type="button"
          class="btn btn-danger btn-sm"
          :disabled="!filterReady"
          :title="
            filterReady
              ? undefined
              : t('admin.riskGate.events.filterDeleteNoFilter')
          "
          data-test="delete-by-filter"
          @click="$emit('delete-preview', cloneData(localFilters))"
        >
          {{ t("admin.riskGate.events.deleteByFilter") }}
        </button>
      </div>
    </div>

    <form
      class="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5"
      @submit.prevent="applyFilters"
    >
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.events.kind") }}</span>
        <select
          v-model="localFilters.kind"
          class="input mt-1 w-full"
          data-test="filter-kind"
          :aria-label="t('admin.riskGate.events.kind')"
          @change="filtersChanged"
        >
          <option value="">{{ t("common.all") }}</option>
          <option v-for="kind in kinds" :key="kind" :value="kind">
            {{ t(`admin.riskGate.events.kinds.${kind}`) }}
          </option>
        </select>
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.events.gate") }}</span>
        <select
          v-model="localFilters.gate"
          class="input mt-1 w-full"
          data-test="filter-gate"
          :aria-label="t('admin.riskGate.events.gate')"
          @change="filtersChanged"
        >
          <option value="">{{ t("common.all") }}</option>
          <option v-for="gate in gates" :key="gate" :value="gate">
            {{ t(`admin.riskGate.gates.${gate}`) }}
          </option>
        </select>
      </label>
      <FilterInput
        v-model="localFilters.provider"
        :label="t('admin.riskGate.events.provider')"
        test-id="filter-provider"
        @change="filtersChanged"
      />
      <FilterInput
        v-model="localFilters.request_id"
        :label="t('admin.riskGate.events.requestId')"
        test-id="filter-request-id"
        @change="filtersChanged"
      />
      <FilterInput
        v-model="localFilters.prompt_hash"
        :label="t('admin.riskGate.events.promptHash')"
        test-id="filter-prompt-hash"
        @change="filtersChanged"
      />
      <FilterInput
        v-model="localFilters.user_id"
        :label="t('admin.riskGate.events.userId')"
        type="number"
        test-id="filter-user-id"
        @change="filtersChanged"
      />
      <FilterInput
        v-model="localFilters.api_key_id"
        :label="t('admin.riskGate.events.apiKeyId')"
        type="number"
        test-id="filter-api-key-id"
        @change="filtersChanged"
      />
      <FilterInput
        v-model="localFilters.group_id"
        :label="t('admin.riskGate.events.groupId')"
        type="number"
        test-id="filter-group-id"
        @change="filtersChanged"
      />
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.events.from") }}</span>
        <input
          v-model="localFilters.from"
          type="datetime-local"
          class="input mt-1 w-full"
          data-test="filter-from"
          :aria-label="t('admin.riskGate.events.from')"
          @change="filtersChanged"
        />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.events.to") }}</span>
        <input
          v-model="localFilters.to"
          type="datetime-local"
          class="input mt-1 w-full"
          data-test="filter-to"
          :aria-label="t('admin.riskGate.events.to')"
          @change="filtersChanged"
        />
      </label>
      <div class="flex items-end gap-2 sm:col-span-2">
        <button type="submit" class="btn btn-primary btn-sm">
          {{ t("common.search") }}
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          data-test="reset-filters"
          @click="resetFilters"
        >
          {{ t("common.reset") }}
        </button>
      </div>
    </form>

    <div
      v-if="error"
      role="alert"
      class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300"
    >
      {{ error }}
    </div>

    <div
      class="mt-5 overflow-x-auto rounded-xl border border-gray-200 dark:border-dark-700/60"
    >
      <table class="w-full min-w-[1080px] text-left text-sm">
        <thead
          class="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-dark-900/70 dark:text-dark-400"
        >
          <tr>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.time") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.route") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.result") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.action") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.score") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.events.evidence") }}
            </th>
            <th class="px-3 py-3 text-right font-medium">
              {{ t("admin.riskGate.events.view") }}
            </th>
          </tr>
        </thead>
        <tbody
          class="divide-y divide-gray-100 bg-white dark:divide-dark-700 dark:bg-transparent"
        >
          <tr v-if="loading">
            <td
              colspan="7"
              class="px-4 py-10 text-center text-gray-500"
              aria-busy="true"
            >
              {{ t("common.loading") }}
            </td>
          </tr>
          <tr v-else-if="events.length === 0">
            <td
              colspan="7"
              class="px-4 py-10 text-center text-gray-500"
              data-test="events-empty"
            >
              {{ t("admin.riskGate.events.empty") }}
            </td>
          </tr>
          <tr
            v-for="row in events"
            v-else
            :key="row.id"
            :data-test="`event-${row.id}`"
            class="align-top"
          >
            <td
              class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300"
            >
              {{ formatDate(row.created_at) }}
            </td>
            <td class="px-3 py-3">
              <p class="font-medium text-gray-900 dark:text-white">
                {{ row.endpoint }}
              </p>
              <p class="mt-1 text-xs text-gray-500">
                {{ row.provider }} · {{ row.model }} · {{ row.protocol }}
              </p>
            </td>
            <td class="px-3 py-3">
              <span
                class="rounded-full px-2 py-0.5 text-xs font-medium"
                :class="outcomeClass(row)"
                >{{ t(`admin.riskGate.feed.${eventOutcome(row)}`) }}</span
              >
              <p class="mt-1 text-xs text-gray-500">{{ row.gate || "—" }}</p>
            </td>
            <td class="px-3 py-3 text-xs text-gray-600 dark:text-dark-300">
              {{ actionLabel(row.action) }}
            </td>
            <td class="px-3 py-3 tabular-nums text-gray-700 dark:text-dark-200">
              {{ row.score }}
            </td>
            <td class="max-w-xs px-3 py-3">
              <p
                class="line-clamp-2 break-words text-gray-600 dark:text-dark-300"
              >
                {{ row.evidence || "—" }}
              </p>
            </td>
            <td class="whitespace-nowrap px-3 py-3 text-right">
              <button
                type="button"
                class="btn btn-ghost btn-sm"
                :data-test="`view-event-${row.id}`"
                @click="$emit('view', row.id)"
              >
                {{ t("admin.riskGate.events.view") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <Pagination
        :total="total"
        :page="page"
        :page-size="pageSize"
        @update:page="$emit('page', $event)"
        @update:page-size="$emit('page-size', $event)"
      />
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, reactive, watch } from "vue";
import { useI18n } from "vue-i18n";
import Pagination from "@/components/common/Pagination.vue";
import type { EventFilter, EventRow } from "../types";
import {
  cloneData,
  emptyEventFilter,
  hasEventFilter,
  eventOutcome,
} from "../viewModel";

const props = defineProps<{
  events: EventRow[];
  total: number;
  page: number;
  pageSize: number;
  filter: EventFilter;
  loading: boolean;
  error: string;
  exporting: boolean;
}>();
const emit = defineEmits<{
  (event: "filters-change", value: EventFilter): void;
  (event: "search", value: EventFilter): void;
  (event: "page", value: number): void;
  (event: "page-size", value: number): void;
  (event: "view", id: number): void;
  (event: "delete-preview", value: EventFilter): void;
  (event: "export", value: EventFilter): void;
}>();
const { t, locale } = useI18n();

const kinds = [
  "blocked",
  "allowed",
  "upstream_pass",
  "upstream_refusal",
] as const;
const gates = [
  "ban",
  "distill",
  "regex",
  "refusal_cache",
  "decision_model",
] as const;

const localFilters = reactive<EventFilter>(cloneData(props.filter));
watch(
  () => props.filter,
  (value) => Object.assign(localFilters, cloneData(value)),
  { deep: true },
);

// 没有任何条件时后端会 400，这里提前禁用「按条件删除」。
const filterReady = computed(() => hasEventFilter(localFilters));

const FilterInput = defineComponent({
  props: {
    modelValue: { type: String, required: true },
    label: { type: String, required: true },
    type: { type: String, default: "text" },
    testId: { type: String, default: "" },
  },
  emits: ["update:modelValue", "change"],
  setup(componentProps, { emit: componentEmit }) {
    return () =>
      h("label", { class: "text-xs text-gray-600 dark:text-dark-200" }, [
        h("span", componentProps.label),
        h("input", {
          value: componentProps.modelValue,
          type: componentProps.type,
          class: "input mt-1 w-full",
          "aria-label": componentProps.label,
          "data-test": componentProps.testId || undefined,
          onInput: (event: Event) =>
            componentEmit(
              "update:modelValue",
              (event.target as HTMLInputElement).value,
            ),
          onChange: () => componentEmit("change"),
        }),
      ]);
  },
});

function filtersChanged() {
  emit("filters-change", cloneData(localFilters));
}
function applyFilters() {
  const value = cloneData(localFilters);
  emit("filters-change", value);
  emit("search", value);
}
function resetFilters() {
  Object.assign(localFilters, emptyEventFilter());
  applyFilters();
}

function outcomeClass(row: EventRow): string {
  const outcome = eventOutcome(row);
  const kind =
    outcome === "observe"
      ? "upstream_pass"
      : outcome === "upstreamRefusal"
        ? "upstream_refusal"
        : row.kind;
  if (kind === "blocked" || kind === "upstream_refusal")
    return "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300";
  if (kind === "upstream_pass")
    return "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300";
  return "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300";
}

function actionLabel(action: string): string {
  if (action === "none" || action === "banned" || action === "would_block") {
    return t(`admin.riskGate.events.actions.${action}`);
  }
  return action || "—";
}

function formatDate(value: string): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}
</script>
