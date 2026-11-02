<template>
  <section aria-labelledby="risk-gate-refusals-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-refusals-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.refusals.title") }}
        </h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.refusals.description") }}
        </p>
      </div>
      <button
        type="button"
        class="btn btn-danger btn-sm"
        :disabled="total === 0"
        data-test="clear-refusals"
        @click="showClear = true"
      >
        {{ t("admin.riskGate.refusals.clearAll") }}
      </button>
    </div>

    <div class="mt-5 grid gap-3 sm:grid-cols-3">
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.refusals.provider") }}</span>
        <input
          v-model="local.provider"
          class="input mt-1 w-full"
          data-test="refusal-provider"
          :aria-label="t('admin.riskGate.refusals.filterProvider')"
          @input="filtersChanged"
        />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.refusals.source") }}</span>
        <select
          v-model="local.source"
          class="input mt-1 w-full"
          data-test="refusal-source"
          :aria-label="t('admin.riskGate.refusals.filterSource')"
          @change="filtersChanged"
        >
          <option value="">{{ t("common.all") }}</option>
          <option value="upstream_refusal">
            {{ t("admin.riskGate.refusals.sources.upstream_refusal") }}
          </option>
          <option value="silent_refusal">
            {{ t("admin.riskGate.refusals.sources.silent_refusal") }}
          </option>
        </select>
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t("admin.riskGate.refusals.promptHash") }}</span>
        <input
          v-model="local.prompt_hash"
          class="input mt-1 w-full font-mono text-xs"
          data-test="refusal-prompt-hash"
          :aria-label="t('admin.riskGate.refusals.filterPromptHash')"
          @input="filtersChanged"
        />
      </label>
    </div>

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
      <table class="w-full min-w-[900px] text-left text-sm">
        <thead
          class="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-dark-900/70 dark:text-dark-400"
        >
          <tr>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.provider") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.model") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.promptHash") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.normalizedPrompt") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.source") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.refusals.createdAt") }}
            </th>
            <th class="px-3 py-3 text-right font-medium">
              {{ t("admin.riskGate.refusals.delete") }}
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
          <tr v-else-if="refusals.length === 0">
            <td
              colspan="7"
              class="px-4 py-10 text-center text-gray-500"
              data-test="refusals-empty"
            >
              {{ t("admin.riskGate.refusals.empty") }}
            </td>
          </tr>
          <tr
            v-for="row in refusals"
            v-else
            :key="row.id"
            :data-test="`refusal-${row.id}`"
            class="align-top"
          >
            <td class="px-3 py-3 text-gray-700 dark:text-dark-200">
              {{ row.provider }}
            </td>
            <td class="px-3 py-3 text-gray-700 dark:text-dark-200">
              {{ row.model || "—" }}
            </td>
            <td
              class="px-3 py-3 font-mono text-xs text-gray-600 dark:text-dark-300"
            >
              {{ shortHash(row.prompt_hash) }}
            </td>
            <td class="max-w-md px-3 py-3">
              <p
                class="line-clamp-2 break-words text-gray-600 dark:text-dark-300"
              >
                {{ row.normalized_prompt || "—" }}
              </p>
            </td>
            <td class="px-3 py-3 text-xs text-gray-600 dark:text-dark-300">
              {{ sourceLabel(row.source) }}
            </td>
            <td
              class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300"
            >
              {{ formatDate(row.created_at) }}
            </td>
            <td class="whitespace-nowrap px-3 py-3 text-right">
              <button
                type="button"
                class="btn btn-ghost btn-sm text-red-600 dark:text-red-300"
                :data-test="`delete-refusal-${row.id}`"
                @click="pendingDelete = row"
              >
                {{ t("admin.riskGate.refusals.delete") }}
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

    <ConfirmDialog
      :show="Boolean(pendingDelete)"
      :title="t('admin.riskGate.refusals.deleteConfirmTitle')"
      :message="t('admin.riskGate.refusals.deleteConfirmMessage')"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmDelete"
      @cancel="pendingDelete = null"
    />
    <ConfirmDialog
      :show="showClear"
      :title="t('admin.riskGate.refusals.clearConfirmTitle')"
      :message="
        t('admin.riskGate.refusals.clearConfirmMessage', { count: total })
      "
      :confirm-text="t('admin.riskGate.refusals.clearAll')"
      danger
      @confirm="confirmClear"
      @cancel="showClear = false"
    >
      <p
        class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
      >
        {{ t("admin.riskGate.refusals.clearWarning") }}
      </p>
    </ConfirmDialog>
  </section>
</template>

<script setup lang="ts">
import { reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import ConfirmDialog from "@/components/common/ConfirmDialog.vue";
import Pagination from "@/components/common/Pagination.vue";
import type { RefusalFilter, RefusalRow } from "../types";
import { cloneData } from "../viewModel";

const props = defineProps<{
  refusals: RefusalRow[];
  total: number;
  page: number;
  pageSize: number;
  filter: RefusalFilter;
  loading: boolean;
  error: string;
}>();
const emit = defineEmits<{
  (event: "delete", id: number): void;
  (event: "clear-all"): void;
  (event: "page", value: number): void;
  (event: "page-size", value: number): void;
  (event: "filter-change", value: RefusalFilter): void;
}>();
const { t, locale } = useI18n();

const local = reactive<RefusalFilter>(cloneData(props.filter));
watch(
  () => props.filter,
  (value) => Object.assign(local, cloneData(value)),
  { deep: true },
);

const pendingDelete = ref<RefusalRow | null>(null);
const showClear = ref(false);

function filtersChanged() {
  emit("filter-change", cloneData(local));
}
function confirmDelete() {
  const row = pendingDelete.value;
  pendingDelete.value = null;
  if (row) emit("delete", row.id);
}
function confirmClear() {
  showClear.value = false;
  emit("clear-all");
}
function sourceLabel(source: string): string {
  if (source === "upstream_refusal" || source === "silent_refusal") {
    return t(`admin.riskGate.refusals.sources.${source}`);
  }
  return source || "—";
}
function shortHash(value: string): string {
  if (!value) return "—";
  return value.length > 16 ? `${value.slice(0, 12)}…` : value;
}
function formatDate(value: string): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}
</script>
