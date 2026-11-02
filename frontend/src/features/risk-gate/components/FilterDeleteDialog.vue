<template>
  <BaseDialog
    :show="show"
    :title="t('admin.riskGate.events.filterDeleteTitle')"
    width="wide"
    @close="$emit('close')"
  >
    <div class="space-y-5 text-sm">
      <p class="text-gray-500 dark:text-dark-300">
        {{ t("admin.riskGate.events.filterDeleteDescription") }}
      </p>

      <div class="grid gap-3 sm:grid-cols-2">
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.events.kind") }}</span>
          <select
            v-model="local.kind"
            class="input mt-1 w-full"
            data-test="delete-kind"
            :aria-label="t('admin.riskGate.events.kind')"
            @change="criteriaChanged"
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
            v-model="local.gate"
            class="input mt-1 w-full"
            data-test="delete-gate"
            :aria-label="t('admin.riskGate.events.gate')"
            @change="criteriaChanged"
          >
            <option value="">{{ t("common.all") }}</option>
            <option v-for="gate in gates" :key="gate" :value="gate">
              {{ t(`admin.riskGate.gates.${gate}`) }}
            </option>
          </select>
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.events.provider") }}</span>
          <input
            v-model="local.provider"
            class="input mt-1 w-full"
            data-test="delete-provider"
            :aria-label="t('admin.riskGate.events.provider')"
            @input="criteriaChanged"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.events.requestId") }}</span>
          <input
            v-model="local.request_id"
            class="input mt-1 w-full"
            data-test="delete-request-id"
            :aria-label="t('admin.riskGate.events.requestId')"
            @input="criteriaChanged"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.events.from") }}</span>
          <input
            v-model="local.from"
            type="datetime-local"
            class="input mt-1 w-full"
            data-test="delete-from"
            :aria-label="t('admin.riskGate.events.from')"
            @change="criteriaChanged"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.events.to") }}</span>
          <input
            v-model="local.to"
            type="datetime-local"
            class="input mt-1 w-full"
            data-test="delete-to"
            :aria-label="t('admin.riskGate.events.to')"
            @change="criteriaChanged"
          />
        </label>
      </div>

      <p
        v-if="!criteriaReady"
        role="status"
        data-test="delete-filter-required"
        class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/20 dark:text-red-300"
      >
        {{ t("admin.riskGate.events.filterDeleteNoFilter") }}
      </p>

      <div
        v-if="preview"
        class="rounded-xl border border-red-200 bg-red-50/60 px-4 py-3 dark:border-red-900/60 dark:bg-red-950/20"
        data-test="delete-preview-result"
      >
        <p class="text-sm font-semibold text-red-700 dark:text-red-300">
          {{
            t("admin.riskGate.events.filterDeleteCount", {
              total: preview.total,
            })
          }}
        </p>
        <p
          class="mt-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
        >
          {{ t("admin.riskGate.events.filterDeleteWarning") }}
        </p>
      </div>
      <p
        v-else
        class="rounded-xl border border-dashed border-gray-300 px-4 py-3 text-xs text-gray-500 dark:border-dark-600 dark:text-dark-400"
        data-test="delete-preview-empty"
      >
        {{ t("admin.riskGate.events.filterDeleteEmpty") }}
      </p>
    </div>

    <template #footer>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <p
          v-if="confirmDisabledReason"
          class="mr-auto text-xs text-gray-500 dark:text-dark-400"
          data-test="delete-confirm-reason"
        >
          {{ t(confirmDisabledReason) }}
        </p>
        <button type="button" class="btn btn-secondary" @click="$emit('close')">
          {{ t("common.cancel") }}
        </button>
        <button
          type="button"
          class="btn btn-secondary"
          :disabled="previewing || deleting"
          data-test="run-delete-preview"
          @click="requestPreview"
        >
          {{
            previewing
              ? t("admin.riskGate.events.filterDeletePreviewing")
              : t("admin.riskGate.events.filterDeletePreview")
          }}
        </button>
        <button
          type="button"
          class="btn btn-danger"
          :disabled="Boolean(confirmDisabledReason)"
          :title="confirmDisabledReason ? t(confirmDisabledReason) : undefined"
          data-test="confirm-filter-delete"
          @click="requestConfirm"
        >
          {{
            deleting
              ? t("common.submitting")
              : t("admin.riskGate.events.filterDeleteConfirm")
          }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from "vue";
import { useI18n } from "vue-i18n";
import BaseDialog from "@/components/common/BaseDialog.vue";
import type { EventFilter } from "../types";
import { cloneData, emptyEventFilter, hasEventFilter } from "../viewModel";

const props = defineProps<{
  show: boolean;
  initialFilter: EventFilter;
  preview: { total: number } | null;
  previewing: boolean;
  deleting: boolean;
}>();
const emit = defineEmits<{
  (event: "close"): void;
  (event: "preview", value: EventFilter): void;
  (event: "confirm", value: EventFilter): void;
  (event: "criteria-change"): void;
}>();
const { t } = useI18n();

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

const local = reactive<EventFilter>(emptyEventFilter());

watch(
  () => props.show,
  (visible) => {
    if (!visible) return;
    Object.assign(local, cloneData(props.initialFilter));
  },
  { immediate: true },
);

// 后端对「没有任何过滤条件」的批量删除直接返回 400，这里提前拦住。
const criteriaReady = computed(() => hasEventFilter(local));

const confirmDisabledReason = computed(() => {
  if (props.previewing || props.deleting) return "";
  if (!criteriaReady.value) return "admin.riskGate.events.filterDeleteNoFilter";
  if (props.preview && props.preview.total === 0)
    return "admin.riskGate.events.filterDeleteNoMatch";
  return "";
});

function criteriaChanged() {
  emit("criteria-change");
}
function requestPreview() {
  if (!criteriaReady.value) return;
  emit("preview", cloneData(local));
}
function requestConfirm() {
  if (confirmDisabledReason.value) return;
  emit("confirm", cloneData(local));
}
</script>
