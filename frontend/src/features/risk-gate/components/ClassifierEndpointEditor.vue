<template>
  <section
    aria-labelledby="risk-gate-classifier-title"
    class="border-b border-gray-200 py-6 dark:border-dark-700/60"
  >
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-classifier-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.classifier.title") }}
        </h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.classifier.description") }}
        </p>
      </div>
      <button
        type="button"
        class="btn btn-primary btn-sm"
        data-test="add-endpoint"
        @click="openCreate"
      >
        {{ t("admin.riskGate.classifier.add") }}
      </button>
    </div>

    <p
      v-if="endpoints.length === 0"
      class="mt-5 rounded-xl border border-dashed border-gray-300 px-5 py-8 text-center text-sm text-gray-500 dark:border-dark-600 dark:bg-dark-900/20 dark:text-dark-300"
      data-test="endpoint-empty"
    >
      {{ t("admin.riskGate.classifier.empty") }}
    </p>

    <div
      v-else
      class="mt-5 divide-y divide-gray-100 overflow-hidden rounded-xl border border-gray-200 dark:divide-dark-800 dark:border-dark-700/60"
    >
      <article
        v-for="endpoint in endpoints"
        :key="endpoint.id"
        :data-test="`endpoint-${endpoint.id}`"
        class="grid gap-3 px-4 py-4 sm:px-5 xl:grid-cols-[minmax(220px,1.3fr)_minmax(200px,1fr)_minmax(160px,.7fr)_auto] xl:items-center xl:gap-4"
      >
        <div class="min-w-0">
          <p class="truncate font-semibold text-gray-950 dark:text-white">
            {{ endpoint.name || endpoint.id }}
          </p>
          <p
            class="mt-0.5 truncate font-mono text-[11px] text-gray-500 dark:text-dark-400"
            :title="endpoint.base_url"
          >
            {{ endpoint.base_url }}
          </p>
        </div>
        <div class="min-w-0">
          <p
            class="truncate text-sm text-gray-700 dark:text-dark-200"
            :title="endpoint.model"
          >
            {{ endpoint.model }}
          </p>
          <p class="mt-0.5 text-xs text-gray-500 dark:text-dark-400">
            {{ endpoint.timeout_ms }} ms
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-1.5 text-xs">
          <span
            class="rounded-full px-2 py-0.5 font-medium"
            :class="
              endpoint.enabled
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300'
                : 'bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300'
            "
          >
            {{
              endpoint.enabled
                ? t("admin.riskGate.classifier.enabled")
                : t("admin.riskGate.mode.off")
            }}
          </span>
          <span
            class="rounded-full px-2 py-0.5 font-medium"
            :class="
              endpoint.has_api_key
                ? 'bg-primary-100 text-primary-700 dark:bg-primary-950/50 dark:text-primary-300'
                : 'bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300'
            "
            :data-test="`endpoint-key-${endpoint.id}`"
          >
            {{
              endpoint.has_api_key
                ? t("admin.riskGate.classifier.keyConfigured")
                : t("admin.riskGate.classifier.keyMissing")
            }}
          </span>
        </div>
        <div class="flex flex-wrap items-center justify-end gap-1">
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            :disabled="probingIds.includes(endpoint.id)"
            :data-test="`probe-${endpoint.id}`"
            @click="$emit('probe', endpoint)"
          >
            {{
              probingIds.includes(endpoint.id)
                ? t("admin.riskGate.classifier.probing")
                : t("admin.riskGate.classifier.probe")
            }}
          </button>
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            @click="openEdit(endpoint)"
          >
            {{ t("common.edit") }}
          </button>
          <button
            type="button"
            class="btn btn-ghost btn-sm text-red-600 dark:text-red-300"
            :data-test="`remove-endpoint-${endpoint.id}`"
            @click="removeEndpoint(endpoint)"
          >
            {{ t("admin.riskGate.classifier.remove") }}
          </button>
        </div>
        <p
          v-if="probeResults[endpoint.id]"
          class="text-xs leading-5 sm:col-span-2 xl:col-span-4"
          :class="
            probeResults[endpoint.id].ok
              ? 'text-emerald-600 dark:text-emerald-300'
              : 'text-red-600 dark:text-red-300'
          "
          :data-test="`probe-result-${endpoint.id}`"
        >
          {{ t(probeLabel(endpoint.id).key, probeLabel(endpoint.id).params) }}
        </p>
      </article>
    </div>

    <BaseDialog
      :show="Boolean(editing)"
      :title="
        editingIndex < 0 ? t('admin.riskGate.classifier.add') : t('common.edit')
      "
      width="wide"
      @close="closeEditor"
    >
      <form
        v-if="editing"
        class="grid gap-4 sm:grid-cols-2"
        @submit.prevent="saveEditor"
      >
        <label class="space-y-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t("admin.riskGate.classifier.name") }}</span>
          <input
            v-model="editing.name"
            class="input w-full"
            required
            :aria-label="t('admin.riskGate.classifier.name')"
          />
        </label>
        <label class="space-y-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t("admin.riskGate.classifier.id") }}</span>
          <input
            v-model="editing.id"
            class="input w-full"
            required
            :disabled="editingIndex >= 0"
            :aria-label="t('admin.riskGate.classifier.id')"
          />
        </label>
        <label
          class="space-y-1 text-sm text-gray-700 dark:text-dark-200 sm:col-span-2"
        >
          <span>{{ t("admin.riskGate.classifier.baseUrl") }}</span>
          <input
            v-model="editing.base_url"
            class="input w-full"
            required
            inputmode="url"
            :aria-label="t('admin.riskGate.classifier.baseUrl')"
          />
        </label>
        <label class="space-y-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t("admin.riskGate.classifier.model") }}</span>
          <input
            v-model="editing.model"
            class="input w-full"
            required
            :aria-label="t('admin.riskGate.classifier.model')"
          />
        </label>
        <label class="space-y-1 text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t("admin.riskGate.classifier.timeout") }}</span>
          <input
            v-model.number="editing.timeout_ms"
            class="input w-full"
            type="number"
            min="100"
            max="60000"
            required
            :aria-label="t('admin.riskGate.classifier.timeout')"
          />
        </label>
        <label
          class="space-y-1 text-sm text-gray-700 dark:text-dark-200 sm:col-span-2"
        >
          <span>{{ t("admin.riskGate.classifier.apiKey") }}</span>
          <input
            v-model="editing.api_key"
            class="input w-full"
            type="password"
            autocomplete="new-password"
            data-test="endpoint-api-key"
            :placeholder="
              editing.has_api_key
                ? t('admin.riskGate.classifier.keyConfigured')
                : ''
            "
            :aria-label="t('admin.riskGate.classifier.apiKey')"
          />
          <span class="block text-xs text-gray-500 dark:text-dark-400">{{
            t("admin.riskGate.classifier.secretHint")
          }}</span>
        </label>
        <label
          class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200 sm:col-span-2"
        >
          <input
            v-model="editing.enabled"
            type="checkbox"
            :aria-label="t('admin.riskGate.classifier.enabled')"
          />
          {{ t("admin.riskGate.classifier.enabled") }}
        </label>
      </form>
      <template #footer>
        <div class="flex justify-end gap-3">
          <button type="button" class="btn btn-secondary" @click="closeEditor">
            {{ t("common.cancel") }}
          </button>
          <button
            type="button"
            class="btn btn-primary"
            data-test="save-endpoint"
            @click="saveEditor"
          >
            {{ t("admin.riskGate.detailExtras.applyDraft") }}
          </button>
        </div>
      </template>
    </BaseDialog>
  </section>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import BaseDialog from "@/components/common/BaseDialog.vue";
import type { ClassifierEndpoint, ProbeResult } from "../types";
import {
  cloneData,
  createDefaultEndpoint,
  probeResultLabel,
} from "../viewModel";

const props = defineProps<{
  endpoints: ClassifierEndpoint[];
  probeResults: Record<string, ProbeResult>;
  probingIds: string[];
}>();
const emit = defineEmits<{
  (event: "update:endpoints", value: ClassifierEndpoint[]): void;
  (event: "probe", endpoint: ClassifierEndpoint): void;
}>();
const { t } = useI18n();

const editing = ref<ClassifierEndpoint | null>(null);
const editingIndex = ref(-1);

function probeLabel(id: string): {
  key: string;
  params: Record<string, string | number>;
} {
  const result = props.probeResults[id];
  return result ? probeResultLabel(result) : { key: "", params: {} };
}

function openCreate() {
  editingIndex.value = -1;
  editing.value = createDefaultEndpoint(props.endpoints.length + 1);
}
function openEdit(endpoint: ClassifierEndpoint) {
  editingIndex.value = props.endpoints.findIndex(
    (item) => item.id === endpoint.id,
  );
  editing.value = cloneData(endpoint);
}
function closeEditor() {
  editing.value = null;
  editingIndex.value = -1;
}
function saveEditor() {
  const value = editing.value;
  if (
    !value ||
    !value.id.trim() ||
    !value.name.trim() ||
    !value.base_url.trim()
  )
    return;
  const next = props.endpoints.map((item) => cloneData(item));
  if (editingIndex.value < 0) next.push(cloneData(value));
  else next.splice(editingIndex.value, 1, cloneData(value));
  emit("update:endpoints", next);
  closeEditor();
}
function removeEndpoint(endpoint: ClassifierEndpoint) {
  if (
    !window.confirm(
      t("admin.riskGate.classifier.removeConfirm", {
        name: endpoint.name || endpoint.id,
      }),
    )
  )
    return;
  emit(
    "update:endpoints",
    props.endpoints
      .filter((item) => item.id !== endpoint.id)
      .map((item) => cloneData(item)),
  );
}
</script>
