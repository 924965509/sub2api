<template>
  <div class="space-y-8" data-test="model-settings">
    <section class="space-y-3">
      <h3 class="text-sm font-semibold">
        {{ t("admin.riskGate.stages.jev.title") }}
      </h3>
      <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">
        {{ t("admin.riskGate.stages.jev.description") }}
      </p>
      <div
        class="grid overflow-hidden rounded-xl border border-gray-200 dark:border-dark-700 md:grid-cols-2"
      >
        <label
          class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700 md:border-r"
          ><span>{{ t("admin.riskGate.stages.jev.enabled") }}</span
          ><input
            type="checkbox"
            :checked="config.gates.decision_model"
            data-test="model-enabled"
            @change="toggleEnabled(checked($event))"
        /></label>
        <label
          class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700"
          ><span>{{ t("admin.riskGate.model.failOpen") }}</span
          ><input
            type="checkbox"
            :checked="config.decision_model.on_unavailable === 'pass'"
            @change="
              patch({
                on_unavailable: checked($event) ? 'pass' : 'fail_closed',
              })
            "
        /></label>
        <label class="flex items-center justify-between gap-4 px-4 py-3 text-sm"
          ><span>{{ t("admin.riskGate.model.blockIfBelow") }}</span
          ><input
            type="checkbox"
            :checked="config.decision_model.block_if_below"
            :disabled="isLegacy"
            @change="patch({ block_if_below: checked($event) })"
        /></label>
        <label class="flex items-center justify-between gap-3 px-4 py-3 text-sm"
          ><span>{{ t("admin.riskGate.model.scoringMode") }}</span
          ><select
            class="input max-w-[13rem] text-xs"
            :value="config.decision_model.scoring_mode"
            data-test="scoring-mode"
            @change="changeScoringMode(value($event) as DecisionScoringMode)"
          >
            <option value="safety_questions">
              {{ t("admin.riskGate.model.safetyQuestions") }}
            </option>
            <option value="risk">
              {{ t("admin.riskGate.model.riskCompatibility") }}
            </option>
          </select></label
        >
      </div>
      <p
        v-if="isLegacy"
        class="rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
        data-test="legacy-scoring-notice"
      >
        {{ t("admin.riskGate.model.legacyCompatibility") }}
      </p>
    </section>

    <section class="space-y-3">
      <h3 class="text-sm font-semibold">
        {{ t("admin.riskGate.classifier.title") }}
      </h3>
      <div
        class="space-y-4 rounded-xl border border-gray-200 p-4 dark:border-dark-700"
      >
        <div
          class="grid grid-cols-2 gap-1 rounded-lg bg-gray-100 p-1 dark:bg-dark-800 sm:grid-cols-4"
          :aria-label="t('admin.riskGate.model.provider')"
        >
          <button
            v-for="provider in providers"
            :key="provider.id"
            type="button"
            :aria-pressed="selectedProvider === provider.id"
            class="rounded-md px-3 py-1.5 text-sm transition-colors"
            :class="
              selectedProvider === provider.id
                ? 'bg-white text-gray-950 shadow-sm dark:bg-dark-700 dark:text-white'
                : 'text-gray-500 dark:text-dark-300'
            "
            :data-test="`provider-${provider.id}`"
            @click="selectProvider(provider.id)"
          >
            {{ provider.label }}
          </button>
        </div>
        <div class="space-y-3">
          <label
            class="grid gap-2 text-sm sm:grid-cols-[4.5rem_minmax(0,1fr)] sm:items-center sm:gap-4"
            ><span class="text-gray-500">{{
              t("admin.riskGate.model.address")
            }}</span
            ><input
              :value="primary.base_url"
              class="input w-full font-mono text-xs"
              placeholder="https://"
              data-test="model-base-url"
              @input="patchEndpoint({ base_url: value($event) })"
          /></label>
          <label
            class="grid gap-2 text-sm sm:grid-cols-[4.5rem_minmax(0,1fr)] sm:items-center sm:gap-4"
            ><span class="text-gray-500">Key</span
            ><input
              type="password"
              autocomplete="new-password"
              :value="primary.api_key ?? ''"
              :placeholder="
                primary.has_api_key
                  ? t('admin.riskGate.model.keyConfigured')
                  : t('admin.riskGate.model.keyPlaceholder')
              "
              class="input w-full font-mono text-xs"
              data-test="model-api-key"
              @input="
                patchEndpoint({
                  api_key: value($event),
                  api_keys: [],
                  clear_api_keys: false,
                })
              "
          /></label>
          <div
            class="grid gap-2 text-sm sm:grid-cols-[4.5rem_minmax(0,1fr)] sm:items-center sm:gap-4"
          >
            <label for="risk-model-name" class="text-gray-500">{{
              t("admin.riskGate.model.model")
            }}</label>
            <div class="flex min-w-0 flex-wrap gap-2">
              <input
                id="risk-model-name"
                :value="primary.model"
                class="input min-w-0 flex-1 font-mono text-xs"
                data-test="model-name"
                @input="patchEndpoint({ model: value($event) })"
              /><button
                type="button"
                class="btn btn-secondary btn-sm"
                :disabled="loadingModels || !primary.base_url.trim()"
                data-test="fetch-models"
                @click="$emit('fetch-models', primary)"
              >
                {{
                  loadingModels
                    ? t("admin.riskGate.actions.loading")
                    : t("admin.riskGate.model.fetchModels")
                }}
              </button>
            </div>
          </div>
          <label
            v-if="models.length"
            class="grid gap-2 text-xs sm:grid-cols-[4.5rem_minmax(0,1fr)] sm:items-center sm:gap-4"
            ><span class="text-gray-500">{{
              t("admin.riskGate.model.availableModels")
            }}</span
            ><select
              class="input"
              :value="primary.model"
              data-test="available-models"
              @change="patchEndpoint({ model: value($event) })"
            >
              <option value="" disabled>
                {{ t("admin.riskGate.model.selectModel") }}
              </option>
              <option v-for="model in models" :key="model.id" :value="model.id">
                {{ model.id }}
              </option>
            </select></label
          >
          <div
            class="grid gap-2 text-sm sm:grid-cols-[4.5rem_minmax(0,1fr)] sm:items-center sm:gap-4"
          >
            <label for="risk-model-timeout" class="text-gray-500">{{
              t("admin.riskGate.model.timeout")
            }}</label>
            <div class="flex flex-wrap items-center gap-2">
              <input
                id="risk-model-timeout"
                type="number"
                min="100"
                max="30000"
                :value="primary.timeout_ms"
                class="input w-28 tabular-nums"
                @change="patchEndpoint({ timeout_ms: number($event) })"
              /><button
                type="button"
                class="btn btn-secondary btn-sm"
                :disabled="probing || !primary.base_url.trim()"
                data-test="probe-model"
                @click="$emit('probe', primary)"
              >
                {{
                  probing
                    ? t("admin.riskGate.actions.loading")
                    : t("admin.riskGate.model.probe")
                }}</button
              ><span v-if="primary.has_api_key" class="text-xs text-gray-500">{{
                t("admin.riskGate.model.keysStored", {
                  count: primary.api_key_count ?? 1,
                })
              }}</span>
            </div>
          </div>
          <div
            v-if="probeResult"
            role="status"
            class="rounded-lg px-3 py-2 text-xs leading-5"
            :class="
              probeResult.ok
                ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-200'
                : 'bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-200'
            "
          >
            <p>
              {{
                probeResult.ok
                  ? t("admin.riskGate.model.probeSuccess", {
                      latency: probeResult.latency_ms,
                      score: probeResult.score,
                    })
                  : `${t("admin.riskGate.model.probeFailed")}：${probeResult.error ?? "—"}`
              }}
            </p>
            <dl
              v-if="probeResult.scores"
              class="mt-2 flex flex-wrap gap-x-4 gap-y-1"
            >
              <div
                v-for="(score, id) in probeResult.scores"
                :key="id"
                class="flex gap-2"
              >
                <dt class="font-mono">{{ id }}</dt>
                <dd class="font-semibold tabular-nums">{{ score }}</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
      <details class="rounded-xl border border-gray-200 dark:border-dark-700">
        <summary class="cursor-pointer px-4 py-3 text-sm">
          {{ t("admin.riskGate.model.keys")
          }}<span class="ml-2 text-xs text-gray-500">{{
            t("admin.riskGate.model.keysStored", {
              count: primary.api_key_count ?? 0,
            })
          }}</span>
        </summary>
        <div
          class="space-y-3 border-t border-gray-200 p-4 dark:border-dark-700"
        >
          <p class="text-xs leading-5 text-gray-500">
            {{ t("admin.riskGate.model.keysHint") }}
          </p>
          <label class="block text-xs"
            ><span class="sr-only">{{ t("admin.riskGate.model.keys") }}</span
            ><textarea
              :value="keyText"
              rows="4"
              autocomplete="off"
              spellcheck="false"
              class="input w-full font-mono text-xs"
              data-test="model-api-keys"
              @input="updateKeys(value($event))"
            /></label
          ><label class="flex items-center justify-between gap-3 text-sm"
            ><span>{{ t("admin.riskGate.model.clearKeys") }}</span
            ><input
              type="checkbox"
              :checked="primary.clear_api_keys"
              data-test="clear-model-keys"
              @change="
                patchEndpoint({
                  clear_api_keys: checked($event),
                  api_key: '',
                  api_keys: [],
                })
              "
          /></label>
        </div>
      </details>
    </section>

    <section class="space-y-3">
      <h3 class="text-sm font-semibold">
        {{ t("admin.riskGate.model.safetyQuestions") }}
      </h3>
      <div class="grid gap-3 sm:grid-cols-3">
        <label class="text-xs"
          >{{ t("admin.riskGate.model.threshold")
          }}<input
            type="number"
            min="0"
            max="1"
            step="0.05"
            :value="
              isLegacy
                ? config.decision_model.threshold
                : config.decision_model.safety_threshold
            "
            class="input mt-1 w-full tabular-nums"
            data-test="model-threshold"
            @change="
              patch(
                isLegacy
                  ? { threshold: number($event) }
                  : { safety_threshold: number($event) },
              )
            " /></label
        ><label class="text-xs"
          >{{ t("admin.riskGate.model.dedup")
          }}<input
            type="number"
            min="0"
            max="3600"
            :value="config.decision_model.dedup_sec"
            class="input mt-1 w-full tabular-nums"
            :disabled="isLegacy"
            @change="patch({ dedup_sec: number($event) })" /></label
        ><label class="text-xs"
          >{{ t("admin.riskGate.model.maxState")
          }}<input
            type="number"
            min="256"
            max="64000"
            :value="config.decision_model.max_state_chars"
            class="input mt-1 w-full tabular-nums"
            :disabled="isLegacy"
            @change="patch({ max_state_chars: number($event) })"
        /></label>
      </div>
      <p v-if="!isLegacy" class="text-xs leading-5 text-gray-500">
        {{ t("admin.riskGate.model.nearMiss") }}
      </p>
      <label v-if="!isLegacy" class="block text-xs"
        >{{ t("admin.riskGate.model.customInstruction")
        }}<textarea
          :value="config.decision_model.safety_instruction"
          class="input mt-1 w-full"
          rows="2"
          data-test="model-custom-instruction"
          @input="patch({ safety_instruction: value($event) })"
        /><span class="mt-1 block text-gray-500">{{
          t("admin.riskGate.model.instructionHint")
        }}</span></label
      >
    </section>

    <section v-if="!isLegacy" class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h3 class="text-sm font-semibold">
          {{ t("admin.riskGate.model.questionBank") }}
          <span class="text-xs font-normal text-gray-500"
            >{{ questions.filter((q) => q.enabled).length }} /
            {{ questions.length }}</span
          >
        </h3>
        <div class="flex gap-2">
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            data-test="reset-questions"
            @click="$emit('reset-questions')"
          >
            {{ t("admin.riskGate.model.resetQuestions") }}</button
          ><button
            type="button"
            class="btn btn-secondary btn-sm"
            data-test="add-question"
            @click="addQuestion"
          >
            {{ t("admin.riskGate.model.addQuestion") }}
          </button>
        </div>
      </div>
      <div
        class="divide-y divide-gray-200 overflow-hidden rounded-xl border border-gray-200 dark:divide-dark-700 dark:border-dark-700"
      >
        <details
          v-for="(question, index) in questions"
          :key="question.id || index"
          :open="!question.instructions"
          :data-test="`question-${index}`"
        >
          <summary
            class="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3"
          >
            <div class="min-w-0">
              <p class="text-sm font-medium">
                {{ question.label || question.id }}
              </p>
              <p class="mt-0.5 truncate text-xs text-gray-500">
                {{ question.summary }}
              </p>
            </div>
            <input
              type="checkbox"
              :checked="question.enabled"
              :aria-label="question.label || question.id"
              @click.stop
              @change="patchQuestion(index, { enabled: checked($event) })"
            />
          </summary>
          <div
            class="grid gap-3 border-t border-gray-200 p-4 dark:border-dark-700 sm:grid-cols-2"
          >
            <label class="text-xs"
              >{{ t("admin.riskGate.model.questionId")
              }}<input
                :value="question.id"
                :disabled="question.builtin"
                class="input mt-1 w-full font-mono"
                @input="patchQuestion(index, { id: value($event) })" /></label
            ><label class="text-xs"
              >{{ t("admin.riskGate.model.questionLabel")
              }}<input
                :value="question.label"
                class="input mt-1 w-full"
                @input="
                  patchQuestion(index, { label: value($event) })
                " /></label
            ><label class="text-xs sm:col-span-2"
              >{{ t("admin.riskGate.model.questionSummary")
              }}<input
                :value="question.summary"
                class="input mt-1 w-full"
                @input="
                  patchQuestion(index, { summary: value($event) })
                " /></label
            ><label class="text-xs sm:col-span-2"
              >{{ t("admin.riskGate.model.instructions")
              }}<textarea
                :value="question.instructions"
                class="input mt-1 w-full"
                rows="4"
                :data-test="`question-instructions-${index}`"
                @input="patchQuestion(index, { instructions: value($event) })"
              />
            </label>
            <div class="sm:col-span-2">
              <button
                type="button"
                class="btn btn-ghost btn-sm text-red-600"
                @click="removeQuestion(index)"
              >
                {{ t("admin.riskGate.actions.remove") }}
              </button>
            </div>
          </div>
        </details>
      </div>
    </section>
    <details class="rounded-xl border border-gray-200 dark:border-dark-700">
      <summary class="cursor-pointer px-4 py-3 text-sm">
        {{ t("admin.riskGate.model.advanced") }}
      </summary>
      <div class="border-t border-gray-200 px-4 dark:border-dark-700">
        <ClassifierEndpointEditor
          :endpoints="config.decision_model.endpoints"
          :probe-results="{}"
          :probing-ids="probing ? [primary.id] : []"
          @update:endpoints="patch({ endpoints: $event })"
          @probe="$emit('probe', $event)"
        />
      </div>
    </details>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import ClassifierEndpointEditor from "./ClassifierEndpointEditor.vue";
import type {
  ClassifierEndpoint,
  DecisionModelConfig,
  DecisionProvider,
  DecisionScoringMode,
  PolicyQuestion,
  ProbeResult,
  RiskGateConfig,
} from "../types";
import { cloneData, defaultPolicyQuestions } from "../viewModel";
const props = defineProps<{
  config: RiskGateConfig;
  models: Array<{ id: string }>;
  probeResult: ProbeResult | null;
  probing: boolean;
  loadingModels: boolean;
}>();
const emit = defineEmits<{
  (event: "update", value: RiskGateConfig): void;
  (event: "probe", value: ClassifierEndpoint): void;
  (event: "fetch-models", value: ClassifierEndpoint): void;
  (event: "reset-questions"): void;
}>();
const { t } = useI18n();
const providers = computed<
  Array<{ id: DecisionProvider; label: string; url: string; model: string }>
>(() => [
  {
    id: "jev",
    label: "Jev",
    url: "https://api.typesafe.ai",
    model: "jev-latest",
  },
  { id: "laya", label: "Laya", url: "http://127.0.0.1:8000", model: "" },
  {
    id: "modernbert",
    label: "ModernBERT",
    url: "http://127.0.0.1:8000",
    model: "english",
  },
  {
    id: "openai",
    label: t("admin.riskGate.model.providers.openai"),
    url: "",
    model: "",
  },
]);
const selectedProvider = computed(
  () => props.config.decision_model.provider ?? "openai",
);
const primary = computed<ClassifierEndpoint>(
  () =>
    props.config.decision_model.endpoints[0] ?? {
      id: "primary",
      name: "Primary",
      base_url: "",
      model: "",
      timeout_ms: 3000,
      enabled: true,
      provider: selectedProvider.value,
      api_key: "",
      api_keys: [],
    },
);
const questions = computed(() => props.config.decision_model.questions ?? []);
const isLegacy = computed(
  () => props.config.decision_model.scoring_mode !== "safety_questions",
);
const keyText = ref("");
watch(
  () => primary.value.api_keys,
  (keys) => {
    if (JSON.stringify(lines(keyText.value)) !== JSON.stringify(keys ?? []))
      keyText.value = (keys ?? []).join("\n");
  },
  { deep: true, immediate: true },
);
function value(event: Event) {
  return (event.target as HTMLInputElement).value;
}
function number(event: Event) {
  return Number(value(event));
}
function checked(event: Event) {
  return (event.target as HTMLInputElement).checked;
}
function lines(text: string) {
  return text
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}
function patch(partial: Partial<DecisionModelConfig>) {
  emit("update", {
    ...cloneData(props.config),
    decision_model: { ...cloneData(props.config.decision_model), ...partial },
  });
}
function patchEndpoint(partial: Partial<ClassifierEndpoint>) {
  const endpoints = cloneData(props.config.decision_model.endpoints);
  if (!endpoints.length) endpoints.push(cloneData(primary.value));
  endpoints[0] = { ...endpoints[0], ...partial };
  patch({ endpoints });
}
function toggleEnabled(enabled: boolean) {
  const next = cloneData(props.config);
  next.gates.decision_model = enabled;
  next.decision_model.enabled = enabled;
  emit("update", next);
}
function updateKeys(text: string) {
  keyText.value = text;
  patchEndpoint({ api_keys: lines(text), api_key: "", clear_api_keys: false });
}
function selectProvider(id: DecisionProvider) {
  const target = providers.value.find((item) => item.id === id)!;
  const existing = primary.value;
  const next = cloneData(props.config);
  next.decision_model.provider = id;
  const knownURLs = providers.value.map((item) => item.url);
  const knownModels = providers.value.map((item) => item.model);
  const endpoint = {
    ...cloneData(existing),
    provider: id,
    base_url:
      !existing.base_url || knownURLs.includes(existing.base_url)
        ? target.url
        : existing.base_url,
    model:
      !existing.model || knownModels.includes(existing.model)
        ? target.model
        : existing.model,
  };
  if (endpoint.base_url !== existing.base_url) {
    endpoint.api_key = "";
    endpoint.api_keys = [];
    endpoint.has_api_key = false;
    endpoint.api_key_count = 0;
    endpoint.clear_api_keys = true;
  }
  next.decision_model.endpoints = [
    endpoint,
    ...next.decision_model.endpoints.slice(1),
  ];
  emit("update", next);
}
function changeScoringMode(mode: DecisionScoringMode) {
  if (mode === props.config.decision_model.scoring_mode) return;
  if (!window.confirm(t("admin.riskGate.model.legacySwitchConfirm"))) return;
  const next = cloneData(props.config);
  next.schema_version = 2;
  next.decision_model.scoring_mode = mode;
  if (mode === "safety_questions" && !next.decision_model.questions?.length)
    next.decision_model.questions = defaultPolicyQuestions();
  emit("update", next);
}
function patchQuestion(index: number, partial: Partial<PolicyQuestion>) {
  patch({
    questions: questions.value.map((question, position) =>
      position === index ? { ...question, ...partial } : { ...question },
    ),
  });
}
function addQuestion() {
  const id = `custom_${Date.now().toString(36)}`;
  patch({
    questions: [
      ...questions.value,
      {
        id,
        label: t("admin.riskGate.model.addQuestion"),
        summary: "",
        instructions: "",
        enabled: true,
      },
    ],
  });
}
function removeQuestion(index: number) {
  patch({
    questions: questions.value.filter((_, position) => position !== index),
  });
}
</script>
