<template>
  <div data-test="gate-config-panel">
    <section aria-labelledby="risk-gate-config-title" class="py-6">
      <h2
        id="risk-gate-config-title"
        class="text-base font-semibold text-gray-950 dark:text-white"
      >
        {{ t("admin.riskGate.config.title") }}
      </h2>
      <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
        {{ t("admin.riskGate.config.description") }}
      </p>

      <div class="mt-5 grid gap-4 lg:grid-cols-2">
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span class="text-sm font-medium text-gray-800 dark:text-dark-100">{{
            t("admin.riskGate.config.mode")
          }}</span>
          <select
            v-model="local.mode"
            class="input mt-1 w-full"
            data-test="mode-select"
            :aria-label="t('admin.riskGate.config.mode')"
            @change="sync"
          >
            <option value="off">{{ t("admin.riskGate.mode.off") }}</option>
            <option value="observe">
              {{ t("admin.riskGate.mode.observe") }}
            </option>
            <option value="blocking">
              {{ t("admin.riskGate.mode.blocking") }}
            </option>
          </select>
          <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{
            t("admin.riskGate.config.modeHint")
          }}</span>
        </label>
        <div
          role="status"
          data-test="mode-hint"
          class="rounded-xl border px-4 py-3 text-xs leading-5"
          :class="
            local.mode === 'blocking'
              ? 'border-red-200 bg-red-50 text-red-800 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-200'
              : local.mode === 'observe'
                ? 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200'
                : 'border-gray-200 bg-gray-50 text-gray-600 dark:border-dark-700/60 dark:bg-dark-900/40 dark:text-dark-300'
          "
        >
          {{ t(`admin.riskGate.modeHints.${local.mode}`) }}
        </div>
      </div>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.gates") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.gatesHint") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <div
            v-for="gate in gateItems"
            :key="gate.id"
            class="flex items-start justify-between gap-3 rounded-lg bg-gray-50 px-3 py-2.5 dark:bg-dark-900/50"
          >
            <div class="min-w-0">
              <p class="text-sm font-medium text-gray-900 dark:text-white">
                {{ t(gate.labelKey) }}
                <span
                  v-if="gate.always"
                  class="ml-1 rounded bg-gray-200 px-1.5 py-0.5 text-[10px] font-semibold text-gray-600 dark:bg-dark-700 dark:text-dark-300"
                >
                  {{ t("admin.riskGate.alwaysOn") }}
                </span>
              </p>
              <p
                class="mt-0.5 text-xs leading-5 text-gray-500 dark:text-dark-400"
              >
                {{ t(`admin.riskGate.gateHints.${gate.id}`) }}
              </p>
            </div>
            <button
              v-if="!gate.always"
              type="button"
              role="switch"
              :aria-checked="gate.enabled"
              :aria-label="t(gate.labelKey)"
              :data-test="`gate-toggle-${gate.id}`"
              class="relative mt-0.5 inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2"
              :class="
                gate.enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-dark-600'
              "
              @click="toggleGate(gate.id)"
            >
              <span
                class="pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ease-in-out"
                :class="gate.enabled ? 'translate-x-5' : 'translate-x-0'"
              />
            </button>
            <span
              v-else
              class="mt-1 h-2 w-2 shrink-0 rounded-full bg-emerald-500"
              aria-hidden="true"
            />
          </div>
        </div>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.distill.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.distill.description") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-3">
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.distill.hardNeedles") }}</span>
            <textarea
              :value="listText.hard_needles"
              class="input mt-1 min-h-24 w-full font-mono text-xs"
              data-test="distill-hard-needles"
              :aria-label="t('admin.riskGate.config.distill.hardNeedles')"
              @input="updateList('hard_needles', $event)"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.distill.needles") }}</span>
            <textarea
              :value="listText.needles"
              class="input mt-1 min-h-24 w-full font-mono text-xs"
              data-test="distill-needles"
              :aria-label="t('admin.riskGate.config.distill.needles')"
              @input="updateList('needles', $event)"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.distill.fingerprints") }}</span>
            <textarea
              :value="listText.fingerprints"
              class="input mt-1 min-h-24 w-full font-mono text-xs"
              data-test="distill-fingerprints"
              :aria-label="t('admin.riskGate.config.distill.fingerprints')"
              @input="updateList('fingerprints', $event)"
            />
          </label>
        </div>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.distill.listHint") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.distill.skip_official"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.distill.skipOfficial')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.distill.skipOfficial") }}
          </label>
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.distill.skip_zero"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.distill.skipZero')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.distill.skipZero") }}
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.distill.minMaxTokens") }}</span>
            <input
              v-model.number="local.distill.min_max_tokens"
              class="input mt-1 w-full"
              type="number"
              min="0"
              :aria-label="t('admin.riskGate.config.distill.minMaxTokens')"
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.distill.contestPattern") }}</span>
            <input
              v-model="local.distill.contest_pattern"
              class="input mt-1 w-full font-mono text-xs"
              :aria-label="t('admin.riskGate.config.distill.contestPattern')"
              @input="sync"
            />
          </label>
        </div>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.regex.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.regex.description") }}
        </p>
        <div class="mt-3 space-y-2">
          <p class="text-xs text-gray-600 dark:text-dark-200">
            {{ t("admin.riskGate.config.regex.categories") }}
          </p>
          <div class="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
            <label
              v-for="category in regexCategories"
              :key="category"
              class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
            >
              <input
                type="checkbox"
                :checked="(local.regex.categories ?? []).includes(category)"
                :aria-label="category"
                :data-test="`regex-category-${category}`"
                @change="toggleCategory(category, $event)"
              />
              {{ category }}
            </label>
          </div>
        </div>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.regex.custom_rules"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.regex.customRules')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.regex.customRules") }}
          </label>
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.regex.expand_base64"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.regex.expandBase64')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.regex.expandBase64") }}
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.regex.maxInputBytes") }}</span>
            <input
              v-model.number="local.regex.max_input_bytes"
              class="input mt-1 w-full"
              type="number"
              min="1024"
              :aria-label="t('admin.riskGate.config.regex.maxInputBytes')"
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.regex.blockMessage") }}</span>
            <input
              v-model="local.regex.block_message"
              class="input mt-1 w-full"
              :placeholder="
                t('admin.riskGate.config.regex.blockMessagePlaceholder')
              "
              :aria-label="t('admin.riskGate.config.regex.blockMessage')"
              @input="sync"
            />
          </label>
        </div>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.refusalCache.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.refusalCache.description") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-3">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.refusal_cache.enabled"
              type="checkbox"
              data-test="refusal-cache-enabled"
              :aria-label="t('admin.riskGate.config.refusalCache.enabled')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.refusalCache.enabled") }}
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.refusalCache.similarityThreshold")
            }}</span>
            <input
              v-model.number="local.refusal_cache.similarity_threshold"
              class="input mt-1 w-full"
              type="number"
              step="0.01"
              min="0"
              max="1"
              :aria-label="
                t('admin.riskGate.config.refusalCache.similarityThreshold')
              "
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.refusalCache.minShingleRunes")
            }}</span>
            <input
              v-model.number="local.refusal_cache.min_shingle_runes"
              class="input mt-1 w-full"
              type="number"
              min="1"
              :aria-label="
                t('admin.riskGate.config.refusalCache.minShingleRunes')
              "
              @change="sync"
            />
          </label>
        </div>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.decisionModel.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.decisionModel.description") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.decision_model.enabled"
              type="checkbox"
              data-test="decision-model-enabled"
              :aria-label="t('admin.riskGate.config.decisionModel.enabled')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.decisionModel.enabled") }}
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.decisionModel.threshold")
            }}</span>
            <input
              v-model.number="local.decision_model.threshold"
              class="input mt-1 w-full"
              type="number"
              step="0.01"
              min="0"
              max="1"
              :aria-label="t('admin.riskGate.config.decisionModel.threshold')"
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.decisionModel.timeoutMs")
            }}</span>
            <input
              v-model.number="local.decision_model.timeout_ms"
              class="input mt-1 w-full"
              type="number"
              min="100"
              :aria-label="t('admin.riskGate.config.decisionModel.timeoutMs')"
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.decisionModel.maxConcurrent")
            }}</span>
            <input
              v-model.number="local.decision_model.max_concurrent"
              class="input mt-1 w-full"
              type="number"
              min="1"
              :aria-label="
                t('admin.riskGate.config.decisionModel.maxConcurrent')
              "
              @change="sync"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{
              t("admin.riskGate.config.decisionModel.onUnavailable")
            }}</span>
            <select
              v-model="local.decision_model.on_unavailable"
              class="input mt-1 w-full"
              data-test="on-unavailable"
              :aria-label="
                t('admin.riskGate.config.decisionModel.onUnavailable')
              "
              @change="sync"
            >
              <option value="pass">
                {{ t("admin.riskGate.config.decisionModel.onUnavailablePass") }}
              </option>
              <option value="fail_closed">
                {{
                  t(
                    "admin.riskGate.config.decisionModel.onUnavailableFailClosed",
                  )
                }}
              </option>
            </select>
          </label>
        </div>
        <p
          class="mt-3 rounded-lg px-3 py-2 text-xs leading-5"
          :class="
            local.decision_model.on_unavailable === 'pass'
              ? 'bg-amber-50 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200'
              : 'bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-300'
          "
          data-test="on-unavailable-hint"
        >
          {{
            local.decision_model.on_unavailable === "pass"
              ? t("admin.riskGate.config.decisionModel.onUnavailablePassHint")
              : t(
                  "admin.riskGate.config.decisionModel.onUnavailableFailClosedHint",
                )
          }}
        </p>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.ban.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.ban.description") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.ban.scope") }}</span>
            <select
              v-model="local.ban.scope"
              class="input mt-1 w-full"
              data-test="ban-scope"
              :aria-label="t('admin.riskGate.config.ban.scope')"
              @change="sync"
            >
              <option value="api_key">
                {{ t("admin.riskGate.config.ban.scopeApiKey") }}
              </option>
              <option value="user">
                {{ t("admin.riskGate.config.ban.scopeUser") }}
              </option>
              <option value="client_fingerprint">
                {{ t("admin.riskGate.config.ban.scopeClientFingerprint") }}
              </option>
            </select>
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.ban.durationHours") }}</span>
            <input
              v-model.number="local.ban.duration_hours"
              class="input mt-1 w-full"
              type="number"
              min="0"
              :aria-label="t('admin.riskGate.config.ban.durationHours')"
              @change="sync"
            />
          </label>
        </div>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.ban.scopeHint") }}
        </p>
        <div class="mt-3 grid gap-2 sm:grid-cols-3">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.ban.on_distill"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.ban.onDistill')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.ban.onDistill") }}
          </label>
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.ban.on_regex"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.ban.onRegex')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.ban.onRegex") }}
          </label>
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.ban.on_decision_model"
              type="checkbox"
              :aria-label="t('admin.riskGate.config.ban.onDecisionModel')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.ban.onDecisionModel") }}
          </label>
        </div>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.ban.durationHint") }}
        </p>
      </fieldset>

      <fieldset
        class="mt-6 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      >
        <legend class="px-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t("admin.riskGate.config.scope.title") }}
        </legend>
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.scope.description") }}
        </p>
        <div class="mt-3 grid gap-3 sm:grid-cols-2">
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.scope.all_groups"
              type="checkbox"
              data-test="all-groups"
              :aria-label="t('admin.riskGate.config.scope.allGroups')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.scope.allGroups") }}
          </label>
          <label
            class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
          >
            <input
              v-model="local.scope.all_providers"
              type="checkbox"
              data-test="all-providers"
              :aria-label="t('admin.riskGate.config.scope.allProviders')"
              @change="sync"
            />
            {{ t("admin.riskGate.config.scope.allProviders") }}
          </label>
          <label
            v-if="!local.scope.all_groups"
            class="text-xs text-gray-600 dark:text-dark-200"
          >
            <span>{{ t("admin.riskGate.config.scope.groupIds") }}</span>
            <textarea
              :value="listText.group_ids"
              class="input mt-1 min-h-20 w-full font-mono text-xs"
              data-test="group-ids"
              :aria-label="t('admin.riskGate.config.scope.groupIds')"
              @input="updateNumberList('group_ids', $event)"
            />
          </label>
          <label
            v-if="!local.scope.all_providers"
            class="text-xs text-gray-600 dark:text-dark-200"
          >
            <span>{{ t("admin.riskGate.config.scope.providers") }}</span>
            <textarea
              :value="listText.providers"
              class="input mt-1 min-h-20 w-full font-mono text-xs"
              data-test="providers"
              :aria-label="t('admin.riskGate.config.scope.providers')"
              @input="updateList('providers', $event)"
            />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t("admin.riskGate.config.scope.retentionDays") }}</span>
            <input
              v-model.number="local.retention_days"
              class="input mt-1 w-full"
              type="number"
              min="1"
              :aria-label="t('admin.riskGate.config.scope.retentionDays')"
              @change="sync"
            />
          </label>
        </div>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.config.scope.retentionHint") }}
        </p>
      </fieldset>
    </section>

    <ClassifierEndpointEditor
      :endpoints="local.decision_model.endpoints"
      :probe-results="probeResults"
      :probing-ids="probingIds"
      @update:endpoints="replaceEndpoints"
      @probe="$emit('probe', $event)"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { ClassifierEndpoint, ProbeResult, RiskGateConfig } from "../types";
import {
  cloneData,
  formatNumberList,
  formatStringList,
  gateSummary,
  parseNumberList,
  parseStringList,
} from "../viewModel";
import ClassifierEndpointEditor from "./ClassifierEndpointEditor.vue";

const props = defineProps<{
  draft: RiskGateConfig;
  probeResults: Record<string, ProbeResult>;
  probingIds: string[];
}>();
const emit = defineEmits<{
  (event: "update:draft", value: RiskGateConfig): void;
  (event: "probe", endpoint: ClassifierEndpoint): void;
}>();
const { t } = useI18n();

const regexCategories = ["sexual", "distill", "jailbreak", "bypass"];
const local = reactive<RiskGateConfig>(cloneData(props.draft));
// 列表类字段单独保存原始文本，避免每次输入都被重新分割导致光标跳动。
const listText = reactive({
  hard_needles: "",
  needles: "",
  fingerprints: "",
  group_ids: "",
  providers: "",
});

function initListText() {
  listText.hard_needles = formatStringList(local.distill.hard_needles);
  listText.needles = formatStringList(local.distill.needles);
  listText.fingerprints = formatStringList(local.distill.fingerprints);
  listText.group_ids = formatNumberList(local.scope.group_ids);
  listText.providers = formatStringList(local.scope.providers);
}
initListText();

// 只有父组件真正换了内容（重置/冲突重载）才覆盖本地草稿；
// 自己 emit 出去的克隆与 local 相等，这条守卫会跳过，避免刷新输入框。
watch(
  () => props.draft,
  (value) => {
    if (JSON.stringify(value) === JSON.stringify(local)) return;
    Object.assign(local, cloneData(value));
    initListText();
  },
  { deep: true },
);

const gateItems = computed(() => gateSummary(local));

function sync() {
  emit("update:draft", cloneData(local));
}

function toggleGate(id: string) {
  const gates = local.gates as unknown as Record<string, boolean>;
  if (!(id in gates)) return;
  gates[id] = !gates[id];
  sync();
}

function toggleCategory(category: string, event: Event) {
  const checked = (event.target as HTMLInputElement).checked;
  const current = new Set(local.regex.categories ?? []);
  if (checked) current.add(category);
  else current.delete(category);
  local.regex.categories = [...current];
  sync();
}

function updateList(
  field: "hard_needles" | "needles" | "fingerprints" | "providers",
  event: Event,
) {
  const value = (event.target as HTMLTextAreaElement).value;
  listText[field] = value;
  const parsed = parseStringList(value);
  if (field === "providers") local.scope.providers = parsed;
  else local.distill[field] = parsed;
  sync();
}

function updateNumberList(field: "group_ids", event: Event) {
  const value = (event.target as HTMLTextAreaElement).value;
  listText[field] = value;
  local.scope.group_ids = parseNumberList(value);
  sync();
}

function replaceEndpoints(endpoints: ClassifierEndpoint[]) {
  local.decision_model.endpoints = endpoints;
  sync();
}
</script>
