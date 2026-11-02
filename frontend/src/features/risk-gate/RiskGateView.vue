<template>
  <AppLayout class="risk-audit-layout">
    <div
      class="risk-audit-workspace mx-auto w-full min-w-0 max-w-[1600px] pb-24"
    >
      <header class="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div class="min-w-0">
          <p
            class="text-xs font-semibold uppercase tracking-[0.16em] text-primary-600 dark:text-primary-400"
          >
            {{ t("nav.securityAudit") }}
          </p>
          <div class="mt-1 flex flex-wrap items-center gap-3">
            <h1
              class="text-2xl font-semibold tracking-tight text-gray-950 dark:text-white"
            >
              {{ t("admin.riskGate.title") }}
            </h1>
            <span
              class="rounded-full px-2.5 py-0.5 text-xs font-semibold"
              :class="modeBadgeClass"
              data-test="mode-badge"
              >{{ t(currentMode.labelKey) }}</span
            ><span
              v-if="draft"
              class="text-xs text-gray-500 dark:text-dark-400"
              data-test="config-version"
              >{{
                t("admin.riskGate.configVersion", { version: configVersion })
              }}</span
            >
          </div>
          <p class="mt-2 max-w-4xl text-sm text-gray-500 dark:text-dark-300">
            {{ t("admin.riskGate.description") }}
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="btn btn-secondary"
            :disabled="refreshing"
            @click="refreshReadOnly"
          >
            {{
              refreshing
                ? t("admin.riskGate.actions.loading")
                : t("admin.riskGate.actions.refresh")
            }}</button
          ><button
            type="button"
            class="btn btn-ghost"
            @click="toolsOpen = !toolsOpen"
          >
            {{ t("admin.riskGate.tools.title") }}
          </button>
        </div>
      </header>

      <div
        v-if="loadErrors.config && !draft"
        role="alert"
        class="rounded-xl border border-red-200 bg-red-50 p-5 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300"
      >
        {{ loadErrors.config }}
        <button
          type="button"
          class="btn btn-secondary btn-sm ml-3"
          @click="loadConfig"
        >
          {{ t("admin.riskGate.actions.retry") }}
        </button>
      </div>
      <template v-else>
        <AccountScopePanel
          v-if="draft"
          :scope="draft.scope"
          :inventory="scopeInventory"
          :dirty="scopeDirty"
          @update:scope="updateScope"
        />
        <p
          v-if="loadErrors.scope"
          role="alert"
          class="mt-2 text-xs text-red-700 dark:text-red-300"
        >
          {{ loadErrors.scope }}
        </p>

        <details
          v-if="draft"
          class="mt-3 rounded-xl border border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900"
          :open="globalOpen"
        >
          <summary class="cursor-pointer px-4 py-3 text-sm font-medium">
            {{ t("admin.riskGate.sections.global")
            }}<span class="ml-3 text-xs text-gray-500">{{
              t(currentMode.labelKey)
            }}</span>
          </summary>
          <div
            class="grid gap-4 border-t border-gray-200 p-4 dark:border-dark-700 sm:grid-cols-3"
          >
            <label class="text-xs"
              >{{ t("admin.riskGate.config.mode")
              }}<select
                v-model="draft.mode"
                data-test="mode-select"
                class="input mt-1 w-full"
              >
                <option value="off">{{ t("admin.riskGate.mode.off") }}</option>
                <option value="observe">
                  {{ t("admin.riskGate.mode.observe") }}
                </option>
                <option value="blocking">
                  {{ t("admin.riskGate.mode.blocking") }}
                </option>
              </select></label
            ><label class="text-xs"
              >{{ t("admin.riskGate.config.ban.scope")
              }}<select v-model="draft.ban.scope" class="input mt-1 w-full">
                <option value="api_key">API Key</option>
                <option value="user">
                  {{ t("admin.riskGate.config.ban.scopeUser") }}
                </option>
                <option value="client_fingerprint">
                  {{ t("admin.riskGate.config.ban.scopeClientFingerprint") }}
                </option>
              </select></label
            ><label class="text-xs"
              >{{ t("admin.riskGate.config.ban.durationHours")
              }}<input
                v-model.number="draft.ban.duration_hours"
                type="number"
                min="0"
                class="input mt-1 w-full" /></label
            ><label class="text-xs"
              >{{ t("admin.riskGate.config.scope.retentionDays")
              }}<input
                v-model.number="draft.retention_days"
                type="number"
                min="1"
                max="3650"
                class="input mt-1 w-full" /></label
            ><label
              v-for="item in [
                { field: 'on_distill', label: 'onDistill' },
                { field: 'on_regex', label: 'onRegex' },
                { field: 'on_decision_model', label: 'onDecisionModel' },
              ] as const"
              :key="item.field"
              class="flex items-center gap-2 text-xs"
              ><input v-model="draft.ban[item.field]" type="checkbox" />{{
                t(`admin.riskGate.config.ban.${item.label}`)
              }}</label
            >
            <p class="text-xs text-gray-500 sm:col-span-3">
              {{ t(`admin.riskGate.modeHints.${draft.mode}`) }}
            </p>
          </div>
        </details>
        <div class="mt-4">
          <GateRail
            :stats="stats"
            :states="railStates"
            :view="view"
            @view="go"
          />
        </div>
        <p
          v-if="loadErrors.stats"
          role="alert"
          class="mt-2 text-sm text-red-700 dark:text-red-300"
        >
          {{ loadErrors.stats }}
        </p>
        <ClassifierUsagePanel
          v-if="view === 'all' || view === 'jev'"
          class="mt-6"
          :usage="usage"
          :loading="loading.usage"
          :error="loadErrors.usage || ''"
          @next-page="loadNextUsage"
        />

        <main
          id="risk-panel"
          class="mt-6 space-y-6"
          role="tabpanel"
          :aria-labelledby="`risk-tab-${view}`"
        >
          <div
            v-if="view !== 'all' && view !== 'pass'"
            class="flex flex-wrap items-baseline gap-x-3 gap-y-1"
          >
            <h2 class="text-lg font-semibold tracking-tight">
              {{ stageLabel(view) }}
            </h2>
            <span
              class="risk-state"
              :class="`risk-state--${railStates[view === 'hard-regex' ? 'hard-regex' : view]}`"
              >{{
                t(
                  `admin.riskGate.states.${railStates[view === "hard-regex" ? "hard-regex" : view]}`,
                )
              }}</span
            >
            <p class="basis-full text-sm text-gray-500 dark:text-dark-300">
              {{ stageDescription(view) }}
            </p>
          </div>
          <div
            v-if="view === 'pass'"
            class="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]"
          >
            <section
              class="overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20"
            >
              <header
                class="border-b border-gray-200 px-4 py-3 dark:border-dark-700/60"
              >
                <h3 class="text-sm font-semibold">
                  {{ t("admin.riskGate.passReasons.title") }}
                </h3>
                <p
                  class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400"
                >
                  {{ t("admin.riskGate.passReasons.hint") }}
                </p>
              </header>
              <ul class="divide-y divide-gray-100 dark:divide-dark-800">
                <li
                  v-for="row in stats?.passes ?? []"
                  :key="row.reason"
                  class="flex items-center gap-3 px-4 py-3"
                >
                  <div class="min-w-0 flex-1">
                    <p class="text-sm">{{ passReason(row.reason) }}</p>
                    <p class="text-xs text-gray-500 dark:text-dark-400">
                      {{ passHint(row.reason) }}
                    </p>
                  </div>
                  <span class="text-sm font-medium tabular-nums">{{
                    row.count.toLocaleString()
                  }}</span
                  ><span class="w-14 text-right text-xs text-gray-500">{{
                    share(row.count, stats?.passed)
                  }}</span>
                </li>
              </ul>
              <p
                v-if="!stats?.passes?.length"
                class="px-4 py-8 text-sm text-gray-500"
              >
                {{ t("admin.riskGate.passReasons.empty") }}
              </p>
            </section>
            <RiskFeed
              :rows="upstreamRows"
              :show-kind="false"
              :title="t('admin.riskGate.passReasons.upstreamTitle')"
              :hint="t('admin.riskGate.passReasons.upstreamHint')"
              :empty="t('admin.riskGate.passReasons.upstreamEmpty')"
              :loading="loading.feed"
              :error="loadErrors.feed || ''"
              @open="openEvent"
            />
          </div>
          <div
            v-else
            class="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]"
          >
            <HitSummary
              :rows="visibleHits"
              :show-source="view === 'all'"
              @stage="go"
              :title="t('admin.riskGate.hits.title')"
              :hint="t('admin.riskGate.hits.hint')"
              :empty="t('admin.riskGate.hits.empty')"
              :loading="loading.stats"
              :error="loadErrors.stats || ''"
              @focus-rule="focusRule"
            /><RiskFeed
              :rows="visibleFeed"
              :show-kind="view === 'all'"
              :title="
                view === 'all'
                  ? t('admin.riskGate.feed.allTitle')
                  : t('admin.riskGate.feed.stageTitle')
              "
              :hint="view === 'all' ? t('admin.riskGate.feed.allHint') : ''"
              :empty="t('admin.riskGate.feed.empty')"
              :loading="loading.feed"
              :error="loadErrors.feed || ''"
              @open="openEvent"
            />
          </div>
          <section
            v-if="view === 'distill'"
            id="risk-settings"
            class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700/60 dark:bg-dark-900/20"
          >
            <DistillSettings
              v-if="draft"
              :config="draft"
              @update="updateDraft"
            />
          </section>
          <section
            v-else-if="view === 'hard-regex'"
            id="risk-settings"
            class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700/60 dark:bg-dark-900/20"
          >
            <HardRegexSettings
              v-if="draft"
              :config="draft"
              :rules="rules"
              :focus-rule="focusedRule"
              :sample="regexSample"
              :validating="loading.ruleValidation"
              :validation="ruleValidation"
              @update="updateDraft"
              @update:rules="updateRules"
              @update:sample="regexSample = $event"
              @validate="validateRules"
              @reset-builtin="resetBuiltinRules"
            />
          </section>
          <section
            v-else-if="view === 'refusal'"
            id="risk-settings"
            class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700/60 dark:bg-dark-900/20"
          >
            <RefusalSettings
              v-if="draft"
              :config="savedBase ?? draft"
              :bans="bans.items"
              :refusals="refusals.items"
              :loading="loading.bans || loading.refusals"
              :busy="loading.deleting || loading.releasing"
              :ban-total="bans.total"
              :refusal-total="refusals.total"
              :saving="loading.refusalSave"
              :error="refusalSaveError"
              :saved="refusalSaved"
              @save="saveRefusalPatch"
              @manage-bans="openTools('bans')"
              @clear-bans="clearAllBans"
              @release="releaseBan"
              @delete-refusal="deleteRefusal"
              @clear-refusals="clearRefusals"
              @manage-refusals="openTools('refusals')"
            />
          </section>
          <section
            v-else-if="view === 'jev'"
            id="risk-settings"
            class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700/60 dark:bg-dark-900/20"
          >
            <ModelSettings
              v-if="draft"
              :config="draft"
              :models="models"
              :probe-result="probeResult"
              :probing="loading.probe"
              :loading-models="loading.models"
              @update="updateDraft"
              @probe="probeModel"
              @fetch-models="fetchModels"
              @reset-questions="resetQuestions"
            />
          </section>
        </main>

        <details
          v-if="toolsOpen"
          open
          class="mt-6 rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20"
        >
          <summary
            class="cursor-pointer list-none px-4 py-3 text-sm font-semibold"
          >
            {{ t("admin.riskGate.tools.title")
            }}<span class="ml-2 text-xs font-normal text-gray-500">{{
              t("admin.riskGate.tools.hint")
            }}</span>
          </summary>
          <div
            class="space-y-4 border-t border-gray-200 p-4 dark:border-dark-700/60"
          >
            <div class="flex flex-wrap gap-2">
              <button
                v-for="tool in toolTabs"
                :key="tool.id"
                type="button"
                class="btn btn-secondary btn-sm"
                :class="{ 'ring-2 ring-primary-500': activeTool === tool.id }"
                @click="openTools(tool.id)"
              >
                {{ tool.label }}
              </button>
            </div>
            <RuntimeOverview
              v-if="activeTool === 'runtime'"
              :status="status"
              :loading="loading.status"
              :error="loadErrors.status || ''"
              @refresh="loadStatus"
            /><RuleTable
              v-if="activeTool === 'rules'"
              :rules="rules"
              :saving="loading.savingRules"
              :error="loadErrors.rules || ''"
              @update:rules="updateRules"
              @save="saveLegacyRules"
            /><BanPanel
              v-if="activeTool === 'bans'"
              :bans="bans.items"
              :total="bans.total"
              :page="bans.page"
              :page-size="bans.page_size"
              :filter="banFilter"
              :loading="loading.bans"
              :error="loadErrors.bans || ''"
              :creating="loading.creatingBan"
              @create="createBan"
              @release="releaseBan"
              @page="changeBanPage"
              @page-size="changeBanPageSize"
              @filter-change="changeBanFilter"
            /><EventWorkspace
              v-if="activeTool === 'events'"
              :events="historyEvents.items"
              :total="historyEvents.total"
              :page="historyEvents.page"
              :page-size="historyEvents.page_size"
              :filter="eventFilter"
              :loading="loading.events"
              :error="loadErrors.events || ''"
              :exporting="loading.exporting"
              @filters-change="eventFilter = $event"
              @search="applyEventFilters"
              @page="changeEventPage"
              @page-size="changeEventPageSize"
              @view="openEvent"
              @delete-preview="openDeletePreview"
              @export="exportEvents"
            /><RefusalPanel
              v-if="activeTool === 'refusals'"
              :refusals="refusals.items"
              :total="refusals.total"
              :page="refusals.page"
              :page-size="refusals.page_size"
              :filter="refusalFilter"
              :loading="loading.refusals"
              :error="loadErrors.refusals || ''"
              @delete="deleteRefusal"
              @clear-all="clearRefusals"
              @page="changeRefusalPage"
              @page-size="changeRefusalPageSize"
              @filter-change="changeRefusalFilter"
            />
          </div>
        </details>
      </template>

      <div
        v-if="conflict"
        data-test="config-conflict"
        role="alert"
        class="fixed inset-x-4 bottom-20 z-30 mx-auto max-w-3xl rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 shadow-lg dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-100"
      >
        <p class="font-medium">{{ t("admin.riskGate.conflict.title") }}</p>
        <p class="mt-1 text-xs">
          {{ t("admin.riskGate.conflict.description") }}
        </p>
        <div class="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            @click="reloadAfterConflict"
          >
            {{ t("admin.riskGate.conflict.reload") }}</button
          ><button
            type="button"
            class="btn btn-secondary btn-sm"
            @click="rebaseAfterConflict"
          >
            {{ t("admin.riskGate.conflict.rebase") }}</button
          ><button
            type="button"
            class="btn btn-ghost btn-sm"
            @click="conflict = false"
          >
            {{ t("admin.riskGate.conflict.keepDraft") }}
          </button>
        </div>
      </div>
      <footer
        v-if="draft && dirty"
        class="pointer-events-none fixed inset-x-4 bottom-4 z-40 mx-auto w-fit max-w-[calc(100%-2rem)] rounded-xl border border-gray-200 bg-white px-4 py-3 shadow-lg dark:border-dark-700 dark:bg-dark-900"
      >
        <div class="pointer-events-auto">
          <div
            class="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3"
          >
            <div
              class="text-xs"
              :class="
                dirty
                  ? 'text-amber-700 dark:text-amber-300'
                  : 'text-gray-500 dark:text-dark-400'
              "
              data-test="dirty-state"
            >
              {{
                dirty
                  ? t("admin.riskGate.saveBar.dirtySections", {
                      sections: dirtySectionLabel,
                    })
                  : t("admin.riskGate.saveBar.synced")
              }}<span v-if="savedAt" class="ml-2 text-gray-400">{{
                t("admin.riskGate.updatedAt", { time: formatDate(savedAt) })
              }}</span>
            </div>
            <div class="flex gap-2">
              <button
                type="button"
                class="btn btn-secondary"
                data-test="reset-config"
                :disabled="!dirty || loading.saving"
                @click="resetDraft"
              >
                {{ t("admin.riskGate.actions.reset") }}</button
              ><button
                type="button"
                class="btn btn-primary"
                data-test="save-config"
                :disabled="
                  !dirty ||
                  loading.saving ||
                  loading.refusalSave ||
                  Boolean(blockReason)
                "
                @click="saveConfig"
              >
                {{
                  loading.saving
                    ? t("admin.riskGate.actions.saving")
                    : t("admin.riskGate.actions.save")
                }}
              </button>
            </div>
          </div>
          <p
            v-if="blockReason"
            data-test="save-block-reason"
            class="mx-auto mt-1 max-w-[1600px] text-xs text-amber-700 dark:text-amber-300"
          >
            {{ t(blockReason) }}
          </p>
        </div>
      </footer>
    </div>
    <FilterDeleteDialog
      :show="showDelete"
      :initial-filter="deleteFilter"
      :preview="deletePreview"
      :previewing="loading.previewing"
      :deleting="loading.deleting"
      @close="showDelete = false"
      @preview="previewDelete"
      @confirm="deleteEventsByFilter"
      @criteria-change="
        deletePreview = null;
        generations.preview = (generations.preview ?? 0) + 1;
      "
    />
    <EventDetailDialog
      :show="showEventDetail"
      :event="activeEvent"
      :loading="loading.detail"
      @close="
        showEventDetail = false;
        generations.detail = (generations.detail ?? 0) + 1;
      "
      @focus-rule="focusRule"
    />
  </AppLayout>
</template>

<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  onMounted,
  reactive,
  ref,
  watch,
} from "vue";
import { onBeforeRouteLeave, useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import AppLayout from "@/components/layout/AppLayout.vue";
import { useAppStore } from "@/stores/app";
import { extractApiErrorCode, extractApiErrorMessage } from "@/utils/apiError";
import AccountScopePanel from "./components/AccountScopePanel.vue";
import BanPanel from "./components/BanPanel.vue";
import ClassifierUsagePanel from "./components/ClassifierUsagePanel.vue";
import DistillSettings from "./components/DistillSettings.vue";
import EventDetailDialog from "./components/EventDetailDialog.vue";
import EventWorkspace from "./components/EventWorkspace.vue";
import FilterDeleteDialog from "./components/FilterDeleteDialog.vue";
import GateRail from "./components/GateRail.vue";
import HardRegexSettings from "./components/HardRegexSettings.vue";
import HitSummary from "./components/HitSummary.vue";
import ModelSettings from "./components/ModelSettings.vue";
import RefusalPanel from "./components/RefusalPanel.vue";
import RefusalSettings from "./components/RefusalSettings.vue";
import RiskFeed from "./components/RiskFeed.vue";
import RuleTable from "./components/RuleTable.vue";
import RuntimeOverview from "./components/RuntimeOverview.vue";
import riskGateAPI from "./api";
import type {
  Ban,
  BanFilter,
  ClassifierEndpoint,
  ClassifierUsagePage,
  CreateBanRequest,
  EventFilter,
  EventRow,
  PageResult,
  ProbeResult,
  RefusalFilter,
  RefusalRow,
  RiskGateConfig,
  RiskGateView,
  RiskStats,
  RiskState,
  Rule,
  RuleValidationResult,
  ScopeInventory,
  StatusSnapshot,
} from "./types";
import {
  buildUpdateRequest,
  cloneData,
  configBlockReason,
  configToDraft,
  defaultPolicyQuestions,
  draftFingerprint,
  emptyEventFilter,
  isRiskGateView,
  modeMeta,
  rebaseRuleDraft,
  riskEventViewQuery,
  share,
} from "./viewModel";

const { t, locale } = useI18n();
const appStore = useAppStore();
const route = useRoute();
const router = useRouter();
const view = computed<RiskGateView>(() =>
  isRiskGateView(route.query.view) ? route.query.view : "all",
);
const draft = ref<RiskGateConfig | null>(null);
const savedBase = ref<RiskGateConfig | null>(null);
const configVersion = ref(0);
const savedAt = ref("");
const status = ref<StatusSnapshot | null>(null);
const stats = ref<RiskStats | null>(null);
const scopeInventory = ref<ScopeInventory | null>(null);
const rules = ref<Rule[]>([]);
const savedRules = ref<Rule[]>([]);
const builtinRules = ref<Rule[]>([]);
const ruleVersion = ref(0);
const ruleValidation = ref<RuleValidationResult | null>(null);
const regexSample = ref("");
const focusedRule = ref<string | null>(null);
const models = ref<Array<{ id: string }>>([]);
const probeResult = ref<ProbeResult | null>(null);
const usage = ref<ClassifierUsagePage | null>(null);
const toolsOpen = ref(false);
const activeTool = ref<"runtime" | "rules" | "bans" | "events" | "refusals">(
  "runtime",
);
const globalOpen = ref(false);
const conflict = ref(false);
const conflictSource = ref<"config" | "rules">("config");
const refusalSaved = ref(false);
const refusalSaveError = ref("");
const refreshing = ref(false);
const loading = reactive({
  config: false,
  status: false,
  stats: false,
  feed: false,
  events: false,
  usage: false,
  scope: false,
  rules: false,
  ruleValidation: false,
  saving: false,
  savingRules: false,
  refusalSave: false,
  probe: false,
  models: false,
  bans: false,
  refusals: false,
  detail: false,
  creatingBan: false,
  releasing: false,
  previewing: false,
  deleting: false,
  exporting: false,
});
const loadErrors = reactive({
  config: "",
  status: "",
  stats: "",
  usage: "",
  scope: "",
  feed: "",
  events: "",
  rules: "",
  bans: "",
  refusals: "",
});
const feedRows = ref<EventRow[]>([]);
const eventFilter = ref<EventFilter>(emptyEventFilter());
const appliedEventFilter = ref<EventFilter>(emptyEventFilter());
const deleteFilter = ref<EventFilter>(emptyEventFilter());
const deletePreview = ref<{ total: number } | null>(null);
const showDelete = ref(false);
const showEventDetail = ref(false);
const activeEvent = ref<EventRow | null>(null);
const banFilter = ref<BanFilter>({ scope: "", subject: "", active_only: true });
const refusalFilter = ref<RefusalFilter>({
  provider: "",
  source: "",
  prompt_hash: "",
});
const emptyPage = <T,>(): PageResult<T> => ({
  items: [],
  total: 0,
  page: 1,
  page_size: 20,
  pages: 0,
});
const bans = reactive(emptyPage<Ban>());
const refusals = reactive(emptyPage<RefusalRow>());
const historyEvents = reactive(emptyPage<EventRow>());
let pollTimer: number | null = null;
let disposed = false;
const generations: Record<string, number> = {};

const configDirty = computed(() =>
  Boolean(
    draft.value &&
    savedBase.value &&
    draftFingerprint(draft.value, 0) !== draftFingerprint(savedBase.value, 0),
  ),
);
const rulesDirty = computed(
  () => JSON.stringify(rules.value) !== JSON.stringify(savedRules.value),
);
const dirty = computed(() => configDirty.value || rulesDirty.value);
const scopeDirty = computed(() =>
  Boolean(
    draft.value &&
    savedBase.value &&
    JSON.stringify(draft.value.scope) !== JSON.stringify(savedBase.value.scope),
  ),
);
const currentMode = computed(() =>
  modeMeta(status.value?.mode ?? savedBase.value?.mode ?? "off"),
);
const modeBadgeClass = computed(() =>
  currentMode.value.tone === "warn"
    ? "bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300"
    : currentMode.value.tone === "danger"
      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300"
      : "bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300",
);
const dirtySectionLabel = computed(() => {
  const labels: string[] = [];
  const mapping = {
    scope: "scope",
    distill: "distill",
    regex: "hard-regex",
    refusal_cache: "refusal",
    decision_model: "jev",
    ban: "global",
    mode: "global",
    retention_days: "global",
    gates: "global",
  } as const;
  if (draft.value && savedBase.value)
    for (const key of Object.keys(mapping) as Array<keyof typeof mapping>) {
      if (
        JSON.stringify(draft.value[key]) !==
        JSON.stringify(savedBase.value[key])
      )
        labels.push(t(`admin.riskGate.sections.${mapping[key]}`));
    }
  if (rulesDirty.value) labels.push(t("admin.riskGate.sections.rules"));
  return [...new Set(labels)].join(" · ");
});
const blockReason = computed(() =>
  configDirty.value ? configBlockReason(draft.value) : "",
);
const railStates = computed<
  Record<"distill" | "hard-regex" | "refusal" | "jev", RiskState>
>(() => ({
  distill: stateFor("distill"),
  "hard-regex": stateFor("regex"),
  refusal: stateFor("refusal_cache"),
  jev: stateFor("decision_model"),
}));
const gateForView = (key: RiskGateView) =>
  ({
    "hard-regex": "regex",
    refusal: "refusal_cache",
    jev: "decision_model",
    distill: "distill",
    all: "",
    pass: "",
  })[key];
const visibleHits = computed(() =>
  (stats.value?.blocks ?? []).filter(
    (row) => view.value === "all" || row.gate === gateForView(view.value),
  ),
);
const visibleFeed = computed(() =>
  feedRows.value.filter(
    (row) =>
      row.kind === "blocked" &&
      (view.value === "all" || row.gate === gateForView(view.value)),
  ),
);
const upstreamRows = computed(() =>
  feedRows.value.filter(
    (row) =>
      row.kind === "upstream_refusal" || row.reason === "upstream_refusal",
  ),
);
const toolTabs = computed(() =>
  (["runtime", "rules", "bans", "events", "refusals"] as const).map((id) => ({
    id,
    label: t(`admin.riskGate.tabs.${id}`),
  })),
);

function stateFor(gate: keyof RiskGateConfig["gates"]): RiskState {
  const config = savedBase.value;
  if (!config || loading.config) return "loading";
  if (config.mode === "off" || !config.gates[gate]) return "off";
  if (
    gate === "decision_model" &&
    !config.decision_model.endpoints.some((e) => e.enabled && e.base_url.trim())
  )
    return "unset";
  return config.mode === "observe" ? "observe" : "on";
}
function stageLabel(stage: RiskGateView) {
  return t(`admin.riskGate.rail.${stage}`);
}
function stageDescription(stage: RiskGateView) {
  return t(`admin.riskGate.stageDescriptions.${stage}`);
}
function passReason(reason: string) {
  const key = `admin.riskGate.passReasons.reasons.${reason}`;
  const text = t(key);
  return text === key ? reason : text;
}
function passHint(reason: string) {
  const key = `admin.riskGate.passReasons.hints.${reason}`;
  const text = t(key);
  return text === key ? "" : text;
}
function errorMessage(error: unknown, fallback: string) {
  const code = extractApiErrorCode(error);
  const key = `admin.riskGate.errors.${code}`;
  const translated = code ? t(key) : "";
  return translated && translated !== key
    ? translated
    : extractApiErrorMessage(error, fallback);
}
function report(error: unknown, key: string) {
  appStore.showError(errorMessage(error, t(`admin.riskGate.errors.${key}`)));
}
function isConflict(error: unknown) {
  const code = extractApiErrorCode(error);
  return (
    code === "risk_gate_config_conflict" ||
    code === "risk_gate_rules_conflict" ||
    (error as { response?: { status?: number } })?.response?.status === 409
  );
}
function updateDraft(value: RiskGateConfig) {
  draft.value = cloneData(value);
}
function updateScope(value: RiskGateConfig["scope"]) {
  if (draft.value) draft.value.scope = cloneData(value);
}
function mergeConfig(
  base: RiskGateConfig,
  partial: Partial<RiskGateConfig>,
): RiskGateConfig {
  const result = cloneData(base);
  for (const key of Object.keys(partial) as Array<keyof RiskGateConfig>) {
    const value = partial[key];
    if (value !== undefined)
      Object.assign(result, {
        [key]:
          value && typeof value === "object" && !Array.isArray(value)
            ? { ...(result[key] as object), ...value }
            : value,
      });
  }
  return result;
}
// Apply only fields changed locally since the shared base. Unrelated remote
// changes are retained; arrays are atomic editor units, never concatenated.
function rebaseValue(base: unknown, local: unknown, remote: unknown): unknown {
  if (JSON.stringify(base) === JSON.stringify(local)) return remote;
  if (!local || typeof local !== "object" || Array.isArray(local)) return local;
  const out: Record<string, unknown> = {
    ...(remote && typeof remote === "object"
      ? (remote as Record<string, unknown>)
      : {}),
  };
  const old =
    base && typeof base === "object" ? (base as Record<string, unknown>) : {};
  for (const [key, value] of Object.entries(local))
    out[key] = rebaseValue(old[key], value, out[key]);
  return out;
}
async function read<T>(
  key: keyof typeof loadErrors,
  task: () => Promise<T>,
  accept: (value: T) => void,
  fallback: string,
) {
  const generation = (generations[key] = (generations[key] ?? 0) + 1);
  loading[key] = true;
  loadErrors[key] = "";
  try {
    const value = await task();
    if (!disposed && generations[key] === generation) accept(value);
  } catch (error) {
    if (!disposed && generations[key] === generation)
      loadErrors[key] = errorMessage(
        error,
        t(`admin.riskGate.errors.${fallback}`),
      );
  } finally {
    if (generations[key] === generation) loading[key] = false;
  }
}
async function loadConfig() {
  return read(
    "config",
    riskGateAPI.getConfig,
    (result) => {
      savedBase.value = configToDraft(result.config);
      draft.value = cloneData(savedBase.value);
      configVersion.value = result.version;
      savedAt.value = result.updated_at ?? "";
    },
    "loadConfig",
  );
}
async function loadStatus() {
  return read(
    "status",
    riskGateAPI.getStatus,
    (value) => {
      status.value = value;
    },
    "loadStatus",
  );
}
async function loadStats() {
  return read(
    "stats",
    () =>
      riskGateAPI.getStats(
        undefined,
        undefined,
        Intl.DateTimeFormat().resolvedOptions().timeZone,
      ),
    (value) => {
      stats.value = value;
    },
    "loadStats",
  );
}
async function loadScope() {
  return read(
    "scope",
    riskGateAPI.getScopeInventory,
    (value) => {
      scopeInventory.value = value;
    },
    "loadScope",
  );
}
async function loadRuleset() {
  return read(
    "rules",
    riskGateAPI.getRuleset,
    (value) => {
      rules.value = cloneData(value.rules ?? []);
      savedRules.value = cloneData(rules.value);
      builtinRules.value = cloneData(value.builtin_rules ?? []);
      ruleVersion.value = value.version;
    },
    "loadRules",
  );
}
async function loadFeed() {
  const filter = {
    ...emptyEventFilter(),
    ...riskEventViewQuery(view.value),
    from: stats.value?.since ?? "",
  };
  return read(
    "feed",
    () => riskGateAPI.getEvents(filter, 1, 100),
    (result) => {
      feedRows.value = result.items ?? [];
    },
    "loadEvents",
  );
}
async function loadUsage(page = 1) {
  return read(
    "usage",
    () => riskGateAPI.getClassifierUsage(page, 50),
    (result) => {
      usage.value = result;
    },
    "loadUsage",
  );
}
async function loadNextUsage() {
  if (usage.value && usage.value.page < usage.value.pages)
    await loadUsage(usage.value.page + 1);
}
async function refreshReadOnly() {
  if (refreshing.value || disposed) return;
  refreshing.value = true;
  try {
    await Promise.allSettled([loadStatus(), loadStats()]);
    await loadFeed();
    if (view.value === "all" || view.value === "jev") await loadUsage();
  } finally {
    refreshing.value = false;
  }
}
async function saveConfig() {
  if (
    !draft.value ||
    !dirty.value ||
    blockReason.value ||
    loading.saving ||
    loading.refusalSave
  )
    return;
  loading.saving = true;
  try {
    if (configDirty.value) {
      const submitted = cloneData(draft.value);
      const result = await riskGateAPI.updateConfig(
        buildUpdateRequest(submitted, configVersion.value),
      );
      const server = configToDraft(result.config);
      draft.value =
        JSON.stringify(submitted) === JSON.stringify(draft.value)
          ? cloneData(server)
          : (rebaseValue(submitted, draft.value, server) as RiskGateConfig);
      savedBase.value = server;
      configVersion.value = result.version;
      savedAt.value = result.updated_at ?? "";
      appStore.showSuccess(t("admin.riskGate.messages.saved"));
    }
    if (rulesDirty.value) await persistRules();
    conflict.value = false;
    await refreshReadOnly();
  } catch (error) {
    if (isConflict(error)) {
      conflict.value = true;
      conflictSource.value =
        extractApiErrorCode(error) === "risk_gate_rules_conflict"
          ? "rules"
          : "config";
    } else report(error, "saveConfig");
  } finally {
    loading.saving = false;
  }
}
async function persistRules() {
  loading.savingRules = true;
  try {
    const submitted = cloneData(rules.value);
    const result = await riskGateAPI.saveRuleset(ruleVersion.value, submitted);
    savedRules.value = cloneData(result.rules);
    if (JSON.stringify(submitted) === JSON.stringify(rules.value))
      rules.value = cloneData(result.rules);
    ruleVersion.value = result.version;
    appStore.showSuccess(t("admin.riskGate.messages.rulesSaved"));
  } finally {
    loading.savingRules = false;
  }
}
function resetDraft() {
  if (savedBase.value) draft.value = cloneData(savedBase.value);
  rules.value = cloneData(savedRules.value);
  conflict.value = false;
  ruleValidation.value = null;
}
async function reloadAfterConflict() {
  if (conflictSource.value === "rules") await loadRuleset();
  else await loadConfig();
  conflict.value = false;
}
async function rebaseAfterConflict() {
  try {
    if (conflictSource.value === "rules") {
      const result = await riskGateAPI.getRuleset();
      rules.value = rebaseRuleDraft(savedRules.value, rules.value, result.rules);
      savedRules.value = cloneData(result.rules);
      ruleVersion.value = result.version;
    } else if (draft.value && savedBase.value) {
      const result = await riskGateAPI.getConfig();
      const server = configToDraft(result.config);
      draft.value = rebaseValue(
        savedBase.value,
        draft.value,
        server,
      ) as RiskGateConfig;
      savedBase.value = server;
      configVersion.value = result.version;
      savedAt.value = result.updated_at ?? "";
    }
    conflict.value = false;
  } catch (error) {
    report(error, "loadConfig");
  }
}
async function saveRefusalPatch(partial: Partial<RiskGateConfig>) {
  if (!savedBase.value || loading.refusalSave || loading.saving) return;
  loading.refusalSave = true;
  refusalSaveError.value = "";
  refusalSaved.value = false;
  try {
    const submitted = mergeConfig(savedBase.value, partial);
    const result = await riskGateAPI.updateConfig(
      buildUpdateRequest(submitted, configVersion.value),
    );
    savedBase.value = configToDraft(result.config);
    configVersion.value = result.version;
    savedAt.value = result.updated_at ?? "";
    if (draft.value) {
      draft.value.refusal_cache = cloneData(savedBase.value.refusal_cache);
      draft.value.gates.refusal_cache = savedBase.value.gates.refusal_cache;
    }
    refusalSaved.value = true;
    await Promise.allSettled([loadStatus(), loadStats()]);
  } catch (error) {
    if (isConflict(error)) {
      conflictSource.value = "config";
      conflict.value = true;
    }
    refusalSaveError.value = errorMessage(
      error,
      t("admin.riskGate.errors.saveRefusal"),
    );
  } finally {
    loading.refusalSave = false;
  }
}
async function validateRules(sample: string) {
  loading.ruleValidation = true;
  const snapshot = JSON.stringify(rules.value);
  try {
    const result = await riskGateAPI.validateRules(rules.value, sample);
    if (snapshot === JSON.stringify(rules.value)) ruleValidation.value = result;
  } catch (error) {
    ruleValidation.value = {
      valid: false,
      errors: [
        {
          index: -1,
          message: errorMessage(
            error,
            t("admin.riskGate.errors.validateRules"),
          ),
        },
      ],
      matches: [],
    };
  } finally {
    loading.ruleValidation = false;
  }
}
function updateRules(value: Rule[]) {
  rules.value = cloneData(value);
  ruleValidation.value = null;
}
function resetBuiltinRules() {
  if (!window.confirm(t("admin.riskGate.stages.hardRegex.resetBuiltinConfirm")))
    return;
  rules.value = cloneData(builtinRules.value);
  ruleValidation.value = null;
}
async function saveLegacyRules(value: Rule[]) {
  updateRules(value);
  try {
    await persistRules();
    await refreshReadOnly();
  } catch (error) {
    if (isConflict(error)) {
      conflictSource.value = "rules";
      conflict.value = true;
    }
    report(error, "saveRules");
  }
}
async function probeModel(endpoint: ClassifierEndpoint) {
  if (loading.probe) return;
  loading.probe = true;
  probeResult.value = null;
  try {
    probeResult.value = await riskGateAPI.probeClassifier({
      endpoint: cloneData(endpoint),
      text: regexSample.value || undefined,
      decision_model: draft.value
        ? cloneData(draft.value.decision_model)
        : undefined,
    });
    await loadUsage();
  } catch (error) {
    probeResult.value = {
      ok: false,
      score: 0,
      category: "",
      latency_ms: 0,
      endpoint_id: endpoint.id,
      error: errorMessage(error, t("admin.riskGate.errors.probe")),
    };
  } finally {
    loading.probe = false;
  }
}
async function fetchModels(endpoint: ClassifierEndpoint) {
  if (loading.models) return;
  loading.models = true;
  models.value = [];
  try {
    models.value =
      (await riskGateAPI.getClassifierModels(endpoint)).models ?? [];
  } catch (error) {
    report(error, "models");
  } finally {
    loading.models = false;
  }
}
function resetQuestions() {
  if (draft.value)
    draft.value.decision_model.questions = defaultPolicyQuestions();
}
async function focusRule(rule: string) {
  const target = rules.value.find(
    (item) => item.rule_key === rule || String(item.id) === rule,
  );
  focusedRule.value = rule;
  await router.replace({
    query: {
      ...route.query,
      view: target?.gate === "distill" ? "distill" : "hard-regex",
    },
  });
  await nextTick();
  const row = document.querySelector<HTMLElement>(
    `[data-rule-key="${CSS.escape(rule)}"]`,
  );
  if (row) {
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.querySelector<HTMLInputElement>('input[type="text"], input:not([type])')?.focus({ preventScroll: true });
  } else {
    document.getElementById("risk-settings")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}
function go(next: RiskGateView) {
  if (next === view.value) return;
  focusedRule.value = null;
  void router.replace({
    query: { ...route.query, view: next === "all" ? undefined : next },
  });
}
function openTools(tool: typeof activeTool.value) {
  toolsOpen.value = true;
  activeTool.value = tool;
  if (tool === "bans") void loadBans();
  if (tool === "events") void loadHistoricalEvents();
  if (tool === "refusals") void loadRefusals();
}
async function loadBans() {
  return read(
    "bans",
    () => riskGateAPI.getBans(banFilter.value, bans.page, bans.page_size),
    (result) => Object.assign(bans, result),
    "loadBans",
  );
}
async function loadHistoricalEvents() {
  return read(
    "events",
    () =>
      riskGateAPI.getEvents(
        appliedEventFilter.value,
        historyEvents.page,
        historyEvents.page_size,
      ),
    (result) => Object.assign(historyEvents, result),
    "loadEvents",
  );
}
async function loadRefusals() {
  return read(
    "refusals",
    () =>
      riskGateAPI.getRefusals(
        refusalFilter.value,
        refusals.page,
        refusals.page_size,
      ),
    (result) => Object.assign(refusals, result),
    "loadRefusals",
  );
}
function changeBanFilter(value: BanFilter) {
  banFilter.value = cloneData(value);
  bans.page = 1;
  void loadBans();
}
function changeBanPage(value: number) {
  bans.page = value;
  void loadBans();
}
function changeBanPageSize(value: number) {
  bans.page_size = value;
  bans.page = 1;
  void loadBans();
}
async function createBan(payload: CreateBanRequest) {
  if (loading.creatingBan) return;
  loading.creatingBan = true;
  try {
    await riskGateAPI.createBan(payload);
    await Promise.allSettled([loadBans(), loadStatus()]);
  } catch (error) {
    report(error, "createBan");
  } finally {
    loading.creatingBan = false;
  }
}
async function releaseBan(id: number) {
  if (loading.releasing) return;
  loading.releasing = true;
  try {
    await riskGateAPI.deleteBan(id);
    await Promise.allSettled([loadBans(), loadStatus()]);
  } catch (error) {
    report(error, "releaseBan");
  } finally {
    loading.releasing = false;
  }
}
async function clearAllBans() {
  if (
    !window.confirm(t("admin.riskGate.stages.refusal.clearBansConfirm")) ||
    loading.releasing
  )
    return;
  loading.releasing = true;
  try {
    await riskGateAPI.clearBans("client_fingerprint");
    await Promise.allSettled([loadBans(), loadStatus()]);
  } catch (error) {
    report(error, "clearBans");
  } finally {
    loading.releasing = false;
  }
}
function applyEventFilters(value: EventFilter) {
  eventFilter.value = cloneData(value);
  appliedEventFilter.value = cloneData(value);
  historyEvents.page = 1;
  deletePreview.value = null;
  void loadHistoricalEvents();
}
function changeEventPage(value: number) {
  historyEvents.page = value;
  void loadHistoricalEvents();
}
function changeEventPageSize(value: number) {
  historyEvents.page = 1;
  historyEvents.page_size = value;
  void loadHistoricalEvents();
}
async function openEvent(id: number) {
  const generation = (generations.detail = (generations.detail ?? 0) + 1);
  showEventDetail.value = true;
  activeEvent.value = null;
  loading.detail = true;
  try {
    const result = await riskGateAPI.getEvent(id);
    if (generation === generations.detail && showEventDetail.value)
      activeEvent.value = result;
  } catch (error) {
    if (generation === generations.detail) {
      report(error, "loadDetail");
      showEventDetail.value = false;
    }
  } finally {
    if (generation === generations.detail) loading.detail = false;
  }
}
function openDeletePreview() {
  deleteFilter.value = cloneData(appliedEventFilter.value);
  deletePreview.value = null;
  showDelete.value = true;
}
async function previewDelete(value: EventFilter) {
  const generation = (generations.preview = (generations.preview ?? 0) + 1);
  loading.previewing = true;
  try {
    const result = await riskGateAPI.previewDeleteEvents(value);
    if (generation === generations.preview) deletePreview.value = result;
  } catch (error) {
    report(error, "previewDelete");
  } finally {
    if (generation === generations.preview) loading.previewing = false;
  }
}
async function deleteEventsByFilter(value: EventFilter) {
  if (loading.deleting || !deletePreview.value) return;
  loading.deleting = true;
  try {
    await riskGateAPI.deleteEventsByFilter(value);
    showDelete.value = false;
    deletePreview.value = null;
    await Promise.allSettled([loadFeed(), loadHistoricalEvents(), loadStats()]);
  } catch (error) {
    deletePreview.value = null;
    report(error, "deleteEvents");
  } finally {
    loading.deleting = false;
  }
}
async function exportEvents() {
  if (loading.exporting) return;
  loading.exporting = true;
  try {
    const filename = await riskGateAPI.exportEvents(appliedEventFilter.value);
    appStore.showSuccess(t("admin.riskGate.messages.exported", { filename }));
  } catch (error) {
    report(error, "export");
  } finally {
    loading.exporting = false;
  }
}
function changeRefusalFilter(value: RefusalFilter) {
  refusalFilter.value = cloneData(value);
  refusals.page = 1;
  void loadRefusals();
}
function changeRefusalPage(value: number) {
  refusals.page = value;
  void loadRefusals();
}
function changeRefusalPageSize(value: number) {
  refusals.page_size = value;
  refusals.page = 1;
  void loadRefusals();
}
async function deleteRefusal(id: number) {
  if (loading.deleting) return;
  loading.deleting = true;
  try {
    await riskGateAPI.deleteRefusal(id);
    await loadRefusals();
  } catch (error) {
    report(error, "deleteRefusal");
  } finally {
    loading.deleting = false;
  }
}
async function clearRefusals() {
  if (loading.deleting) return;
  loading.deleting = true;
  try {
    await riskGateAPI.deleteAllRefusals();
    await loadRefusals();
  } catch (error) {
    report(error, "clearRefusals");
  } finally {
    loading.deleting = false;
  }
}
function formatDate(value: string) {
  return value
    ? new Intl.DateTimeFormat(locale.value, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(new Date(value))
    : "—";
}
async function start() {
  await Promise.allSettled([
    loadConfig(),
    loadStatus(),
    loadStats(),
    loadScope(),
    loadRuleset(),
  ]);
  await Promise.allSettled([loadFeed(), loadUsage()]);
  if (view.value === "refusal")
    await Promise.allSettled([loadBans(), loadRefusals()]);
}
function startPolling() {
  stopPolling();
  if (document.visibilityState !== "visible") return;
  pollTimer = window.setInterval(() => {
    if (document.visibilityState === "visible") void refreshReadOnly();
  }, 30_000);
}
function stopPolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
}
function onVisibility() {
  if (document.visibilityState === "visible") {
    void refreshReadOnly();
    startPolling();
  } else stopPolling();
}
function beforeUnload(event: BeforeUnloadEvent) {
  if (!dirty.value) return;
  event.preventDefault();
  event.returnValue = "";
}
watch(view, () => {
  void loadFeed();
  if (view.value === "all" || view.value === "jev") void loadUsage();
  if (view.value === "refusal")
    void Promise.allSettled([loadBans(), loadRefusals()]);
});
onMounted(() => {
  void start();
  document.addEventListener("visibilitychange", onVisibility);
  window.addEventListener("beforeunload", beforeUnload);
  startPolling();
});
onBeforeUnmount(() => {
  disposed = true;
  stopPolling();
  document.removeEventListener("visibilitychange", onVisibility);
  window.removeEventListener("beforeunload", beforeUnload);
  for (const key of Object.keys(generations)) generations[key]++;
});
onBeforeRouteLeave(
  () =>
    !dirty.value || window.confirm(t("admin.riskGate.saveBar.leaveConfirm")),
);
</script>

<style scoped>
.risk-audit-layout :deep(.bg-mesh-gradient) {
  display: none;
}

.risk-audit-workspace :deep(input[type="checkbox"]) {
  appearance: none;
  -webkit-appearance: none;
  position: relative;
  display: inline-block;
  width: 2.25rem;
  height: 1.25rem;
  min-width: 2.25rem;
  border: 0;
  border-radius: 999px;
  background: #d1d5db;
  cursor: pointer;
  vertical-align: middle;
  transition: background 0.15s;
}
.risk-audit-workspace :deep(input[type="checkbox"]::before) {
  content: "";
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 50%;
  background: white;
  box-shadow: 0 1px 2px #0002;
  transition: transform 0.15s;
}
.risk-audit-workspace :deep(input[type="checkbox"]:checked) {
  background: #16a34a;
}
.risk-audit-workspace :deep(input[type="checkbox"]:checked::before) {
  transform: translateX(1rem);
}
.risk-audit-workspace :deep(input[type="checkbox"]:disabled) {
  cursor: not-allowed;
  opacity: 0.45;
}
.risk-audit-workspace :deep(input[type="checkbox"]:focus-visible) {
  outline: 2px solid #16a34a;
  outline-offset: 3px;
}
.risk-audit-workspace :deep(.input) {
  min-width: 0;
}
:global(.dark .risk-audit-workspace .input:not(:disabled)) {
  color: #f3f4f6;
}

.risk-audit-workspace :deep(summary) {
  list-style: none;
}
.risk-audit-workspace :deep(summary::-webkit-details-marker) {
  display: none;
}
.risk-audit-workspace :deep(summary::after) {
  content: "⌄";
  float: right;
  margin-left: 0.5rem;
  color: #9ca3af;
}
.risk-audit-workspace :deep(details[open] > summary::after) {
  content: "⌃";
}
:global(.dark .risk-audit-workspace input[type="checkbox"]) {
  background: #475569;
}
:global(.dark .risk-audit-workspace input[type="checkbox"]:checked) {
  background: #16a34a;
}
@media (prefers-reduced-motion: reduce) {
  .risk-audit-workspace :deep(input[type="checkbox"]),
  .risk-audit-workspace :deep(input[type="checkbox"]::before) {
    transition: none;
  }
}
</style>
