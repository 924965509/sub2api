<template>
  <div class="space-y-8" data-test="refusal-settings">
    <section class="space-y-3">
      <h3 class="text-sm font-semibold">
        {{ t("admin.riskGate.stages.refusal.title") }}
      </h3>
      <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">
        {{ t("admin.riskGate.stages.refusal.description") }}
      </p>
      <div
        class="grid overflow-hidden rounded-xl border border-gray-200 dark:border-dark-700 md:grid-cols-2"
      >
        <label
          class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700 md:border-r"
          ><span>{{ t("admin.riskGate.stages.refusal.enabled") }}</span
          ><input
            type="checkbox"
            :checked="config.gates.refusal_cache"
            :disabled="saving"
            data-test="refusal-enabled"
            @change="saveEnabled(checked($event))"
        /></label>
        <label
          class="flex items-center justify-between gap-4 border-b border-gray-200 px-4 py-3 text-sm dark:border-dark-700"
          ><span>{{ t("admin.riskGate.stages.refusal.similarity") }}</span
          ><input
            type="checkbox"
            :checked="config.refusal_cache.similarity_enabled"
            :disabled="saving || !config.gates.refusal_cache"
            data-test="refusal-similarity"
            @change="save({ similarity_enabled: checked($event) })"
        /></label>
        <label
          class="flex items-center justify-between gap-4 px-4 py-3 text-sm md:border-r dark:border-dark-700"
          ><span>{{ t("admin.riskGate.stages.refusal.deviceBlock") }}</span
          ><input
            type="checkbox"
            :checked="config.refusal_cache.device_block_enabled"
            :disabled="saving"
            data-test="refusal-device-block"
            @change="save({ device_block_enabled: checked($event) })"
        /></label>
        <label class="flex items-center justify-between gap-4 px-4 py-3 text-sm"
          ><span>{{ t("admin.riskGate.stages.refusal.threshold") }}</span
          ><select
            class="input w-24 tabular-nums"
            :value="Math.round(config.refusal_cache.similarity_threshold * 100)"
            :disabled="saving || !config.refusal_cache.similarity_enabled"
            data-test="refusal-threshold"
            @change="
              save({ similarity_threshold: Number(value($event)) / 100 })
            "
          >
            <option
              v-for="percent in thresholds"
              :key="percent"
              :value="percent"
            >
              {{ percent }}%
            </option>
          </select></label
        >
      </div>
      <p class="text-xs leading-5 text-gray-500">
        {{ t("admin.riskGate.stages.refusal.cacheOnlyUpstream") }}
        {{ t("admin.riskGate.stages.refusal.shortTextHint") }}
      </p>
      <p
        v-if="error"
        role="alert"
        class="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/30 dark:text-red-200"
      >
        {{ error }}
      </p>
      <p v-else-if="saving" role="status" class="text-xs text-gray-500">
        {{ t("admin.riskGate.actions.saving") }}
      </p>
      <p
        v-else-if="saved"
        role="status"
        class="text-xs text-emerald-700 dark:text-emerald-300"
      >
        {{ t("admin.riskGate.stages.refusal.saved") }}
      </p>
    </section>
    <div class="grid gap-8 xl:grid-cols-2">
      <section class="min-w-0 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold">
            {{ t("admin.riskGate.stages.refusal.identityBans") }}
            <span class="text-xs font-normal text-gray-500">{{
              banTotal
            }}</span>
          </h3>
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            :disabled="
              busy || !bans.some((ban) => ban.scope === 'client_fingerprint')
            "
            @click="$emit('clear-bans')"
          >
            {{ t("admin.riskGate.stages.refusal.clearBans") }}
          </button>
        </div>
        <p class="text-xs leading-5 text-gray-500">
          {{ t("admin.riskGate.stages.refusal.identityHint") }}
        </p>
        <div
          class="max-h-[28rem] divide-y divide-gray-200 overflow-y-auto rounded-xl border border-gray-200 dark:divide-dark-700 dark:border-dark-700"
        >
          <p v-if="loading" class="p-4 text-sm text-gray-500">
            {{ t("common.loading") }}
          </p>
          <p v-else-if="!bans.length" class="p-4 text-sm text-gray-500">
            {{ t("admin.riskGate.bans.empty") }}
          </p>
          <div
            v-for="ban in bans"
            v-else
            :key="ban.id"
            class="flex items-start gap-3 px-4 py-3"
          >
            <div class="min-w-0 flex-1">
              <p class="break-all font-mono text-xs">
                {{ ban.scope }} · {{ ban.subject }}
              </p>
              <p class="mt-1 break-words text-xs text-gray-500">
                {{ ban.reason }}
              </p>
              <p class="mt-1 text-xs text-gray-400">
                {{ date(ban.banned_at) }} · {{ ban.hit_count }}
              </p>
            </div>
            <button
              type="button"
              class="btn btn-ghost btn-sm shrink-0"
              :disabled="busy"
              :data-test="`inline-release-${ban.id}`"
              @click="confirmRelease(ban)"
            >
              {{ t("admin.riskGate.bans.release") }}
            </button>
          </div>
        </div>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          @click="$emit('manage-bans')"
        >
          {{ t("admin.riskGate.tools.manageBans") }}
        </button>
      </section>
      <section class="min-w-0 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold">
            {{ t("admin.riskGate.stages.refusal.fingerprints") }}
            <span class="text-xs font-normal text-gray-500">{{
              refusalTotal
            }}</span>
          </h3>
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            :disabled="busy || !refusalTotal"
            @click="confirmClear"
          >
            {{ t("admin.riskGate.actions.clear") }}
          </button>
        </div>
        <p class="text-xs leading-5 text-gray-500">
          {{ t("admin.riskGate.stages.refusal.fingerprintHint") }}
        </p>
        <div
          class="max-h-[28rem] divide-y divide-gray-200 overflow-y-auto rounded-xl border border-gray-200 dark:divide-dark-700 dark:border-dark-700"
        >
          <p v-if="loading" class="p-4 text-sm text-gray-500">
            {{ t("common.loading") }}
          </p>
          <p v-else-if="!refusals.length" class="p-4 text-sm text-gray-500">
            {{ t("admin.riskGate.refusals.empty") }}
          </p>
          <div
            v-for="row in refusals"
            v-else
            :key="row.id"
            class="flex items-start gap-3 px-4 py-3"
          >
            <div class="min-w-0 flex-1">
              <p class="line-clamp-3 break-words text-sm">
                {{ row.normalized_prompt || "—" }}
              </p>
              <p
                v-if="row.error_message"
                class="mt-1 line-clamp-2 text-xs text-gray-500"
              >
                {{ row.error_message }}
              </p>
              <p class="mt-1 break-all font-mono text-[11px] text-gray-400">
                {{ row.prompt_hash }}
              </p>
              <p class="mt-1 text-xs text-gray-500">
                {{ row.model }} · {{ date(row.created_at)
                }}<span v-if="row.hit_count !== undefined">
                  · {{ row.hit_count }}</span
                >
              </p>
            </div>
            <button
              type="button"
              class="btn btn-ghost btn-sm shrink-0"
              :disabled="busy"
              :data-test="`inline-refusal-delete-${row.id}`"
              @click="confirmDelete(row)"
            >
              {{ t("common.delete") }}
            </button>
          </div>
        </div>
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          @click="$emit('manage-refusals')"
        >
          {{ t("admin.riskGate.tabs.refusals") }} · {{ t("common.all") }}
        </button>
      </section>
    </div>
    <ConfirmDialog
      :show="Boolean(pending)"
      :title="confirmationTitle"
      :message="confirmationMessage"
      :confirm-text="t('common.confirm')"
      :loading="busy"
      danger
      @confirm="confirmAction"
      @cancel="pending = null"
    />
  </div>
</template>
<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import ConfirmDialog from "@/components/common/ConfirmDialog.vue";
import type { Ban, RefusalRow, RiskGateConfig } from "../types";
const props = defineProps<{
  config: RiskGateConfig;
  saving: boolean;
  error: string;
  saved: boolean;
  bans: Ban[];
  refusals: RefusalRow[];
  loading: boolean;
  busy: boolean;
  banTotal: number;
  refusalTotal: number;
}>();
const emit = defineEmits<{
  (event: "save", value: Partial<RiskGateConfig>): void;
  (event: "manage-bans"): void;
  (event: "clear-bans"): void;
  (event: "release", id: number): void;
  (event: "delete-refusal", id: number): void;
  (event: "clear-refusals"): void;
  (event: "manage-refusals"): void;
}>();
const { t, locale } = useI18n();
const pending = ref<{
  type: "release" | "delete" | "clear";
  id?: number;
} | null>(null);
const thresholds = computed(() =>
  [
    ...new Set([
      80,
      85,
      90,
      95,
      Math.round(props.config.refusal_cache.similarity_threshold * 100),
    ]),
  ].sort((a, b) => a - b),
);
const confirmationTitle = computed(() =>
  t(
    pending.value?.type === "release"
      ? "admin.riskGate.bans.releaseConfirmTitle"
      : pending.value?.type === "clear"
        ? "admin.riskGate.refusals.clearConfirmTitle"
        : "admin.riskGate.refusals.deleteConfirmTitle",
  ),
);
const confirmationMessage = computed(() =>
  t(
    pending.value?.type === "release"
      ? "admin.riskGate.bans.releaseConfirmMessage"
      : pending.value?.type === "clear"
        ? "admin.riskGate.refusals.clearConfirmMessage"
        : "admin.riskGate.refusals.deleteConfirmMessage",
    { count: props.refusalTotal },
  ),
);
function checked(event: Event) {
  return (event.target as HTMLInputElement).checked;
}
function value(event: Event) {
  return (event.target as HTMLSelectElement).value;
}
function save(partial: Partial<RiskGateConfig["refusal_cache"]>) {
  emit("save", {
    refusal_cache: { ...props.config.refusal_cache, ...partial },
  });
}
function saveEnabled(enabled: boolean) {
  emit("save", {
    gates: { ...props.config.gates, refusal_cache: enabled },
    refusal_cache: { ...props.config.refusal_cache, enabled },
  });
}
function confirmRelease(row: Ban) {
  pending.value = { type: "release", id: row.id };
}
function confirmDelete(row: RefusalRow) {
  pending.value = { type: "delete", id: row.id };
}
function confirmClear() {
  pending.value = { type: "clear" };
}
function confirmAction() {
  const action = pending.value;
  if (!action || props.busy) return;
  pending.value = null;
  if (action.type === "release") emit("release", action.id!);
  else if (action.type === "delete") emit("delete-refusal", action.id!);
  else emit("clear-refusals");
}
function date(value: string) {
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
</script>
