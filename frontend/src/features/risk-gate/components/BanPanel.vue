<template>
  <section aria-labelledby="risk-gate-bans-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-bans-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.bans.title") }}
        </h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.bans.description") }}
        </p>
      </div>
      <label
        class="flex items-center gap-2 text-sm text-gray-700 dark:text-dark-200"
      >
        <input
          :checked="filter.active_only"
          type="checkbox"
          data-test="active-only"
          :aria-label="t('admin.riskGate.bans.activeOnly')"
          @change="toggleActiveOnly"
        />
        {{ t("admin.riskGate.bans.activeOnly") }}
      </label>
    </div>

    <form
      class="mt-5 rounded-xl border border-gray-200 px-4 py-4 dark:border-dark-700/60"
      data-test="ban-form"
      @submit.prevent="submitBan"
    >
      <h3 class="text-sm font-medium text-gray-900 dark:text-white">
        {{ t("admin.riskGate.bans.forms.title") }}
      </h3>
      <div class="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.bans.scope") }}</span>
          <select
            v-model="form.scope"
            class="input mt-1 w-full"
            data-test="ban-form-scope"
            :aria-label="t('admin.riskGate.bans.scope')"
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
          <span>{{ t("admin.riskGate.bans.subject") }}</span>
          <input
            v-model="form.subject"
            class="input mt-1 w-full"
            required
            data-test="ban-form-subject"
            :placeholder="t('admin.riskGate.bans.subjectPlaceholder')"
            :aria-label="t('admin.riskGate.bans.subject')"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.bans.reason") }}</span>
          <input
            v-model="form.reason"
            class="input mt-1 w-full"
            data-test="ban-form-reason"
            :placeholder="t('admin.riskGate.bans.reasonPlaceholder')"
            :aria-label="t('admin.riskGate.bans.reason')"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.bans.durationHoursField") }}</span>
          <input
            v-model.number="form.duration_hours"
            class="input mt-1 w-full"
            type="number"
            min="0"
            data-test="ban-form-duration"
            :aria-label="t('admin.riskGate.bans.durationHoursField')"
          />
        </label>
        <label class="text-xs text-gray-600 dark:text-dark-200">
          <span>{{ t("admin.riskGate.bans.gateField") }}</span>
          <input
            v-model="form.gate"
            class="input mt-1 w-full"
            data-test="ban-form-gate"
            :placeholder="t('admin.riskGate.bans.gateManual')"
            :aria-label="t('admin.riskGate.bans.gateField')"
          />
        </label>
      </div>
      <div class="mt-3 flex flex-wrap items-center justify-between gap-3">
        <p class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.bans.expiresAt") }}: {{ previewExpiry }}
        </p>
        <button
          type="submit"
          class="btn btn-primary btn-sm"
          :disabled="creating || !canSubmit"
          data-test="create-ban"
        >
          {{
            creating
              ? t("admin.riskGate.bans.creating")
              : t("admin.riskGate.bans.forms.submit")
          }}
        </button>
      </div>
      <p
        v-if="!canSubmit"
        class="mt-2 text-xs text-red-600 dark:text-red-300"
        data-test="ban-form-invalid"
      >
        {{ t("admin.riskGate.bans.forms.invalid") }}
      </p>
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
      <table class="w-full min-w-[960px] text-left text-sm">
        <thead
          class="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-dark-900/70 dark:text-dark-400"
        >
          <tr>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.scope") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.subject") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.reason") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.gate") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.hitCount") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.bannedAt") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.expiresAt") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.bans.createdBy") }}
            </th>
            <th class="px-3 py-3 text-right font-medium">
              {{ t("admin.riskGate.bans.release") }}
            </th>
          </tr>
        </thead>
        <tbody
          class="divide-y divide-gray-100 bg-white dark:divide-dark-700 dark:bg-transparent"
        >
          <tr v-if="loading">
            <td
              colspan="9"
              class="px-4 py-10 text-center text-gray-500"
              aria-busy="true"
            >
              {{ t("common.loading") }}
            </td>
          </tr>
          <tr v-else-if="bans.length === 0">
            <td
              colspan="9"
              class="px-4 py-10 text-center text-gray-500"
              data-test="bans-empty"
            >
              {{ t("admin.riskGate.bans.empty") }}
            </td>
          </tr>
          <tr
            v-for="ban in bans"
            v-else
            :key="ban.id"
            :data-test="`ban-${ban.id}`"
          >
            <td class="px-3 py-3 text-gray-700 dark:text-dark-200">
              {{ ban.scope }}
            </td>
            <td
              class="px-3 py-3 font-mono text-xs text-gray-800 dark:text-dark-100"
            >
              {{ ban.subject }}
            </td>
            <td
              class="max-w-56 truncate px-3 py-3 text-gray-600 dark:text-dark-300"
              :title="ban.reason"
            >
              {{ ban.reason || "—" }}
            </td>
            <td class="px-3 py-3 text-gray-700 dark:text-dark-200">
              {{ ban.gate || "—" }}
            </td>
            <td class="px-3 py-3 tabular-nums text-gray-700 dark:text-dark-200">
              {{ ban.hit_count }}
            </td>
            <td
              class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300"
            >
              {{ formatDate(ban.banned_at) }}
            </td>
            <td
              class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300"
            >
              {{
                ban.expires_at
                  ? formatDate(ban.expires_at)
                  : t("admin.riskGate.bans.durationPermanent")
              }}
              <span class="ml-1 text-gray-400"
                >· {{ t(durationOf(ban).key, durationOf(ban).params) }}</span
              >
            </td>
            <td class="px-3 py-3 text-xs text-gray-600 dark:text-dark-300">
              {{ ban.created_by || "—" }}
            </td>
            <td class="whitespace-nowrap px-3 py-3 text-right">
              <button
                type="button"
                class="btn btn-ghost btn-sm text-red-600 dark:text-red-300"
                :data-test="`release-ban-${ban.id}`"
                @click="requestRelease(ban)"
              >
                {{ t("admin.riskGate.bans.release") }}
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
      :show="Boolean(pendingRelease)"
      :title="t('admin.riskGate.bans.releaseConfirmTitle')"
      :message="t('admin.riskGate.bans.releaseConfirmMessage')"
      :confirm-text="t('admin.riskGate.bans.release')"
      danger
      @confirm="confirmRelease"
      @cancel="pendingRelease = null"
    >
      <p
        class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
      >
        {{ t("admin.riskGate.bans.releaseWarning") }}
      </p>
    </ConfirmDialog>
  </section>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import ConfirmDialog from "@/components/common/ConfirmDialog.vue";
import Pagination from "@/components/common/Pagination.vue";
import type { Ban, BanFilter, CreateBanRequest } from "../types";
import { banDurationLabel, expiresAtFromHours } from "../viewModel";

const props = defineProps<{
  bans: Ban[];
  total: number;
  page: number;
  pageSize: number;
  filter: BanFilter;
  loading: boolean;
  error: string;
  creating: boolean;
}>();
const emit = defineEmits<{
  (event: "create", value: CreateBanRequest): void;
  (event: "release", id: number): void;
  (event: "page", value: number): void;
  (event: "page-size", value: number): void;
  (event: "filter-change", value: BanFilter): void;
}>();
const { t, locale } = useI18n();

const form = reactive<CreateBanRequest>({
  scope: "api_key",
  subject: "",
  reason: "",
  duration_hours: 24,
  gate: "manual",
});
const pendingRelease = ref<Ban | null>(null);

const canSubmit = computed(
  () => form.subject.trim().length > 0 && Number(form.duration_hours) >= 0,
);
const previewExpiry = computed(() => {
  const value = expiresAtFromHours(Number(form.duration_hours));
  return value ? formatDate(value) : t("admin.riskGate.bans.durationPermanent");
});

function toggleActiveOnly(event: Event) {
  emit("filter-change", {
    ...props.filter,
    active_only: (event.target as HTMLInputElement).checked,
  });
}

function submitBan() {
  if (!canSubmit.value || props.creating) return;
  emit("create", {
    scope: form.scope,
    subject: form.subject.trim(),
    reason: form.reason.trim(),
    duration_hours: Number(form.duration_hours),
    gate: form.gate.trim() || "manual",
  });
}

function requestRelease(ban: Ban) {
  pendingRelease.value = ban;
}
function confirmRelease() {
  const ban = pendingRelease.value;
  pendingRelease.value = null;
  if (ban) emit("release", ban.id);
}

function durationOf(ban: Ban): { key: string; params: Record<string, number> } {
  return banDurationLabel(ban);
}

function formatDate(value: string): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
</script>
