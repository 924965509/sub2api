<template>
  <section class="min-w-0 overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20" data-test="risk-feed">
    <header class="border-b border-gray-200 px-4 py-3 dark:border-dark-700/60">
      <h3 class="text-sm font-semibold">{{ title }}</h3>
      <p v-if="hint" class="mt-1 text-xs leading-5 text-gray-500 dark:text-dark-400">{{ hint }}</p>
    </header>
    <div v-if="loading" class="px-4 py-8 text-sm text-gray-500" aria-busy="true">{{ t("admin.riskGate.feed.loading") }}</div>
    <p v-else-if="error" role="alert" class="px-4 py-8 text-sm text-red-700 dark:text-red-300">{{ error }}</p>
    <p v-else-if="!rows.length" class="px-4 py-8 text-sm text-gray-500">{{ empty }}</p>
    <ul v-else class="max-h-[34rem] divide-y divide-gray-100 overflow-y-auto dark:divide-dark-800">
      <li v-for="row in rows" :key="row.id">
        <button type="button" class="grid w-full min-w-0 grid-cols-[4.5rem_minmax(0,1fr)] items-baseline gap-x-3 gap-y-1 px-4 py-2.5 text-left transition-colors hover:bg-gray-50 focus-visible:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary-500 dark:hover:bg-dark-800/50 dark:focus-visible:bg-dark-800/50 md:grid-cols-[4.5rem_auto_minmax(0,1fr)_minmax(0,11rem)] motion-reduce:transition-none" :data-test="`feed-event-${row.id}`" @click="$emit('open', row.id)">
          <time :datetime="row.created_at" :title="absoluteTime(row.created_at)" class="text-xs tabular-nums text-gray-500 dark:text-dark-400">{{ relativeTime(row.created_at) }}</time>
          <span v-if="showKind || eventOutcome(row) === 'observe'" class="w-fit whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs" :class="kindClass(row)">{{ labelFor(row) }}</span>
          <span v-else class="hidden md:block" aria-hidden="true" />
          <span class="col-start-2 min-w-0 truncate font-mono text-xs text-gray-700 dark:text-dark-200 md:col-start-auto" :title="row.evidence || row.reason || ''">{{ row.evidence || row.reason || row.category || "—" }}</span>
          <span class="col-start-2 min-w-0 truncate text-xs text-gray-500 dark:text-dark-400 md:col-start-auto md:text-right" :title="identity(row)">{{ identity(row) }}<span v-if="row.model"> · {{ row.model }}</span></span>
        </button>
      </li>
    </ul>
    <p v-if="!loading && !error && rows.length" class="border-t border-gray-200 px-4 py-2 text-xs text-gray-500 dark:border-dark-700/60 dark:text-dark-400">{{ t("admin.riskGate.feed.note", { count: rows.length }) }}</p>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from "vue-i18n";
import type { EventRow } from "../types";
import { eventOutcome } from "../viewModel";
withDefaults(defineProps<{
  rows: EventRow[];
  title: string;
  hint: string;
  empty: string;
  loading: boolean;
  error: string;
  showKind?: boolean;
}>(), { showKind: true });
defineEmits<{ (event: "open", id: number): void }>();
const { t, locale } = useI18n();
function identity(row: EventRow): string {
  const user = row.user_name || row.user_email || (row.user_id ? `user:${row.user_id}` : "");
  const key = row.api_key_name || (row.api_key_id ? `key:${row.api_key_id}` : "");
  return [user, key].filter(Boolean).join(" · ") || t("admin.riskGate.feed.identityUnknown");
}
function labelFor(row: EventRow): string {
  const outcome = eventOutcome(row);
  if (outcome === "blocked" && ["ban", "distill", "regex", "refusal_cache", "decision_model"].includes(row.gate))
    return t(`admin.riskGate.gates.${row.gate}`);
  return t(`admin.riskGate.feed.${outcome}`);
}
function kindClass(row: EventRow): string {
  const outcome = eventOutcome(row);
  if (outcome === "observe" || outcome === "upstreamRefusal" || outcome === "upstreamPass")
    return "bg-amber-50 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300";
  return "bg-gray-100 text-gray-800 dark:bg-dark-800 dark:text-dark-200";
}
function absoluteTime(value: string): string {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(locale.value, { dateStyle: "short", timeStyle: "medium" }).format(date);
}
function relativeTime(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!value || !Number.isFinite(timestamp)) return "—";
  const seconds = Math.round((timestamp - Date.now()) / 1000);
  const relative = new Intl.RelativeTimeFormat(locale.value, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return relative.format(seconds, "second");
  if (Math.abs(seconds) < 3600) return relative.format(Math.round(seconds / 60), "minute");
  if (Math.abs(seconds) < 86400) return relative.format(Math.round(seconds / 3600), "hour");
  return new Intl.DateTimeFormat(locale.value, { month: "numeric", day: "numeric" }).format(timestamp);
}
</script>
