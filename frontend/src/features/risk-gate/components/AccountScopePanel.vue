<template>
  <details
    class="rounded-xl border border-gray-200 bg-white dark:border-dark-700/60 dark:bg-dark-900/20"
    :open="open || dirty"
    @toggle="onToggle"
  >
    <summary
      class="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500"
    >
      <span>{{ t("admin.riskGate.scope.title") }}</span
      ><span
        class="ml-auto min-w-0 truncate text-xs font-normal text-gray-500 dark:text-dark-400"
        >{{ summary }}</span
      >
    </summary>
    <div
      class="space-y-5 border-t border-gray-200 px-4 py-4 dark:border-dark-700/60"
    >
      <p class="text-xs leading-5 text-gray-500 dark:text-dark-400">
        {{ t("admin.riskGate.scope.description") }}
      </p>
      <section>
        <div class="mb-2 flex items-center justify-between gap-2">
          <div>
            <h3 class="text-sm font-medium">
              {{ t("admin.riskGate.scope.platformPlans") }}
            </h3>
            <p class="text-xs text-gray-500 dark:text-dark-400">
              {{ t("admin.riskGate.scope.platformPlansHint") }}
            </p>
          </div>
          <button
            v-if="scope.account_platform_plans?.length"
            type="button"
            class="btn btn-ghost btn-sm"
            @click="patch({ account_platform_plans: [] })"
          >
            {{ t("admin.riskGate.actions.clear") }}
          </button>
        </div>
        <div
          v-if="inventory?.account_platform_plan_options?.length"
          class="flex flex-wrap gap-2"
        >
          <button
            v-for="option in inventory.account_platform_plan_options"
            :key="option.id"
            type="button"
            class="rounded-lg border px-3 py-1.5 text-xs transition-colors"
            :class="
              scope.account_platform_plans?.includes(option.id)
                ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-950/30 dark:text-primary-300'
                : 'border-gray-200 text-gray-600 hover:border-primary-300 dark:border-dark-700 dark:text-dark-300'
            "
            :aria-pressed="scope.account_platform_plans?.includes(option.id)"
            @click="togglePlan(option.id)"
          >
            {{ option.label }}
            <span class="tabular-nums opacity-60">{{ option.count }}</span>
          </button>
        </div>
        <p v-else class="text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.scope.noAccounts") }}
        </p>
      </section>
      <section>
        <label class="text-sm font-medium" for="risk-scope-accounts">{{
          t("admin.riskGate.scope.accounts")
        }}</label>
        <p class="mb-2 text-xs text-gray-500 dark:text-dark-400">
          {{ t("admin.riskGate.scope.accountsHint") }}
        </p>
        <textarea
          id="risk-scope-accounts"
          class="input min-h-24 w-full font-mono text-xs"
          :value="(scope.account_ids ?? []).join('\n')"
          :placeholder="t('admin.riskGate.scope.accountsPlaceholder')"
          @input="onAccountsInput"
        />
      </section>
      <section
        class="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-gray-50 px-3 py-2.5 text-xs dark:bg-dark-900/50"
      >
        <span>{{
          t("admin.riskGate.scope.matchSummary", {
            matched: matched ?? "—",
            total,
          })
        }}</span
        ><span
          v-if="configured && matched === 0"
          class="font-medium text-amber-700 dark:text-amber-300"
          >{{ t("admin.riskGate.scope.emptyWarning") }}</span
        >
      </section>
      <section
        class="rounded-lg border border-gray-200 px-3 py-3 dark:border-dark-700/60"
      >
        <button
          type="button"
          class="flex w-full items-center justify-between text-left text-xs font-medium"
          :aria-expanded="advancedOpen"
          @click="advancedOpen = !advancedOpen"
        >
          <span>{{ t("admin.riskGate.scope.advanced") }}</span
          ><span aria-hidden="true">{{ advancedOpen ? "−" : "+" }}</span>
        </button>
        <div v-if="advancedOpen" class="mt-3 grid gap-3 sm:grid-cols-2">
          <label class="flex items-center gap-2 text-xs"
            ><input
              type="checkbox"
              :checked="scope.openai_platform_enabled !== false"
              @change="
                patch({
                  openai_platform_enabled: ($event.target as HTMLInputElement)
                    .checked,
                })
              "
            />{{ t("admin.riskGate.scope.openaiPlatform") }}</label
          ><label class="text-xs"
            ><span class="mb-1 block">{{
              t("admin.riskGate.scope.groupIds")
            }}</span
            ><input
              class="input w-full font-mono text-xs"
              :value="(scope.group_ids ?? []).join(', ')"
              @input="onGroupIdsInput" /></label
          ><label class="text-xs"
            ><span class="mb-1 block">{{
              t("admin.riskGate.scope.providers")
            }}</span
            ><input
              class="input w-full font-mono text-xs"
              :value="(scope.providers ?? []).join(', ')"
              @input="onProvidersInput"
          /></label>
        </div>
      </section>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import type { ScopeConfig, ScopeInventory } from "../types";
import {
  parseNumberList,
  parseStringList,
  scopeConfigured,
  scopeMatches,
} from "../viewModel";
const props = defineProps<{
  scope: ScopeConfig;
  inventory: ScopeInventory | null;
  dirty: boolean;
}>();
const emit = defineEmits<{
  (event: "update:scope", value: ScopeConfig): void;
}>();
const { t } = useI18n();
const open = ref(false);
const advancedOpen = ref(false);
const configured = computed(() => scopeConfigured(props.scope));
const matched = computed(() =>
  props.inventory
    ? scopeMatches(props.scope, props.inventory.accounts).length
    : null,
);
const total = computed(
  () =>
    props.inventory?.accounts_total ?? props.inventory?.accounts.length ?? 0,
);
const summary = computed(() =>
  configured.value
    ? t("admin.riskGate.scope.summaryConfigured", {
        matched: matched.value ?? "—",
        total: total.value,
      })
    : t("admin.riskGate.scope.summaryAll", { total: total.value }),
);
function patch(partial: Partial<ScopeConfig>) {
  emit("update:scope", { ...props.scope, ...partial });
}
function togglePlan(id: string) {
  const selected = props.scope.account_platform_plans ?? [];
  patch({
    account_platform_plans: selected.includes(id)
      ? selected.filter((value) => value !== id)
      : [...selected, id],
  });
}
function onAccountsInput(event: Event) {
  patch({
    account_ids: (event.target as HTMLTextAreaElement).value
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean),
  });
}
function onGroupIdsInput(event: Event) {
  patch({
    group_ids: parseNumberList((event.target as HTMLInputElement).value),
    all_groups: false,
  });
}
function onProvidersInput(event: Event) {
  patch({
    providers: parseStringList((event.target as HTMLInputElement).value),
    all_providers: false,
  });
}
function onToggle(event: Event) {
  open.value = (event.target as HTMLDetailsElement).open;
}
</script>
