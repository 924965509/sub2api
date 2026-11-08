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

      <section
        v-if="inventory?.accounts?.length"
        class="space-y-3 rounded-lg border border-gray-200 p-3 dark:border-dark-700/60"
      >
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 class="text-sm font-medium">
              {{ t("admin.riskGate.scope.apiChannels") }}
            </h3>
            <p class="text-xs text-gray-500 dark:text-dark-400">
              {{ t("admin.riskGate.scope.apiChannelsHint") }}
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <button
              v-for="tab in filterTabs"
              :key="tab.id"
              type="button"
              class="rounded-md border px-2.5 py-1 text-xs transition-colors"
              :class="
                accountTypeFilter === tab.id
                  ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-950/30 dark:text-primary-300'
                  : 'border-gray-200 text-gray-600 hover:border-primary-300 dark:border-dark-700 dark:text-dark-300'
              "
              @click="accountTypeFilter = tab.id"
            >
              {{ tab.label }}
              <span class="tabular-nums opacity-60">{{ tab.count }}</span>
            </button>
          </div>
        </div>

        <div v-if="apiDomainOptions.length" class="space-y-1.5">
          <div class="text-xs font-medium text-gray-500 dark:text-dark-400">
            {{ t("admin.riskGate.scope.apiDomains") }}
          </div>
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="domain in apiDomainOptions"
              :key="domain.baseUrl"
              type="button"
              data-test="api-domain-chip"
              class="rounded-lg border px-2.5 py-1 font-mono text-xs transition-colors"
              :class="
                isAccountTokenSelected(domain.baseUrl)
                  ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-950/30 dark:text-primary-300'
                  : 'border-gray-200 text-gray-600 hover:border-primary-300 dark:border-dark-700 dark:text-dark-300'
              "
              :aria-pressed="isAccountTokenSelected(domain.baseUrl)"
              @click="toggleAccountToken(domain.baseUrl)"
            >
              {{ domain.host }}
              <span class="tabular-nums opacity-60">{{ domain.count }}</span>
            </button>
          </div>
        </div>

        <input
          v-model="searchQuery"
          type="search"
          data-test="scope-account-search"
          class="input w-full text-xs"
          :placeholder="t('admin.riskGate.scope.searchAccountsPlaceholder')"
        />

        <div class="flex max-h-48 flex-wrap gap-1.5 overflow-y-auto pr-1">
          <button
            v-for="account in filteredAccounts"
            :key="account.id"
            type="button"
            data-test="scope-account-chip"
            class="inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs transition-colors"
            :class="
              isAccountDirectlySelected(account)
                ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-950/30 dark:text-primary-300'
                : 'border-gray-200 text-gray-600 hover:border-primary-300 dark:border-dark-700 dark:text-dark-300'
            "
            :aria-pressed="isAccountDirectlySelected(account)"
            @click="toggleAccount(account)"
          >
            <span class="font-mono opacity-60">#{{ account.id }}</span>
            <span class="max-w-[220px] truncate font-medium">{{
              account.name
            }}</span>
            <span
              class="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] uppercase text-gray-600 dark:bg-dark-800 dark:text-dark-300"
              >{{ account.platform }} · {{ accountBadgeType(account) }}</span
            >
          </button>
        </div>
      </section>

      <section>
        <div class="mb-1 flex items-center justify-between gap-2">
          <label class="text-sm font-medium" for="risk-scope-accounts">{{
            t("admin.riskGate.scope.accounts")
          }}</label>
          <button
            v-if="scope.account_ids?.length"
            type="button"
            class="btn btn-ghost btn-sm"
            @click="patch({ account_ids: [] })"
          >
            {{ t("admin.riskGate.actions.clear") }}
          </button>
        </div>
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
import type { ScopeAccount, ScopeConfig, ScopeInventory } from "../types";
import {
  extractBaseURLHost,
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
const accountTypeFilter = ref<"all" | "apikey" | "oauth">("all");
const searchQuery = ref("");

const allAccounts = computed(() => props.inventory?.accounts ?? []);
const isApiKeyAccount = (account: ScopeAccount) =>
  account.account_type?.toLowerCase() === "apikey" ||
  account.plan_type?.toLowerCase() === "apikey";

const filterTabs = computed(() => {
  const apiCount = allAccounts.value.filter(isApiKeyAccount).length;
  const oauthCount = allAccounts.value.length - apiCount;
  return [
    {
      id: "all" as const,
      label: t("admin.riskGate.scope.filterAll"),
      count: allAccounts.value.length,
    },
    {
      id: "apikey" as const,
      label: t("admin.riskGate.scope.filterApiKey"),
      count: apiCount,
    },
    {
      id: "oauth" as const,
      label: t("admin.riskGate.scope.filterOAuth"),
      count: oauthCount,
    },
  ];
});

const apiDomainOptions = computed(() => {
  const map = new Map<string, { baseUrl: string; host: string; count: number }>();
  for (const account of allAccounts.value) {
    if (!account.base_url) continue;
    const baseUrl = account.base_url.trim().replace(/\/+$/, "");
    const host = extractBaseURLHost(baseUrl);
    if (!baseUrl || !host) continue;
    const key = host.toLowerCase();
    const existing = map.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      map.set(key, { baseUrl, host, count: 1 });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count || a.host.localeCompare(b.host));
});

const filteredAccounts = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  return allAccounts.value.filter((account) => {
    if (accountTypeFilter.value === "apikey" && !isApiKeyAccount(account)) {
      return false;
    }
    if (accountTypeFilter.value === "oauth" && isApiKeyAccount(account)) {
      return false;
    }
    if (!q) return true;
    const haystack = [
      account.id,
      account.name,
      account.email,
      account.base_url,
      account.platform,
      account.plan_type,
      account.account_type,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
});

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
function accountBadgeType(account: ScopeAccount): string {
  if (isApiKeyAccount(account)) return "apikey";
  return account.plan_type || account.account_type || "oauth";
}
function normalizeToken(value?: string | null): string {
  return (value ?? "").trim().toLowerCase().replace(/\/+$/, "");
}
function isAccountTokenSelected(token: string): boolean {
  const target = normalizeToken(token);
  const targetHost = extractBaseURLHost(token);
  return (props.scope.account_ids ?? []).some((item) => {
    const norm = normalizeToken(item);
    return norm === target || (targetHost && norm === targetHost);
  });
}
function toggleAccountToken(token: string) {
  const target = normalizeToken(token);
  const targetHost = extractBaseURLHost(token);
  const current = props.scope.account_ids ?? [];
  const exists = current.some((item) => {
    const norm = normalizeToken(item);
    return norm === target || (targetHost && norm === targetHost);
  });
  patch({
    account_ids: exists
      ? current.filter((item) => {
          const norm = normalizeToken(item);
          return norm !== target && (!targetHost || norm !== targetHost);
        })
      : [...current, token],
  });
}
function isAccountDirectlySelected(account: ScopeAccount): boolean {
  const identities = new Set(
    [
      account.id,
      account.name,
      account.email,
      account.base_url,
      extractBaseURLHost(account.base_url),
    ]
      .map((v) => normalizeToken(v))
      .filter(Boolean),
  );
  return (props.scope.account_ids ?? []).some((item) =>
    identities.has(normalizeToken(item)),
  );
}
function toggleAccount(account: ScopeAccount) {
  const current = props.scope.account_ids ?? [];
  const directIdentities = new Set(
    [account.id, account.name, account.email]
      .map((v) => normalizeToken(v))
      .filter(Boolean),
  );
  const hasDirect = current.some((item) =>
    directIdentities.has(normalizeToken(item)),
  );
  if (hasDirect) {
    patch({
      account_ids: current.filter(
        (item) => !directIdentities.has(normalizeToken(item)),
      ),
    });
  } else {
    patch({
      account_ids: [...current, account.id],
    });
  }
}
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
