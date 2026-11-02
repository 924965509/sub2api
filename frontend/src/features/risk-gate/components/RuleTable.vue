<template>
  <section aria-labelledby="risk-gate-rules-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2
          id="risk-gate-rules-title"
          class="text-base font-semibold text-gray-950 dark:text-white"
        >
          {{ t("admin.riskGate.rules.title") }}
        </h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
          {{ t("admin.riskGate.rules.description") }}
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="btn btn-secondary btn-sm"
          data-test="add-rule"
          @click="addRule"
        >
          {{ t("admin.riskGate.rules.add") }}
        </button>
        <button
          type="button"
          class="btn btn-primary btn-sm"
          :disabled="!canSave"
          :title="canSave ? undefined : t('admin.riskGate.rules.invalid')"
          data-test="save-rules"
          @click="$emit('save', rules)"
        >
          {{
            saving
              ? t("admin.riskGate.actions.saving")
              : t("admin.riskGate.rules.save")
          }}
        </button>
      </div>
    </div>

    <div
      v-if="error"
      role="alert"
      class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300"
    >
      {{ error }}
    </div>
    <p
      v-if="invalidCount > 0"
      role="status"
      data-test="rules-invalid-notice"
      class="mt-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200"
    >
      {{ t("admin.riskGate.rules.invalid") }}
    </p>

    <p
      v-if="rules.length === 0"
      class="mt-5 rounded-xl border border-dashed border-gray-300 px-5 py-8 text-center text-sm text-gray-500 dark:border-dark-600 dark:text-dark-300"
      data-test="rules-empty"
    >
      {{ t("admin.riskGate.rules.empty") }}
    </p>

    <div
      v-else
      class="mt-5 overflow-x-auto rounded-xl border border-gray-200 dark:border-dark-700/60"
    >
      <table class="w-full min-w-[1080px] text-left text-sm">
        <thead
          class="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-dark-900/70 dark:text-dark-400"
        >
          <tr>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.gate") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.category") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.pattern") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.isRegex") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.action") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.enabled") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.sortOrder") }}
            </th>
            <th class="px-3 py-3 font-medium">
              {{ t("admin.riskGate.rules.ruleDescription") }}
            </th>
            <th class="px-3 py-3 text-right font-medium">
              {{ t("admin.riskGate.rules.remove") }}
            </th>
          </tr>
        </thead>
        <tbody
          class="divide-y divide-gray-100 bg-white dark:divide-dark-700 dark:bg-transparent"
        >
          <tr
            v-for="(rule, index) in rules"
            :key="rule.id ?? `new-${index}`"
            :data-test="`rule-row-${index}`"
          >
            <td class="px-3 py-3">
              <select
                v-model="rule.gate"
                class="input w-full"
                :aria-label="t('admin.riskGate.rules.gate')"
                @change="update"
              >
                <option value="regex">regex</option>
                <option value="distill">distill</option>
              </select>
            </td>
            <td class="px-3 py-3">
              <select
                v-model="rule.category"
                class="input w-full"
                :aria-label="t('admin.riskGate.rules.category')"
                @change="update"
              >
                <option
                  v-for="category in RULE_CATEGORIES"
                  :key="category"
                  :value="category"
                >
                  {{ category }}
                </option>
              </select>
            </td>
            <td class="px-3 py-3">
              <input
                v-model="rule.pattern"
                class="input w-full font-mono text-xs"
                :placeholder="t('admin.riskGate.rules.patternPlaceholder')"
                :aria-label="t('admin.riskGate.rules.pattern')"
                :data-test="`rule-pattern-${index}`"
                @input="update"
              />
              <p
                v-for="key in errorsOf(rule)"
                :key="key"
                class="mt-1 text-xs text-red-600 dark:text-red-300"
                :data-test="`rule-error-${index}`"
              >
                {{ t(key) }}
              </p>
            </td>
            <td class="px-3 py-3 text-center">
              <input
                v-model="rule.is_regex"
                type="checkbox"
                :aria-label="t('admin.riskGate.rules.isRegex')"
                @change="update"
              />
            </td>
            <td class="px-3 py-3">
              <select
                v-model="rule.action"
                class="input w-full"
                :aria-label="t('admin.riskGate.rules.action')"
                @change="update"
              >
                <option value="block">block</option>
                <option value="observe">observe</option>
              </select>
            </td>
            <td class="px-3 py-3 text-center">
              <input
                v-model="rule.enabled"
                type="checkbox"
                :aria-label="t('admin.riskGate.rules.enabled')"
                @change="update"
              />
            </td>
            <td class="px-3 py-3">
              <input
                v-model.number="rule.sort_order"
                class="input w-20"
                type="number"
                min="0"
                :aria-label="t('admin.riskGate.rules.sortOrder')"
                @change="update"
              />
            </td>
            <td class="px-3 py-3">
              <input
                v-model="rule.description"
                class="input w-full"
                :aria-label="t('admin.riskGate.rules.ruleDescription')"
                @input="update"
              />
            </td>
            <td class="px-3 py-3 text-right">
              <button
                type="button"
                class="btn btn-ghost btn-sm text-red-600 dark:text-red-300"
                :data-test="`remove-rule-${index}`"
                @click="removeRule(index)"
              >
                {{ t("admin.riskGate.rules.remove") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import type { Rule } from "../types";
import {
  RULE_CATEGORIES,
  createDefaultRule,
  validateRuleDraft,
} from "../viewModel";

const props = defineProps<{ rules: Rule[]; saving: boolean; error: string }>();
const emit = defineEmits<{
  (event: "update:rules", value: Rule[]): void;
  (event: "save", value: Rule[]): void;
}>();
const { t } = useI18n();

const invalidCount = computed(
  () => props.rules.filter((rule) => validateRuleDraft(rule).length > 0).length,
);
const canSave = computed(() => !props.saving && invalidCount.value === 0);

function errorsOf(rule: Rule): string[] {
  return validateRuleDraft(rule);
}

function update() {
  emit(
    "update:rules",
    props.rules.map((rule) => ({ ...rule })),
  );
}

function addRule() {
  emit("update:rules", [
    ...props.rules.map((rule) => ({ ...rule })),
    createDefaultRule(props.rules.length + 1),
  ]);
}

function removeRule(index: number) {
  emit(
    "update:rules",
    props.rules
      .filter((_, position) => position !== index)
      .map((rule) => ({ ...rule })),
  );
}
</script>
