<template>
  <nav
    class="risk-rail"
    role="tablist"
    :aria-label="t('admin.riskGate.rail.label')"
    @keydown="onKeydown"
  >
    <button
      v-for="(cell, index) in cells"
      :id="`risk-tab-${cell.id}`"
      :key="cell.id"
      type="button"
      role="tab"
      :aria-selected="view === cell.id"
      aria-controls="risk-panel"
      :tabindex="view === cell.id ? 0 : -1"
      :data-test="`rail-${cell.id}`"
      class="risk-rail-cell"
      :class="{ selected: view === cell.id }"
      @click="$emit('view', cell.id)"
    >
      <span v-if="index" aria-hidden="true" class="risk-rail-arrow">›</span>
      <span class="risk-rail-top"
        ><span class="risk-rail-name"
          ><span v-if="index > 0 && index < 5" class="risk-rail-step">{{
            index
          }}</span
          >{{ cell.label }}</span
        ><span
          v-if="cell.state"
          class="risk-state"
          :class="`risk-state-${cell.state}`"
          ><i aria-hidden="true" />{{
            t(`admin.riskGate.states.${cell.state}`)
          }}</span
        ></span
      >
      <strong>{{
        cell.value === null ? "—" : cell.value.toLocaleString()
      }}</strong>
      <span class="risk-rail-foot">{{ cell.foot }}</span>
      <span v-if="cell.id === 'pass' && failOpen" class="risk-fail-open">{{
        t("admin.riskGate.rail.failOpen", { count: failOpen })
      }}</span>
    </button>
  </nav>
</template>
<script setup lang="ts">
import { computed, nextTick } from "vue";
import { useI18n } from "vue-i18n";
import type { RiskGateView, RiskState, RiskStats } from "../types";
import { share } from "../viewModel";
const props = defineProps<{
  view: RiskGateView;
  stats: RiskStats | null;
  states: Record<"distill" | "hard-regex" | "refusal" | "jev", RiskState>;
}>();
const emit = defineEmits<{ (event: "view", view: RiskGateView): void }>();
const { t } = useI18n();
const order: RiskGateView[] = [
  "all",
  "distill",
  "hard-regex",
  "refusal",
  "jev",
  "pass",
];
const gateIds = {
  distill: "distill",
  "hard-regex": "regex",
  refusal: "refusal_cache",
  jev: "decision_model",
} as const;
const failOpen = computed(() =>
  (props.stats?.passes ?? [])
    .filter(
      (row) =>
        row.reason === "fail-open" || row.reason === "classifier_unavailable",
    )
    .reduce((total, row) => total + row.count, 0),
);
const cells = computed(() =>
  order.map((id) => {
    let value: number | null = null;
    let foot = t("admin.riskGate.rail.loading");
    let state: RiskState | undefined;
    if (id === "all") {
      value = props.stats?.total ?? null;
      if (props.stats)
        foot = t("admin.riskGate.rail.blockedShare", {
          count: props.stats.blocked,
          share: share(props.stats.blocked, props.stats.total),
        });
    } else if (id === "pass") {
      value = props.stats?.passed ?? null;
      if (props.stats)
        foot = t("admin.riskGate.rail.passedShare", {
          share: share(props.stats.passed, props.stats.total),
        });
    } else {
      state = props.states[id];
      value = props.stats
        ? (props.stats.blocks ?? [])
            .filter(
              (row) => row.gate === gateIds[id] && row.action !== "would_block",
            )
            .reduce((sum, row) => sum + row.count, 0)
        : null;
      if (props.stats)
        foot = t("admin.riskGate.rail.stageShare", {
          share: share(value ?? 0, props.stats.total),
        });
    }
    return { id, label: t(`admin.riskGate.rail.${id}`), value, foot, state };
  }),
);
function onKeydown(event: KeyboardEvent) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const next =
    event.key === "Home"
      ? order[0]
      : event.key === "End"
        ? order[order.length - 1]
        : order[
            (order.indexOf(props.view) +
              (event.key === "ArrowRight" ? 1 : -1) +
              order.length) %
              order.length
          ];
  emit("view", next);
  void nextTick(() => document.getElementById(`risk-tab-${next}`)?.focus());
}
</script>
<style scoped>
.risk-rail {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1px;
  border: 1px solid #e5e7eb;
  border-radius: 0.75rem;
  background: #e5e7eb;
  overflow: hidden;
}
.risk-rail-cell {
  position: relative;
  display: flex;
  min-width: 0;
  min-height: 7rem;
  flex-direction: column;
  gap: 0.5rem;
  background: #fff;
  padding: 0.75rem 1rem 0.875rem;
  text-align: left;
  outline: none;
  transition: background 0.15s;
}
.risk-rail-cell:hover {
  background: #f8faf9;
}
.risk-rail-cell.selected {
  background: #f1f5f3;
  box-shadow: inset 0 -2px 0 #16a34a;
}
.risk-rail-cell:focus-visible {
  z-index: 2;
  box-shadow: inset 0 0 0 2px #16a34a;
}
.risk-rail-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.4rem;
  font-size: 0.875rem;
  font-weight: 500;
}
.risk-rail-name {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 0.4rem;
}
.risk-rail-step {
  font-family: monospace;
  font-size: 0.75rem;
  color: #6b7280;
}
.risk-rail-cell strong {
  font-size: 1.5rem;
  font-weight: 600;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.risk-rail-foot {
  margin-top: auto;
  font-size: 0.75rem;
  color: #6b7280;
  font-variant-numeric: tabular-nums;
}
.risk-state {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  white-space: nowrap;
  font-size: 0.6875rem;
  color: #6b7280;
}
.risk-state i {
  width: 0.35rem;
  height: 0.35rem;
  border-radius: 50%;
  background: currentColor;
}
.risk-state-on {
  color: #15803d;
}
.risk-state-unset,
.risk-state-observe {
  color: #b45309;
}
.risk-fail-open {
  width: fit-content;
  border-radius: 0.3rem;
  background: #fef3c7;
  padding: 0.125rem 0.375rem;
  font-size: 0.6875rem;
  color: #92400e;
}
.risk-rail-arrow {
  display: none;
  position: absolute;
  top: 50%;
  left: 0;
  z-index: 1;
  width: 1.25rem;
  height: 1.25rem;
  align-items: center;
  justify-content: center;
  transform: translate(-50%, -50%);
  border: 1px solid #e5e7eb;
  border-radius: 50%;
  background: #fff;
  font-size: 1rem;
  color: #6b7280;
}
:global(.dark .risk-rail) {
  border-color: #334155;
  background: #334155;
}
:global(.dark .risk-rail-cell) {
  background: #111827;
  color: #f3f4f6;
}
:global(.dark .risk-rail-cell:hover),
:global(.dark .risk-rail-cell.selected) {
  background: #1f2937;
}
:global(.dark .risk-rail-foot),
:global(.dark .risk-rail-step),
:global(.dark .risk-state) {
  color: #94a3b8;
}
:global(.dark .risk-state-on) {
  color: #4ade80;
}
:global(.dark .risk-state-unset),
:global(.dark .risk-state-observe) {
  color: #fbbf24;
}
:global(.dark .risk-rail-arrow) {
  background: #111827;
  border-color: #334155;
  color: #94a3b8;
}
:global(.dark .risk-fail-open) {
  background: #422006;
  color: #fbbf24;
}
@media (min-width: 640px) {
  .risk-rail {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}
@media (min-width: 1024px) {
  .risk-rail {
    grid-template-columns: repeat(6, minmax(0, 1fr));
  }
  .risk-rail-arrow {
    display: flex;
  }
}
@media (prefers-reduced-motion: reduce) {
  .risk-rail-cell {
    transition: none;
  }
}
</style>
