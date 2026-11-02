import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import en from "@/i18n/locales/en";
import zh from "@/i18n/locales/zh";

const here = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => readFileSync(resolve(here, path), "utf8");

// 动态拼接的 key（t(`...${id}`)）不会被 i18n 完整性扫描覆盖，
// 这里按叶子节点逐一比对 en / zh，保证两边 key 一一对应。
function leafKeys(tree: Record<string, unknown>, prefix = ""): string[] {
  return Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object")
      return leafKeys(value as Record<string, unknown>, path);
    return [path];
  });
}

describe("Risk Gate integration surface", () => {
  it("registers an admin and risk-control guarded route next to Prompt Audit", () => {
    const router = read("../../../router/index.ts");
    expect(router).toContain("path: '/admin/risk-gate'");
    expect(router).toContain("name: 'AdminRiskGate'");
    expect(router).toContain("import('@/features/risk-gate/RiskGateView.vue')");

    const route = router.slice(
      router.indexOf("path: '/admin/risk-gate'"),
      router.indexOf("path: '/admin/usage'"),
    );
    expect(route).toContain("requiresAuth: true");
    expect(route).toContain("requiresAdmin: true");
    expect(route).toContain("requiresRiskControl: true");
    expect(route).toContain("titleKey: 'admin.riskGate.title'");
    expect(route).toContain("descriptionKey: 'admin.riskGate.description'");
    // 必须排在 Prompt Audit 之后、Usage 之前，才能落在安全审计分组里。
    expect(router.indexOf("path: '/admin/prompt-audit'")).toBeLessThan(
      router.indexOf("path: '/admin/risk-gate'"),
    );
  });

  it("adds the page to the expand-only security sidebar group", () => {
    const sidebar = read("../../../components/layout/AppSidebar.vue");
    const group = sidebar.slice(
      sidebar.indexOf("path: '/admin/security-audit'"),
      sidebar.indexOf("path: '/admin/redeem'"),
    );
    expect(group).toContain("expandOnly: true");
    expect(group).toContain("path: '/admin/prompt-audit'");
    expect(group).toContain("path: '/admin/risk-gate'");
    expect(group).toContain("t('nav.riskGate')");
  });

  it("keeps the Risk Gate locale trees symmetric in both languages", () => {
    const enKeys = leafKeys(
      en.admin.riskGate as unknown as Record<string, unknown>,
    );
    const zhKeys = leafKeys(
      zh.admin.riskGate as unknown as Record<string, unknown>,
    );
    expect(zhKeys).toEqual(enKeys);

    // 关键运维文案必须存在且不是占位符。
    for (const key of [
      "title",
      "description",
      "configVersion",
      "tabs.runtime",
      "tabs.config",
      "tabs.rules",
      "tabs.bans",
      "tabs.events",
      "tabs.refusals",
      "modeHints.observe",
      "gateHints.decision_model",
      "config.decisionModel.onUnavailablePassHint",
      "config.decisionModel.onUnavailableFailClosedHint",
      "bans.releaseWarning",
      "refusals.clearWarning",
    ]) {
      expect(enKeys).toContain(key);
      expect(
        (en.admin.riskGate as unknown as Record<string, unknown>).title,
      ).toBeTruthy();
      expect(
        (zh.admin.riskGate as unknown as Record<string, unknown>).title,
      ).toBeTruthy();
    }

    expect(en.nav.riskGate).toBeTruthy();
    expect(zh.nav.riskGate).toBeTruthy();
    expect(en.nav.securityAudit).toBeTruthy();
    expect(zh.nav.securityAudit).toBeTruthy();
  });

  it("names every operational control with a stable data-test hook", () => {
    const view = read("../RiskGateView.vue");
    for (const hook of [
      "mode-badge",
      "config-version",
      "dirty-state",
      "reset-config",
      "save-config",
      "save-block-reason",
    ]) {
      expect(view).toContain(`data-test="${hook}"`);
    }
    // The main workspace follows the reference stage workflow; historical
    // management remains accessible without dominating the primary navigation.
    for (const component of [
      "GateRail",
      "AccountScopePanel",
      "DistillSettings",
      "HardRegexSettings",
      "RefusalSettings",
      "ModelSettings",
      "ClassifierUsagePanel",
      "HitSummary",
      "RiskFeed",
    ]) {
      expect(view).toContain(component);
    }
    expect(view).toContain("riskEventViewQuery");
    expect(view).toContain("onBeforeRouteLeave");
    expect(view).toContain("config-conflict");
    expect(view).toContain("EventWorkspace");
    expect(view).toContain("FilterDeleteDialog");
    expect(view).toContain("BanPanel");
    expect(view).toContain("RuntimeOverview");
  });
});
