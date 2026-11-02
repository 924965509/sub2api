import { apiClient } from "@/api/client";
import type {
  Ban,
  BanFilter,
  ClassifierEndpoint,
  ClassifierUsagePage,
  ConfigView,
  CreateBanRequest,
  EventFilter,
  EventRow,
  PageResult,
  ProbeRequest,
  ProbeResult,
  RiskStats,
  RefusalFilter,
  RefusalRow,
  Rule,
  RuleSetView,
  RuleValidationResult,
  ScopeInventory,
  StatusSnapshot,
  UpdateConfigRequest,
} from "./types";
import { csvFilename, eventQuery } from "./viewModel";

const basePath = "/admin/risk-gate";

// 配置读写：PUT 的请求体是 { expected_version, ...RiskGateConfig }，版本冲突返回 409。
export async function getConfig(): Promise<ConfigView> {
  const { data } = await apiClient.get<ConfigView>(`${basePath}/config`);
  return data;
}

export async function updateConfig(
  payload: UpdateConfigRequest,
): Promise<ConfigView> {
  const { data } = await apiClient.put<ConfigView>(
    `${basePath}/config`,
    payload,
  );
  return data;
}

export async function getStatus(): Promise<StatusSnapshot> {
  const { data } = await apiClient.get<StatusSnapshot>(`${basePath}/status`);
  return data;
}

export async function getStats(
  from?: string,
  to?: string,
  timezone?: string,
): Promise<RiskStats> {
  const params: Record<string, string> = {};
  if (from) params.from = from;
  if (to) params.to = to;
  if (timezone) params.timezone = timezone;
  const { data } = await apiClient.get<RiskStats>(`${basePath}/stats`, {
    params,
  });
  return data;
}

// probeClassifier 探测决策模型端点：失败不是接口失败，错误写在 result.error 里。
export async function probeClassifier(
  request: ProbeRequest,
): Promise<ProbeResult> {
  const { data } = await apiClient.post<ProbeResult>(
    `${basePath}/classifier/probe`,
    request,
  );
  return data;
}

export async function getClassifierModels(
  endpoint: ClassifierEndpoint,
): Promise<{ models: Array<{ id: string }> }> {
  const { data } = await apiClient.post<{ models: Array<{ id: string }> }>(
    `${basePath}/classifier/models`,
    { endpoint },
  );
  return data;
}

export async function getClassifierUsage(
  page = 1,
  pageSize = 50,
  from?: string,
  to?: string,
): Promise<ClassifierUsagePage> {
  const params: Record<string, string | number> = { page, page_size: pageSize };
  if (from) params.from = from;
  if (to) params.to = to;
  const { data } = await apiClient.get<ClassifierUsagePage>(
    `${basePath}/classifier/usage`,
    { params },
  );
  return data;
}

// 自定义规则整表读写：GET 返回 { rules }，PUT 请求体 { rules }。
export async function getRules(): Promise<Rule[]> {
  const { data } = await apiClient.get<{ rules: Rule[] }>(`${basePath}/rules`);
  return data.rules ?? [];
}

export async function saveRules(rules: Rule[]): Promise<Rule[]> {
  const { data } = await apiClient.put<{ rules: Rule[] }>(`${basePath}/rules`, {
    rules: rules.map((rule) => ({
      ...(rule.id ? { id: rule.id } : {}),
      gate: rule.gate,
      category: rule.category,
      pattern: rule.pattern,
      is_regex: rule.is_regex,
      action: rule.action,
      enabled: rule.enabled,
      sort_order: rule.sort_order,
      description: rule.description,
    })),
  });
  return data.rules ?? [];
}

export async function getRuleset(): Promise<RuleSetView> {
  const { data } = await apiClient.get<RuleSetView>(`${basePath}/ruleset`);
  return data;
}

export async function saveRuleset(
  expectedVersion: number,
  rules: Rule[] | null,
): Promise<RuleSetView> {
  const { data } = await apiClient.put<RuleSetView>(`${basePath}/ruleset`, {
    expected_version: expectedVersion,
    rules,
  });
  return data;
}

export async function validateRules(
  rules: Rule[],
  text?: string,
): Promise<RuleValidationResult> {
  const { data } = await apiClient.post<RuleValidationResult>(
    `${basePath}/rules/validate`,
    {
      rules,
      ...(text === undefined ? {} : { text }),
    },
  );
  return data;
}

export async function getScopeInventory(): Promise<ScopeInventory> {
  const { data } = await apiClient.get<ScopeInventory>(
    `${basePath}/scope-inventory`,
  );
  return data;
}

// 封禁列表：分页信封 + scope/subject/active_only 过滤。
export async function getBans(
  filter: BanFilter,
  page: number,
  pageSize: number,
): Promise<PageResult<Ban>> {
  const params: Record<string, string | number | boolean> = {
    page,
    page_size: pageSize,
  };
  if (filter.scope.trim()) params.scope = filter.scope.trim();
  if (filter.subject.trim()) params.subject = filter.subject.trim();
  if (filter.active_only) params.active_only = true;
  const { data } = await apiClient.get<PageResult<Ban>>(`${basePath}/bans`, {
    params,
  });
  return data;
}

export async function createBan(payload: CreateBanRequest): Promise<Ban> {
  const { data } = await apiClient.post<Ban>(`${basePath}/bans`, payload);
  return data;
}

export async function deleteBan(id: number): Promise<{ deleted: number }> {
  const { data } = await apiClient.delete<{ deleted: number }>(
    `${basePath}/bans/${id}`,
  );
  return data;
}

export async function clearBans(scope?: string): Promise<{ deleted: number }> {
  const { data } = await apiClient.delete<{ deleted: number }>(
    `${basePath}/bans`,
    {
      data: { confirm: true, ...(scope ? { scope } : {}) },
    },
  );
  return data;
}

// 事件查询：过滤条件去掉空值后只带非空参数，分页由 page/page_size 承担。
export async function getEvents(
  filter: EventFilter,
  page: number,
  pageSize: number,
): Promise<PageResult<EventRow>> {
  const { data } = await apiClient.get<PageResult<EventRow>>(
    `${basePath}/events`,
    {
      params: { page, page_size: pageSize, ...eventQuery(filter) },
    },
  );
  return data;
}

export async function getEvent(id: number): Promise<EventRow> {
  const { data } = await apiClient.get<EventRow>(`${basePath}/events/${id}`);
  return data;
}

// 预览删除：请求体与查询参数同名；没有任何条件时后端返回 400 risk_gate_filter_required。
export async function previewDeleteEvents(
  filter: EventFilter,
): Promise<{ total: number }> {
  const { data } = await apiClient.post<{ total: number }>(
    `${basePath}/events/delete-preview`,
    eventQuery(filter),
  );
  return data;
}

export async function deleteEventsByFilter(
  filter: EventFilter,
): Promise<{ deleted: number }> {
  const { data } = await apiClient.post<{ deleted: number }>(
    `${basePath}/events/delete-by-filter`,
    eventQuery(filter),
  );
  return data;
}

// 拒答语料：分页列表 + 单条删除 + 清空全部。
export async function getRefusals(
  filter: RefusalFilter,
  page: number,
  pageSize: number,
): Promise<PageResult<RefusalRow>> {
  const params: Record<string, string | number> = { page, page_size: pageSize };
  if (filter.provider.trim()) params.provider = filter.provider.trim();
  if (filter.source.trim()) params.source = filter.source.trim();
  if (filter.prompt_hash.trim()) params.prompt_hash = filter.prompt_hash.trim();
  const { data } = await apiClient.get<PageResult<RefusalRow>>(
    `${basePath}/refusals`,
    { params },
  );
  return data;
}

export async function deleteRefusal(id: number): Promise<{ deleted: number }> {
  const { data } = await apiClient.delete<{ deleted: number }>(
    `${basePath}/refusals/${id}`,
  );
  return data;
}

export async function deleteAllRefusals(): Promise<{ deleted: number }> {
  const { data } = await apiClient.delete<{ deleted: number }>(
    `${basePath}/refusals`,
  );
  return data;
}

// exportEvents 以 blob 方式拉取 CSV，并直接触发浏览器下载。
export async function exportEvents(filter: EventFilter): Promise<string> {
  const response = await apiClient.get<Blob>(`${basePath}/export`, {
    params: eventQuery(filter),
    responseType: "blob",
  });
  const filename = csvFilename("risk-gate-events", Date.now());
  const blob = response.data;
  if (
    blob &&
    typeof URL !== "undefined" &&
    typeof URL.createObjectURL === "function"
  ) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }
  return filename;
}

export const riskGateAPI = {
  getConfig,
  updateConfig,
  getStatus,
  getStats,
  probeClassifier,
  getClassifierModels,
  getClassifierUsage,
  getRules,
  saveRules,
  getRuleset,
  saveRuleset,
  validateRules,
  getScopeInventory,
  getBans,
  createBan,
  deleteBan,
  clearBans,
  getEvents,
  getEvent,
  previewDeleteEvents,
  deleteEventsByFilter,
  getRefusals,
  deleteRefusal,
  deleteAllRefusals,
  exportEvents,
};

export default riskGateAPI;
