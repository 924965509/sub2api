import { beforeEach, describe, expect, it, vi } from "vitest";
import { emptyEventFilter, eventQuery } from "../viewModel";
import type { BanFilter } from "../types";

const client = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  post: vi.fn(),
  delete: vi.fn(),
}));
vi.mock("@/api/client", () => ({ apiClient: client }));

import riskGateAPI from "../api";

describe("Risk Gate API", () => {
  beforeEach(() => Object.values(client).forEach((mock) => mock.mockReset()));

  it("reads and writes the versioned config under the admin namespace", async () => {
    client.get.mockResolvedValue({
      data: { config: { mode: "off" }, version: 3 },
    });
    const view = await riskGateAPI.getConfig();
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/config");
    expect(view.version).toBe(3);

    // PUT 的请求体必须带 expected_version，后端据此做乐观锁。
    client.put.mockResolvedValue({
      data: { config: { mode: "blocking" }, version: 4 },
    });
    await riskGateAPI.updateConfig({
      expected_version: 3,
      mode: "blocking",
    } as never);
    expect(client.put).toHaveBeenCalledWith("/admin/risk-gate/config", {
      expected_version: 3,
      mode: "blocking",
    });
  });

  it("loads the runtime status snapshot and probes one classifier endpoint", async () => {
    client.get.mockResolvedValue({
      data: { mode: "observe", config_version: 2 },
    });
    await riskGateAPI.getStatus();
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/status");

    // 探测失败也走 200，错误写在 result.error 里，接口层不抛异常。
    client.post.mockResolvedValue({
      data: { ok: false, error: "timeout", endpoint_id: "c-1" },
    });
    const probe = await riskGateAPI.probeClassifier({
      endpoint_index: 0,
      endpoint: { id: "c-1" } as never,
      text: "hello",
    });
    expect(client.post).toHaveBeenCalledWith(
      "/admin/risk-gate/classifier/probe",
      {
        endpoint_index: 0,
        endpoint: { id: "c-1" },
        text: "hello",
      },
    );
    expect(probe.ok).toBe(false);
  });

  it("reads and writes the whole rule table through the {rules} envelope", async () => {
    client.get.mockResolvedValue({
      data: { rules: [{ id: 1, pattern: "abc" }] },
    });
    const rules = await riskGateAPI.getRules();
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/rules");
    expect(rules).toHaveLength(1);

    client.put.mockResolvedValue({ data: { rules: [] } });
    await riskGateAPI.saveRules([
      {
        gate: "regex",
        category: "custom",
        pattern: "abc",
        is_regex: false,
        action: "block",
        enabled: true,
        sort_order: 1,
        description: "",
      },
      {
        id: 7,
        gate: "distill",
        category: "distill",
        pattern: "def",
        is_regex: true,
        action: "observe",
        enabled: false,
        sort_order: 2,
        description: "desc",
      },
    ]);
    const [url, body] = client.put.mock.calls[0];
    expect(url).toBe("/admin/risk-gate/rules");
    expect(Object.keys(body)).toEqual(["rules"]);
    // 新增行不带 id，已存在行保留 id，避免后端把编辑当成新增。
    expect(body.rules[0]).not.toHaveProperty("id");
    expect(body.rules[1]).toMatchObject({
      id: 7,
      gate: "distill",
      is_regex: true,
      action: "observe",
      enabled: false,
    });
  });

  it("paginates bans and only sends non-empty filters", async () => {
    client.get.mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
    });
    const filter: BanFilter = {
      scope: "api_key",
      subject: " ",
      active_only: true,
    };
    await riskGateAPI.getBans(filter, 2, 50);
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/bans", {
      params: { page: 2, page_size: 50, scope: "api_key", active_only: true },
    });

    await riskGateAPI.getBans(
      { scope: "", subject: "", active_only: false },
      1,
      20,
    );
    expect(client.get).toHaveBeenLastCalledWith("/admin/risk-gate/bans", {
      params: { page: 1, page_size: 20 },
    });

    client.post.mockResolvedValue({ data: { id: 1 } });
    await riskGateAPI.createBan({
      scope: "user",
      subject: "u1",
      reason: "harvest",
      duration_hours: 0,
      gate: "manual",
    });
    expect(client.post).toHaveBeenCalledWith("/admin/risk-gate/bans", {
      scope: "user",
      subject: "u1",
      reason: "harvest",
      duration_hours: 0,
      gate: "manual",
    });

    client.delete.mockResolvedValue({ data: { deleted: 1 } });
    expect(await riskGateAPI.deleteBan(9)).toEqual({ deleted: 1 });
    expect(client.delete).toHaveBeenCalledWith("/admin/risk-gate/bans/9");
  });

  it("forwards event filters as query params and as filter-delete bodies", async () => {
    client.get.mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
    });
    const filter = emptyEventFilter();
    filter.kind = "blocked";
    filter.from = "2026-07-15T00:00";
    await riskGateAPI.getEvents(filter, 3, 100);
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/events", {
      params: { page: 3, page_size: 100, ...eventQuery(filter) },
    });

    client.get.mockResolvedValue({ data: { id: 12 } });
    await riskGateAPI.getEvent(12);
    expect(client.get).toHaveBeenLastCalledWith("/admin/risk-gate/events/12");

    client.post.mockResolvedValue({ data: { total: 5 } });
    const preview = await riskGateAPI.previewDeleteEvents(filter);
    expect(client.post).toHaveBeenCalledWith(
      "/admin/risk-gate/events/delete-preview",
      eventQuery(filter),
    );
    expect(preview.total).toBe(5);

    client.post.mockResolvedValue({ data: { deleted: 5 } });
    expect(await riskGateAPI.deleteEventsByFilter(filter)).toEqual({
      deleted: 5,
    });
    expect(client.post).toHaveBeenLastCalledWith(
      "/admin/risk-gate/events/delete-by-filter",
      eventQuery(filter),
    );
  });

  it("lists and deletes refusal corpus rows", async () => {
    client.get.mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
    });
    await riskGateAPI.getRefusals(
      { provider: "claude", source: "", prompt_hash: "h" },
      1,
      20,
    );
    expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/refusals", {
      params: { page: 1, page_size: 20, provider: "claude", prompt_hash: "h" },
    });

    client.delete.mockResolvedValue({ data: { deleted: 1 } });
    await riskGateAPI.deleteRefusal(4);
    expect(client.delete).toHaveBeenCalledWith("/admin/risk-gate/refusals/4");

    client.delete.mockResolvedValue({ data: { deleted: 3 } });
    expect(await riskGateAPI.deleteAllRefusals()).toEqual({ deleted: 3 });
    expect(client.delete).toHaveBeenLastCalledWith("/admin/risk-gate/refusals");
  });

  it("downloads the CSV export as a blob and names it after the server pattern", async () => {
    const blob = new Blob(["a,b\n"], { type: "text/csv" });
    client.get.mockResolvedValue({ data: blob });
    const createObjectURL = vi.fn(() => "blob:canary");
    const revokeObjectURL = vi.fn();
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});

    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    try {
      const filter = emptyEventFilter();
      filter.gate = "regex";
      const filename = await riskGateAPI.exportEvents(filter);
      expect(client.get).toHaveBeenCalledWith("/admin/risk-gate/export", {
        params: eventQuery(filter),
        responseType: "blob",
      });
      expect(filename).toMatch(/^risk-gate-events-\d{8}T\d{6}Z\.csv$/);
      expect(createObjectURL).toHaveBeenCalledWith(blob);
      // 下载完成后必须释放 blob URL，否则页面会一直持有内存。
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:canary");
      expect(click).toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
      click.mockRestore();
    }
  });
});
