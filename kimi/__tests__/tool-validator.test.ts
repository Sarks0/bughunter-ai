import { describe, it, expect } from "bun:test";
import { checkTool, validateTools, validateToolsForMode, formatToolReport } from "../Tools/lib/tool-validator.ts";

describe("checkTool", () => {
  it("reports installed for a common shell command", async () => {
    const result = await checkTool("sh");
    expect(result.installed).toBe(true);
  });

  it("reports not installed for a fake command", async () => {
    const result = await checkTool("__not_a_real_tool_12345__");
    expect(result.installed).toBe(false);
    expect(result.error).toContain("not found on PATH");
  });

  it("probes unknown tools generically", async () => {
    const result = await checkTool("totally-unknown-tool-name", true);
    expect(result.installed).toBe(false);
    expect(result.error).toContain("not found on PATH");
    expect(result.required).toBe(true);
  });
});

describe("validateTools", () => {
  it("aggregates results for multiple tools", async () => {
    const results = await validateTools(["sh", "__not_a_real_tool_12345__"]);
    expect(results).toHaveLength(2);
    expect(results[0].installed).toBe(true);
    expect(results[1].installed).toBe(false);
  });
});

describe("validateToolsForMode", () => {
  it("returns checks relevant to bounty mode", async () => {
    const results = await validateToolsForMode("bounty");
    expect(results.length).toBeGreaterThan(0);
    // curl is required in all modes
    const curl = results.find((r) => r.name === "curl");
    expect(curl).toBeDefined();
    expect(curl!.required).toBe(true);
  });
});

describe("formatToolReport", () => {
  it("includes totals and per-tool status", () => {
    const report = formatToolReport([
      { name: "curl", command: "curl", required: true, installed: true, version: "8.0" },
      { name: "fake", command: "fake", required: false, installed: false, error: "missing" },
    ]);
    expect(report).toContain("1/2 available");
    expect(report).toContain("curl");
    expect(report).toContain("fake");
  });
});
