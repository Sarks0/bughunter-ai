import { describe, it, expect } from "bun:test";
import {
  KNOWN_TOOLS,
  checkTool,
  validateTools,
  validateToolsForMode,
  formatToolReport,
} from "../Tools/lib/tool-validator.ts";

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

  it("includes adb/aapt/frida for the mobile (comprehensive) mode", async () => {
    const results = await validateToolsForMode("comprehensive");
    const names = results.map((r) => r.name);
    for (const tool of ["adb", "aapt", "frida", "apktool", "jadx"]) {
      expect(names).toContain(tool);
    }
  });
});

describe("KNOWN_TOOLS", () => {
  const reconTools = [
    "katana",
    "waymore",
    "gau",
    "jsluice",
    "arjun",
    "kiterunner",
    "dalfox",
    "trufflehog",
    "interactsh-client",
  ];
  const allModes = ["bounty", "pentest", "comprehensive"] as const;

  it("includes modern recon/content tools in all modes", () => {
    for (const name of reconTools) {
      const def = KNOWN_TOOLS[name];
      expect(def, `missing KNOWN_TOOLS entry: ${name}`).toBeDefined();
      for (const mode of allModes) {
        expect(def.modes, `${name} should cover ${mode}`).toContain(mode);
      }
      expect(def.required).toBe(false);
    }
  });

  it("includes mobile tools hard-required by appium-harness", () => {
    for (const name of ["adb", "aapt", "frida", "apktool", "jadx"]) {
      const def = KNOWN_TOOLS[name];
      expect(def, `missing KNOWN_TOOLS entry: ${name}`).toBeDefined();
      expect(def.modes).toContain("comprehensive");
    }
  });

  it("includes LLM security tools as optional (never required)", () => {
    for (const name of ["garak", "pyrit", "promptfoo"]) {
      const def = KNOWN_TOOLS[name];
      expect(def, `missing KNOWN_TOOLS entry: ${name}`).toBeDefined();
      expect(def.required).toBe(false);
      expect(def.modes.length).toBeGreaterThan(0);
    }
  });

  it("includes optional API tools", () => {
    expect(KNOWN_TOOLS["graphql-cop"]).toBeDefined();
    expect(KNOWN_TOOLS["graphql-cop"].required).toBe(false);
    expect(KNOWN_TOOLS["grpc_cli"]).toBeDefined();
    expect(KNOWN_TOOLS["grpc_cli"].required).toBe(false);
  });

  it("marks burpsuite as a manual/GUI application, not a hard CLI failure", () => {
    const def = KNOWN_TOOLS["burpsuite"];
    expect(def).toBeDefined();
    expect(def.manual).toBe(true);
    expect(def.required).toBe(false);
  });

  it("does not probe versions for manual/GUI applications", async () => {
    const result = await checkTool("burpsuite");
    expect(result.required).toBe(false);
    if (result.installed) {
      expect(result.version).toBe("manual/GUI application");
    } else {
      expect(result.error).toContain("manual/GUI application");
    }
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

  it("keeps the report shape unchanged", () => {
    const report = formatToolReport([
      { name: "curl", command: "curl", required: true, installed: true, version: "8.0" },
      { name: "fake", command: "fake", required: false, installed: false, error: "missing" },
      { name: "need", command: "need", required: true, installed: false, error: "missing" },
    ]);
    const lines = report.split("\n");
    expect(lines[0]).toBe("Tool health: 1/3 available");
    // Per-tool lines: two-space indent, status icon, name, detail.
    expect(lines[1]).toMatch(/^ {2}✓ curl\s+8\.0$/);
    expect(lines[2]).toMatch(/^ {2}○ fake\s+missing$/);
    expect(lines[3]).toMatch(/^ {2}✗ need\s+missing$/);
    // Missing required tools are summarized at the end.
    expect(report).toContain("Required tools missing: need");
  });
});
