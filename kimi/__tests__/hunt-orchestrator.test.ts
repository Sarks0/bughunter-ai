import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  createHuntState,
  loadState,
  advancePhase,
  failPhase,
  addFinding,
  setPhaseStatus,
  deriveTargetFromScope,
  checkPhaseGates,
  evaluateGateMetric,
  getPhaseList,
  parseSetPhaseStatusArg,
  PHASES,
} from "../Tools/hunt-orchestrator.ts";
import { getSessionDir, toSlug, MEMORY_DIR } from "../Tools/lib/paths.ts";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const TEST_TARGET = "https://test.example.com";
const TEST_SLUG = "test-example-com";
const EXTRA_SLUGS = ["example-com", "evil-com"];

function metricsFile(slug: string): string {
  return join(MEMORY_DIR.learning, `${slug}-phases.jsonl`);
}

async function cleanup() {
  for (const slug of [TEST_SLUG, ...EXTRA_SLUGS]) {
    await Bun.$`rm -rf ${getSessionDir(slug)}`.quiet().nothrow();
    await Bun.$`rm -f ${metricsFile(slug)}`.quiet().nothrow();
  }
}

describe("hunt-orchestrator", () => {
  beforeEach(async () => {
    await Bun.write(`${getSessionDir(TEST_SLUG)}/.gitkeep`, "");
  });

  afterEach(cleanup);

  it("creates a hunt session with correct defaults", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty");
    expect(state.target).toBe(TEST_TARGET);
    expect(state.targetSlug).toBe(TEST_SLUG);
    expect(state.mode).toBe("bounty");
    expect(state.config.minCvss).toBe(8.0);
    expect(state.currentPhase).toBe("INIT");
    expect(PHASES.every((p) => state.phases[p].status === "pending" || p === "INIT")).toBe(true);
  });

  it("stores workflow name when provided", async () => {
    const state = await createHuntState(TEST_TARGET, "pentest", "W_HUNT_WEB");
    expect(state.workflow).toBe("W_HUNT_WEB");
    expect(state.config.minCvss).toBe(4.0);
  });

  it("advances phases sequentially", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state = await advancePhase(state);
    expect(state.currentPhase).toBe("MEMORY_LOAD");
    expect(state.phases.INIT.status).toBe("completed");
  });

  it("can jump to a specific phase", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state = await advancePhase(state, "RECON");
    expect(state.currentPhase).toBe("RECON");
    expect(state.phases.INIT.status).toBe("completed");
  });

  it("persists and loads state", async () => {
    const created = await createHuntState(TEST_TARGET, "comprehensive");
    const loaded = await loadState(TEST_SLUG);
    expect(loaded).not.toBeNull();
    expect(loaded!.target).toBe(created.target);
    expect(loaded!.mode).toBe("comprehensive");
  });

  it("adds findings and increments counters", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state.currentPhase = "RECON";
    state.phases.RECON.status = "running";
    state = await addFinding(state, { severity: "critical", type: "SSRF", title: "AWS metadata access" });
    expect(state.totalFindings).toBe(1);
    expect(state.findings[0].id).toBe("F-001");
    expect(state.phases.RECON.findingsCount).toBe(1);
  });

  it("sets phase status and stores reason", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state = await setPhaseStatus(state, "INIT", "completed", "Started successfully");
    expect(state.phases.INIT.status).toBe("completed");
    expect(state.phases.INIT.error).toBe("Started successfully");
  });

  it("setPhaseStatus rejects unknown phases with a clear error (no undefined deref)", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty");
    await expect(setPhaseStatus(state, "NOPE_PHASE", "completed")).rejects.toThrow(
      /Unknown phase "NOPE_PHASE".*Known phases:/
    );
  });

  it("slug matches the canonical paths.toSlug (https://example.com/ → example-com)", async () => {
    const state = await createHuntState("https://example.com/", "bounty");
    expect(state.targetSlug).toBe("example-com");
    expect(state.targetSlug).toBe(toSlug("https://example.com/"));
  });

  it("failPhase retries until maxRetries, then marks failed and skips ahead", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty"); // maxRetries: 1
    state = await failPhase(state, "boom");
    expect(state.currentPhase).toBe("INIT");
    expect(state.phases.INIT.status).toBe("running");
    expect(state.phases.INIT.retryCount).toBe(1);

    state = await failPhase(state, "boom again");
    expect(state.phases.INIT.status).toBe("failed");
    expect(state.phases.INIT.error).toBe("boom again");
    expect(state.currentPhase).toBe("MEMORY_LOAD");
    expect(state.phases.MEMORY_LOAD.status).toBe("running");
  });

  it("advancePhase skips phases marked as skipped", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state = await setPhaseStatus(state, "MEMORY_LOAD", "skipped", "nothing to load");
    state = await advancePhase(state);
    expect(state.phases.INIT.status).toBe("completed");
    expect(state.currentPhase).toBe("TARGET_INGEST");
    expect(state.phases.MEMORY_LOAD.status).toBe("skipped");
  });

  it("records phase metrics on completion", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state = await advancePhase(state);
    const lines = (await Bun.file(metricsFile(TEST_SLUG)).text()).trim().split("\n");
    expect(lines.length).toBe(1);
    const metric = JSON.parse(lines[0]);
    expect(metric.phase).toBe("INIT");
    expect(metric.status).toBe("completed");
    expect(metric).toHaveProperty("started_at");
    expect(metric).toHaveProperty("completed_at");
    expect(metric).toHaveProperty("duration_ms");
    expect(metric).toHaveProperty("findings_count");
  });
});

describe("hunt-orchestrator scope gate", () => {
  afterEach(cleanup);

  it("refuses to create a hunt for an out-of-scope target", async () => {
    const scope = { in: ["other.com"], out: [] };
    await expect(createHuntState("https://evil.com", "bounty", undefined, scope)).rejects.toThrow(
      /Refusing to create hunt.*--force/
    );
    expect(await loadState("evil-com")).toBeNull();
  });

  it("creates the hunt for an out-of-scope target when forced", async () => {
    const scope = { in: ["other.com"], out: [] };
    const state = await createHuntState("https://evil.com", "bounty", undefined, scope, { force: true });
    expect(state.targetSlug).toBe("evil-com");
  });

  it("creates the hunt when the target is in scope", async () => {
    const scope = { in: ["*.example.com"], out: [] };
    const state = await createHuntState(TEST_TARGET, "bounty", undefined, scope);
    expect(state.targetSlug).toBe(TEST_SLUG);
  });
});

describe("deriveTargetFromScope", () => {
  it("parses URL-pattern entries down to the origin", () => {
    expect(deriveTargetFromScope({ in: ["https://api.example.com/*"], out: [] })).toBe("https://api.example.com");
  });

  it("strips wildcard prefixes from host entries", () => {
    expect(deriveTargetFromScope({ in: ["*.example.com"], out: [] })).toBe("https://example.com");
  });

  it("strips a wildcard host from URL-pattern entries", () => {
    expect(deriveTargetFromScope({ in: ["https://*.example.com/*"], out: [] })).toBe("https://example.com");
  });

  it("handles plain host entries and strips ports/paths", () => {
    expect(deriveTargetFromScope({ in: ["api.example.com:8443/admin"], out: [] })).toBe("https://api.example.com");
  });

  it("throws on garbage scopes with no usable entry", () => {
    expect(() => deriveTargetFromScope({ in: ["/.*regex.*/", "!!!"], out: [] })).toThrow(
      /Could not derive a target/
    );
    expect(() => deriveTargetFromScope({ in: [], out: [] })).toThrow(/Could not derive a target/);
  });
});

describe("setPhaseStatus findings recount", () => {
  afterEach(cleanup);

  it("is idempotent and accepts wrapper findings files", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    const findingsPath = `${state.sessionDir}/findings/recon-findings.json`;
    await Bun.write(
      findingsPath,
      JSON.stringify({
        target: TEST_TARGET,
        findings: [
          { title: "a", severity: "low", cvss: 2, confirmed: false, description: "x" },
          { title: "b", severity: "low", cvss: 2, confirmed: false, description: "y" },
        ],
      })
    );

    state = await setPhaseStatus(state, "RECON", "completed", undefined, undefined, findingsPath);
    expect(state.totalFindings).toBe(2);
    expect(state.phases.RECON.findingsCount).toBe(2);

    // Re-registering the same file must not double-count.
    state = await setPhaseStatus(state, "RECON", "completed", undefined, undefined, findingsPath);
    expect(state.totalFindings).toBe(2);
    expect(state.phases.RECON.findingsCount).toBe(2);
  });

  it("accepts bare-array findings files and combines with addFinding", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty");
    state.currentPhase = "RECON";
    state = await addFinding(state, { severity: "high", type: "XSS", title: "reflected" });

    const findingsPath = `${state.sessionDir}/findings/scan-findings.json`;
    await Bun.write(findingsPath, JSON.stringify([{ title: "c", severity: "low", cvss: 1, confirmed: false, description: "z" }]));
    state = await setPhaseStatus(state, "RECON", "completed", undefined, undefined, findingsPath);

    expect(state.totalFindings).toBe(2);
    expect(state.phases.RECON.findingsCount).toBe(2);
  });
});

describe("workflows", () => {
  afterEach(cleanup);

  it("loads a valid workflow definition into hunt state", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_WEB");
    expect(state.workflowDefinition?.name).toBe("W_HUNT_WEB");
    expect(getPhaseList(state)[0]).toBe("RECON");
    expect(state.currentPhase).toBe("RECON");
    expect(state.phases.INJECTION).toBeDefined();
    expect(state.phases.INIT).toBeUndefined();
  });

  it("advances along the workflow's phase list", async () => {
    let state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_WEB");
    state = await advancePhase(state);
    expect(state.currentPhase).toBe("APP_UNDERSTANDING");
    expect(state.phases.RECON.status).toBe("completed");
  });

  it("rejects unknown workflow names with a list of available workflows", async () => {
    await expect(createHuntState(TEST_TARGET, "bounty", "W_NOPE")).rejects.toThrow(
      /Unknown workflow "W_NOPE".*W_HUNT_WEB/
    );
  });
});

describe("workflow gates", () => {
  afterEach(cleanup);

  it("reports unmet when artifacts are missing", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_WEB");
    // W_HUNT_WEB RECON gate: { metric: "live_hosts", min: 1 }
    const result = await checkPhaseGates(state, "RECON");
    expect(result.ok).toBe(false);
    expect(result.failures.some((f) => f.startsWith("live_hosts"))).toBe(true);
  });

  it("reports met when the alive-hosts artifact exists", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_WEB");
    await Bun.write(
      `${state.sessionDir}/recon/alive-hosts.json`,
      '{"url":"https://a.example.com"}\n{"url":"https://b.example.com"}\n'
    );
    expect(await evaluateGateMetric(state, "live_hosts")).toBe(2);
    const result = await checkPhaseGates(state, "RECON");
    expect(result.ok).toBe(true);
    expect(result.failures).toHaveLength(0);
  });

  it("treats unevaluable metrics as unmet", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_WEB");
    state.workflowDefinition = {
      name: "W_FAKE",
      phases: [{ name: "RECON", gates: [{ metric: "no_such_metric", min: 1 }] }],
    };
    const result = await checkPhaseGates(state, "RECON");
    expect(result.ok).toBe(false);
    expect(result.unevaluable).toEqual(["no_such_metric"]);
  });

  it("evaluates alive_hosts as an alias of live_hosts (0 and >0 cases)", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_NETWORK");
    expect(await evaluateGateMetric(state, "alive_hosts")).toBe(0);

    await Bun.write(`${state.sessionDir}/recon/alive-hosts.json`, '{"host":"10.0.0.1"}\n');
    expect(await evaluateGateMetric(state, "alive_hosts")).toBe(1);

    // Falls back to alive_urls when alive-hosts.json is absent.
    const fresh = await createHuntState("https://example.com", "bounty");
    await Bun.write(`${fresh.sessionDir}/recon/alive-urls.txt`, "https://a.example.com\nhttps://b.example.com\n");
    expect(await evaluateGateMetric(fresh, "alive_hosts")).toBe(2);
  });

  it("evaluates apk_exists (0 without an APK, 1 via apkPath or artifacts dir)", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_MOBILE");
    expect(await evaluateGateMetric(state, "apk_exists")).toBe(0);

    // Via the stored --apk path.
    const apkPath = `${state.sessionDir}/artifacts/app.apk`;
    state.apkPath = apkPath;
    expect(await evaluateGateMetric(state, "apk_exists")).toBe(0); // path known but file missing
    await Bun.write(apkPath, "PK fake apk");
    expect(await evaluateGateMetric(state, "apk_exists")).toBe(1);

    // Via any *.apk in the artifacts dir (no apkPath set).
    const fresh = await createHuntState("https://example.com", "bounty");
    expect(await evaluateGateMetric(fresh, "apk_exists")).toBe(0);
    await Bun.write(`${fresh.sessionDir}/artifacts/dropped.apk`, "PK fake apk");
    expect(await evaluateGateMetric(fresh, "apk_exists")).toBe(1);
  });

  it("stores --apk in hunt state at creation", async () => {
    const state = await createHuntState(TEST_TARGET, "bounty", "W_HUNT_MOBILE", undefined, {
      apkPath: "/tmp/app.apk",
    });
    expect(state.apkPath).toBe("/tmp/app.apk");
    const loaded = await loadState(TEST_SLUG);
    expect(loaded!.apkPath).toBe("/tmp/app.apk");
  });
});

describe("parseSetPhaseStatusArg", () => {
  it("parses valid PHASE:STATUS pairs", () => {
    expect(parseSetPhaseStatusArg("RECON:completed")).toEqual({ phase: "RECON", status: "completed" });
    expect(parseSetPhaseStatusArg("RECON:failed")).toEqual({ phase: "RECON", status: "failed" });
    expect(parseSetPhaseStatusArg("RECON:skipped")).toEqual({ phase: "RECON", status: "skipped" });
  });

  it("rejects malformed shapes", () => {
    expect(() => parseSetPhaseStatusArg("RECON")).toThrow(/expected PHASE:STATUS/);
    expect(() => parseSetPhaseStatusArg("RECON:")).toThrow(/expected PHASE:STATUS/);
    expect(() => parseSetPhaseStatusArg("a:b:c")).toThrow(/expected PHASE:STATUS/);
  });

  it("rejects disallowed statuses (including running and pending)", () => {
    expect(() => parseSetPhaseStatusArg("RECON:running")).toThrow(/Invalid phase status "running"/);
    expect(() => parseSetPhaseStatusArg("RECON:pending")).toThrow(/Invalid phase status "pending"/);
    expect(() => parseSetPhaseStatusArg("RECON:done")).toThrow(/Invalid phase status "done"/);
  });
});

describe("hunt-orchestrator CLI error handling", () => {
  const CLI = join(import.meta.dir, "..", "Tools", "hunt-orchestrator.ts");

  function runCli(argv: string[]) {
    const proc = Bun.spawnSync([process.execPath, CLI, ...argv], {
      cwd: join(import.meta.dir, ".."),
    });
    return {
      exitCode: proc.exitCode,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
    };
  }

  it("scope refusal exits 1 with a clean one-line error (no stack trace)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bh-orch-test-"));
    try {
      const config = join(dir, "target-config.json");
      await Bun.write(config, JSON.stringify({ scope_in: ["127.0.0.1"], scope_out: [] }));
      const { exitCode, stderr } = runCli(["--target", "http://evil.example.com", "--config", config]);
      expect(exitCode).toBe(1);
      expect(stderr).toContain("[HUNT] ERROR: Refusing to create hunt: NOT IN SCOPE");
      expect(stderr).not.toContain("at createHuntState");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("unknown workflow exits 1 with a clean one-line error", () => {
    const { exitCode, stderr } = runCli(["--target", "http://wf-test.example.com", "--workflow", "W_NOPE"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('[HUNT] ERROR: Unknown workflow "W_NOPE"');
    expect(stderr).not.toContain("at ");
  });

  it("--set-phase-status with an invalid status exits 1 with a clean error", async () => {
    await createHuntState(TEST_TARGET, "bounty");
    try {
      const { exitCode, stderr } = runCli(["--target", TEST_TARGET, "--set-phase-status", "RECON:running"]);
      expect(exitCode).toBe(1);
      expect(stderr).toContain('[HUNT] ERROR: Invalid phase status "running"');
      expect(stderr).not.toContain("at ");
    } finally {
      await cleanup();
    }
  });
});
