import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  createHuntState,
  loadState,
  advancePhase,
  addFinding,
  setPhaseStatus,
  PHASES,
} from "../Tools/hunt-orchestrator.ts";
import { getSessionDir } from "../Tools/lib/paths.ts";

const TEST_TARGET = "https://test.example.com";
const TEST_SLUG = "test-example-com";

describe("hunt-orchestrator", () => {
  beforeEach(async () => {
    await Bun.write(`${getSessionDir(TEST_SLUG)}/.gitkeep`, "");
  });

  afterEach(async () => {
    await Bun.$`rm -rf ${getSessionDir(TEST_SLUG)}`;
  });

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
});
