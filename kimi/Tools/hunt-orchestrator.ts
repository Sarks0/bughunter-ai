#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Hunt orchestrator: state machine, session persistence, progress tracking.
 */

import { parseArgs } from "util";
import { getSessionDir, SESSIONS_DIR } from "./lib/paths.ts";

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    target: { type: "string" },
    mode: { type: "string", default: "bounty" },
    workflow: { type: "string" },
    resume: { type: "boolean", default: false },
    status: { type: "boolean", default: false },
    advance: { type: "string" },
    fail: { type: "string" },
    "add-finding": { type: "string" },
    reset: { type: "boolean", default: false },
    "scope-check": { type: "boolean", default: false },
    "set-phase-status": { type: "string" },
    reason: { type: "string" },
    data: { type: "string" },
    findings: { type: "string" },
  },
});

export type PhaseStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type HuntMode = "bounty" | "pentest" | "comprehensive";

export const PHASES = [
  "INIT",
  "MEMORY_LOAD",
  "TARGET_INGEST",
  "APP_UNDERSTANDING",
  "RECON",
  "AGENT_DEPLOY",
  "DYNAMIC_TEST",
  "VULN_ASSESS",
  "LEARNING",
  "REPORT",
] as const;

export type PhaseName = (typeof PHASES)[number];

export interface PhaseState {
  name: PhaseName;
  status: PhaseStatus;
  startTime: string | null;
  endTime: string | null;
  findingsCount: number;
  error: string | null;
  retryCount: number;
}

export interface HuntState {
  target: string;
  targetSlug: string;
  mode: HuntMode;
  workflow?: string;
  sessionDir: string;
  startedAt: string;
  lastUpdated: string;
  currentPhase: PhaseName;
  phases: Record<PhaseName, PhaseState>;
  totalFindings: number;
  findings: Array<{ id: string; severity: string; type: string; title: string; timestamp: string }>;
  config: {
    minCvss: number;
    maxRetries: number;
    targetFindingCount: number;
  };
}

function toSlug(url: string): string {
  return url
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]/gi, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

function getStatePath(slug: string): string {
  return `${getSessionDir(slug)}/hunt-state.json`;
}

function getLogPath(slug: string): string {
  return `${getSessionDir(slug)}/hunt-events.jsonl`;
}

function modeToConfig(mode: HuntMode) {
  switch (mode) {
    case "bounty":
      return { minCvss: 8.0, maxRetries: 1, targetFindingCount: 10 };
    case "pentest":
      return { minCvss: 4.0, maxRetries: 2, targetFindingCount: 20 };
    case "comprehensive":
      return { minCvss: 0.0, maxRetries: 2, targetFindingCount: 50 };
  }
}

export async function logEvent(slug: string, event: Record<string, unknown>) {
  const logPath = getLogPath(slug);
  const entry = JSON.stringify({ ...event, timestamp: new Date().toISOString() }) + "\n";
  const file = Bun.file(logPath);
  const existing = (await file.exists()) ? await file.text() : "";
  await Bun.write(logPath, existing + entry);
}

export async function createHuntState(
  target: string,
  mode: HuntMode,
  workflow?: string
): Promise<HuntState> {
  const slug = toSlug(target);
  const sessionDir = getSessionDir(slug);

  const dirs = [
    sessionDir,
    `${sessionDir}/findings`,
    `${sessionDir}/screenshots`,
    `${sessionDir}/artifacts`,
    `${sessionDir}/recon`,
  ];
  for (const dir of dirs) {
    await Bun.write(`${dir}/.gitkeep`, "");
  }

  const phases: Record<string, PhaseState> = {};
  for (const name of PHASES) {
    phases[name] = {
      name,
      status: "pending",
      startTime: null,
      endTime: null,
      findingsCount: 0,
      error: null,
      retryCount: 0,
    };
  }

  const state: HuntState = {
    target,
    targetSlug: slug,
    mode,
    workflow,
    sessionDir,
    startedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    currentPhase: "INIT",
    phases: phases as Record<PhaseName, PhaseState>,
    totalFindings: 0,
    findings: [],
    config: modeToConfig(mode),
  };

  await saveState(state);
  await logEvent(slug, { event: "HUNT_CREATED", target, mode, workflow });
  return state;
}

export async function loadState(slug: string): Promise<HuntState | null> {
  const path = getStatePath(slug);
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  return JSON.parse(await file.text());
}

export async function saveState(state: HuntState): Promise<void> {
  state.lastUpdated = new Date().toISOString();
  await Bun.write(getStatePath(state.targetSlug), JSON.stringify(state, null, 2));
}

export async function advancePhase(state: HuntState, toPhase?: PhaseName): Promise<HuntState> {
  const currentIdx = PHASES.indexOf(state.currentPhase);
  const currentPhaseState = state.phases[state.currentPhase];

  currentPhaseState.status = "completed";
  currentPhaseState.endTime = new Date().toISOString();

  let nextIdx: number;
  if (toPhase) {
    nextIdx = PHASES.indexOf(toPhase);
    if (nextIdx === -1) throw new Error(`Unknown phase: ${toPhase}`);
  } else {
    nextIdx = currentIdx + 1;
    while (nextIdx < PHASES.length && state.phases[PHASES[nextIdx]].status === "skipped") {
      nextIdx++;
    }
  }

  if (nextIdx >= PHASES.length) {
    await logEvent(state.targetSlug, { event: "HUNT_COMPLETE", totalFindings: state.totalFindings });
    console.log(`\n[HUNT COMPLETE] ${state.target} — ${state.totalFindings} findings in ${state.mode} mode`);
    await saveState(state);
    return state;
  }

  const nextPhase = PHASES[nextIdx];
  state.currentPhase = nextPhase;
  state.phases[nextPhase].status = "running";
  state.phases[nextPhase].startTime = new Date().toISOString();

  await logEvent(state.targetSlug, { event: "PHASE_ADVANCE", from: PHASES[currentIdx], to: nextPhase });
  await saveState(state);
  return state;
}

export async function failPhase(state: HuntState, error: string): Promise<HuntState> {
  const phase = state.phases[state.currentPhase];
  phase.retryCount++;

  if (phase.retryCount <= state.config.maxRetries) {
    phase.status = "running";
    phase.error = `Retry ${phase.retryCount}: ${error}`;
    await logEvent(state.targetSlug, { event: "PHASE_RETRY", phase: state.currentPhase, error, attempt: phase.retryCount });
    console.log(`[RETRY] Phase ${state.currentPhase} — attempt ${phase.retryCount}/${state.config.maxRetries}: ${error}`);
  } else {
    phase.status = "failed";
    phase.endTime = new Date().toISOString();
    phase.error = error;
    await logEvent(state.targetSlug, { event: "PHASE_FAILED", phase: state.currentPhase, error });
    console.log(`[FAILED] Phase ${state.currentPhase} — skipping after ${phase.retryCount} retries: ${error}`);
    state = await advancePhase(state);
  }

  await saveState(state);
  return state;
}

export async function setPhaseStatus(
  state: HuntState,
  phase: PhaseName,
  status: Exclude<PhaseStatus, "running">,
  reason?: string,
  data?: unknown,
  findingsPath?: string
): Promise<HuntState> {
  const phaseState = state.phases[phase];
  phaseState.status = status;
  phaseState.endTime = new Date().toISOString();
  phaseState.error = reason ?? null;

  if (findingsPath) {
    try {
      const file = Bun.file(findingsPath);
      if (await file.exists()) {
        const findings = JSON.parse(await file.text());
        const count = Array.isArray(findings) ? findings.length : 0;
        phaseState.findingsCount += count;
        state.totalFindings += count;
      }
    } catch {
      // ignore malformed findings file
    }
  }

  await logEvent(state.targetSlug, { event: "PHASE_STATUS_SET", phase, status, reason, data, findings: findingsPath });
  await saveState(state);
  return state;
}

export async function addFinding(
  state: HuntState,
  finding: { severity: string; type: string; title: string }
): Promise<HuntState> {
  const id = `F-${String(state.totalFindings + 1).padStart(3, "0")}`;
  state.findings.push({ id, ...finding, timestamp: new Date().toISOString() });
  state.totalFindings++;
  state.phases[state.currentPhase].findingsCount++;

  await logEvent(state.targetSlug, { event: "FINDING_ADDED", id, ...finding });
  await saveState(state);
  console.log(`[FINDING ${id}] [${finding.severity}] ${finding.type}: ${finding.title}`);
  return state;
}

export function getHuntStatus(state: HuntState): string {
  const elapsed = Date.now() - new Date(state.startedAt).getTime();
  const elapsedMin = Math.floor(elapsed / 60000);

  const lines: string[] = [];
  lines.push(`\n${"=".repeat(70)}`);
  lines.push(`  HUNT STATUS: ${state.target}`);
  lines.push(`  Mode: ${state.mode.toUpperCase()} | Elapsed: ${elapsedMin}m | Findings: ${state.totalFindings}`);
  lines.push(`  Min CVSS: ${state.config.minCvss} | Target: ${state.config.targetFindingCount} findings`);
  if (state.workflow) lines.push(`  Workflow: ${state.workflow}`);
  lines.push(`${"=".repeat(70)}`);

  for (const name of PHASES) {
    const p = state.phases[name];
    const icon =
      p.status === "completed" ? "[OK]"
      : p.status === "running" ? "[>>]"
      : p.status === "failed" ? "[!!]"
      : p.status === "skipped" ? "[--]"
      : "[  ]";

    const time =
      p.startTime && p.endTime
        ? `${Math.round((new Date(p.endTime).getTime() - new Date(p.startTime).getTime()) / 1000)}s`
        : p.startTime ? "running..." : "";

    const findings = p.findingsCount > 0 ? ` (${p.findingsCount} findings)` : "";
    const error = p.error ? ` ERR: ${p.error.slice(0, 50)}` : "";

    lines.push(`  ${icon} ${name.padEnd(20)} ${time.padEnd(12)} ${findings}${error}`);
  }

  if (state.findings.length > 0) {
    lines.push(`\n  FINDINGS:`);
    for (const f of state.findings.slice(-10)) {
      lines.push(`    ${f.id} [${f.severity}] ${f.type}: ${f.title}`);
    }
  }

  lines.push(`${"=".repeat(70)}\n`);
  return lines.join("\n");
}

async function listSessions(): Promise<void> {
  const glob = new Bun.Glob("*/hunt-state.json");
  const matches: string[] = [];

  for await (const path of glob.scan({ cwd: SESSIONS_DIR })) {
    matches.push(path);
  }

  if (matches.length === 0) {
    console.log("No hunt sessions found.");
    return;
  }

  console.log(`\nHunt Sessions (${matches.length}):\n`);
  for (const path of matches) {
    const state: HuntState = JSON.parse(await Bun.file(`${SESSIONS_DIR}/${path}`).text());
    const age = Math.floor((Date.now() - new Date(state.lastUpdated).getTime()) / 86400000);
    const completedPhases = PHASES.filter((p) => state.phases[p].status === "completed").length;
    console.log(
      `  ${state.targetSlug.padEnd(40)} ${state.mode.padEnd(14)} ${completedPhases}/${PHASES.length} phases  ${state.totalFindings} findings  ${age}d ago`
    );
  }
}

function printUsage(): void {
  console.log(`hunt-orchestrator — BugHunter AI state machine

Usage:
  hunt-orchestrator --target URL [--mode bounty|pentest|comprehensive] [--workflow NAME]
  hunt-orchestrator --target URL --resume
  hunt-orchestrator --target URL --status
  hunt-orchestrator --target URL --advance [PHASE]
  hunt-orchestrator --target URL --fail 'error message'
  hunt-orchestrator --target URL --add-finding '{"severity":"critical","type":"SSRF","title":"..."}'
  hunt-orchestrator --target URL --set-phase-status PHASE:STATUS [--reason '...'] [--data '...'] [--findings path.json]
  hunt-orchestrator --target URL --scope-check
  hunt-orchestrator --status  (list all sessions)
  hunt-orchestrator --target URL --reset`);
}

async function main() {
  if (!args.target && !args.status) {
    printUsage();
    return;
  }

  if (args.status && !args.target) {
    await listSessions();
    return;
  }

  const target = args.target!;
  const slug = toSlug(target);

  if (args.status) {
    const state = await loadState(slug);
    if (!state) {
      console.log(`No hunt session found for ${target}`);
      return;
    }
    console.log(getHuntStatus(state));
    return;
  }

  if (args["scope-check"]) {
    console.log(`[SCOPE CHECK] ${target} — scope enforcement is configured via target profiles`);
    return;
  }

  if (args.resume) {
    const state = await loadState(slug);
    if (!state) {
      console.log(`No session to resume for ${target}. Starting new hunt.`);
    } else {
      console.log(`[RESUME] Resuming hunt for ${target} at phase ${state.currentPhase}`);
      console.log(getHuntStatus(state));
      return;
    }
  }

  if (args.reset) {
    const mode = (args.mode || "bounty") as HuntMode;
    const state = await createHuntState(target, mode, args.workflow);
    console.log(`[RESET] Hunt reset for ${target}`);
    console.log(getHuntStatus(state));
    return;
  }

  if (args.advance !== undefined) {
    const state = await loadState(slug);
    if (!state) {
      console.log("No active hunt.");
      return;
    }
    const toPhase = args.advance ? (args.advance as PhaseName) : undefined;
    const updated = await advancePhase(state, toPhase);
    console.log(`[ADVANCE] Now at phase: ${updated.currentPhase}`);
    return;
  }

  if (args.fail) {
    const state = await loadState(slug);
    if (!state) {
      console.log("No active hunt.");
      return;
    }
    await failPhase(state, args.fail);
    return;
  }

  if (args["add-finding"]) {
    const state = await loadState(slug);
    if (!state) {
      console.log("No active hunt.");
      return;
    }
    const finding = JSON.parse(args["add-finding"]);
    await addFinding(state, finding);
    return;
  }

  if (args["set-phase-status"]) {
    const state = await loadState(slug);
    if (!state) {
      console.log("No active hunt.");
      return;
    }
    const [phase, status] = args["set-phase-status"].split(":") as [PhaseName, Exclude<PhaseStatus, "running">];
    await setPhaseStatus(state, phase, status, args.reason, args.data ? JSON.parse(args.data) : undefined, args.findings);
    console.log(`[PHASE STATUS] ${phase} → ${status}`);
    return;
  }

  const mode = (args.mode || "bounty") as HuntMode;
  const existing = await loadState(slug);
  if (existing && !args.reset) {
    console.log(`[EXISTS] Hunt session already exists for ${target}. Use --resume or --reset.`);
    console.log(getHuntStatus(existing));
    return;
  }

  const state = await createHuntState(target, mode, args.workflow);
  state.phases.INIT.status = "running";
  state.phases.INIT.startTime = new Date().toISOString();
  await saveState(state);

  console.log(`[HUNT STARTED] ${target} in ${mode} mode`);
  console.log(`  Session: ${state.sessionDir}`);
  console.log(`  Min CVSS: ${state.config.minCvss}`);
  console.log(`  Target findings: ${state.config.targetFindingCount}`);
  console.log(getHuntStatus(state));
}

if (import.meta.main) {
  main().catch(console.error);
}
