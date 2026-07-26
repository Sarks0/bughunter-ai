#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Hunt orchestrator: state machine, session persistence, progress tracking.
 */

import { parseArgs } from "util";
import { appendFileSync, existsSync, mkdirSync, readdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { getSessionDir, toSlug, MEMORY_DIR, REPO_ROOT, SESSIONS_DIR } from "./lib/paths.ts";
import { isInScope, loadScopeFromConfig, scopeSummary, type Scope } from "./lib/scope.ts";
import { normalizeFindings } from "./lib/finding.ts";
import { validateToolsForMode, writeToolReport, formatToolReport } from "./lib/tool-validator.ts";

const WORKFLOWS_DIR = join(REPO_ROOT, "kimi", "Workflows");

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
  "VALIDATION",
  "REPORT",
] as const;

export type PhaseName = (typeof PHASES)[number];

export interface PhaseState {
  name: string;
  status: PhaseStatus;
  startTime: string | null;
  endTime: string | null;
  findingsCount: number;
  /** Findings-file path → finding count, so recounts are idempotent. */
  findingFiles?: Record<string, number>;
  error: string | null;
  retryCount: number;
}

export interface WorkflowGate {
  metric: string;
  min: number;
}

export interface WorkflowPhase {
  name: string;
  blocking?: boolean;
  agents?: string[];
  tools?: string[];
  gates?: WorkflowGate[];
  max_concurrent_agents?: number;
  conditional?: boolean;
}

export interface WorkflowDefinition {
  name: string;
  description?: string;
  trigger?: string;
  phases: WorkflowPhase[];
}

export interface HuntState {
  target: string;
  targetSlug: string;
  mode: HuntMode;
  workflow?: string;
  workflowDefinition?: WorkflowDefinition;
  sessionDir: string;
  startedAt: string;
  lastUpdated: string;
  currentPhase: string;
  phases: Record<string, PhaseState>;
  totalFindings: number;
  findings: Array<{ id: string; severity: string; type: string; title: string; phase?: string; timestamp: string }>;
  config: {
    minCvss: number;
    maxRetries: number;
    targetFindingCount: number;
  };
  scope?: Scope;
  /** Path to the APK/IPA under test (mobile hunts); set via --apk at creation. */
  apkPath?: string;
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

/** Append-only event log (read+rewrite was O(n²) and raced parallel agents). */
export async function logEvent(slug: string, event: Record<string, unknown>) {
  const logPath = getLogPath(slug);
  const entry = JSON.stringify({ ...event, timestamp: new Date().toISOString() }) + "\n";
  mkdirSync(dirname(logPath), { recursive: true });
  appendFileSync(logPath, entry);
}

export async function listWorkflows(): Promise<string[]> {
  try {
    return readdirSync(WORKFLOWS_DIR)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.replace(/\.json$/, ""))
      .sort();
  } catch {
    return [];
  }
}

export async function loadWorkflow(name: string): Promise<WorkflowDefinition> {
  const path = join(WORKFLOWS_DIR, `${name}.json`);
  const file = Bun.file(path);
  if (!(await file.exists())) {
    const available = await listWorkflows();
    throw new Error(
      `Unknown workflow "${name}". Available workflows: ${available.length > 0 ? available.join(", ") : "(none found)"}`
    );
  }
  const definition = (await file.json()) as WorkflowDefinition;
  if (!Array.isArray(definition.phases) || definition.phases.length === 0) {
    throw new Error(`Workflow "${name}" at ${path} has no phases.`);
  }
  return definition;
}

/** The phase sequence for a hunt: the workflow's phases when one is loaded, else the default state machine. */
export function getPhaseList(state: HuntState): string[] {
  return state.workflowDefinition ? state.workflowDefinition.phases.map((p) => p.name) : [...PHASES];
}

/** Best-effort per-phase metrics: one JSON line per completed phase, the seed for cost/efficiency tracking. */
function recordPhaseMetric(state: HuntState, phase: PhaseState): void {
  try {
    mkdirSync(MEMORY_DIR.learning, { recursive: true });
    const completedAt = phase.endTime ?? new Date().toISOString();
    const line = JSON.stringify({
      phase: phase.name,
      started_at: phase.startTime,
      completed_at: completedAt,
      duration_ms: phase.startTime ? new Date(completedAt).getTime() - new Date(phase.startTime).getTime() : null,
      findings_count: phase.findingsCount,
      status: phase.status,
    }) + "\n";
    appendFileSync(join(MEMORY_DIR.learning, `${state.targetSlug}-phases.jsonl`), line);
  } catch {
    // metrics are best-effort; never break a hunt over them
  }
}

/**
 * Recompute findingsCount per phase and totalFindings from stored data
 * (direct findings + per-phase findings files) instead of accumulating,
 * so repeated --set-phase-status --findings calls stay idempotent.
 */
function recomputeFindingTotals(state: HuntState): void {
  let total = state.findings.length;
  for (const [name, phase] of Object.entries(state.phases)) {
    const fileCount = Object.values(phase.findingFiles ?? {}).reduce((a, b) => a + b, 0);
    const directCount = state.findings.filter((f) => f.phase === name).length;
    phase.findingsCount = directCount + fileCount;
    total += fileCount;
  }
  state.totalFindings = total;
}

export async function createHuntState(
  target: string,
  mode: HuntMode,
  workflow?: string,
  scope?: Scope,
  opts: { force?: boolean; apkPath?: string } = {}
): Promise<HuntState> {
  // Refuse out-of-scope targets unless explicitly forced.
  if (scope && (scope.in.length > 0 || scope.out.length > 0)) {
    const check = isInScope(target, scope);
    if (!check.inScope && !opts.force) {
      throw new Error(`Refusing to create hunt: ${check.reason}. Pass --force to override.`);
    }
  }

  const workflowDefinition = workflow ? await loadWorkflow(workflow) : undefined;
  const phaseNames = workflowDefinition ? workflowDefinition.phases.map((p) => p.name) : [...PHASES];

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
  for (const name of phaseNames) {
    phases[name] = {
      name,
      status: "pending",
      startTime: null,
      endTime: null,
      findingsCount: 0,
      findingFiles: {},
      error: null,
      retryCount: 0,
    };
  }

  const state: HuntState = {
    target,
    targetSlug: slug,
    mode,
    workflow,
    workflowDefinition,
    sessionDir,
    startedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    currentPhase: phaseNames[0],
    phases,
    totalFindings: 0,
    findings: [],
    config: modeToConfig(mode),
    scope,
    ...(opts.apkPath ? { apkPath: opts.apkPath } : {}),
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
  // Atomic write (tmp file + rename) so parallel agents never see a torn state file.
  const path = getStatePath(state.targetSlug);
  const tmpPath = `${path}.tmp-${process.pid}`;
  await Bun.write(tmpPath, JSON.stringify(state, null, 2));
  renameSync(tmpPath, path);
}

export async function advancePhase(state: HuntState, toPhase?: string): Promise<HuntState> {
  const phaseList = getPhaseList(state);
  const currentIdx = phaseList.indexOf(state.currentPhase);
  const currentPhaseState = state.phases[state.currentPhase];
  if (!currentPhaseState) {
    throw new Error(`Current phase "${state.currentPhase}" not found in hunt state (stale or corrupt session).`);
  }

  // A phase that already failed (via failPhase) keeps its "failed" status;
  // advancePhase only completes phases that are still running/pending.
  if (currentPhaseState.status !== "failed") {
    currentPhaseState.status = "completed";
    currentPhaseState.endTime = new Date().toISOString();
    recordPhaseMetric(state, currentPhaseState);
  }

  let nextIdx: number;
  if (toPhase) {
    nextIdx = phaseList.indexOf(toPhase);
    if (nextIdx === -1) throw new Error(`Unknown phase: ${toPhase}. Valid phases: ${phaseList.join(", ")}`);
  } else {
    nextIdx = currentIdx + 1;
    while (nextIdx < phaseList.length && state.phases[phaseList[nextIdx]]?.status === "skipped") {
      nextIdx++;
    }
  }

  if (nextIdx >= phaseList.length) {
    await logEvent(state.targetSlug, { event: "HUNT_COMPLETE", totalFindings: state.totalFindings });
    console.log(`\n[HUNT COMPLETE] ${state.target} — ${state.totalFindings} findings in ${state.mode} mode`);
    await saveState(state);
    return state;
  }

  const nextPhase = phaseList[nextIdx];
  const nextPhaseState = state.phases[nextPhase];
  if (!nextPhaseState) {
    throw new Error(`Phase "${nextPhase}" not found in hunt state (stale or corrupt session).`);
  }
  state.currentPhase = nextPhase;
  nextPhaseState.status = "running";
  nextPhaseState.startTime = new Date().toISOString();

  await logEvent(state.targetSlug, { event: "PHASE_ADVANCE", from: phaseList[currentIdx], to: nextPhase });
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
    recordPhaseMetric(state, phase);
    state = await advancePhase(state);
  }

  await saveState(state);
  return state;
}

export async function setPhaseStatus(
  state: HuntState,
  phase: string,
  status: Exclude<PhaseStatus, "running">,
  reason?: string,
  data?: unknown,
  findingsPath?: string
): Promise<HuntState> {
  const phaseState = state.phases[phase];
  if (!phaseState) {
    const known = Object.keys(state.phases).join(", ");
    throw new Error(`Unknown phase "${phase}" for this hunt's workflow. Known phases: ${known}`);
  }
  phaseState.status = status;
  phaseState.endTime = new Date().toISOString();
  phaseState.error = reason ?? null;

  if (findingsPath) {
    try {
      const file = Bun.file(findingsPath);
      if (await file.exists()) {
        // Accepts a bare findings array or a `{findings: [...]}` wrapper.
        const findings = normalizeFindings(JSON.parse(await file.text()));
        // Keyed by file path: re-registering the same file overwrites, never double-counts.
        phaseState.findingFiles ??= {};
        phaseState.findingFiles[findingsPath] = findings.length;
      }
    } catch {
      // ignore malformed findings file
    }
  }

  recomputeFindingTotals(state);
  if (status !== "pending") recordPhaseMetric(state, phaseState);
  await logEvent(state.targetSlug, { event: "PHASE_STATUS_SET", phase, status, reason, data, findings: findingsPath });
  await saveState(state);
  return state;
}

export async function addFinding(
  state: HuntState,
  finding: { severity: string; type: string; title: string }
): Promise<HuntState> {
  const id = `F-${String(state.findings.length + 1).padStart(3, "0")}`;
  state.findings.push({ id, ...finding, phase: state.currentPhase, timestamp: new Date().toISOString() });
  recomputeFindingTotals(state);

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
  lines.push(`  Scope: ${scopeSummary(state.scope)}`);
  if (state.workflow) lines.push(`  Workflow: ${state.workflow}`);
  lines.push(`${"=".repeat(70)}`);

  for (const name of getPhaseList(state)) {
    const p = state.phases[name];
    if (!p) continue;
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
    const phaseList = getPhaseList(state);
    const completedPhases = phaseList.filter((p) => state.phases[p]?.status === "completed").length;
    console.log(
      `  ${state.targetSlug.padEnd(40)} ${state.mode.padEnd(14)} ${completedPhases}/${phaseList.length} phases  ${state.totalFindings} findings  ${age}d ago`
    );
  }
}

function printUsage(): void {
  console.log(`hunt-orchestrator — BugHunter AI state machine

Usage:
  hunt-orchestrator --target URL [--mode bounty|pentest|comprehensive] [--workflow NAME] [--config path.json] [--apk path.apk] [--force]
  hunt-orchestrator --config path.json [--mode bounty|pentest|comprehensive] [--workflow NAME]
  hunt-orchestrator --target URL --resume
  hunt-orchestrator --target URL --status
  hunt-orchestrator --target URL --advance [PHASE]   (also: --advance --advance-to PHASE; --force skips gate checks)
  hunt-orchestrator --target URL --fail 'error message'
  hunt-orchestrator --target URL --add-finding '{"severity":"critical","type":"SSRF","title":"..."}'
  hunt-orchestrator --target URL --set-phase-status PHASE:STATUS [--reason '...'] [--data '...'] [--findings path.json]
  hunt-orchestrator --target URL --scope-check [--config path.json]
  hunt-orchestrator --target URL --validate-tools
  hunt-orchestrator --status  (list all sessions)
  hunt-orchestrator --target URL --reset

Options:
  --apk      Path to the APK under test (mobile hunts); stored in hunt state, satisfies the apk_exists gate
  --force    Override scope refusal on hunt creation and unmet workflow gates on --advance`);
}

/**
 * Evaluate a workflow gate metric against the session's artifacts.
 * Returns null when the metric cannot be evaluated.
 *
 * Metrics:
 * - alive_urls: line count of recon/alive-urls.txt (0 when missing).
 * - live_hosts: line count of recon/alive-hosts.json, falling back to alive_urls.
 * - alive_hosts: alias of live_hosts (W_HUNT_NETWORK wording).
 * - app_profile_exists: 1 when app-profile.json exists in the session dir, else 0.
 * - apk_exists: 1 when an APK is known and present — either the hunt's stored
 *   apkPath (--apk at creation) exists, or any *.apk sits in the session's
 *   artifacts dir — else 0.
 */
export async function evaluateGateMetric(state: HuntState, metric: string): Promise<number | null> {
  const reconDir = `${state.sessionDir}/recon`;
  try {
    switch (metric) {
      case "alive_urls": {
        const file = Bun.file(`${reconDir}/alive-urls.txt`);
        if (!(await file.exists())) return 0;
        return (await file.text()).split("\n").filter((l) => l.trim().length > 0).length;
      }
      case "alive_hosts": // alias: W_HUNT_NETWORK gates on this name
      case "live_hosts": {
        const file = Bun.file(`${reconDir}/alive-hosts.json`);
        if (await file.exists()) {
          // httpx -json emits one JSON object per line.
          return (await file.text()).split("\n").filter((l) => l.trim().length > 0).length;
        }
        return evaluateGateMetric(state, "alive_urls");
      }
      case "app_profile_exists": {
        return (await Bun.file(`${state.sessionDir}/app-profile.json`).exists()) ? 1 : 0;
      }
      case "apk_exists": {
        if (state.apkPath && existsSync(state.apkPath)) return 1;
        const artifactsDir = `${state.sessionDir}/artifacts`;
        if (existsSync(artifactsDir) && readdirSync(artifactsDir).some((f) => f.endsWith(".apk"))) return 1;
        return 0;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

export interface GateCheckResult {
  ok: boolean;
  failures: string[];
  unevaluable: string[];
}

/** Evaluate the workflow gates of a phase. Unevaluable metrics count as unmet. */
export async function checkPhaseGates(state: HuntState, phaseName: string): Promise<GateCheckResult> {
  const workflowPhase = state.workflowDefinition?.phases.find((p) => p.name === phaseName);
  const gates = workflowPhase?.gates ?? [];
  const result: GateCheckResult = { ok: true, failures: [], unevaluable: [] };
  for (const gate of gates) {
    const value = await evaluateGateMetric(state, gate.metric);
    if (value === null) {
      result.unevaluable.push(gate.metric);
      result.ok = false;
    } else if (value < gate.min) {
      result.failures.push(`${gate.metric}: ${value} < ${gate.min}`);
      result.ok = false;
    }
  }
  return result;
}

/**
 * Derive a usable target URL from a scope: the first in-scope entry that
 * yields a clean origin (scheme + host, wildcards and paths stripped).
 * Throws when no entry is usable.
 */
export function deriveTargetFromScope(scope: Scope): string {
  for (const entry of scope.in) {
    // URL-shaped entry: strip a leading wildcard label from the host
    // (https://*.example.com/* → https://example.com), then take the origin
    // (drop path, port preserved, no wildcards).
    if (entry.includes("://")) {
      try {
        const url = new URL(entry.replace(/:\/\/\*\./, "://").replace(/\*/g, "x"));
        if (url.hostname) return url.origin;
      } catch {
        continue;
      }
    }
    // Host-shaped entry: strip a leading wildcard label, path, and port.
    const host = entry.replace(/^\*\./, "").split("/")[0].split(":")[0].trim().toLowerCase();
    if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
      return `https://${host}`;
    }
  }
  throw new Error(
    "Could not derive a target from the scope: no usable in-scope entry. Pass --target or add 'target' to the config."
  );
}

/** Statuses accepted by --set-phase-status (never "running"/"pending" — those are machine-managed). */
const SETTABLE_PHASE_STATUSES = ["completed", "failed", "skipped"] as const;

/**
 * Parse a `--set-phase-status PHASE:STATUS` argument.
 * @throws Error on a malformed shape or a status outside completed/failed/skipped.
 */
export function parseSetPhaseStatusArg(raw: string): { phase: string; status: (typeof SETTABLE_PHASE_STATUSES)[number] } {
  const match = /^([^:]+):([^:]+)$/.exec(raw);
  if (!match) {
    throw new Error(
      `Invalid --set-phase-status "${raw}": expected PHASE:STATUS (e.g. RECON:completed). Allowed statuses: ${SETTABLE_PHASE_STATUSES.join(", ")}`
    );
  }
  const [, phase, status] = match;
  if (!(SETTABLE_PHASE_STATUSES as readonly string[]).includes(status)) {
    throw new Error(
      `Invalid phase status "${status}" in --set-phase-status. Allowed statuses: ${SETTABLE_PHASE_STATUSES.join(", ")}`
    );
  }
  return { phase, status: status as (typeof SETTABLE_PHASE_STATUSES)[number] };
}

async function resolveTargetAndScope(cliArgs: { target?: string; config?: string }): Promise<{ target: string; scope?: Scope }> {
  if (cliArgs.config) {
    const scope = await loadScopeFromConfig(cliArgs.config);
    const file = Bun.file(cliArgs.config);
    const config = await file.json();
    // Precedence: explicit --target, then the config's 'target' field, then derive from scope.
    const target = cliArgs.target ?? config.target ?? deriveTargetFromScope(scope);
    return { target, scope };
  }

  if (!cliArgs.target) {
    throw new Error("--target or --config is required");
  }
  return { target: cliArgs.target };
}

async function main() {
  const { values: args, positionals } = parseArgs({
    args: Bun.argv.slice(2),
    allowPositionals: true, // lets `--advance PHASE` work alongside bare `--advance`
    options: {
      target: { type: "string" },
      config: { type: "string" },
      mode: { type: "string", default: "bounty" },
      workflow: { type: "string" },
      resume: { type: "boolean", default: false },
      status: { type: "boolean", default: false },
      advance: { type: "boolean", default: false },
      "advance-to": { type: "string" },
      fail: { type: "string" },
      "add-finding": { type: "string" },
      reset: { type: "boolean", default: false },
      "scope-check": { type: "boolean", default: false },
      "validate-tools": { type: "boolean", default: false },
      "set-phase-status": { type: "string" },
      apk: { type: "string" },
      reason: { type: "string" },
      data: { type: "string" },
      findings: { type: "string" },
      force: { type: "boolean", default: false },
    },
  });

  if (!args.target && !args.status && !args.config && !args["validate-tools"]) {
    printUsage();
    return;
  }

  if (args.status && !args.target) {
    await listSessions();
    return;
  }

  if (args["validate-tools"]) {
    const mode = (args.mode || "bounty") as HuntMode;
    const checks = await validateToolsForMode(mode);
    console.log(formatToolReport(checks));
    return;
  }

  const { target, scope } = await resolveTargetAndScope({ target: args.target, config: args.config });
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
    const checkScope = scope ?? (await loadState(slug))?.scope;
    const result = isInScope(target, checkScope);
    console.log(`[SCOPE CHECK] ${target}`);
    console.log(`  ${result.reason}`);
    process.exit(result.inScope ? 0 : 1);
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
    const state = await createHuntState(target, mode, args.workflow, scope, { force: args.force, apkPath: args.apk });
    console.log(`[RESET] Hunt reset for ${target}`);
    console.log(getHuntStatus(state));
    return;
  }

  if (args.advance) {
    const state = await loadState(slug);
    if (!state) {
      console.log("No active hunt.");
      return;
    }
    // `--advance PHASE` (positional) or `--advance --advance-to PHASE`; bare `--advance` = next phase.
    const toPhase = args["advance-to"] ?? (positionals.length > 0 ? positionals[0] : undefined);

    // Enforce the workflow's gates on the phase being left.
    if (state.workflowDefinition) {
      const gates = await checkPhaseGates(state, state.currentPhase);
      for (const metric of gates.unevaluable) {
        console.log(`[GATE WARN] metric "${metric}" cannot be evaluated; treating as unmet`);
      }
      if (!gates.ok && !args.force) {
        const problems = [...gates.failures, ...gates.unevaluable.map((m) => `${m} (unevaluable)`)];
        console.log(`[GATE] Phase ${state.currentPhase} gates unmet: ${problems.join("; ")}`);
        console.log(`[GATE] Re-run with --force to advance anyway.`);
        process.exit(1);
      }
    }

    const updated = await advancePhase(state, toPhase);

    // Validate external tools when entering TARGET_INGEST.
    if (updated.currentPhase === "TARGET_INGEST") {
      const checks = await validateToolsForMode(updated.mode);
      const reportPath = `${updated.sessionDir}/recon/tool-health.json`;
      await writeToolReport(reportPath, checks);
      console.log(formatToolReport(checks));
      await logEvent(updated.targetSlug, {
        event: "TOOLS_VALIDATED",
        reportPath,
        installed: checks.filter((c) => c.installed).length,
        total: checks.length,
      });
    }

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
    const { phase, status } = parseSetPhaseStatusArg(args["set-phase-status"]);
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

  const state = await createHuntState(target, mode, args.workflow, scope, { force: args.force, apkPath: args.apk });
  const firstPhase = getPhaseList(state)[0];
  state.phases[firstPhase].status = "running";
  state.phases[firstPhase].startTime = new Date().toISOString();
  await saveState(state);

  console.log(`[HUNT STARTED] ${target} in ${mode} mode`);
  console.log(`  Session: ${state.sessionDir}`);
  console.log(`  Min CVSS: ${state.config.minCvss}`);
  console.log(`  Target findings: ${state.config.targetFindingCount}`);
  console.log(getHuntStatus(state));
}

if (import.meta.main) {
  // All user-facing failures (scope refusal, unknown workflow, unresolvable
  // target) funnel through here: one clean line on stderr, exit 1.
  main().catch((err) => {
    console.error(`[HUNT] ERROR: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
