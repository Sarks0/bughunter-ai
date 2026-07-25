/**
 * BugHunter AI — Kimi port
 * External tool availability and health checks.
 */

export type HuntMode = "bounty" | "pentest" | "comprehensive";

export interface ToolCheck {
  /** Human-readable tool name. */
  name: string;
  /** Command to run on the PATH. */
  command: string;
  /** Whether the tool is considered required for the current mode. */
  required: boolean;
  /** Whether the command was found and responded to a version probe. */
  installed: boolean;
  /** Raw version string, if available. */
  version?: string;
  /** Error message when not installed or not healthy. */
  error?: string;
}

interface ToolDefinition {
  command: string;
  versionArgs: string[];
  modes: HuntMode[];
  required: boolean;
}

/** Tools commonly used by BugHunter AI agents. */
export const KNOWN_TOOLS: Record<string, ToolDefinition> = {
  curl: { command: "curl", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: true },
  jq: { command: "jq", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  git: { command: "git", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  nmap: { command: "nmap", versionArgs: ["--version"], modes: ["pentest", "comprehensive"], required: false },
  subfinder: { command: "subfinder", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  amass: { command: "amass", versionArgs: ["-version"], modes: ["comprehensive"], required: false },
  httpx: { command: "httpx", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  naabu: { command: "naabu", versionArgs: ["--version"], modes: ["pentest", "comprehensive"], required: false },
  dnsx: { command: "dnsx", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  ffuf: { command: "ffuf", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  nuclei: { command: "nuclei", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  dalfox: { command: "dalfox", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  gospider: { command: "gospider", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  katana: { command: "katana", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  sqlmap: { command: "sqlmap", versionArgs: ["--version"], modes: ["pentest", "comprehensive"], required: false },
  commix: { command: "commix", versionArgs: ["--version"], modes: ["pentest", "comprehensive"], required: false },
  masscan: { command: "masscan", versionArgs: ["--version"], modes: ["comprehensive"], required: false },
  burpsuite: { command: "burpsuite", versionArgs: ["--version"], modes: ["bounty", "pentest", "comprehensive"], required: false },
  apktool: { command: "apktool", versionArgs: ["--version"], modes: ["comprehensive"], required: false },
  jadx: { command: "jadx", versionArgs: ["--version"], modes: ["comprehensive"], required: false },
};

function decode(data: Uint8Array | ArrayBuffer | undefined): string {
  if (!data) return "";
  return new TextDecoder().decode(data);
}

/**
 * Check whether a single tool is installed and can report a version.
 * Unknown tool names are probed generically with `which` and common version flags.
 */
export async function checkTool(name: string, required = false): Promise<ToolCheck> {
  const def = KNOWN_TOOLS[name];
  const command = def?.command ?? name;
  const versionArgs = def?.versionArgs ?? ["--version", "-version", "-V"];

  // First probe: is it on PATH?
  const which = Bun.spawnSync(["which", command], { stdout: "pipe", stderr: "pipe" });
  if (which.exitCode !== 0) {
    return {
      name,
      command,
      required,
      installed: false,
      error: `${command} not found on PATH`,
    };
  }

  // Second probe: can it report a version?
  for (const args of versionArgs.map((a) => [a])) {
    try {
      const result = Bun.spawnSync([command, ...args], { stdout: "pipe", stderr: "pipe" });
      if (result.exitCode === 0 || result.exitCode === 1) {
        const stdout = decode(result.stdout);
        const stderr = decode(result.stderr);
        const version = (stdout || stderr).split("\n")[0].trim() || undefined;
        return { name, command, required, installed: true, version };
      }
    } catch {
      // try next version flag
    }
  }

  return {
    name,
    command,
    required,
    installed: true,
    error: `${command} found but version probe failed`,
  };
}

/**
 * Validate a list of tools by name.
 */
export async function validateTools(toolNames: string[], required = false): Promise<ToolCheck[]> {
  const checks: ToolCheck[] = [];
  for (const name of toolNames) {
    checks.push(await checkTool(name, required));
  }
  return checks;
}

/**
 * Validate the default tool set for a hunt mode.
 */
export async function validateToolsForMode(mode: HuntMode): Promise<ToolCheck[]> {
  const checks: ToolCheck[] = [];
  for (const [name, def] of Object.entries(KNOWN_TOOLS)) {
    if (!def.modes.includes(mode)) continue;
    checks.push(await checkTool(name, def.required));
  }
  return checks;
}

/** Summarize a list of tool checks for human output. */
export function formatToolReport(checks: ToolCheck[]): string {
  const installed = checks.filter((c) => c.installed).length;
  const requiredMissing = checks.filter((c) => c.required && !c.installed);
  const lines: string[] = [];
  lines.push(`Tool health: ${installed}/${checks.length} available`);
  for (const c of checks) {
    const icon = c.installed ? "✓" : c.required ? "✗" : "○";
    const detail = c.installed ? c.version || "installed" : c.error || "missing";
    lines.push(`  ${icon} ${c.name.padEnd(14)} ${detail}`);
  }
  if (requiredMissing.length > 0) {
    lines.push(`\nRequired tools missing: ${requiredMissing.map((c) => c.name).join(", ")}`);
  }
  return lines.join("\n");
}

/** Write a tool-health report to JSON. */
export async function writeToolReport(path: string, checks: ToolCheck[]): Promise<void> {
  await Bun.write(path, JSON.stringify({ generatedAt: new Date().toISOString(), checks }, null, 2));
}
