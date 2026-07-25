/**
 * BugHunter AI — Kimi port
 * Scope matching and platform scope import utilities.
 *
 * Scope patterns are globs by default:
 *   - `*.example.com`          matches any subdomain of example.com
 *   - `example.com`            matches example.com exactly
 *   - `https://api.example.com/*` matches URLs under that host
 *   - `/.*\.example\.com$/`   regex literal (wrapped in /.../)
 */

import { join, dirname } from "path";

export interface Scope {
  /** In-scope glob/regex patterns. */
  in: string[];
  /** Out-of-scope glob/regex patterns. */
  out: string[];
  /** Where this scope came from (config path, platform, etc.). */
  source?: string;
}

/** Result of a scope check. */
export interface ScopeCheckResult {
  inScope: boolean;
  reason: string;
}

function escapeRegex(str: string): string {
  return str.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

function globToHostRegex(pattern: string): string {
  const segments = pattern.split(".").map((seg) => (seg === "*" ? "[^.]+" : escapeRegex(seg).replace(/\\\*/g, "[^.]*").replace(/\\\?/g, ".")));
  return `^(?:[^.]+\\.)*${segments.join("\\.")}$`;
}

function globToUrlRegex(pattern: string): string {
  let regex = escapeRegex(pattern)
    .replace(/\\\*\\\*/g, ".*")
    .replace(/\\\*/g, "[^?#]*")
    .replace(/\\\?/g, ".");
  return `^${regex}`;
}

function isHostPattern(pattern: string): boolean {
  const trimmed = pattern.trim();
  if (trimmed.startsWith("/") && trimmed.endsWith("/") && trimmed.length > 1) {
    return !/:\/\//.test(trimmed);
  }
  return !/:\/\//.test(trimmed);
}

function patternToRegex(pattern: string): RegExp {
  const trimmed = pattern.trim();
  if (trimmed.startsWith("/") && trimmed.endsWith("/") && trimmed.length > 1) {
    return new RegExp(trimmed.slice(1, -1), "i");
  }
  const source = isHostPattern(trimmed) ? globToHostRegex(trimmed) : globToUrlRegex(trimmed);
  return new RegExp(source, "i");
}

function extractHost(target: string): string {
  try {
    return new URL(target).hostname;
  } catch {
    return target.replace(/:\d+$/, "");
  }
}

/**
 * Check whether a host or URL is in scope.
 * Out-of-scope patterns take precedence over in-scope patterns.
 */
export function isInScope(target: string, scope?: Scope): ScopeCheckResult {
  if (!scope || (scope.in.length === 0 && scope.out.length === 0)) {
    return { inScope: true, reason: "No scope configured; target allowed by default" };
  }

  const normalizedTarget = target.trim().toLowerCase();
  const normalizedHost = extractHost(normalizedTarget).toLowerCase();

  for (const outPattern of scope.out) {
    const candidate = isHostPattern(outPattern) ? normalizedHost : normalizedTarget;
    if (patternToRegex(outPattern).test(candidate)) {
      return { inScope: false, reason: `OUT OF SCOPE: ${target} matches "${outPattern}"` };
    }
  }

  for (const inPattern of scope.in) {
    const candidate = isHostPattern(inPattern) ? normalizedHost : normalizedTarget;
    if (patternToRegex(inPattern).test(candidate)) {
      return { inScope: true, reason: `IN SCOPE: ${target} matches "${inPattern}"` };
    }
  }

  return { inScope: false, reason: `NOT IN SCOPE: ${target} does not match any in-scope pattern` };
}

interface BurpScopeEntry {
  enabled?: boolean;
  protocol?: string;
  host?: string;
  port?: string | number;
  file?: string;
}

function burpEntryToPattern(entry: string | BurpScopeEntry): string | null {
  if (typeof entry === "string") {
    return entry;
  }
  if (!entry || entry.enabled === false || !entry.host) {
    return null;
  }

  const protocol = entry.protocol && entry.protocol !== "any" ? `${entry.protocol}://` : "*://";
  const host = entry.host;
  const port = entry.port ? `:${entry.port}` : "";
  const file = entry.file ? entry.file : "/*";

  // Burp advanced scope uses regex hosts; if the host already looks like regex,
  // surface it as a regex literal so we do not double-escape it.
  const looksLikeRegex = host.includes("\\") || host.includes("^") || host.includes("$");
  if (looksLikeRegex) {
    return `/${host.replace(/^\^?/, "^").replace(/\$?$/, "$")}/`;
  }

  return `${protocol}${host}${port}${file}`;
}

/**
 * Parse a Burp Suite Project Configuration JSON (HackerOne export) into a Scope.
 * Supports both simple-mode URL strings and advanced-mode objects.
 */
export function parseBurpScope(json: unknown): Scope {
  const scope: Scope = { in: [], out: [] };

  const target = (json as Record<string, unknown>)?.target;
  const burpScope = target && typeof target === "object" ? (target as Record<string, unknown>).scope : undefined;
  if (!burpScope || typeof burpScope !== "object") {
    return scope;
  }

  const include = (burpScope as Record<string, unknown>).include;
  const exclude = (burpScope as Record<string, unknown>).exclude;

  if (Array.isArray(include)) {
    for (const entry of include) {
      const pattern = burpEntryToPattern(entry as string | BurpScopeEntry);
      if (pattern) scope.in.push(pattern);
    }
  }
  if (Array.isArray(exclude)) {
    for (const entry of exclude) {
      const pattern = burpEntryToPattern(entry as string | BurpScopeEntry);
      if (pattern) scope.out.push(pattern);
    }
  }

  return scope;
}

export interface TargetConfig {
  program_name?: string;
  platform?: string;
  scope_in?: string[];
  scope_out?: string[];
  burp_scope_file?: string;
  target?: string;
  [key: string]: unknown;
}

/**
 * Load scope from a BugHunter AI target config JSON.
 * If `burp_scope_file` is present, merge those entries as well.
 */
export async function loadScopeFromConfig(path: string): Promise<Scope> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new Error(`Target config not found: ${path}`);
  }

  const config: TargetConfig = await file.json();
  const scope: Scope = {
    in: config.scope_in ?? [],
    out: config.scope_out ?? [],
    source: path,
  };

  if (config.burp_scope_file) {
    const burpPath = config.burp_scope_file.startsWith("/")
      ? config.burp_scope_file
      : join(dirname(path), config.burp_scope_file);
    const burpFile = Bun.file(burpPath);
    if (await burpFile.exists()) {
      const burpScope = parseBurpScope(await burpFile.json());
      scope.in = [...new Set([...scope.in, ...burpScope.in])];
      scope.out = [...new Set([...scope.out, ...burpScope.out])];
      scope.source = `${path} + ${burpPath}`;
    }
  }

  return scope;
}

/** Format a scope as a short human-readable summary. */
export function scopeSummary(scope?: Scope): string {
  if (!scope) return "no scope";
  return `${scope.in.length} in / ${scope.out.length} out`;
}
