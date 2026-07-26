/**
 * BugHunter AI — Kimi port
 * Scope matching and platform scope import utilities.
 *
 * Scope patterns are globs by default:
 *   - `example.com`            matches the apex host only (example.com), NOT subdomains
 *   - `*.example.com`          matches example.com AND any subdomain (one or more labels)
 *   - `cdn*.example.com`       `*`/`?` inside a label match within that label only
 *                              (`*` -> `[^.]*`, `?` -> `[^.]`); wildcards never cross dots
 *   - `https://api.example.com/*` matches any path on that origin (anchored:
 *                              does NOT match `https://api.example.com.evil.com/x`)
 *   - `/.*\.example\.com$/`   regex literal (wrapped in /.../)
 *
 * Host matching is case-insensitive. Out-of-scope patterns take precedence
 * over in-scope patterns.
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
  // Escapes EVERY regex metacharacter, including `*` and `?`. Glob handling
  // below then rewrites the escaped forms `\*` / `\?` back into wildcards.
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Convert one hostname label to regex. `*` -> `[^.]*`, `?` -> `[^.]` (never crosses dots). */
function labelToRegex(label: string): string {
  if (label === "*") return "[^.]+"; // a full-label wildcard matches exactly one label
  return escapeRegex(label).replace(/\\\*/g, "[^.]*").replace(/\\\?/g, "[^.]");
}

/** Regex source (unanchored) for a hostname glob. See header for semantics. */
function hostGlobSource(host: string): string {
  const labels = host.trim().toLowerCase().split(".");
  if (labels[0] === "*") {
    // Leading `*.` matches the bare domain AND any depth of subdomains.
    const rest = labels.slice(1);
    if (rest.length === 0) return ".+"; // pattern is just "*"
    return `(?:[^.]+\\.)*${rest.map(labelToRegex).join("\\.")}`;
  }
  // No leading wildcard: match the host exactly, label for label.
  return labels.map(labelToRegex).join("\\.");
}

function globToHostRegex(pattern: string): string {
  return `^${hostGlobSource(pattern)}$`;
}

/** Convert the non-host parts of a URL glob (scheme, path). `**` -> `.*`, `*` -> `[^?#]*`, `?` -> `[^?#]`. */
function urlGlobSource(text: string): string {
  return escapeRegex(text)
    .replace(/\\\*\\\*/g, ".*")
    .replace(/\\\*/g, "[^?#]*")
    .replace(/\\\?/g, "[^?#]");
}

function globToUrlRegex(pattern: string): string {
  const trimmed = pattern.trim();
  // Split into scheme, host, and the remainder (port/path/query). The host
  // gets strict host-glob semantics and a boundary lookahead, so
  // `https://api.example.com/*` can never match `https://api.example.com.evil.com/x`.
  const match = trimmed.match(/^([^/]*):\/\/([^/?#:]*)(.*)$/);
  if (!match) {
    // No recognizable scheme://host structure; fall back to a plain glob.
    return `^${urlGlobSource(trimmed)}`;
  }
  const [, scheme, host, rest] = match;
  return `^${urlGlobSource(scheme)}:\\/\\/${hostGlobSource(host)}(?=[/?#:]|$)${urlGlobSource(rest)}`;
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

/** Error thrown by {@link assertInScope} when a URL falls outside the scope. */
export class ScopeError extends Error {
  readonly target: string;
  readonly reason: string;

  constructor(target: string, reason: string) {
    super(`Scope violation for "${target}": ${reason}`);
    this.name = "ScopeError";
    this.target = target;
    this.reason = reason;
  }
}

/**
 * Central scope gate: throws a ScopeError when `url` is not in scope.
 * Returns normally when the URL is in scope (or no scope is configured).
 */
export function assertInScope(url: string, scope: Scope): void {
  const result = isInScope(url, scope);
  if (!result.inScope) {
    throw new ScopeError(url, result.reason);
  }
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
