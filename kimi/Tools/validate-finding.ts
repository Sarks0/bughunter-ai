#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Finding validator: the framework's precision gate. Nothing may reach a
 * report unvalidated. Each finding is re-tested with a deterministic,
 * type-specific strategy and labeled:
 *
 *   validated            a deterministic check reproduced the issue
 *   refuted              the check ran cleanly and the issue did NOT reproduce
 *   inconclusive         the check could not decide (conservative default)
 *   skipped_out_of_scope a scope config was supplied and the finding's URL
 *                        failed isInScope — no validation requests were sent
 *
 * `confirmed` is set true ONLY for "validated". Any finding that did not pass
 * a deterministic check is downgraded to confirmed: false with a note.
 *
 * Validation strategies (dispatched on title/type/severity keywords):
 *   xss     — Playwright: load the URL; validated if the payload executes
 *             (dialog / window.__xss_confirmed) or appears unencoded in the
 *             DOM; refuted if not reflected at all; inconclusive otherwise.
 *   sqli    — re-request with the finding's payload vs a control request;
 *             validated only on a clear differential (SQL error in payload
 *             response only, or a large boolean/length differential).
 *   idor    — re-request with session auth context vs unauthenticated;
 *             validated when the unauthenticated request returns 200 with a
 *             near-identical body. Needs session auth state to run.
 *   oob     — SSRF/XXE/blind classes: evidence-based only. Validated when
 *             the finding's evidence documents a RECEIVED OOB callback
 *             (interactsh/collaborator-style); never validated without it.
 *   generic — re-request the URL once; validated when the finding's key
 *             evidence string is still present in the response, refuted when
 *             absent, inconclusive on request failure/ambiguity.
 *
 * Safety rules: max 2 requests per finding plus control, sequential
 * execution with a small delay between requests, per-request timeout,
 * redirects never followed off-origin (fetch: never followed at all),
 * optional --proxy (http://127.0.0.1:8080 routes through Burp), and every
 * strategy is wrapped so one bad finding cannot kill the run.
 *
 * This file is import-safe: argument parsing happens inside main(). Library
 * callers tune behavior via the exported `validatorConfig` object or by
 * building their own ValidationContext.
 */

import { parseArgs } from "util";
import { join } from "path";
import { getSessionDir, toSlug } from "./lib/paths.ts";
import { isInScope, loadScopeFromConfig, scopeSummary, type Scope } from "./lib/scope.ts";
import { normalizeFindings, type Finding } from "./lib/finding.ts";
import { loadFindings } from "./generate-report.ts";

export type ValidationStatus = "validated" | "refuted" | "inconclusive" | "skipped_out_of_scope";

/** A finding after validation: the original fields plus the verdict. */
export interface ValidatedFinding extends Finding {
  validation_status: ValidationStatus;
  validation_evidence: string;
  validated_at: string;
}

/** Strategy verdict. `skipped_out_of_scope` is applied before strategies run. */
export interface ValidationVerdict {
  status: Exclude<ValidationStatus, "skipped_out_of_scope">;
  evidence: string;
}

export type StrategyName = "xss" | "sqli" | "idor" | "oob" | "generic";

export interface ValidatorConfig {
  /** Per-request timeout in milliseconds. */
  timeoutMs: number;
  /** Skip browser-based strategies (XSS falls back to inconclusive). */
  noBrowser: boolean;
  /** HTTP proxy for all validation requests ("" = none; http://127.0.0.1:8080 = Burp). */
  proxy: string;
  /** Chromium sandbox is ON by default; set true to pass --no-sandbox (e.g. as root). */
  noSandbox: boolean;
  headless: boolean;
  /** Delay between requests/findings — no hammering. */
  requestDelayMs: number;
  /** Path to a target-config JSON; when set, request URLs are scope-checked. */
  scopeConfig?: string;
  scope?: Scope;
}

/** Mutable configuration; the CLI populates it in main(), library callers may set it directly. */
export const validatorConfig: ValidatorConfig = {
  timeoutMs: 15000,
  noBrowser: false,
  proxy: "",
  noSandbox: false,
  headless: true,
  requestDelayMs: 100,
};

/** Everything a strategy needs besides the finding. */
export interface ValidationContext {
  target: string;
  sessionSlug: string;
  /** Cookie header built from session auth state, when available. */
  cookieHeader?: string;
  /** Path to a Playwright storage-state.json, when available. */
  storageStatePath?: string;
  scope?: Scope;
  config: ValidatorConfig;
}

/** Minimal view of an HTTP response for the pure comparison functions. */
export interface HttpResponseView {
  status: number;
  body: string;
}

interface HttpResult extends HttpResponseView {
  ok: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Pure decision logic (unit-testable without browser or network)
// ---------------------------------------------------------------------------

/** Keyword → strategy, matched against title/type/subtype/severity (mirrors suggestVrtCategory). */
const STRATEGY_KEYWORDS: Array<[RegExp, StrategyName]> = [
  [/cross[- ]site scripting|\bxss\b/i, "xss"],
  [/\bsql\s*injection\b|\bsqli\b/i, "sqli"],
  [
    /\bidor\b|insecure direct object|broken (access control|object level)|\bbola\b|auth(?:entication|orization)?[- ]bypass|missing auth(?:entication|orization)|unauthenticated access|privilege escalation/i,
    "idor",
  ],
  [
    /\bssrf\b|server[- ]side request forgery|\bxxe\b|xml external entit|out[- ]of[- ]band|\boob\b|\boast\b|blind (ssrf|xss|sqli|rce)|\brce\b|remote code execution|command injection/i,
    "oob",
  ],
];

/** Pick the validation strategy for a finding from its title/type/subtype. */
export function classifyFinding(finding: Finding): StrategyName {
  const text = `${finding.title ?? ""} ${finding.type ?? ""} ${finding.subtype ?? ""} ${finding.severity ?? ""}`;
  for (const [pattern, strategy] of STRATEGY_KEYWORDS) {
    if (pattern.test(text)) return strategy;
  }
  return "generic";
}

/** Rough body similarity: 1.0 = identical, otherwise 1 - relative length difference. */
export function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - Math.abs(a.length - b.length) / maxLen;
}

/** Common server-side SQL error signatures. */
const SQL_ERROR_RE =
  /you have an error in your sql syntax|warning.*\bmysql_|mysqli?_|\bpg_query\(|\bpg_exec\(|postgresql.*error|ora-\d{4,5}|microsoft sql server|sqlserver|odbc.*driver|sqlite3?(::|\.)|unclosed quotation mark|unterminated string|invalid query|syntax error.*(near|at).*(select|from|where)|db2 sql error|syntax error in string in query expression/i;

/** True when a response body contains a recognizable SQL error message. */
export function containsSqlError(body: string): boolean {
  return SQL_ERROR_RE.test(body);
}

/** True for absolute http(s) URLs. */
export function isHttpUrl(value?: string): boolean {
  if (!value) return false;
  return /^https?:\/\//i.test(value);
}

function pocAsString(poc: Finding["poc"]): string | undefined {
  if (typeof poc === "string") return poc;
  if (poc && typeof poc === "object") return poc.prompt_used ?? poc.response_received;
  return undefined;
}

/** The URL a finding points at: url, then endpoint, then a URL-shaped poc. */
export function findingRequestUrl(finding: Finding): string | null {
  if (isHttpUrl(finding.url)) return finding.url!;
  if (isHttpUrl(finding.endpoint)) return finding.endpoint!;
  const poc = pocAsString(finding.poc);
  if (isHttpUrl(poc)) return poc!;
  return null;
}

/** First quoted/backtick-quoted token of a usable length in a text. */
function quotedToken(text: string): string | null {
  let best: string | null = null;
  for (const re of [/`([^`\n]{4,300})`/g, /"([^"\n]{4,300})"/g, /'([^'\n]{4,300})'/g]) {
    for (const match of text.matchAll(re)) {
      if (!best || match[1].length > best.length) best = match[1];
    }
  }
  return best;
}

/**
 * The payload string to re-fire for a finding: a non-URL poc, else the value
 * of the finding's parameter (or the last query value) in the poc/request URL.
 */
export function extractPayload(finding: Finding): string | null {
  const poc = pocAsString(finding.poc);
  if (poc && !isHttpUrl(poc)) return poc;
  const url = isHttpUrl(poc) ? poc! : findingRequestUrl(finding);
  if (url) {
    try {
      const params = new URL(url).searchParams;
      if (finding.parameter && params.has(finding.parameter)) {
        return params.get(finding.parameter);
      }
      let last: string | null = null;
      for (const value of params.values()) last = value;
      if (last) return last;
    } catch {
      // ignore invalid URLs
    }
  }
  return finding.evidence ? quotedToken(finding.evidence) : null;
}

/**
 * The key evidence string a generic re-request should still contain: a
 * non-URL poc, else the longest quoted token in the evidence.
 */
export function extractEvidenceMarker(finding: Finding): string | null {
  const poc = pocAsString(finding.poc);
  if (poc && !isHttpUrl(poc) && poc.length >= 4) return poc;
  if (finding.evidence) {
    const token = quotedToken(finding.evidence);
    if (token) return token;
  }
  return null;
}

/** Insert or replace `parameter` (or the first query param) with `payload`. */
export function injectPayloadIntoUrl(url: string, parameter: string | undefined, payload: string): string {
  const parsed = new URL(url);
  if (parameter && parsed.searchParams.has(parameter)) {
    parsed.searchParams.set(parameter, payload);
  } else if (parameter) {
    parsed.searchParams.append(parameter, payload);
  } else {
    const firstKey = parsed.searchParams.keys().next().value;
    if (firstKey !== undefined) parsed.searchParams.set(firstKey, payload);
    else parsed.searchParams.append("input", payload);
  }
  return parsed.toString();
}

/** Length differential beyond which two responses count as a boolean difference. */
export const SQLI_LENGTH_DIFFERENTIAL = 0.3;
/** Similarity above which an unauthenticated IDOR response counts as equivalent. */
export const IDOR_SIMILARITY_THRESHOLD = 0.9;

/**
 * SQLi verdict from a payload response vs a control response. Validated only
 * on a clear differential; a payload with no observable effect is refuted;
 * anything ambiguous is inconclusive.
 */
export function compareSqliResponses(payload: HttpResponseView, control: HttpResponseView): ValidationVerdict {
  const payloadError = containsSqlError(payload.body);
  const controlError = containsSqlError(control.body);

  if (payloadError && !controlError) {
    return {
      status: "validated",
      evidence: `SQL error pattern in payload response (HTTP ${payload.status}) but not in control (HTTP ${control.status})`,
    };
  }
  if (payloadError && controlError) {
    return {
      status: "inconclusive",
      evidence: "SQL error pattern present in both payload and control responses — endpoint may always error",
    };
  }

  const similarity = bodySimilarity(payload.body, control.body);
  if (similarity >= 0.98) {
    return {
      status: "refuted",
      evidence: `Payload produced no observable effect (bodies ~identical, ${payload.body.length} vs ${control.body.length} bytes)`,
    };
  }
  const differential = 1 - similarity;
  if (differential > SQLI_LENGTH_DIFFERENTIAL) {
    return {
      status: "validated",
      evidence: `Boolean differential: response lengths differ by ${Math.round(differential * 100)}% (${payload.body.length} vs ${control.body.length} bytes) between payload and control`,
    };
  }
  return {
    status: "inconclusive",
    evidence: `Minor response difference (${Math.round(differential * 100)}% length differential) — below the validation threshold`,
  };
}

/**
 * IDOR/auth-bypass verdict from an authenticated vs an unauthenticated
 * response. Validated when the unauthenticated request returns 200 with a
 * near-identical body; refuted when unauthenticated access is rejected.
 */
export function compareIdorResponses(authed: HttpResponseView, unauth: HttpResponseView): ValidationVerdict {
  if (authed.status !== 200) {
    return {
      status: "inconclusive",
      evidence: `Authenticated baseline request did not return 200 (HTTP ${authed.status}) — cannot compare`,
    };
  }
  if (unauth.status === 401 || unauth.status === 403) {
    return {
      status: "refuted",
      evidence: `Unauthenticated request rejected with HTTP ${unauth.status} — authorization check appears effective`,
    };
  }
  if (unauth.status >= 300 && unauth.status < 400) {
    return {
      status: "refuted",
      evidence: `Unauthenticated request redirected (HTTP ${unauth.status}) — likely bounced to login`,
    };
  }
  if (unauth.status === 200) {
    const similarity = bodySimilarity(authed.body, unauth.body);
    if (similarity >= IDOR_SIMILARITY_THRESHOLD) {
      return {
        status: "validated",
        evidence: `Unauthenticated request returned HTTP 200 with a body ${Math.round(similarity * 100)}% similar to the authenticated response (${authed.body.length} vs ${unauth.body.length} bytes)`,
      };
    }
    return {
      status: "inconclusive",
      evidence: `Unauthenticated request returned HTTP 200 but body is only ${Math.round(similarity * 100)}% similar — possible generic error page`,
    };
  }
  return {
    status: "inconclusive",
    evidence: `Unauthenticated request returned HTTP ${unauth.status} — cannot decide`,
  };
}

const OOB_TOKEN_RE =
  /interactsh|\boast\.(fun|live|site|pro|cloud)\b|burpcollaborator|collaborator\.net|\bdnslog\b|requestbin|webhook\.site|canarytokens|pipedream\.net|ngrok\.io/i;
const OOB_RECEIVED_RE =
  /(callback|interaction|dns (lookup|query|resolution)|http request|hit|connection).{0,60}(received|observed|recorded|logged|confirmed|captured)|(received|observed|recorded|logged|confirmed|captured).{0,60}(callback|interaction|dns (lookup|query|resolution)|http request|from (the )?(target|server))/i;

/**
 * SSRF/XXE/blind classes are only credible with an out-of-band callback.
 * Evidence-based only — no new requests are fired: validated when the
 * finding documents a RECEIVED interaction with an OOB token, otherwise
 * inconclusive. Never validated without callback evidence.
 */
export function oobEvidenceVerdict(finding: Finding): ValidationVerdict {
  const text = `${finding.evidence ?? ""}\n${pocAsString(finding.poc) ?? ""}\n${finding.description ?? ""}`;
  const hasToken = OOB_TOKEN_RE.test(text);
  const hasReceived = OOB_RECEIVED_RE.test(text);
  if (hasToken && hasReceived) {
    return {
      status: "validated",
      evidence: "Finding evidence documents a received out-of-band callback (interactsh/collaborator-style) — accepted as proof without firing new requests",
    };
  }
  if (hasToken) {
    return {
      status: "inconclusive",
      evidence: "OOB callback identifier present in evidence, but no received interaction is documented — cannot confirm without callback proof",
    };
  }
  return {
    status: "inconclusive",
    evidence: "No out-of-band callback evidence — blind-class findings are only credible with a documented received callback",
  };
}

// ---------------------------------------------------------------------------
// Network / browser strategies
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * GET with the validator's safety defaults: per-request timeout, redirects
 * never followed (so never off-origin), optional proxy, optional session
 * cookie header.
 */
async function httpGet(url: string, ctx: ValidationContext, options: { auth?: boolean } = {}): Promise<HttpResult> {
  try {
    const headers: Record<string, string> = { "user-agent": "BugHunterAI-Validator/1.0" };
    if (options.auth && ctx.cookieHeader) headers.cookie = ctx.cookieHeader;
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(ctx.config.timeoutMs),
      headers,
      ...(ctx.config.proxy ? { proxy: ctx.config.proxy } : {}),
    } as RequestInit);
    return { ok: true, status: response.status, body: await response.text() };
  } catch (err) {
    return { ok: false, status: 0, body: "", error: errorMessage(err) };
  }
}

/**
 * XSS: load the finding URL in Chromium and look for execution. Validated
 * when the payload executes (dialog fires or the payload sets
 * window.__xss_confirmed) or appears unencoded in the DOM after load;
 * refuted when the payload is not reflected at all; inconclusive otherwise.
 */
export async function validateXss(finding: Finding, ctx: ValidationContext): Promise<ValidationVerdict> {
  const url = findingRequestUrl(finding);
  if (!url) return { status: "inconclusive", evidence: "No URL to re-test" };
  if (ctx.config.noBrowser) {
    return {
      status: "inconclusive",
      evidence: "Browser strategies disabled (--no-browser); XSS execution cannot be verified without a DOM",
    };
  }

  const payload = extractPayload(finding);
  let browser;
  try {
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: ctx.config.headless,
      proxy: ctx.config.proxy ? { server: ctx.config.proxy } : undefined,
      args: ["--ignore-certificate-errors", ...(ctx.config.noSandbox ? ["--no-sandbox"] : [])],
    });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      ...(ctx.storageStatePath ? { storageState: ctx.storageStatePath } : {}),
    });
    await context.addInitScript(() => {
      (window as unknown as { __xss_confirmed?: boolean }).__xss_confirmed =
        (window as unknown as { __xss_confirmed?: boolean }).__xss_confirmed ?? false;
    });
    const page = await context.newPage();
    let dialogFired = false;
    page.on("dialog", (dialog) => {
      dialogFired = true;
      dialog.dismiss().catch(() => {});
    });

    const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: ctx.config.timeoutMs });
    if (!response) {
      return { status: "inconclusive", evidence: "Navigation produced no response" };
    }
    // Never follow redirects off-origin: bail if the page landed elsewhere.
    try {
      if (new URL(page.url()).origin !== new URL(url).origin) {
        return { status: "inconclusive", evidence: `Redirected off-origin to ${page.url()} — validation aborted` };
      }
    } catch {
      // ignore URL parse errors
    }
    await page.waitForTimeout(500);

    const markerSet = await page
      .evaluate(() => Boolean((window as unknown as { __xss_confirmed?: boolean }).__xss_confirmed))
      .catch(() => false);
    if (dialogFired || markerSet) {
      return {
        status: "validated",
        evidence: `Payload executed in the browser (${dialogFired ? "dialog fired" : "window.__xss_confirmed marker set"})`,
      };
    }

    const dom = await page.content();
    if (payload && dom.includes(payload)) {
      return {
        status: "validated",
        evidence: "Payload appears unencoded in the DOM after page load",
      };
    }
    if (payload) {
      return {
        status: "refuted",
        evidence: "Payload is not reflected in the response at all",
      };
    }
    return {
      status: "inconclusive",
      evidence: "No payload could be extracted from the finding — manual verification required",
    };
  } catch (err) {
    return { status: "inconclusive", evidence: `Browser validation failed: ${errorMessage(err)}` };
  } finally {
    await browser?.close().catch(() => {});
  }
}

/**
 * SQLi: fire the finding's payload at the endpoint and compare against a
 * control request. Two requests maximum.
 */
export async function validateSqli(finding: Finding, ctx: ValidationContext): Promise<ValidationVerdict> {
  const url = findingRequestUrl(finding);
  if (!url) return { status: "inconclusive", evidence: "No URL to re-test" };
  const payload = extractPayload(finding);
  if (!payload) {
    return { status: "inconclusive", evidence: "No payload could be extracted from poc/evidence — cannot build a differential test" };
  }

  let payloadUrl: string;
  try {
    payloadUrl = injectPayloadIntoUrl(url, finding.parameter, payload);
  } catch (err) {
    return { status: "inconclusive", evidence: `Could not inject payload into URL: ${errorMessage(err)}` };
  }

  const control = await httpGet(url, ctx, { auth: true });
  if (!control.ok) {
    return { status: "inconclusive", evidence: `Control request failed: ${control.error}` };
  }
  await sleep(ctx.config.requestDelayMs);
  const attacked = await httpGet(payloadUrl, ctx, { auth: true });
  if (!attacked.ok) {
    return { status: "inconclusive", evidence: `Payload request failed: ${attacked.error}` };
  }
  return compareSqliResponses(attacked, control);
}

/**
 * IDOR / auth bypass: compare the session-auth response against an
 * unauthenticated one. Requires session auth state to run.
 */
export async function validateIdor(finding: Finding, ctx: ValidationContext): Promise<ValidationVerdict> {
  const url = findingRequestUrl(finding);
  if (!url) return { status: "inconclusive", evidence: "No URL to re-test" };
  if (!ctx.cookieHeader) {
    return {
      status: "inconclusive",
      evidence: `No session auth state for "${ctx.sessionSlug}" — run auth-manager first; cannot compare authenticated vs unauthenticated access`,
    };
  }

  const authed = await httpGet(url, ctx, { auth: true });
  if (!authed.ok) {
    return { status: "inconclusive", evidence: `Authenticated request failed: ${authed.error}` };
  }
  await sleep(ctx.config.requestDelayMs);
  const unauth = await httpGet(url, ctx, { auth: false });
  if (!unauth.ok) {
    return { status: "inconclusive", evidence: `Unauthenticated request failed: ${unauth.error}` };
  }
  return compareIdorResponses(authed, unauth);
}

/**
 * SSRF/XXE/blind: evidence-based only. Never fires requests and never
 * validates without a documented received OOB callback.
 */
export function validateOob(finding: Finding, _ctx: ValidationContext): ValidationVerdict {
  return oobEvidenceVerdict(finding);
}

/**
 * Generic fallback: re-request the finding URL once (authenticated context
 * when available) and look for the finding's key evidence string.
 */
export async function validateGeneric(finding: Finding, ctx: ValidationContext): Promise<ValidationVerdict> {
  const url = findingRequestUrl(finding);
  if (!url) return { status: "inconclusive", evidence: "No URL to re-test" };
  const marker = extractEvidenceMarker(finding);
  if (!marker) {
    return {
      status: "inconclusive",
      evidence: "No machine-checkable evidence string in poc/evidence — manual verification required",
    };
  }

  const response = await httpGet(url, ctx, { auth: true });
  if (!response.ok) {
    return { status: "inconclusive", evidence: `Request failed: ${response.error}` };
  }
  if (response.body.includes(marker)) {
    return {
      status: "validated",
      evidence: `Key evidence string still present in response (HTTP ${response.status})`,
    };
  }
  return {
    status: "refuted",
    evidence: `Key evidence string absent from response (HTTP ${response.status}) — issue does not reproduce`,
  };
}

const STRATEGIES: Record<StrategyName, (finding: Finding, ctx: ValidationContext) => Promise<ValidationVerdict> | ValidationVerdict> = {
  xss: validateXss,
  sqli: validateSqli,
  idor: validateIdor,
  oob: validateOob,
  generic: validateGeneric,
};

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

const DOWNGRADE_NOTE =
  "[note: input was confirmed:true; downgraded — the finding did not pass a deterministic validation check]";

/** Apply a verdict to a finding, enforcing the confirmed-flag rules. */
export function applyVerdict(finding: Finding, status: ValidationStatus, evidence: string, validatedAt: string): ValidatedFinding {
  const out: ValidatedFinding = {
    ...finding,
    validation_status: status,
    validation_evidence: evidence,
    validated_at: validatedAt,
  };
  if (status === "validated") {
    out.confirmed = true;
  } else if (out.confirmed) {
    out.confirmed = false;
    out.validation_evidence = `${evidence} ${DOWNGRADE_NOTE}`;
  }
  return out;
}

/** Validate one finding: scope gate first, then dispatch to its strategy. */
export async function validateFinding(finding: Finding, ctx: ValidationContext): Promise<ValidatedFinding> {
  const validatedAt = new Date().toISOString();

  if (ctx.scope) {
    // Refuse to send validation requests to any out-of-scope URL.
    const urls = [finding.url, finding.endpoint, pocAsString(finding.poc)].filter(isHttpUrl) as string[];
    for (const url of urls) {
      const check = isInScope(url, ctx.scope);
      if (!check.inScope) {
        return applyVerdict(finding, "skipped_out_of_scope", `Skipped: no validation requests sent. ${check.reason}`, validatedAt);
      }
    }
  }

  const strategy = STRATEGIES[classifyFinding(finding)];
  const verdict = await strategy(finding, ctx);
  return applyVerdict(finding, verdict.status, verdict.evidence, validatedAt);
}

/** Validate findings sequentially with a small delay — no hammering. One bad finding never kills the run. */
export async function runValidation(findings: Finding[], ctx: ValidationContext): Promise<ValidatedFinding[]> {
  const results: ValidatedFinding[] = [];
  for (const finding of findings) {
    try {
      results.push(await validateFinding(finding, ctx));
    } catch (err) {
      results.push(
        applyVerdict(finding, "inconclusive", `Validation error: ${errorMessage(err)}`, new Date().toISOString())
      );
    }
    await sleep(ctx.config.requestDelayMs);
  }
  return results;
}

export interface ValidationSummary {
  total: number;
  validated: number;
  refuted: number;
  inconclusive: number;
  skipped: number;
}

export function buildSummary(findings: ValidatedFinding[]): ValidationSummary {
  return {
    total: findings.length,
    validated: findings.filter((f) => f.validation_status === "validated").length,
    refuted: findings.filter((f) => f.validation_status === "refuted").length,
    inconclusive: findings.filter((f) => f.validation_status === "inconclusive").length,
    skipped: findings.filter((f) => f.validation_status === "skipped_out_of_scope").length,
  };
}

export interface ValidationReport {
  target: string;
  generated_at: string;
  summary: ValidationSummary;
  findings: ValidatedFinding[];
}

// ---------------------------------------------------------------------------
// Session auth state
// ---------------------------------------------------------------------------

interface StoredCookie {
  name: string;
  value: string;
  domain?: string;
  expires?: number;
}

function cookieApplies(cookie: StoredCookie, host: string, nowSeconds: number): boolean {
  if (typeof cookie.expires === "number" && cookie.expires > 0 && cookie.expires < nowSeconds) return false;
  if (!cookie.domain) return true;
  const domain = cookie.domain.replace(/^\./, "").toLowerCase();
  const normalizedHost = host.toLowerCase();
  return normalizedHost === domain || normalizedHost.endsWith(`.${domain}`);
}

/**
 * Load session auth state written by auth-manager: storage-state.json
 * (Playwright format) preferred, auth-state.json as fallback. Returns a
 * Cookie header scoped to the target host plus the storage-state path for
 * browser strategies. Missing/invalid state yields empty results.
 */
export async function loadSessionAuth(
  sessionSlug: string,
  targetHost: string
): Promise<{ cookieHeader?: string; storageStatePath?: string }> {
  const sessionDir = getSessionDir(sessionSlug);
  const storageStatePath = join(sessionDir, "storage-state.json");
  const authStatePath = join(sessionDir, "auth-state.json");

  let cookies: StoredCookie[] = [];
  let usableStorageState: string | undefined;

  const storageFile = Bun.file(storageStatePath);
  if (await storageFile.exists()) {
    try {
      const parsed = JSON.parse(await storageFile.text()) as { cookies?: StoredCookie[] };
      if (Array.isArray(parsed.cookies)) {
        cookies = parsed.cookies;
        usableStorageState = storageStatePath;
      }
    } catch {
      // fall through to auth-state.json
    }
  }
  if (cookies.length === 0) {
    const authFile = Bun.file(authStatePath);
    if (await authFile.exists()) {
      try {
        const parsed = JSON.parse(await authFile.text()) as { cookies?: StoredCookie[] };
        if (Array.isArray(parsed.cookies)) cookies = parsed.cookies;
      } catch {
        // no usable auth state
      }
    }
  }

  const nowSeconds = Date.now() / 1000;
  const applicable = cookies.filter((c) => c.name && cookieApplies(c, targetHost, nowSeconds));
  return {
    cookieHeader: applicable.length > 0 ? applicable.map((c) => `${c.name}=${c.value}`).join("; ") : undefined,
    storageStatePath: usableStorageState,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage(): string {
  return `validate-finding — BugHunter AI Finding Validator (precision gate)

Usage:
  bun validate-finding.ts --findings <path|dir> --target <url>
      [--session <slug>] [--output <path>] [--scope-config <path>]
      [--timeout-ms <n>] [--no-browser] [--proxy <url>] [--no-sandbox]

  --findings      findings JSON file (bare array or {findings:[...]}) or a
                  directory of *-findings.json files (merged)
  --target        target URL; default session slug is derived from it
  --session       session slug for auth state (storage-state.json /
                  auth-state.json) and the default output location
  --output        default: $SESSION_DIR/findings/validated-findings.json
  --scope-config  target-config JSON; findings whose URLs fail isInScope are
                  skipped (validation_status: skipped_out_of_scope)
  --timeout-ms    per-request timeout (default 15000)
  --no-browser    skip browser strategies (XSS becomes inconclusive)
  --proxy         route requests through a proxy (http://127.0.0.1:8080 = Burp)
  --no-sandbox    pass --no-sandbox to Chromium (needed when running as root)`;
}

async function main(): Promise<void> {
  const { values: args } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      findings: { type: "string" },
      target: { type: "string" },
      session: { type: "string" },
      output: { type: "string" },
      "scope-config": { type: "string" },
      "timeout-ms": { type: "string", default: "15000" },
      "no-browser": { type: "boolean", default: false },
      proxy: { type: "string", default: "" },
      "no-sandbox": { type: "boolean", default: false },
    },
  });

  if (!args.findings || !args.target) {
    console.error(usage());
    process.exit(1);
  }

  validatorConfig.timeoutMs = Number(args["timeout-ms"]) || 15000;
  validatorConfig.noBrowser = args["no-browser"];
  validatorConfig.proxy = args.proxy;
  validatorConfig.noSandbox = args["no-sandbox"];
  validatorConfig.scopeConfig = args["scope-config"];

  if (validatorConfig.scopeConfig) {
    validatorConfig.scope = await loadScopeFromConfig(validatorConfig.scopeConfig);
    console.log(`[*] Scope enforcement active: ${scopeSummary(validatorConfig.scope)}`);
  } else {
    console.error("[*] WARNING: no --scope-config provided; validation requests are NOT scope-enforced");
  }

  let findings: Finding[];
  try {
    findings = normalizeFindings(await loadFindings(args.findings));
  } catch (err) {
    console.error(`[validate] ${errorMessage(err)}`);
    process.exit(1);
  }

  const sessionSlug = args.session ?? toSlug(args.target);
  let targetHost = "";
  try {
    targetHost = new URL(args.target).hostname;
  } catch {
    console.error(`[validate] WARNING: could not parse target URL "${args.target}"; session cookies will not be loaded`);
  }
  const sessionAuth = targetHost ? await loadSessionAuth(sessionSlug, targetHost) : {};

  const ctx: ValidationContext = {
    target: args.target,
    sessionSlug,
    cookieHeader: sessionAuth.cookieHeader,
    storageStatePath: sessionAuth.storageStatePath,
    scope: validatorConfig.scope,
    config: validatorConfig,
  };

  console.log(`[*] BugHunter Finding Validator`);
  console.log(`[*] Target: ${args.target} (session: ${sessionSlug})`);
  console.log(`[*] Findings: ${findings.length} | browser: ${validatorConfig.noBrowser ? "disabled" : "enabled"} | proxy: ${validatorConfig.proxy || "none"}`);
  if (sessionAuth.cookieHeader) console.log(`[*] Session auth state loaded (cookies for ${targetHost})`);

  const results = await runValidation(findings, ctx);
  const summary = buildSummary(results);

  const outputPath = args.output ?? join(getSessionDir(sessionSlug), "findings", "validated-findings.json");
  const report: ValidationReport = {
    target: args.target,
    generated_at: new Date().toISOString(),
    summary,
    findings: results,
  };
  await Bun.write(outputPath, JSON.stringify(report, null, 2));

  console.log(
    `[+] Done: ${summary.validated} validated, ${summary.refuted} refuted, ` +
      `${summary.inconclusive} inconclusive, ${summary.skipped} skipped (of ${summary.total}) → ${outputPath}`
  );
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[validate] Fatal: ${errorMessage(err)}`);
    process.exit(1);
  });
}
