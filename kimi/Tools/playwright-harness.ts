#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Browser harness using Playwright directly.
 * Modes: map-flows (observation), test (XSS, auth-bypass, IDOR).
 *
 * This file is import-safe: argument parsing happens inside main(), so
 * importing it as a library never touches process argv. Library callers can
 * tune behavior via the exported `harnessConfig` object.
 */

import { parseArgs } from "util";
import { chromium, type Browser, type BrowserContext } from "playwright";
import { DATA_DIR, getSessionDir, toSlug } from "./lib/paths.ts";
import { assertInScope, isInScope, loadScopeFromConfig, scopeSummary, type Scope } from "./lib/scope.ts";
import { parseExtraHeaders } from "./lib/headers.ts";
import type { Finding } from "./lib/finding.ts";

export { parseExtraHeaders };

export interface HarnessConfig {
  target?: string;
  proxy: string;
  authCookie: string;
  authToken: string;
  crawlDepth: number;
  mode: string;
  testXss: boolean;
  testAuthBypass: boolean;
  testIdor: boolean;
  screenshots: string;
  output: string;
  headless: boolean;
  maxPages: number;
  /** Chromium sandbox is ON by default; --no-sandbox opts out (needed as root). */
  noSandbox: boolean;
  /** Extra HTTP headers (--header "Name: value") applied to every browser context. */
  extraHeaders: Record<string, string>;
  /** Path to a target-config JSON; when set, crawl/scan URLs are scope-checked. */
  scopeConfig?: string;
  scope?: Scope;
}

/** Mutable configuration; the CLI populates it in main(), library callers may set it directly. */
export const harnessConfig: HarnessConfig = {
  proxy: "http://127.0.0.1:8080",
  authCookie: "",
  authToken: "",
  crawlDepth: 3,
  mode: "test",
  testXss: false,
  testAuthBypass: false,
  testIdor: false,
  screenshots: "",
  output: "",
  headless: true,
  maxPages: 60,
  noSandbox: false,
  extraHeaders: {},
};

interface FormField {
  name: string;
  type: string;
}

interface FormInfo {
  action: string;
  method: string;
  inputs: FormField[];
}

interface Flow {
  url: string;
  title: string;
  purpose: string;
  forms: FormInfo[];
  trust_boundary_crossings: string[];
  agents_to_deploy: string[];
}

interface AppProfile {
  target: string;
  app_narrative: string;
  tech_stack: {
    framework: string;
    language: string;
    cloud: string;
    auth_pattern: string;
    api_style: string;
    file_processing: string[];
  };
  crown_jewels: string[];
  high_value_flows: Array<{
    flow: string;
    endpoint: string;
    why_interesting: string;
    agents: string[];
    priority: "critical" | "high" | "medium";
  }>;
  attack_priority_order: string[];
  trust_boundary_crossings: string[];
  /** AI/LLM features detected in page source (LLM endpoints, chat widgets, SDKs). */
  ai_llm_features: string[];
  all_discovered_urls: string[];
  timestamp: string;
}

function resolveOutputPath(defaultName: string): string {
  if (harnessConfig.output) return harnessConfig.output;
  if (harnessConfig.target) {
    return `${getSessionDir(toSlug(harnessConfig.target))}/${defaultName}`;
  }
  return `${DATA_DIR}/${defaultName}`;
}

function resolveScreenshotsDir(): string {
  if (harnessConfig.screenshots) return harnessConfig.screenshots;
  if (harnessConfig.target) return `${getSessionDir(toSlug(harnessConfig.target))}/screenshots`;
  return `${DATA_DIR}/screenshots`;
}

/** True when `url` parses and shares an origin with `baseUrl` (scheme + host + port). */
export function isSameOrigin(url: string, baseUrl: string): boolean {
  try {
    return new URL(url).origin === new URL(baseUrl).origin;
  } catch {
    return false;
  }
}

/**
 * True when a navigation landed somewhere it shouldn't: outside the
 * configured scope, or (with no scope configured) off the target origin.
 * Checked after every page.goto() — cross-origin redirects (e.g. to an
 * SSO provider) must never be crawled or tested.
 */
export function isOffScopeNavigation(finalUrl: string, baseUrl: string, scope?: Scope): boolean {
  if (!finalUrl || finalUrl === "about:blank") return false;
  if (scope) return !isInScope(finalUrl, scope).inScope;
  return !isSameOrigin(finalUrl, baseUrl);
}

/** True when a URL may be crawled: same origin, and in scope when a scope is configured. */
function isCrawlable(url: string, baseUrl: string): boolean {
  if (!isSameOrigin(url, baseUrl)) return false;
  if (harnessConfig.scope && !isInScope(url, harnessConfig.scope).inScope) return false;
  return true;
}

async function createBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: harnessConfig.headless,
    proxy: harnessConfig.proxy ? { server: harnessConfig.proxy } : undefined,
    args: ["--ignore-certificate-errors", ...(harnessConfig.noSandbox ? ["--no-sandbox"] : [])],
  });
}

async function createContext(browser: Browser): Promise<BrowserContext> {
  const extraHeaders: Record<string, string> = { ...harnessConfig.extraHeaders };
  if (harnessConfig.authToken) extraHeaders.Authorization = `Bearer ${harnessConfig.authToken}`;

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
  });

  if (harnessConfig.authCookie) {
    const domain = new URL(harnessConfig.target!).hostname;
    const cookies = harnessConfig.authCookie.split(";").map((c) => {
      const [name, ...valueParts] = c.trim().split("=");
      return { name: name.trim(), value: valueParts.join("=").trim(), domain, path: "/" };
    });
    await context.addCookies(cookies);
  }

  return context;
}

async function crawl(baseUrl: string, context: BrowserContext): Promise<{ urls: string[]; flows: Flow[] }> {
  const maxPages = harnessConfig.maxPages;
  const maxDepth = harnessConfig.crawlDepth;
  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: baseUrl, depth: 0 }];
  const urls: string[] = [];
  const flows: Flow[] = [];

  const highValuePatterns = [
    { p: /login|signin|auth/, purpose: "Authentication entry point" },
    { p: /register|signup|create.account/, purpose: "User registration" },
    { p: /forgot|reset|password/, purpose: "Password reset flow" },
    { p: /admin|management|dashboard/, purpose: "Administrative interface" },
    { p: /api\//, purpose: "API endpoint" },
    { p: /upload|attach|import/, purpose: "File upload / import" },
    { p: /export|download|report/, purpose: "Data export" },
    { p: /webhook|callback|notify/, purpose: "Webhook / callback URL handler" },
    { p: /payment|checkout|billing|subscribe/, purpose: "Payment processing" },
    { p: /profile|account|settings/, purpose: "User data management" },
    { p: /search|query|filter/, purpose: "Search / query endpoint" },
    { p: /oauth|sso|saml/, purpose: "OAuth / SSO flow" },
    { p: /graphql/, purpose: "GraphQL endpoint" },
    { p: /preview|render|template|pdf/, purpose: "Server-side rendering" },
    { p: /share|invite|refer/, purpose: "Social / referral flow" },
  ];

  while (queue.length > 0 && visited.size < maxPages) {
    const { url, depth } = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);

    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });

      // Block cross-origin redirects (e.g. to an SSO provider): never crawl
      // or analyze a page that landed outside scope / off the target origin.
      const finalUrl = page.url();
      if (isOffScopeNavigation(finalUrl, baseUrl, harnessConfig.scope)) {
        console.error(`[!] Skipping off-scope redirect: ${url} -> ${finalUrl}`);
        continue;
      }
      urls.push(url);

      const title = await page.title().catch(() => "");
      const urlLower = url.toLowerCase();
      let purpose = "General page";
      for (const hv of highValuePatterns) {
        if (hv.p.test(urlLower) || hv.p.test(title.toLowerCase())) {
          purpose = hv.purpose;
          break;
        }
      }

      const forms = await page.$$eval("form", (forms) =>
        forms.map((f) => ({
          action: f.action || window.location.pathname,
          method: (f.method || "GET").toUpperCase(),
          inputs: Array.from(f.querySelectorAll("input, textarea, select, [contenteditable]"))
            .map((i) => ({ name: (i as HTMLInputElement).name || (i as HTMLElement).id || "unnamed", type: (i as HTMLInputElement).type || i.tagName.toLowerCase() }))
            .filter((i) => i.name !== "unnamed"),
        }))
      );

      // Only follow links while below the configured crawl depth.
      if (depth < maxDepth) {
        const links = await page.$$eval("a[href]", (els) =>
          els
            .map((el) => el.getAttribute("href"))
            .filter((h): h is string => {
              if (!h) return false;
              return !h.startsWith("#") && !h.startsWith("javascript");
            })
        );

        for (const link of links) {
          try {
            // Resolve against the page's actual (post-redirect) URL, not the
            // configured target, so links are attributed to the real origin.
            const full = new URL(link, finalUrl).href;
            if (isCrawlable(full, baseUrl) && !visited.has(full)) queue.push({ url: full, depth: depth + 1 });
          } catch {
            // ignore invalid URLs
          }
        }
      }

      const boundaries: string[] = [];
      const agents: string[] = [];
      for (const form of forms) {
        const fields = form.inputs.map((i) => i.name.toLowerCase()).join(" ");
        const action = (form.action || url).toLowerCase();

        if (/password|passwd|pass/.test(fields) && /login|signin|auth/.test(action)) {
          boundaries.push("User credential → database authentication query");
          agents.push("AuthAgent", "SQLiAgent");
        }
        if (/url|link|href|src|redirect|callback|webhook|endpoint/.test(fields)) {
          boundaries.push("User-controlled URL → server-side HTTP fetch (SSRF risk)");
          agents.push("SSRFAgent");
        }
        if (/search|query|q=|keyword|term/.test(fields) || /search|find/.test(action)) {
          boundaries.push("User input → database query / HTML reflection");
          agents.push("SQLiAgent", "XSSAgent");
        }
        if (/message|body|content|comment|description|text/.test(fields)) {
          boundaries.push("User content → HTML rendering context");
          agents.push("XSSAgent");
        }
        if (/file|upload|attachment|image|avatar/.test(fields) || form.inputs.some((i) => i.type === "file")) {
          boundaries.push("File upload → server filesystem / image processing");
          agents.push("FileUploadAgent", "XXEAgent");
        }
        if (/template|render|report|pdf|export/.test(action)) {
          boundaries.push("User content → server-side template rendering (SSTI risk)");
          agents.push("RCEAgent", "SSRFAgent");
        }
        if (/price|amount|quantity|balance|transfer/.test(fields)) {
          boundaries.push("Numeric input → financial calculation");
          agents.push("BusinessLogicAgent");
        }
        if (/user_id|account_id|id=|object_id/.test(fields) || /\/\d+|\/[a-f0-9-]{8,}/.test(action)) {
          boundaries.push("Object ID → authorization check → data access");
          agents.push("IDORAgent");
        }
      }

      if (boundaries.length > 0 || forms.length > 0) {
        flows.push({
          url,
          title,
          purpose,
          forms: forms.map((f) => ({ ...f, likely_function: purpose })),
          trust_boundary_crossings: [...new Set(boundaries)],
          agents_to_deploy: [...new Set(agents)],
        });
      }
    } catch {
      // ignore page errors
    } finally {
      await page.close();
    }
  }

  return { urls, flows };
}

/** Known AI/LLM signatures looked for in page HTML/JS. */
const AI_SIGNATURES: Array<[RegExp, string]> = [
  [/openai|chatgpt|gpt-[34]/i, "OpenAI integration"],
  [/anthropic|claude\.ai|\bclaude\b/i, "Anthropic Claude integration"],
  [/\/v1\/chat\/completions/i, "LLM chat-completions endpoint"],
  [/langchain/i, "LangChain framework"],
  [/copilot/i, "Copilot widget"],
  [/hugging\s*face|huggingface/i, "Hugging Face integration"],
  [/gemini|makersuite|generativelanguage/i, "Google Gemini integration"],
  [/cohere/i, "Cohere integration"],
  [/intercom|drift|zendesk.*chat|chat-widget|chatbot/i, "Embedded chat widget (possible LLM backend)"],
];

/** Detect AI/LLM features in raw HTML/JS source. Returns human-readable labels. */
export function detectAiFeatures(source: string): string[] {
  const found: string[] = [];
  for (const [pattern, label] of AI_SIGNATURES) {
    if (pattern.test(source)) found.push(label);
  }
  return found;
}

async function detectTechStack(
  baseUrl: string,
  context: BrowserContext
): Promise<{ signals: Record<string, string>; aiFeatures: string[] }> {
  const page = await context.newPage();
  const signals: Record<string, string> = {};
  let aiFeatures: string[] = [];
  let cloudProvider = "unknown";

  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    const finalUrl = page.url();
    if (isOffScopeNavigation(finalUrl, baseUrl, harnessConfig.scope)) {
      console.error(`[!] Tech detection skipped: ${baseUrl} redirected off-scope -> ${finalUrl}`);
      signals.redirect = `off-scope: ${new URL(finalUrl).origin}`;
      return { signals, aiFeatures };
    }
    const src = await page.innerHTML("html");

    if (/amazonaws\.com|aws\.|cloudfront\.net/.test(src)) cloudProvider = "AWS";
    else if (/googleapis\.com|gcp\.|appspot\.com/.test(src)) cloudProvider = "GCP";
    else if (/azure\.com|azurewebsites\.net/.test(src)) cloudProvider = "Azure";

    if (/Auth0|auth0\.com/.test(src)) signals.auth = "Auth0";
    else if (/Cognito|cognito/.test(src)) signals.auth = "AWS Cognito";
    else if (/firebase|Firebase/.test(src)) signals.auth = "Firebase Auth";
    else if (/Okta|okta\.com/.test(src)) signals.auth = "Okta";

    if (/graphql|GraphQL/.test(src)) signals.api = "GraphQL";
    else if (/swagger|openapi|api-docs/i.test(src)) signals.api = "REST with docs";
    else signals.api = "REST";

    signals.cloud = cloudProvider;
    aiFeatures = detectAiFeatures(src);
  } catch {
    // ignore
  } finally {
    await page.close();
  }

  return { signals, aiFeatures };
}

function buildAppProfile(
  baseUrl: string,
  crawlResult: { urls: string[]; flows: Flow[] },
  techSignals: Record<string, string>,
  aiFeatures: string[]
): AppProfile {
  const highValueFlows = crawlResult.flows
    .filter((f) => f.trust_boundary_crossings.length > 0)
    .flatMap((f) =>
      f.trust_boundary_crossings.map((crossing) => ({
        flow: f.purpose,
        endpoint: f.url,
        why_interesting: crossing,
        agents: f.agents_to_deploy,
        priority: (f.agents_to_deploy.includes("SSRFAgent") || f.agents_to_deploy.includes("RCEAgent")
          ? "critical"
          : f.agents_to_deploy.includes("AuthAgent") || f.agents_to_deploy.includes("IDORAgent")
            ? "high"
            : "medium") as "critical" | "high" | "medium",
      }))
    )
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2 };
      return order[a.priority] - order[b.priority];
    });

  const uniqueAgents = [...new Set(highValueFlows.flatMap((f) => f.agents))];

  return {
    target: baseUrl,
    app_narrative: `Web application at ${baseUrl}. Discovered ${crawlResult.urls.length} pages with ${highValueFlows.length} high-value flows identified through functional analysis.`,
    tech_stack: {
      framework: techSignals.framework || "Unknown — check response headers",
      language: techSignals.language || "Unknown",
      cloud: techSignals.cloud || "unknown",
      auth_pattern: techSignals.auth || "Standard session/JWT — inspect login flow",
      api_style: techSignals.api || "REST",
      file_processing: crawlResult.flows.some((f) => f.agents_to_deploy.includes("FileUploadAgent"))
        ? ["File upload detected — check server-side processing"]
        : [],
    },
    crown_jewels: [
      ...new Set(
        crawlResult.flows
          .filter((f) => f.agents_to_deploy.some((a) => ["AuthAgent", "IDORAgent", "SSRFAgent"].includes(a)))
          .map((f) => f.purpose)
      ),
    ],
    high_value_flows: highValueFlows,
    attack_priority_order: uniqueAgents,
    trust_boundary_crossings: [...new Set(crawlResult.flows.flatMap((f) => f.trust_boundary_crossings))],
    ai_llm_features: aiFeatures,
    all_discovered_urls: crawlResult.urls,
    timestamp: new Date().toISOString(),
  };
}

async function testXSS(url: string, context: BrowserContext, screenshotsDir: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const payloads = [
    '<script>document.title="XSS_CONFIRMED"</script>',
    '<img src=x onerror="document.title=\'XSS2_CONFIRMED\'">',
    '"><svg onload="document.title=\'XSS3\'">',
  ];

  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    const finalUrl = page.url();
    if (isOffScopeNavigation(finalUrl, url, harnessConfig.scope)) {
      console.error(`[!] XSS test skipped: ${url} redirected off-scope -> ${finalUrl}`);
      return findings;
    }
    const forms = await page.$$eval("form", (fs) => fs.length);

    for (let fi = 0; fi < forms; fi++) {
      for (const payload of payloads) {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
        const inputs = await page.$$eval(
          `form:nth-of-type(${fi + 1}) input[type=text], form:nth-of-type(${fi + 1}) textarea`,
          (els) => els.map((e) => (e as HTMLInputElement).name || (e as HTMLElement).id).filter(Boolean)
        );

        for (const inputName of inputs) {
          try {
            await page.fill(`[name="${inputName}"]`, payload);
            await page.click(`form:nth-of-type(${fi + 1}) [type=submit], form:nth-of-type(${fi + 1}) button`);
            await page.waitForTimeout(1000);
            const title = await page.title();
            if (title.includes("XSS_CONFIRMED") || title.includes("XSS2") || title.includes("XSS3")) {
              const screenshotPath = `${screenshotsDir}/xss-${Date.now()}.png`;
              await page.screenshot({ path: screenshotPath });
              findings.push({
                type: "XSS",
                title: `Reflected XSS in parameter "${inputName}"`,
                severity: "high",
                cvss: 8.0,
                confirmed: true,
                url,
                parameter: inputName,
                poc: payload,
                evidence: `Page title changed to: ${title}`,
                description: `Payload reflected and executed in parameter "${inputName}" on ${url}.`,
                timestamp: new Date().toISOString(),
              });
            }
          } catch {
            // ignore field errors
          }
        }
      }
    }
  } catch {
    // ignore page errors
  } finally {
    await page.close();
  }

  return findings;
}

const PROTECTED_KEYWORDS = /dashboard|profile|admin|settings|account|billing/i;
const AUTH_ONLY_MARKERS = /logout|log out|sign out|my account|welcome back/i;

async function testAuthBypass(protectedUrls: string[], context: BrowserContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const page = await context.newPage();
  try {
    for (const url of protectedUrls) {
      try {
        const response = await page.goto(url, { timeout: 10000, waitUntil: "domcontentloaded" });
        const status = response?.status() ?? 0;
        const finalUrl = page.url();
        if (isOffScopeNavigation(finalUrl, url, harnessConfig.scope)) {
          console.error(`[!] Auth-bypass test skipped: ${url} redirected off-scope -> ${finalUrl}`);
          continue;
        }
        const body = (await page.textContent("body")) || "";
        if (!PROTECTED_KEYWORDS.test(body)) continue;

        // A keyword match alone is a lead, not a finding: login pages and error
        // pages routinely contain words like "account". Higher confidence
        // requires a 200, no login form, no redirect to a login page, and
        // authenticated-only markers (logout links etc.) in the body.
        const hasLoginForm = (await page.$('input[type="password"]')) !== null;
        const redirectedToLogin = /login|signin/i.test(finalUrl) && !/login|signin/i.test(url);
        const hasAuthMarkers = AUTH_ONLY_MARKERS.test(body);
        const strongSignal = status === 200 && !hasLoginForm && !redirectedToLogin && hasAuthMarkers;

        findings.push({
          type: "AUTH_BYPASS",
          title: strongSignal
            ? "Protected page appears accessible without authentication"
            : "Possible unauthenticated access to protected page (unverified lead)",
          severity: strongSignal ? "high" : "medium",
          cvss: strongSignal ? 7.5 : 5.0,
          confirmed: false,
          url,
          evidence: strongSignal
            ? `HTTP ${status}, no login form, no login redirect, authenticated-only markers present`
            : `Keyword match on protected path (HTTP ${status}${hasLoginForm ? ", login form present" : ""}${redirectedToLogin ? ", redirected to login" : ""}) — manual verification required`,
          description: `Protected-looking page ${url} returned protected keywords without authentication.${
            strongSignal ? " Strong signal: page rendered authenticated content." : " Weak signal: keyword match only."
          }`,
          timestamp: new Date().toISOString(),
        });
      } catch {
        // ignore
      }
    }
  } finally {
    await page.close();
  }
  return findings;
}

/** Rough body similarity: 1.0 = identical, otherwise based on relative length difference. */
function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - Math.abs(a.length - b.length) / maxLen;
}

/**
 * Minimal IDOR / missing-authorization check: re-request each parameterized
 * endpoint with the authenticated context and a fresh unauthenticated context,
 * and flag endpoints that return 200 with a near-identical body to both.
 */
async function testIdor(urls: string[], authContext: BrowserContext, browser: Browser): Promise<Finding[]> {
  const findings: Finding[] = [];
  const parameterized = urls.filter((u) => /[?&][^=]+=[^&]+/.test(u) || /\/\d+(?:\/|$)/.test(u));
  if (parameterized.length === 0) return findings;

  // The unauthenticated context still carries --header extras (e.g. a
  // deployment-protection bypass) so its requests reach the real app.
  const unauthContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: Object.keys(harnessConfig.extraHeaders).length > 0 ? { ...harnessConfig.extraHeaders } : undefined,
  });
  try {
    for (const url of parameterized.slice(0, 30)) {
      try {
        const [authResp, unauthResp] = await Promise.all([
          authContext.request.get(url, { timeout: 10000 }),
          unauthContext.request.get(url, { timeout: 10000 }),
        ]);
        if (authResp.status() !== 200 || unauthResp.status() !== 200) continue;

        const authBody = await authResp.text();
        const unauthBody = await unauthResp.text();
        const similarity = bodySimilarity(authBody, unauthBody);
        if (similarity >= 0.9) {
          findings.push({
            type: "IDOR",
            title: "Parameterized endpoint accessible without authentication",
            severity: "medium",
            cvss: 5.3,
            confirmed: false,
            url,
            evidence: `Unauthenticated request returned HTTP 200 with a body ${Math.round(similarity * 100)}% similar to the authenticated response (${authBody.length} vs ${unauthBody.length} bytes)`,
            description: `${url} returned equivalent content to an unauthenticated client. Possible missing authorization check — verify object-level access control manually with a second account.`,
            timestamp: new Date().toISOString(),
          });
        }
      } catch {
        // ignore request errors
      }
    }
  } finally {
    await unauthContext.close();
  }
  return findings;
}

function buildMinimalProfile(baseUrl: string): AppProfile {
  return {
    target: baseUrl,
    app_narrative: `Web application at ${baseUrl}. Minimal profile — manual investigation recommended.`,
    tech_stack: {
      framework: "Unknown",
      language: "Unknown",
      cloud: "unknown",
      auth_pattern: "Unknown",
      api_style: "REST",
      file_processing: [],
    },
    crown_jewels: [],
    high_value_flows: [],
    attack_priority_order: [],
    trust_boundary_crossings: [],
    ai_llm_features: [],
    all_discovered_urls: [baseUrl],
    timestamp: new Date().toISOString(),
  };
}

async function main() {
  const { values: args } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      target: { type: "string" },
      proxy: { type: "string", default: "http://127.0.0.1:8080" },
      "auth-cookie": { type: "string", default: "" },
      "auth-token": { type: "string", default: "" },
      "crawl-depth": { type: "string", default: "3" },
      mode: { type: "string", default: "test" },
      "test-xss": { type: "boolean", default: false },
      "test-auth-bypass": { type: "boolean", default: false },
      "test-idor": { type: "boolean", default: false },
      screenshots: { type: "string", default: "" },
      output: { type: "string", default: "" },
      headless: { type: "boolean", default: true },
      // Show the browser window (overrides --headless).
      headful: { type: "boolean", default: false },
      "max-pages": { type: "string", default: "60" },
      // Chromium sandbox is on by default; --no-sandbox opts out (e.g. as root).
      "no-sandbox": { type: "boolean", default: false },
      // Optional target-config JSON; when set, the target is asserted in scope
      // and crawled links outside scope are skipped.
      "scope-config": { type: "string" },
      // Repeatable extra header applied to every browser context, e.g.
      // --header "x-vercel-protection-bypass: <secret>". Values may contain
      // colons; the split happens on the first one.
      header: { type: "string", multiple: true },
    },
  });

  harnessConfig.target = args.target;
  harnessConfig.proxy = args.proxy;
  harnessConfig.authCookie = args["auth-cookie"];
  harnessConfig.authToken = args["auth-token"];
  harnessConfig.crawlDepth = Number(args["crawl-depth"]) || 3;
  harnessConfig.mode = args.mode;
  harnessConfig.testXss = args["test-xss"];
  harnessConfig.testAuthBypass = args["test-auth-bypass"];
  harnessConfig.testIdor = args["test-idor"];
  harnessConfig.screenshots = args.screenshots;
  harnessConfig.output = args.output;
  harnessConfig.headless = args.headful ? false : args.headless;
  harnessConfig.maxPages = Number(args["max-pages"]) || 60;
  harnessConfig.noSandbox = args["no-sandbox"];
  harnessConfig.scopeConfig = args["scope-config"];
  try {
    harnessConfig.extraHeaders = parseExtraHeaders(args.header ?? []);
  } catch (err) {
    console.error(`[*] Fatal: ${(err as Error).message}`);
    process.exit(1);
  }
  if (Object.keys(harnessConfig.extraHeaders).length > 0) {
    console.log(`[*] Extra headers: ${Object.keys(harnessConfig.extraHeaders).join(", ")} (values redacted)`);
  }

  if (!harnessConfig.target) {
    console.error("Usage: bun playwright-harness.ts --target https://example.com [options]");
    process.exit(1);
  }

  if (harnessConfig.scopeConfig) {
    harnessConfig.scope = await loadScopeFromConfig(harnessConfig.scopeConfig);
    assertInScope(harnessConfig.target, harnessConfig.scope); // throws ScopeError on violation
    console.log(`[*] Scope enforcement active: ${scopeSummary(harnessConfig.scope)}`);
  } else {
    console.error("[*] WARNING: no --scope-config provided; crawling without scope enforcement");
  }

  const screenshotsDir = resolveScreenshotsDir();
  await Bun.write(`${screenshotsDir}/.gitkeep`, "");

  console.log(`[*] BugHunter Browser Harness — engine: Playwright`);
  console.log(`[*] Target: ${harnessConfig.target}`);
  console.log(`[*] Proxy: ${harnessConfig.proxy || "none"}`);
  console.log(`[*] Mode: ${harnessConfig.mode}`);

  const browser = await createBrowser();
  const context = await createContext(browser);

  try {
    if (harnessConfig.mode === "map-flows") {
      console.log("[*] MODE: map-flows — Observation only, no payloads");
      const crawlResult = await crawl(harnessConfig.target, context);
      const { signals: techSignals, aiFeatures } = await detectTechStack(harnessConfig.target, context);
      const appProfile = buildAppProfile(harnessConfig.target, crawlResult, techSignals, aiFeatures);

      const outputPath = resolveOutputPath("app-profile.json");
      await Bun.write(outputPath, JSON.stringify(appProfile, null, 2));
      console.log(`[+] AppProfile written to ${outputPath}`);
      console.log(`[+] Discovered ${appProfile.all_discovered_urls.length} URLs`);
      console.log(`[+] Found ${appProfile.high_value_flows.length} high-value flows`);
      console.log(`[+] Attack priority order: ${appProfile.attack_priority_order.join(", ")}`);
      if (appProfile.ai_llm_features.length > 0) {
        console.log(`[+] AI/LLM features detected: ${appProfile.ai_llm_features.join(", ")}`);
      }

      console.log("\n[*] TOP PRIORITY FLOWS:");
      appProfile.high_value_flows
        .filter((f) => f.priority === "critical")
        .slice(0, 5)
        .forEach((f) => {
          console.log(`  [CRITICAL] ${f.flow} @ ${f.endpoint}`);
          console.log(`             Why: ${f.why_interesting}`);
          console.log(`             Agents: ${f.agents.join(", ")}`);
        });
    } else {
      const findings: Finding[] = [];
      console.log("[*] Crawling application...");
      const crawlResult = await crawl(harnessConfig.target, context);
      console.log(`[+] Discovered ${crawlResult.urls.length} endpoints`);

      if (harnessConfig.testXss) {
        console.log("[*] Testing for XSS...");
        for (const url of crawlResult.urls.slice(0, 50)) {
          findings.push(...(await testXSS(url, context, screenshotsDir)));
        }
      }

      if (harnessConfig.testAuthBypass) {
        console.log("[*] Testing for auth bypass...");
        const protectedPaths = crawlResult.urls.filter((u) =>
          /admin|dashboard|profile|settings|account|billing|private/i.test(u)
        );
        findings.push(...(await testAuthBypass(protectedPaths, context)));
      }

      if (harnessConfig.testIdor) {
        console.log("[*] Testing for IDOR / missing authorization...");
        findings.push(...(await testIdor(crawlResult.urls, context, browser)));
      }

      const criticalFindings = findings.filter((f) => f.cvss >= 8.0 || f.severity === "critical");
      const outputPath = resolveOutputPath("playwright-findings.json");
      await Bun.write(
        outputPath,
        JSON.stringify(
          {
            target: harnessConfig.target,
            engine: "playwright",
            generated_at: new Date().toISOString(),
            endpoints_discovered: crawlResult.urls.length,
            total_findings: findings.length,
            findings,
            critical_findings: criticalFindings,
            timestamp: new Date().toISOString(),
          },
          null,
          2
        )
      );
      console.log(`[+] Complete. ${findings.length} findings (${criticalFindings.length} critical) → ${outputPath}`);
    }
  } finally {
    await browser.close();
  }
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[*] Fatal: ${err.message}`);
    process.exit(1);
  });
}
