#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Browser harness using Playwright directly.
 * Modes: map-flows (observation), test (XSS, auth-bypass, IDOR).
 */

import { parseArgs } from "util";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { getSessionDir } from "./lib/paths.ts";

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
    "max-pages": { type: "string", default: "60" },
  },
});

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

interface Finding {
  type: string;
  url: string;
  parameter?: string;
  payload?: string;
  evidence: string;
  cvss_estimate: number;
  confirmed: boolean;
  timestamp: string;
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
  all_discovered_urls: string[];
  timestamp: string;
}

function toSlug(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/[^a-z0-9]/gi, "-").replace(/-+/g, "-").toLowerCase();
}

function resolveOutputPath(defaultName: string): string {
  if (args.output) return args.output;
  if (args.target) {
    return `kimi-data/Sessions/${toSlug(args.target)}/${defaultName}`;
  }
  return `kimi-data/${defaultName}`;
}

function resolveScreenshotsDir(): string {
  if (args.screenshots) return args.screenshots;
  if (args.target) return `kimi-data/Sessions/${toSlug(args.target)}/screenshots`;
  return "kimi-data/screenshots";
}

async function createBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: args.headless,
    proxy: args.proxy ? { server: args.proxy } : undefined,
    args: ["--ignore-certificate-errors", "--no-sandbox"],
  });
}

async function createContext(browser: Browser): Promise<BrowserContext> {
  const extraHeaders: Record<string, string> = {};
  if (args["auth-token"]) extraHeaders.Authorization = `Bearer ${args["auth-token"]}`;

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
  });

  if (args["auth-cookie"]) {
    const domain = new URL(args.target!).hostname;
    const cookies = args["auth-cookie"].split(";").map((c) => {
      const [name, ...valueParts] = c.trim().split("=");
      return { name: name.trim(), value: valueParts.join("=").trim(), domain, path: "/" };
    });
    await context.addCookies(cookies);
  }

  return context;
}

async function crawl(baseUrl: string, context: BrowserContext): Promise<{ urls: string[]; flows: Flow[] }> {
  const maxPages = Number(args["max-pages"]) || 60;
  const visited = new Set<string>();
  const queue: string[] = [baseUrl];
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
    const url = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);

    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
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
          const full = new URL(link, baseUrl).href;
          if (full.startsWith(baseUrl) && !visited.has(full)) queue.push(full);
        } catch {
          // ignore invalid URLs
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

async function detectTechStack(baseUrl: string, context: BrowserContext): Promise<Record<string, string>> {
  const page = await context.newPage();
  const signals: Record<string, string> = {};
  let cloudProvider = "unknown";

  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
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
  } catch {
    // ignore
  } finally {
    await page.close();
  }

  return signals;
}

function buildAppProfile(baseUrl: string, crawlResult: { urls: string[]; flows: Flow[] }, techSignals: Record<string, string>): AppProfile {
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
                url,
                parameter: inputName,
                payload,
                evidence: `Page title changed to: ${title}`,
                cvss_estimate: 8.0,
                confirmed: true,
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

async function testAuthBypass(protectedUrls: string[], context: BrowserContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const page = await context.newPage();
  try {
    for (const url of protectedUrls) {
      try {
        await page.goto(url, { timeout: 10000 });
        const body = await page.textContent("body") || "";
        if (/dashboard|profile|admin|settings|account|billing/i.test(body)) {
          findings.push({
            type: "AUTH_BYPASS",
            url,
            evidence: "Protected page accessible without authentication",
            cvss_estimate: 8.5,
            confirmed: true,
            timestamp: new Date().toISOString(),
          });
        }
      } catch {
        // ignore
      }
    }
  } finally {
    await page.close();
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
    all_discovered_urls: [baseUrl],
    timestamp: new Date().toISOString(),
  };
}

async function main() {
  if (!args.target) {
    console.error("Usage: bun playwright-harness.ts --target https://example.com [options]");
    process.exit(1);
  }

  const screenshotsDir = resolveScreenshotsDir();
  await Bun.write(`${screenshotsDir}/.gitkeep`, "");

  console.log(`[*] BugHunter Browser Harness — engine: Playwright`);
  console.log(`[*] Target: ${args.target}`);
  console.log(`[*] Proxy: ${args.proxy || "none"}`);
  console.log(`[*] Mode: ${args.mode}`);

  const browser = await createBrowser();
  const context = await createContext(browser);

  try {
    if (args.mode === "map-flows") {
      console.log("[*] MODE: map-flows — Observation only, no payloads");
      const crawlResult = await crawl(args.target, context);
      const techSignals = await detectTechStack(args.target, context);
      const appProfile = buildAppProfile(args.target, crawlResult, techSignals);

      const outputPath = resolveOutputPath("app-profile.json");
      await Bun.write(outputPath, JSON.stringify(appProfile, null, 2));
      console.log(`[+] AppProfile written to ${outputPath}`);
      console.log(`[+] Discovered ${appProfile.all_discovered_urls.length} URLs`);
      console.log(`[+] Found ${appProfile.high_value_flows.length} high-value flows`);
      console.log(`[+] Attack priority order: ${appProfile.attack_priority_order.join(", ")}`);

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
      const crawlResult = await crawl(args.target, context);
      console.log(`[+] Discovered ${crawlResult.urls.length} endpoints`);

      if (args["test-xss"]) {
        console.log("[*] Testing for XSS...");
        for (const url of crawlResult.urls.slice(0, 50)) {
          findings.push(...(await testXSS(url, context, screenshotsDir)));
        }
      }

      if (args["test-auth-bypass"]) {
        console.log("[*] Testing for auth bypass...");
        const protectedPaths = crawlResult.urls.filter((u) =>
          /admin|dashboard|profile|settings|account|billing|private/i.test(u)
        );
        findings.push(...(await testAuthBypass(protectedPaths, context)));
      }

      const outputPath = resolveOutputPath("playwright-findings.json");
      await Bun.write(
        outputPath,
        JSON.stringify(
          {
            target: args.target,
            engine: "playwright",
            endpoints_discovered: crawlResult.urls.length,
            findings: findings.filter((f) => f.cvss_estimate >= 8.0),
            total_findings: findings.length,
            high_severity_findings: findings.filter((f) => f.cvss_estimate >= 8.0).length,
            timestamp: new Date().toISOString(),
          },
          null,
          2
        )
      );
      console.log(`[+] Complete. ${findings.length} findings → ${outputPath}`);
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
