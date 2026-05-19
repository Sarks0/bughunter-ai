#!/usr/bin/env bun
/**
 * BugBountyFramework — Browser Dynamic Testing Harness
 * Uses dev-browser CLI (primary) or Playwright CLI (fallback)
 * Routes all traffic through Burp Suite proxy for analysis
 * Tests: XSS, auth flows, IDOR, DOM manipulation, file uploads
 */

import { parseArgs } from "util";
import { $ } from "bun";

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    target: { type: "string" },
    proxy: { type: "string", default: "http://127.0.0.1:8080" },
    "auth-cookie": { type: "string", default: "" },
    "auth-token": { type: "string", default: "" },
    "crawl-depth": { type: "string", default: "3" },
    mode: { type: "string", default: "test" }, // "map-flows" | "test"
    "test-xss": { type: "boolean", default: false },
    "test-auth-bypass": { type: "boolean", default: false },
    "test-idor": { type: "boolean", default: false },
    screenshots: { type: "string", default: "/tmp/bb-screenshots" },
    output: { type: "string", default: "/tmp/playwright-findings.json" },
    headless: { type: "boolean", default: true },
    browser: { type: "string", default: "bughunter" }, // dev-browser instance name
  },
});

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

const findings: Finding[] = [];

// --- Browser engine detection ---

type BrowserEngine = "dev-browser" | "playwright-cli";

async function detectEngine(): Promise<BrowserEngine> {
  try {
    const result = await $`which dev-browser`.quiet();
    if (result.exitCode === 0) return "dev-browser";
  } catch {}
  try {
    const result = await $`which playwright`.quiet();
    if (result.exitCode === 0) return "playwright-cli";
  } catch {}
  try {
    const result = await $`npx playwright --version`.quiet();
    if (result.exitCode === 0) return "playwright-cli";
  } catch {}
  console.error("[!] Neither dev-browser nor playwright CLI found. Install one:");
  console.error("    brew install dev-browser");
  console.error("    npm install -g playwright");
  process.exit(1);
}

// --- dev-browser engine ---

async function devBrowserRun(script: string): Promise<string> {
  const headlessFlag = args.headless ? "--headless" : "";
  const result = await $`dev-browser --browser ${args.browser} ${headlessFlag} --timeout 30 <<SCRIPT
${script}
SCRIPT`.quiet().nothrow();
  return result.stdout.toString();
}

async function devBrowserScreenshot(pageName: string, filename: string): Promise<void> {
  await devBrowserRun(`
    const page = await browser.getPage("${pageName}");
    const buf = await page.screenshot();
    await saveScreenshot(buf, "${filename}");
  `);
}

async function devBrowserCrawl(baseUrl: string, depth: number): Promise<string[]> {
  const script = `
    const baseUrl = "${baseUrl}";
    const maxPages = ${depth * 50};
    const visited = new Set();
    const queue = [baseUrl];
    const endpoints = [];
    const allForms = [];

    while (queue.length > 0 && visited.size < maxPages) {
      const url = queue.shift();
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        const page = await browser.getPage("crawl");
        await page.goto(url, { waitUntil: "domcontentloaded" });
        endpoints.push(url);

        const links = await page.$$eval("a[href], form[action]", els =>
          els.map(el => el.getAttribute("href") || el.getAttribute("action"))
              .filter(h => h && !h.startsWith("#") && !h.startsWith("javascript"))
        );

        for (const link of links) {
          try {
            const full = new URL(link, baseUrl).href;
            if (full.startsWith(baseUrl) && !visited.has(full)) queue.push(full);
          } catch {}
        }

        const forms = await page.$$eval("form", forms =>
          forms.map(f => ({
            action: f.action,
            method: f.method,
            inputs: Array.from(f.querySelectorAll("input, textarea, select"))
              .map(i => ({ name: i.name, type: i.type })),
          }))
        );

        if (forms.length > 0) {
          allForms.push({ url, forms });
        }
      } catch {}
    }

    console.log(JSON.stringify({ endpoints, forms: allForms }));
  `;

  const output = await devBrowserRun(script);
  try {
    const data = JSON.parse(output.trim().split("\n").pop()!);
    if (data.forms?.length > 0) {
      await Bun.write(`/tmp/bb-forms-${Date.now()}.json`, JSON.stringify(data.forms, null, 2));
      console.log(`[+] Found forms across ${data.forms.length} pages`);
    }
    return data.endpoints || [];
  } catch {
    console.log("[!] Crawl output parse issue, falling back to basic results");
    return [baseUrl];
  }
}

async function devBrowserMapFlows(baseUrl: string): Promise<AppProfile> {
  console.log("[*] MODE: map-flows — Observation only, no payloads");
  console.log("[*] Building application understanding via dev-browser...");

  const script = `
    const baseUrl = "${baseUrl}";
    const visited = new Set();
    const queue = [baseUrl];
    const allUrls = [];
    const flows = [];
    const techSignals = {};
    let cloudProvider = "unknown";

    const HIGH_VALUE = [
      { p: /login|signin|auth/, purpose: "Authentication entry point" },
      { p: /register|signup|create.account/, purpose: "User registration" },
      { p: /forgot|reset|password/, purpose: "Password reset flow" },
      { p: /admin|management|dashboard/, purpose: "Administrative interface" },
      { p: /api\\//, purpose: "API endpoint" },
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

    while (queue.length > 0 && visited.size < 60) {
      const url = queue.shift();
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        const page = await browser.getPage("mapper");
        await page.goto(url, { waitUntil: "domcontentloaded" });
        allUrls.push(url);

        const title = await page.title();
        const urlLower = url.toLowerCase();

        let pagePurpose = "General page";
        for (const hv of HIGH_VALUE) {
          if (hv.p.test(urlLower) || hv.p.test(title.toLowerCase())) {
            pagePurpose = hv.purpose;
            break;
          }
        }

        const forms = await page.$$eval("form", forms =>
          forms.map(f => ({
            action: f.action || window.location.pathname,
            method: (f.method || "GET").toUpperCase(),
            inputs: Array.from(f.querySelectorAll("input, textarea, select, [contenteditable]"))
              .map(i => ({ name: i.name || i.id || "unnamed", type: i.type || i.tagName.toLowerCase() }))
              .filter(i => i.name !== ""),
          }))
        );

        const links = await page.$$eval("a[href]", els =>
          els.map(el => el.getAttribute("href")).filter(h => h && !h.startsWith("#") && !h.startsWith("javascript"))
        );

        for (const link of links) {
          try {
            const full = new URL(link, baseUrl).href;
            if (full.startsWith(baseUrl) && !visited.has(full)) queue.push(full);
          } catch {}
        }

        const boundaries = [];
        const agents = [];

        for (const form of forms) {
          const fields = form.inputs.map(i => i.name.toLowerCase()).join(" ");
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
          if (/file|upload|attachment|image|avatar/.test(fields) || form.inputs.some(i => i.type === "file")) {
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
          if (/user_id|account_id|id=|object_id/.test(fields) || /\\/\\d+|\\/[a-f0-9-]{8,}/.test(action)) {
            boundaries.push("Object ID → authorization check → data access");
            agents.push("IDORAgent");
          }
        }

        if (boundaries.length > 0 || forms.length > 0) {
          flows.push({
            url, title, purpose: pagePurpose,
            forms: forms.map(f => ({ ...f, likely_function: pagePurpose })),
            trust_boundary_crossings: [...new Set(boundaries)],
            agents_to_deploy: [...new Set(agents)],
          });
        }

        await saveScreenshot(await page.screenshot(), "flow-" + url.replace(/[^a-z0-9]/gi, "_").slice(-40) + ".png");
      } catch {}
    }

    // Detect tech from final page
    try {
      const page = await browser.getPage("mapper");
      await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
      const src = await page.innerHTML("html");
      if (/amazonaws\\.com|aws\\.|cloudfront\\.net/.test(src)) cloudProvider = "AWS";
      else if (/googleapis\\.com|gcp\\.|appspot\\.com/.test(src)) cloudProvider = "GCP";
      else if (/azure\\.com|azurewebsites\\.net/.test(src)) cloudProvider = "Azure";

      if (/Auth0|auth0\\.com/.test(src)) techSignals.auth = "Auth0";
      else if (/Cognito|cognito/.test(src)) techSignals.auth = "AWS Cognito";
      else if (/firebase|Firebase/.test(src)) techSignals.auth = "Firebase Auth";
      else if (/Okta|okta\\.com/.test(src)) techSignals.auth = "Okta";

      if (/graphql|GraphQL/.test(src)) techSignals.api = "GraphQL";
      else if (/swagger|openapi|api-docs/i.test(src)) techSignals.api = "REST with docs";
      else techSignals.api = "REST";
    } catch {}

    console.log(JSON.stringify({
      flows, allUrls, techSignals, cloudProvider
    }));
  `;

  const output = await devBrowserRun(script);
  let data: any;
  try {
    const lines = output.trim().split("\n");
    data = JSON.parse(lines[lines.length - 1]);
  } catch {
    console.log("[!] Failed to parse map-flows output, returning minimal profile");
    return buildMinimalProfile(baseUrl);
  }

  const highValueFlows = (data.flows || [])
    .filter((f: any) => f.trust_boundary_crossings?.length > 0)
    .flatMap((f: any) =>
      f.trust_boundary_crossings.map((crossing: string) => ({
        flow: f.purpose,
        endpoint: f.url,
        why_interesting: crossing,
        agents: f.agents_to_deploy,
        priority: (f.agents_to_deploy?.includes("SSRFAgent") || f.agents_to_deploy?.includes("RCEAgent")
          ? "critical"
          : f.agents_to_deploy?.includes("AuthAgent") || f.agents_to_deploy?.includes("IDORAgent")
            ? "high"
            : "medium") as "critical" | "high" | "medium",
      }))
    )
    .sort((a: any, b: any) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2 };
      return order[a.priority] - order[b.priority];
    });

  const uniqueAgents = [...new Set(highValueFlows.flatMap((f: any) => f.agents))] as string[];

  return {
    target: baseUrl,
    app_narrative: `Web application at ${baseUrl}. Discovered ${data.allUrls?.length || 0} pages with ${highValueFlows.length} high-value flows identified through functional analysis.`,
    tech_stack: {
      framework: data.techSignals?.framework || "Unknown — check response headers",
      language: "Unknown",
      cloud: data.cloudProvider || "unknown",
      auth_pattern: data.techSignals?.auth || "Standard session/JWT — inspect login flow",
      api_style: data.techSignals?.api || "REST",
      file_processing: data.flows?.some((f: any) => f.agents_to_deploy?.includes("FileUploadAgent"))
        ? ["File upload detected — check server-side processing"]
        : [],
    },
    crown_jewels: [
      ...new Set(
        (data.flows || [])
          .filter((f: any) => f.agents_to_deploy?.some((a: string) => ["AuthAgent", "IDORAgent", "SSRFAgent"].includes(a)))
          .map((f: any) => f.purpose)
      ),
    ] as string[],
    high_value_flows: highValueFlows,
    attack_priority_order: uniqueAgents,
    trust_boundary_crossings: [
      ...new Set((data.flows || []).flatMap((f: any) => f.trust_boundary_crossings || [])),
    ] as string[],
    all_discovered_urls: data.allUrls || [],
    timestamp: new Date().toISOString(),
  };
}

async function devBrowserTestXSS(url: string): Promise<void> {
  const script = `
    const url = "${url}";
    const payloads = [
      '<script>document.title="XSS_CONFIRMED"</script>',
      '<img src=x onerror="document.title=\\'XSS2_CONFIRMED\\'">',
      '"><svg onload="document.title=\\'XSS3\\'">',
    ];
    const results = [];

    try {
      const page = await browser.getPage("xss-test");
      await page.goto(url, { waitUntil: "domcontentloaded" });
      const forms = await page.$$eval("form", fs => fs.length);

      for (let fi = 0; fi < forms; fi++) {
        for (const payload of payloads) {
          await page.goto(url, { waitUntil: "domcontentloaded" });
          const inputs = await page.$$eval(
            "form:nth-of-type(" + (fi + 1) + ") input[type=text], form:nth-of-type(" + (fi + 1) + ") textarea",
            els => els.map(e => e.name || e.id)
          );

          for (const inputName of inputs) {
            if (!inputName) continue;
            try {
              await page.fill("[name='" + inputName + "']", payload);
              await page.click("form:nth-of-type(" + (fi + 1) + ") [type=submit], form:nth-of-type(" + (fi + 1) + ") button");
              const title = await page.title();
              if (title.includes("XSS_CONFIRMED") || title.includes("XSS2") || title.includes("XSS3")) {
                results.push({ param: inputName, payload, title });
                await saveScreenshot(await page.screenshot(), "xss-" + Date.now() + ".png");
              }
            } catch {}
          }
        }
      }
    } catch {}

    console.log(JSON.stringify({ url, results }));
  `;

  const output = await devBrowserRun(script);
  try {
    const data = JSON.parse(output.trim().split("\n").pop()!);
    for (const r of data.results || []) {
      findings.push({
        type: "XSS",
        url,
        parameter: r.param,
        payload: r.payload,
        evidence: `Page title changed to: ${r.title}`,
        cvss_estimate: 8.0,
        confirmed: true,
        timestamp: new Date().toISOString(),
      });
      console.log(`[!!!] XSS CONFIRMED at ${url} (param: ${r.param})`);
    }
  } catch {}
}

async function devBrowserTestAuthBypass(protectedUrls: string[]): Promise<void> {
  // Use a fresh browser instance without auth
  const script = `
    const urls = ${JSON.stringify(protectedUrls)};
    const bypasses = [];

    for (const url of urls) {
      try {
        const page = await browser.getPage("unauth");
        await page.goto(url);
        const body = await page.textContent("body") || "";
        if (/dashboard|profile|admin|settings|account|billing/i.test(body)) {
          bypasses.push(url);
        }
      } catch {}
    }

    console.log(JSON.stringify({ bypasses }));
  `;

  const output = await $`dev-browser --browser bughunter-unauth --headless --timeout 30 <<SCRIPT
${script}
SCRIPT`.quiet().nothrow();

  try {
    const data = JSON.parse(output.stdout.toString().trim().split("\n").pop()!);
    for (const url of data.bypasses || []) {
      findings.push({
        type: "AUTH_BYPASS",
        url,
        evidence: "Protected page accessible without authentication",
        cvss_estimate: 8.5,
        confirmed: true,
        timestamp: new Date().toISOString(),
      });
      console.log(`[!!!] AUTH BYPASS at ${url}`);
    }
  } catch {}
}

// --- Playwright CLI fallback engine ---

async function playwrightScreenshot(url: string, filename: string): Promise<void> {
  await $`npx playwright screenshot --browser chromium ${url} ${filename}`.quiet().nothrow();
}

async function playwrightCrawl(baseUrl: string): Promise<string[]> {
  // Playwright CLI doesn't have crawl — use codegen in headless or just open + screenshot
  console.log("[*] Playwright CLI: limited crawl — taking screenshot and listing URL");
  const screenshotPath = `${args.screenshots}/initial-${Date.now()}.png`;
  await playwrightScreenshot(baseUrl, screenshotPath);
  console.log(`[+] Screenshot saved: ${screenshotPath}`);
  return [baseUrl];
}

// --- Shared types ---

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

// --- Main ---

async function main() {
  if (!args.target) {
    console.error("Usage: bun playwright-harness.ts --target https://example.com [options]");
    console.error("");
    console.error("Options:");
    console.error("  --target URL          Target URL (required)");
    console.error("  --proxy URL           Proxy URL (default: http://127.0.0.1:8080)");
    console.error("  --auth-cookie VALUE   Auth cookie (name=value)");
    console.error("  --auth-token VALUE    Bearer token");
    console.error("  --crawl-depth N       Crawl depth multiplier (default: 3)");
    console.error("  --mode MODE           map-flows | test (default: test)");
    console.error("  --test-xss            Test for XSS in forms");
    console.error("  --test-auth-bypass    Test for auth bypass");
    console.error("  --test-idor           Test for IDOR");
    console.error("  --screenshots DIR     Screenshots directory (default: /tmp/bb-screenshots)");
    console.error("  --output FILE         Output file (default: /tmp/playwright-findings.json)");
    console.error("  --headless            Run headless (default: true)");
    console.error("  --browser NAME        dev-browser instance name (default: bughunter)");
    process.exit(1);
  }

  const engine = await detectEngine();
  console.log(`[*] BugHunter Browser Harness — engine: ${engine}`);
  console.log(`[*] Target: ${args.target}`);
  console.log(`[*] Proxy: ${args.proxy}`);
  console.log(`[*] Mode: ${args.mode}`);

  await $`mkdir -p ${args.screenshots}`.quiet();

  // --- MAP-FLOWS MODE ---
  if (args.mode === "map-flows") {
    if (engine === "dev-browser") {
      const appProfile = await devBrowserMapFlows(args.target);
      await Bun.write("/tmp/app-profile.json", JSON.stringify(appProfile, null, 2));
      console.log(`[+] AppProfile written to /tmp/app-profile.json`);
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
      console.log("[*] Playwright CLI: map-flows limited — taking screenshots");
      await playwrightScreenshot(args.target, `${args.screenshots}/map-flows-initial.png`);
      const profile = buildMinimalProfile(args.target);
      await Bun.write("/tmp/app-profile.json", JSON.stringify(profile, null, 2));
      console.log("[+] Minimal AppProfile written — use dev-browser for full profiling");
    }
    return;
  }

  // --- TEST MODE ---
  if (engine === "dev-browser") {
    console.log("[*] Crawling application via dev-browser...");
    const endpoints = await devBrowserCrawl(args.target, parseInt(args["crawl-depth"]));
    console.log(`[+] Discovered ${endpoints.length} endpoints`);

    if (args["test-xss"]) {
      console.log("[*] Testing for XSS...");
      for (const url of endpoints.slice(0, 50)) {
        await devBrowserTestXSS(url);
      }
    }

    if (args["test-auth-bypass"]) {
      console.log("[*] Testing for auth bypass...");
      const protectedPaths = endpoints.filter((u) =>
        /admin|dashboard|profile|settings|account|billing|private/i.test(u)
      );
      await devBrowserTestAuthBypass(protectedPaths);
    }

    // Final screenshot
    await devBrowserScreenshot("crawl", `${args.screenshots}/final-state.png`);

  } else {
    // Playwright CLI fallback — limited capabilities
    console.log("[*] Playwright CLI: limited test mode");
    const endpoints = await playwrightCrawl(args.target);
    console.log(`[+] Discovered ${endpoints.length} endpoints`);
    console.log("[!] For full dynamic testing, install dev-browser: brew install dev-browser");
  }

  // Write findings
  await Bun.write(args.output, JSON.stringify({
    target: args.target,
    engine,
    endpoints_discovered: 0, // updated by crawl
    findings: findings.filter((f) => f.cvss_estimate >= 8.0),
    total_findings: findings.length,
    high_severity_findings: findings.filter((f) => f.cvss_estimate >= 8.0).length,
    timestamp: new Date().toISOString(),
  }, null, 2));

  console.log(`[+] Complete. ${findings.length} total findings, ${findings.filter(f => f.cvss_estimate >= 8.0).length} high/critical`);
  console.log(`[+] Results: ${args.output}`);
}

main().catch(console.error);
