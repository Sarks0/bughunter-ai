#!/usr/bin/env bun
/**
 * BugBountyFramework — Playwright Dynamic Testing Harness
 * Routes all traffic through Burp Suite proxy for analysis
 * Tests: XSS, auth flows, IDOR, DOM manipulation, file uploads
 */

import { chromium, type Browser, type Page } from "playwright";
import { parseArgs } from "util";

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

async function setupBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: args.headless,
    proxy: { server: args.proxy },
    args: [
      "--ignore-certificate-errors",
      "--ignore-ssl-errors",
      "--disable-web-security",
      "--no-sandbox",
    ],
  });
}

async function injectAuth(page: Page): Promise<void> {
  if (args["auth-cookie"]) {
    const cookieParts = args["auth-cookie"].split("=");
    await page.context().addCookies([{
      name: cookieParts[0],
      value: cookieParts.slice(1).join("="),
      domain: new URL(args.target!).hostname,
      path: "/",
    }]);
  }
  if (args["auth-token"]) {
    await page.setExtraHTTPHeaders({
      "Authorization": `Bearer ${args["auth-token"]}`,
    });
  }
}

async function crawlApplication(page: Page, baseUrl: string, depth: number): Promise<string[]> {
  const visitedUrls = new Set<string>();
  const urlsToVisit = [baseUrl];
  const discoveredEndpoints: string[] = [];

  while (urlsToVisit.length > 0 && visitedUrls.size < depth * 50) {
    const url = urlsToVisit.shift()!;
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    try {
      await page.goto(url, { waitUntil: "networkidle", timeout: 10000 });
      discoveredEndpoints.push(url);

      // Extract all links on page
      const links = await page.evaluate(() =>
        Array.from(document.querySelectorAll("a[href], form[action]"))
          .map((el) => el.getAttribute("href") || el.getAttribute("action"))
          .filter((href) => href && !href.startsWith("#") && !href.startsWith("javascript"))
      );

      for (const link of links) {
        if (!link) continue;
        const fullUrl = new URL(link, baseUrl).href;
        if (fullUrl.startsWith(baseUrl) && !visitedUrls.has(fullUrl)) {
          urlsToVisit.push(fullUrl);
        }
      }

      // Find all form inputs (potential injection points)
      const forms = await page.evaluate(() =>
        Array.from(document.querySelectorAll("form")).map((form) => ({
          action: form.action,
          method: form.method,
          inputs: Array.from(form.querySelectorAll("input, textarea, select"))
            .map((i) => ({ name: (i as HTMLInputElement).name, type: (i as HTMLInputElement).type })),
        }))
      );

      if (forms.length > 0) {
        console.log(`[+] Found ${forms.length} forms at ${url}`);
        await Bun.write(
          `/tmp/bb-forms-${Date.now()}.json`,
          JSON.stringify({ url, forms }, null, 2)
        );
      }
    } catch (e) {
      // Skip failed navigations
    }
  }

  return discoveredEndpoints;
}

async function testXSSInForms(page: Page, url: string): Promise<void> {
  const XSS_PAYLOADS = [
    '<script>document.title="XSS_CONFIRMED_'+url.replace(/[^a-z0-9]/gi,"_")+'"</script>',
    '<img src=x onerror="document.title=\'XSS2_CONFIRMED\'">',
    '"><svg onload="document.title=\'XSS3\'">',
    "javascript:document.title='XSS4'",
  ];

  try {
    await page.goto(url, { waitUntil: "networkidle", timeout: 10000 });
    const forms = await page.$$("form");

    for (const form of forms) {
      const inputs = await form.$$("input[type=text], input[type=search], textarea");
      for (const input of inputs) {
        for (const payload of XSS_PAYLOADS) {
          await input.fill(payload);
          await form.evaluate((f: HTMLFormElement) => f.submit());
          await page.waitForTimeout(500);

          const title = await page.title();
          if (title.includes("XSS_CONFIRMED") || title.includes("XSS2") || title.includes("XSS3")) {
            const finding: Finding = {
              type: "XSS",
              url,
              parameter: await input.getAttribute("name") || "unknown",
              payload,
              evidence: `Page title changed to: ${title}`,
              cvss_estimate: 8.0,
              confirmed: true,
              timestamp: new Date().toISOString(),
            };
            findings.push(finding);
            console.log(`[!!!] XSS CONFIRMED at ${url}`);
            await page.screenshot({ path: `${args.screenshots}/xss-${Date.now()}.png` });
          }
        }
      }
    }
  } catch (e) {
    // Continue
  }
}

async function testAuthBypass(page: Page, protectedUrls: string[]): Promise<void> {
  // Test if protected pages are accessible without auth
  const unauthContext = await (await setupBrowser()).newContext();
  const unauthPage = await unauthContext.newPage();

  for (const url of protectedUrls) {
    try {
      const response = await unauthPage.goto(url, { timeout: 5000 });
      if (response?.status() === 200) {
        const bodyText = await unauthPage.textContent("body") || "";
        // Check if page shows sensitive content without auth
        const hasSensitiveContent = /dashboard|profile|admin|settings|account|billing/i.test(bodyText);
        if (hasSensitiveContent) {
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
      }
    } catch (e) {
      // Continue
    }
  }
  await unauthContext.close();
}

interface AppFlow {
  url: string;
  title: string;
  purpose: string; // inferred from page content
  forms: Array<{
    action: string;
    method: string;
    inputs: Array<{ name: string; type: string }>;
    likely_function: string;
  }>;
  api_calls: Array<{ url: string; method: string; content_type?: string }>;
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
  all_discovered_urls: string[];
  timestamp: string;
}

async function mapApplicationFlows(page: Page, baseUrl: string): Promise<AppProfile> {
  console.log("[*] MODE: map-flows — Observation only, no payloads");
  console.log("[*] Building application understanding before any testing...");

  const flows: AppFlow[] = [];
  const networkRequests: Array<{ url: string; method: string; contentType?: string }> = [];

  // Intercept network requests to understand API patterns
  page.on("request", (request) => {
    const url = request.url();
    const method = request.method();
    if (!url.match(/\.(js|css|png|jpg|gif|ico|woff|ttf|svg)(\?|$)/)) {
      networkRequests.push({
        url,
        method,
        contentType: request.headers()["content-type"],
      });
    }
  });

  // Crawl and profile each page
  const visitedUrls = new Set<string>();
  const urlsToVisit = [baseUrl];
  const allDiscoveredUrls: string[] = [];

  const HIGH_VALUE_PATTERNS = [
    { pattern: /login|signin|auth/, purpose: "Authentication entry point" },
    { pattern: /register|signup|create.account/, purpose: "User registration" },
    { pattern: /forgot|reset|password/, purpose: "Password reset flow" },
    { pattern: /admin|management|dashboard/, purpose: "Administrative interface" },
    { pattern: /api\//, purpose: "API endpoint" },
    { pattern: /upload|attach|import/, purpose: "File upload / import" },
    { pattern: /export|download|report/, purpose: "Data export" },
    { pattern: /webhook|callback|notify/, purpose: "Webhook / callback URL handler" },
    { pattern: /payment|checkout|billing|subscribe/, purpose: "Payment processing" },
    { pattern: /profile|account|settings/, purpose: "User data management" },
    { pattern: /search|query|filter/, purpose: "Search / query endpoint" },
    { pattern: /oauth|sso|saml/, purpose: "OAuth / SSO flow" },
    { pattern: /graphql/, purpose: "GraphQL endpoint" },
    { pattern: /preview|render|template|pdf/, purpose: "Server-side rendering" },
    { pattern: /share|invite|refer/, purpose: "Social / referral flow" },
  ];

  const TECH_SIGNALS: Record<string, string> = {};

  while (urlsToVisit.length > 0 && visitedUrls.size < 60) {
    const url = urlsToVisit.shift()!;
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    try {
      const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 8000 });
      allDiscoveredUrls.push(url);

      // Detect technology from headers
      const headers = response?.headers() || {};
      if (headers["x-powered-by"]) TECH_SIGNALS["server_tech"] = headers["x-powered-by"];
      if (headers["server"]) TECH_SIGNALS["web_server"] = headers["server"];
      if (headers["set-cookie"]) {
        const cookie = headers["set-cookie"];
        if (/laravel_session/i.test(cookie)) TECH_SIGNALS["framework"] = "Laravel/PHP";
        else if (/django/i.test(cookie) || /csrftoken/i.test(cookie)) TECH_SIGNALS["framework"] = "Django/Python";
        else if (/rails/i.test(cookie)) TECH_SIGNALS["framework"] = "Rails/Ruby";
        else if (/jsessionid/i.test(cookie)) TECH_SIGNALS["framework"] = "Java/Spring";
        else if (/express/i.test(cookie)) TECH_SIGNALS["framework"] = "Express/Node.js";
      }

      const title = await page.title();

      // Extract forms with context
      const forms = await page.evaluate(() =>
        Array.from(document.querySelectorAll("form")).map((form) => ({
          action: form.action || window.location.pathname,
          method: form.method?.toUpperCase() || "GET",
          inputs: Array.from(form.querySelectorAll("input, textarea, select, [contenteditable]"))
            .map((i) => ({
              name: (i as HTMLInputElement).name || (i as HTMLInputElement).id || "unnamed",
              type: (i as HTMLInputElement).type || i.tagName.toLowerCase(),
            }))
            .filter((i) => i.name !== ""),
        }))
      );

      // Extract links for continued crawl
      const links = await page.evaluate(() =>
        Array.from(document.querySelectorAll("a[href]"))
          .map((el) => el.getAttribute("href"))
          .filter((href) => href && !href.startsWith("#") && !href.startsWith("javascript"))
      );

      for (const link of links) {
        if (!link) continue;
        try {
          const fullUrl = new URL(link, baseUrl).href;
          if (fullUrl.startsWith(baseUrl) && !visitedUrls.has(fullUrl)) {
            urlsToVisit.push(fullUrl);
          }
        } catch { /* skip invalid URLs */ }
      }

      // Determine page purpose and agents to deploy
      const urlLower = url.toLowerCase();
      const pageTrustBoundaries: string[] = [];
      const agentsToDeploy: string[] = [];
      let pagePurpose = "General page";

      for (const { pattern, purpose } of HIGH_VALUE_PATTERNS) {
        if (pattern.test(urlLower) || pattern.test(title.toLowerCase())) {
          pagePurpose = purpose;
          break;
        }
      }

      // Infer trust boundary crossings and agent assignments from forms and URL
      for (const form of forms) {
        const fieldNames = form.inputs.map((i) => i.name.toLowerCase()).join(" ");
        const formAction = (form.action || url).toLowerCase();

        if (/password|passwd|pass/.test(fieldNames) && /login|signin|auth/.test(formAction)) {
          pageTrustBoundaries.push("User credential → database authentication query");
          agentsToDeploy.push("AuthAgent", "SQLiAgent");
        }
        if (/url|link|href|src|redirect|callback|webhook|endpoint/.test(fieldNames)) {
          pageTrustBoundaries.push("User-controlled URL → server-side HTTP fetch (SSRF risk)");
          agentsToDeploy.push("SSRFAgent");
        }
        if (/search|query|q=|keyword|term/.test(fieldNames) || /search|find/.test(formAction)) {
          pageTrustBoundaries.push("User input → database query / HTML reflection");
          agentsToDeploy.push("SQLiAgent", "XSSAgent");
        }
        if (/message|body|content|comment|description|text/.test(fieldNames)) {
          pageTrustBoundaries.push("User content → HTML rendering context");
          agentsToDeploy.push("XSSAgent");
        }
        if (/file|upload|attachment|image|avatar/.test(fieldNames) || form.inputs.some((i) => i.type === "file")) {
          pageTrustBoundaries.push("File upload → server filesystem / image processing");
          agentsToDeploy.push("FileUploadAgent", "XXEAgent");
        }
        if (/template|render|report|pdf|export/.test(formAction)) {
          pageTrustBoundaries.push("User content → server-side template rendering (SSTI risk)");
          agentsToDeploy.push("RCEAgent", "SSRFAgent");
        }
        if (/price|amount|quantity|balance|transfer/.test(fieldNames)) {
          pageTrustBoundaries.push("Numeric input → financial calculation");
          agentsToDeploy.push("BusinessLogicAgent");
        }
        if (/user_id|account_id|id=|object_id/.test(fieldNames) || /\/\d+|\/[a-f0-9-]{8,}/.test(formAction)) {
          pageTrustBoundaries.push("Object ID → authorization check → data access");
          agentsToDeploy.push("IDORAgent");
        }
      }

      // Take screenshot for documentation (non-intrusive)
      const slug = url.replace(/[^a-z0-9]/gi, "_").slice(-40);
      await page.screenshot({ path: `${args.screenshots}/flow-${slug}.png`, fullPage: false });

      if (pageTrustBoundaries.length > 0 || forms.length > 0) {
        flows.push({
          url,
          title,
          purpose: pagePurpose,
          forms: forms.map((f) => ({
            ...f,
            likely_function: pagePurpose,
          })),
          api_calls: networkRequests
            .filter((r) => r.url.includes(new URL(url).hostname))
            .slice(-10),
          trust_boundary_crossings: [...new Set(pageTrustBoundaries)],
          agents_to_deploy: [...new Set(agentsToDeploy)],
        });
      }

    } catch {
      // Skip failed navigations silently
    }
  }

  // Detect cloud provider from JS globals and meta tags
  let cloudProvider = "unknown";
  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 8000 });
    const pageSource = await page.content();
    if (/amazonaws\.com|aws\.|cloudfront\.net/.test(pageSource)) cloudProvider = "AWS";
    else if (/googleapis\.com|gcp\.|appspot\.com/.test(pageSource)) cloudProvider = "GCP";
    else if (/azure\.com|azurewebsites\.net|blob\.core\.windows/.test(pageSource)) cloudProvider = "Azure";
    else if (/digitalocean|do-nyc/.test(pageSource)) cloudProvider = "DigitalOcean";

    // Detect auth pattern
    if (/Auth0|auth0\.com/.test(pageSource)) TECH_SIGNALS["auth"] = "Auth0";
    else if (/Cognito|cognito/.test(pageSource)) TECH_SIGNALS["auth"] = "AWS Cognito";
    else if (/firebase|Firebase/.test(pageSource)) TECH_SIGNALS["auth"] = "Firebase Auth";
    else if (/Okta|okta\.com/.test(pageSource)) TECH_SIGNALS["auth"] = "Okta";

    // Detect API style
    if (/graphql|GraphQL/.test(pageSource)) TECH_SIGNALS["api"] = "GraphQL";
    else if (/swagger|openapi|api-docs/i.test(pageSource)) TECH_SIGNALS["api"] = "REST with docs";
    else TECH_SIGNALS["api"] = "REST";
  } catch { /* ignore */ }

  // Build AppProfile
  const highValueFlows = flows
    .filter((f) => f.trust_boundary_crossings.length > 0)
    .flatMap((f) =>
      f.trust_boundary_crossings.map((crossing, i) => ({
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

  const appProfile: AppProfile = {
    target: baseUrl,
    app_narrative: `Web application at ${baseUrl}. Discovered ${allDiscoveredUrls.length} pages with ${highValueFlows.length} high-value flows identified through functional analysis.`,
    tech_stack: {
      framework: TECH_SIGNALS["framework"] || "Unknown — check response headers",
      language: TECH_SIGNALS["framework"]?.includes("PHP") ? "PHP"
        : TECH_SIGNALS["framework"]?.includes("Python") ? "Python"
          : TECH_SIGNALS["framework"]?.includes("Ruby") ? "Ruby"
            : TECH_SIGNALS["framework"]?.includes("Java") ? "Java"
              : TECH_SIGNALS["framework"]?.includes("Node") ? "Node.js"
                : "Unknown",
      cloud: cloudProvider,
      auth_pattern: TECH_SIGNALS["auth"] || "Standard session/JWT — inspect login flow",
      api_style: TECH_SIGNALS["api"] || "REST",
      file_processing: flows.some((f) => f.agents_to_deploy.includes("FileUploadAgent"))
        ? ["File upload detected — check server-side processing"]
        : [],
    },
    crown_jewels: [
      ...new Set(flows
        .filter((f) => f.agents_to_deploy.some((a) => ["AuthAgent", "IDORAgent", "SSRFAgent"].includes(a)))
        .map((f) => f.purpose)),
    ],
    high_value_flows: highValueFlows,
    attack_priority_order: uniqueAgents,
    trust_boundary_crossings: [
      ...new Set(flows.flatMap((f) => f.trust_boundary_crossings)),
    ],
    all_discovered_urls: allDiscoveredUrls,
    timestamp: new Date().toISOString(),
  };

  return appProfile;
}

async function main() {
  if (!args.target) {
    console.error("Usage: bun playwright-harness.ts --target https://example.com [options]");
    process.exit(1);
  }

  console.log(`[*] BugBounty Playwright Harness starting — target: ${args.target}`);
  console.log(`[*] Proxy: ${args.proxy}`);
  console.log(`[*] Mode: ${args.mode}`);

  await Bun.write(args.screenshots + "/.gitkeep", "");

  const browser = await setupBrowser();
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 720 },
  });
  const page = await context.newPage();

  await injectAuth(page);

  // --- MAP-FLOWS MODE: Observe and profile, no injection ---
  if (args.mode === "map-flows") {
    console.log("[*] Building AppProfile from application behavior...");
    const appProfile = await mapApplicationFlows(page, args.target);

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

    await browser.close();
    return;
  }

  // --- TEST MODE: Active testing with payloads ---
  console.log("[*] Crawling application...");
  const endpoints = await crawlApplication(page, args.target, parseInt(args["crawl-depth"]));
  console.log(`[+] Discovered ${endpoints.length} endpoints`);

  if (args["test-xss"]) {
    console.log("[*] Testing for XSS...");
    for (const url of endpoints.slice(0, 50)) {
      await testXSSInForms(page, url);
    }
  }

  if (args["test-auth-bypass"]) {
    console.log("[*] Testing for auth bypass...");
    const protectedPaths = endpoints.filter((u) =>
      /admin|dashboard|profile|settings|account|billing|private/i.test(u)
    );
    await testAuthBypass(page, protectedPaths);
  }

  // Final screenshot
  await page.screenshot({ path: `${args.screenshots}/final-state.png` });

  // Write findings
  await Bun.write(args.output, JSON.stringify({
    target: args.target,
    endpoints_discovered: endpoints.length,
    findings: findings.filter((f) => f.cvss_estimate >= 8.0),
    total_findings: findings.length,
    high_severity_findings: findings.filter((f) => f.cvss_estimate >= 8.0).length,
    timestamp: new Date().toISOString(),
  }, null, 2));

  console.log(`[+] Complete. ${findings.length} total findings, ${findings.filter(f => f.cvss_estimate >= 8.0).length} high/critical`);
  console.log(`[+] Results: ${args.output}`);

  await browser.close();
}

main().catch(console.error);
