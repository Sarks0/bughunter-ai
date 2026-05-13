#!/usr/bin/env bun
/**
 * BugBountyFramework — Burp Suite REST API Bridge
 * Provides programmatic access to Burp Suite Professional via its REST API.
 * Handles health checks, scope sync, sitemap/history export, collaborator
 * polling, HAR export, scanner issues, and active scan initiation.
 *
 * Falls back gracefully with mitmproxy guidance when Burp is unavailable.
 */

import { parseArgs } from "util";

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    "api-url": { type: "string", default: "http://127.0.0.1:1337/v0.1" },
    "proxy-url": { type: "string", default: "http://127.0.0.1:8080" },
    health: { type: "boolean", default: false },
    "sync-scope": { type: "boolean", default: false },
    scope: { type: "string", default: "" },
    sitemap: { type: "boolean", default: false },
    history: { type: "boolean", default: false },
    filter: { type: "string", default: "" },
    "collaborator-poll": { type: "boolean", default: false },
    "poll-interval": { type: "string", default: "5000" },
    "poll-max": { type: "string", default: "60" },
    "export-har": { type: "boolean", default: false },
    output: { type: "string", default: "" },
    issues: { type: "boolean", default: false },
    "start-scan": { type: "boolean", default: false },
    target: { type: "string", default: "" },
    json: { type: "boolean", default: false },
  },
});

const API_URL = (args["api-url"] as string).replace(/\/+$/, "");
const PROXY_URL = args["proxy-url"] as string;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BurpHealth {
  proxy: boolean;
  api: boolean;
  version: string;
}

interface HistoryFilter {
  status?: number;
  method?: string;
  [key: string]: string | number | undefined;
}

interface ProxyHistoryItem {
  host: string;
  port: number;
  protocol: string;
  method: string;
  path: string;
  status: number;
  request?: string;
  response?: string;
  [key: string]: unknown;
}

interface CollaboratorInteraction {
  type: string;
  client_ip?: string;
  timestamp?: string;
  data?: unknown;
  [key: string]: unknown;
}

interface ScannerIssue {
  name: string;
  severity: string;
  confidence: string;
  url: string;
  detail?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function log(msg: string): void {
  console.error(`[burp-bridge] ${msg}`);
}

function output(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

function parseFilter(raw: string): HistoryFilter {
  if (!raw) return {};
  const filter: HistoryFilter = {};
  for (const pair of raw.split(",")) {
    const [key, val] = pair.split(":");
    if (key && val) {
      filter[key.trim()] = /^\d+$/.test(val.trim())
        ? Number(val.trim())
        : val.trim();
    }
  }
  return filter;
}

function suggestMitmproxyFallback(): void {
  log("WARNING: Burp Suite is not reachable.");
  log("Fallback option — use mitmproxy as an alternative:");
  log("  1. Install: brew install mitmproxy   (or pip install mitmproxy)");
  log("  2. Run:     mitmproxy --listen-port 8080");
  log("  3. Export:  mitmdump -w traffic.flow");
  log("  4. Convert: mitmproxy2har traffic.flow > traffic.har");
  log("mitmproxy provides interception, replay, and scripting capabilities.");
}

// ---------------------------------------------------------------------------
// Core API functions
// ---------------------------------------------------------------------------

/**
 * Health check — verifies both the Burp proxy and REST API are reachable.
 */
export async function isBurpAlive(): Promise<BurpHealth> {
  const result: BurpHealth = { proxy: false, api: false, version: "unknown" };

  // Test API endpoint
  try {
    const apiResp = await fetch(`${API_URL}/`, {
      signal: AbortSignal.timeout(5000),
    });
    if (apiResp.ok) {
      result.api = true;
      try {
        const body = await apiResp.json();
        result.version = body?.version ?? body?.burpVersion ?? "unknown";
      } catch {
        result.version = "unknown (non-JSON response)";
      }
    }
  } catch {
    result.api = false;
  }

  // Test proxy via TCP connection check
  try {
    const url = new URL(PROXY_URL);
    await new Promise<void>((resolve, reject) => {
      const socket = Bun.connect({
        hostname: url.hostname,
        port: Number(url.port) || 8080,
        socket: {
          data() {},
          open(sock) {
            sock.end();
            resolve();
          },
          error(_sock, err) {
            reject(err);
          },
          close() {
            resolve();
          },
        },
      });
    });
    result.proxy = true;
  } catch {
    result.proxy = false;
  }

  return result;
}

/**
 * Import scope definitions into Burp's target scope.
 * Accepts a comma-separated list of patterns (e.g. "*.example.com,api.example.com").
 */
export async function syncScope(
  patterns: string,
): Promise<{ success: boolean; imported: string[] }> {
  const entries = patterns
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const imported: string[] = [];

  for (const pattern of entries) {
    const scopeEntry: Record<string, unknown> = {
      enabled: true,
      protocol: "any",
      host: pattern.replace(/^\*\./, ""),
      port: "",
      file: "",
    };

    // Wildcard subdomain — use regex matching
    if (pattern.startsWith("*.")) {
      scopeEntry.host_regex = true;
      scopeEntry.host = `.*\\.${pattern.slice(2).replace(/\./g, "\\.")}$`;
    }

    try {
      const resp = await fetch(`${API_URL}/target/scope`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scopeEntry),
        signal: AbortSignal.timeout(5000),
      });

      if (resp.ok) {
        imported.push(pattern);
        log(`Scope imported: ${pattern}`);
      } else {
        log(`Failed to import scope "${pattern}": HTTP ${resp.status}`);
      }
    } catch (err) {
      log(
        `Error importing scope "${pattern}": ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  return { success: imported.length === entries.length, imported };
}

/**
 * Export Burp sitemap as JSON.
 */
export async function getSitemap(): Promise<unknown[]> {
  try {
    const resp = await fetch(`${API_URL}/target/sitemap`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      log(`Sitemap request failed: HTTP ${resp.status}`);
      return [];
    }
    const data = await resp.json();
    return Array.isArray(data) ? data : [data];
  } catch (err) {
    log(`Error fetching sitemap: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

/**
 * Export proxy history with optional filtering.
 */
export async function getHistory(
  filter?: HistoryFilter,
): Promise<ProxyHistoryItem[]> {
  try {
    const resp = await fetch(`${API_URL}/proxy/history`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      log(`History request failed: HTTP ${resp.status}`);
      return [];
    }
    const raw: ProxyHistoryItem[] = await resp.json();

    if (!filter || Object.keys(filter).length === 0) return raw;

    return raw.filter((item) => {
      for (const [key, val] of Object.entries(filter)) {
        if (val === undefined) continue;
        const itemVal = item[key as keyof ProxyHistoryItem];
        if (typeof val === "number" && itemVal !== val) return false;
        if (
          typeof val === "string" &&
          String(itemVal).toLowerCase() !== val.toLowerCase()
        )
          return false;
      }
      return true;
    });
  } catch (err) {
    log(`Error fetching history: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

/**
 * Verify that Burp actually captured traffic after a crawl.
 */
export async function verifyTrafficCapture(
  minExpected = 1,
): Promise<{ captured: boolean; count: number }> {
  const history = await getHistory();
  const count = history.length;
  const captured = count >= minExpected;

  if (!captured) {
    log(
      `WARNING: Expected at least ${minExpected} proxy history entries, found ${count}.`,
    );
    log(
      "Possible causes: proxy not configured, scope mismatch, or target unreachable.",
    );
  } else {
    log(`Traffic verified: ${count} entries captured.`);
  }

  return { captured, count };
}

/**
 * Poll Burp Collaborator for out-of-band interactions.
 * Yields interactions as they arrive.
 */
export async function* pollCollaborator(
  intervalMs = 5000,
  maxPolls = 60,
): AsyncGenerator<CollaboratorInteraction> {
  let polls = 0;

  while (polls < maxPolls) {
    try {
      const resp = await fetch(`${API_URL}/collaborator/interactions`, {
        signal: AbortSignal.timeout(10000),
      });

      if (resp.ok) {
        const data = await resp.json();
        const interactions: CollaboratorInteraction[] = Array.isArray(data)
          ? data
          : (data?.interactions ?? []);

        for (const interaction of interactions) {
          yield interaction;
        }
      } else if (resp.status === 404) {
        log(
          "Collaborator endpoint not available (Burp Community or feature disabled).",
        );
        return;
      }
    } catch (err) {
      log(
        `Collaborator poll error: ${err instanceof Error ? err.message : err}`,
      );
    }

    polls++;
    if (polls < maxPolls) {
      await Bun.sleep(intervalMs);
    }
  }

  log(`Collaborator polling completed after ${polls} polls.`);
}

/**
 * Export proxy history as a HAR (HTTP Archive) file.
 */
export async function exportHar(outputPath: string): Promise<boolean> {
  const history = await getHistory();

  if (history.length === 0) {
    log("No proxy history to export.");
    return false;
  }

  const har = {
    log: {
      version: "1.2",
      creator: { name: "burp-bridge", version: "1.0.0" },
      entries: history.map((item) => ({
        startedDateTime: new Date().toISOString(),
        time: 0,
        request: {
          method: item.method ?? "GET",
          url: `${item.protocol ?? "https"}://${item.host}:${item.port}${item.path}`,
          httpVersion: "HTTP/1.1",
          headers: [],
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: -1,
        },
        response: {
          status: item.status ?? 0,
          statusText: "",
          httpVersion: "HTTP/1.1",
          headers: [],
          content: { size: 0, mimeType: "text/html" },
          redirectURL: "",
          headersSize: -1,
          bodySize: -1,
          cookies: [],
        },
        cache: {},
        timings: { send: 0, wait: 0, receive: 0 },
      })),
    },
  };

  try {
    await Bun.write(outputPath, JSON.stringify(har, null, 2));
    log(`HAR exported to ${outputPath} (${history.length} entries).`);
    return true;
  } catch (err) {
    log(
      `Failed to write HAR file: ${err instanceof Error ? err.message : err}`,
    );
    return false;
  }
}

/**
 * Export Burp scanner issues as JSON.
 */
export async function getIssues(): Promise<ScannerIssue[]> {
  try {
    const resp = await fetch(`${API_URL}/scan/issues`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      log(`Issues request failed: HTTP ${resp.status}`);
      return [];
    }
    const data = await resp.json();
    return Array.isArray(data) ? data : (data?.issues ?? []);
  } catch (err) {
    log(`Error fetching issues: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

/**
 * Start an active scan on a target URL (Burp Pro only).
 */
export async function startScan(
  targetUrl: string,
): Promise<{ success: boolean; taskId?: string }> {
  try {
    const resp = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        urls: [targetUrl],
        scope: {
          include: [{ rule: targetUrl }],
        },
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (resp.ok) {
      const taskId = resp.headers.get("location") ?? undefined;
      log(
        `Active scan started for ${targetUrl}${taskId ? ` (task: ${taskId})` : ""}`,
      );
      return { success: true, taskId };
    }

    const errText = await resp.text().catch(() => "");
    log(`Failed to start scan: HTTP ${resp.status} ${errText}`);
    return { success: false };
  } catch (err) {
    log(`Error starting scan: ${err instanceof Error ? err.message : err}`);
    return { success: false };
  }
}

// ---------------------------------------------------------------------------
// CLI dispatcher
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // --health
  if (args.health) {
    const status = await isBurpAlive();
    output(status);
    if (!status.api && !status.proxy) {
      suggestMitmproxyFallback();
      process.exit(1);
    }
    return;
  }

  // --sync-scope
  if (args["sync-scope"]) {
    const scope = args.scope as string;
    if (!scope) {
      log('ERROR: --sync-scope requires --scope "pattern1,pattern2"');
      process.exit(1);
    }
    const result = await syncScope(scope);
    output(result);
    if (!result.success) process.exit(1);
    return;
  }

  // --sitemap
  if (args.sitemap) {
    const sitemap = await getSitemap();
    output(sitemap);
    return;
  }

  // --history
  if (args.history) {
    const filter = parseFilter(args.filter as string);
    const history = await getHistory(filter);
    output(history);
    return;
  }

  // --collaborator-poll
  if (args["collaborator-poll"]) {
    const intervalMs = Number(args["poll-interval"]) || 5000;
    const maxPolls = Number(args["poll-max"]) || 60;

    log(
      `Polling Burp Collaborator every ${intervalMs}ms (max ${maxPolls} polls)...`,
    );
    const interactions: CollaboratorInteraction[] = [];

    for await (const interaction of pollCollaborator(intervalMs, maxPolls)) {
      log(`Interaction received: ${interaction.type ?? "unknown"}`);
      interactions.push(interaction);
      // Stream each interaction immediately
      console.log(JSON.stringify(interaction));
    }

    if (interactions.length === 0) {
      log("No collaborator interactions detected.");
    }
    return;
  }

  // --export-har
  if (args["export-har"]) {
    const outputPath = (args.output as string) || "/tmp/burp-export.har";
    const success = await exportHar(outputPath);
    output({ success, path: outputPath });
    if (!success) process.exit(1);
    return;
  }

  // --issues
  if (args.issues) {
    const issues = await getIssues();
    output(issues);
    return;
  }

  // --start-scan
  if (args["start-scan"]) {
    const target = args.target as string;
    if (!target) {
      log("ERROR: --start-scan requires --target URL");
      process.exit(1);
    }
    const result = await startScan(target);
    output(result);
    if (!result.success) process.exit(1);
    return;
  }

  // No command — print usage
  console.log(`burp-bridge — Burp Suite REST API Bridge

Usage:
  burp-bridge --health                              Check Burp availability
  burp-bridge --sync-scope --scope "*.example.com"  Import scope into Burp
  burp-bridge --sitemap                             Export sitemap as JSON
  burp-bridge --history [--filter "status:200"]     Export proxy history
  burp-bridge --collaborator-poll                   Poll for OOB interactions
  burp-bridge --export-har --output path.har        Export traffic as HAR
  burp-bridge --issues                              Export scanner issues
  burp-bridge --start-scan --target URL             Start active scan (Pro)

Options:
  --api-url URL      Burp REST API URL (default: http://127.0.0.1:1337/v0.1)
  --proxy-url URL    Burp proxy URL (default: http://127.0.0.1:8080)
  --filter FILTERS   Filter history (e.g. "status:200,method:POST")
  --poll-interval MS Collaborator poll interval (default: 5000)
  --poll-max N       Max collaborator polls (default: 60)
`);
}

main().catch((err) => {
  log(`Fatal error: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
});
