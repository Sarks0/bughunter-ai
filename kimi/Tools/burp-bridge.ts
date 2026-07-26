#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Burp Suite REST API bridge.
 */

import { parseArgs } from "util";
import { isInScope, loadScopeFromConfig } from "./lib/scope.ts";

/**
 * Mutable connection config; the CLI populates it in main(), library callers
 * may set it directly. Parsing args at module scope would make this file
 * unsafe to import (it would touch process argv).
 */
export const burpConfig = {
  apiUrl: "http://127.0.0.1:1337/v0.1",
  proxyUrl: "http://127.0.0.1:8080",
};

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

function log(msg: string): void {
  console.error(`[burp-bridge] ${msg}`);
}

function output(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function parseFilter(raw: string): HistoryFilter {
  if (!raw) return {};
  const filter: HistoryFilter = {};
  for (const pair of raw.split(",")) {
    // Split on the FIRST colon only, so values may contain colons
    // (e.g. "url:http://example.com").
    const idx = pair.indexOf(":");
    const key = idx >= 0 ? pair.slice(0, idx) : "";
    const val = idx >= 0 ? pair.slice(idx + 1) : "";
    if (key && val) {
      filter[key.trim()] = /^\d+$/.test(val.trim()) ? Number(val.trim()) : val.trim();
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
}

export async function isBurpAlive(): Promise<BurpHealth> {
  const result: BurpHealth = { proxy: false, api: false, version: "unknown" };

  try {
    const apiResp = await fetch(`${burpConfig.apiUrl}/`, { signal: AbortSignal.timeout(5000) });
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

  try {
    const url = new URL(burpConfig.proxyUrl);
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

export async function syncScope(patterns: string): Promise<{ success: boolean; imported: string[] }> {
  const entries = patterns.split(",").map((p) => p.trim()).filter(Boolean);
  const imported: string[] = [];

  for (const pattern of entries) {
    // NOTE: this assumes the Burp REST API accepts a single scope-entry object
    // via PUT /target/scope (advanced-mode shape: enabled/protocol/host/port/
    // file plus host_regex). This request shape has NOT been verified against a
    // live Burp instance — verify before relying on it.
    const scopeEntry: Record<string, unknown> = {
      enabled: true,
      protocol: "any",
      host: pattern.replace(/^\*\./, ""),
      port: "",
      file: "",
    };

    if (pattern.startsWith("*.")) {
      scopeEntry.host_regex = true;
      scopeEntry.host = `.*\\.${pattern.slice(2).replace(/\./g, "\\.")}$`;
    }

    try {
      const resp = await fetch(`${burpConfig.apiUrl}/target/scope`, {
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
      log(`Error importing scope "${pattern}": ${err instanceof Error ? err.message : err}`);
    }
  }

  return { success: imported.length === entries.length, imported };
}

export async function getSitemap(): Promise<unknown[]> {
  try {
    const resp = await fetch(`${burpConfig.apiUrl}/target/sitemap`, { signal: AbortSignal.timeout(15000) });
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

export async function getHistory(filter?: HistoryFilter): Promise<ProxyHistoryItem[]> {
  try {
    const resp = await fetch(`${burpConfig.apiUrl}/proxy/history`, { signal: AbortSignal.timeout(15000) });
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
        if (typeof val === "string" && String(itemVal).toLowerCase() !== val.toLowerCase()) return false;
      }
      return true;
    });
  } catch (err) {
    log(`Error fetching history: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

export async function verifyTrafficCapture(minExpected = 1): Promise<{ captured: boolean; count: number }> {
  const history = await getHistory();
  const count = history.length;
  const captured = count >= minExpected;

  if (!captured) {
    log(`WARNING: Expected at least ${minExpected} proxy history entries, found ${count}.`);
  } else {
    log(`Traffic verified: ${count} entries captured.`);
  }

  return { captured, count };
}

/** Stable identity for a collaborator interaction (id field if present, else content hash). */
export function interactionId(interaction: CollaboratorInteraction): string {
  const id = (interaction as Record<string, unknown>).id ?? (interaction as Record<string, unknown>).interaction_id;
  return id !== undefined && id !== null ? String(id) : JSON.stringify(interaction);
}

/**
 * Return only interactions not already in `seen` (mutates `seen`). Used to
 * dedup collaborator polling, where each poll returns ALL interactions.
 */
export function filterNewInteractions(
  interactions: CollaboratorInteraction[],
  seen: Set<string>
): CollaboratorInteraction[] {
  const fresh: CollaboratorInteraction[] = [];
  for (const interaction of interactions) {
    const id = interactionId(interaction);
    if (seen.has(id)) continue;
    seen.add(id);
    fresh.push(interaction);
  }
  return fresh;
}

export async function* pollCollaborator(intervalMs = 5000, maxPolls = 60): AsyncGenerator<CollaboratorInteraction> {
  let polls = 0;
  const seen = new Set<string>();
  while (polls < maxPolls) {
    try {
      const resp = await fetch(`${burpConfig.apiUrl}/collaborator/interactions`, { signal: AbortSignal.timeout(10000) });
      if (resp.ok) {
        const data = await resp.json();
        const interactions: CollaboratorInteraction[] = Array.isArray(data) ? data : (data?.interactions ?? []);
        // Each poll returns ALL interactions; yield only the ones not seen before.
        for (const interaction of filterNewInteractions(interactions, seen)) yield interaction;
      } else if (resp.status === 404) {
        log("Collaborator endpoint not available (Burp Community or feature disabled).");
        return;
      }
    } catch (err) {
      log(`Collaborator poll error: ${err instanceof Error ? err.message : err}`);
    }
    polls++;
    if (polls < maxPolls) await Bun.sleep(intervalMs);
  }
  log(`Collaborator polling completed after ${polls} polls.`);
}

interface ParsedHttpMessage {
  headers: Array<{ name: string; value: string }>;
  body: string;
  mimeType?: string;
}

/** Burp's REST API returns request/response base64-encoded; decode when it looks like it. */
function decodeMaybeBase64(raw: string): string {
  if (!raw) return raw;
  if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|HTTP\/)/.test(raw)) return raw;
  try {
    const decoded = Buffer.from(raw, "base64").toString("utf-8");
    if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|HTTP\/)/m.test(decoded)) return decoded;
  } catch {
    // not base64 — return as-is
  }
  return raw;
}

/** Split a raw HTTP message into headers and body. Tolerates LF-only endings. */
function parseHttpMessage(raw: string): ParsedHttpMessage {
  const text = decodeMaybeBase64(raw).replace(/\r\n/g, "\n");
  const splitAt = text.indexOf("\n\n");
  const head = splitAt >= 0 ? text.slice(0, splitAt) : text;
  const body = splitAt >= 0 ? text.slice(splitAt + 2) : "";
  const headers: Array<{ name: string; value: string }> = [];
  for (const line of head.split("\n").slice(1)) {
    const colon = line.indexOf(":");
    if (colon > 0) headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  const mimeType = headers.find((h) => h.name.toLowerCase() === "content-type")?.value;
  return { headers, body, mimeType };
}

function buildHarEntry(item: ProxyHistoryItem) {
  const request = parseHttpMessage(item.request ?? "");
  const response = parseHttpMessage(item.response ?? "");
  return {
    startedDateTime: new Date().toISOString(),
    time: 0,
    request: {
      method: item.method ?? "GET",
      url: `${item.protocol ?? "https"}://${item.host}:${item.port}${item.path}`,
      httpVersion: "HTTP/1.1",
      headers: request.headers,
      queryString: [],
      cookies: [],
      ...(request.body
        ? { postData: { mimeType: request.mimeType ?? "application/octet-stream", text: request.body } }
        : {}),
      headersSize: -1,
      bodySize: request.body.length,
    },
    response: {
      status: item.status ?? 0,
      statusText: "",
      httpVersion: "HTTP/1.1",
      headers: response.headers,
      content: {
        size: response.body.length,
        mimeType: response.mimeType ?? "text/html",
        text: response.body,
      },
      redirectURL: response.headers.find((h) => h.name.toLowerCase() === "location")?.value ?? "",
      headersSize: -1,
      bodySize: response.body.length,
      cookies: [],
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
  };
}

export async function exportHar(outputPath: string): Promise<boolean> {
  const history = await getHistory();
  if (history.length === 0) {
    log("No proxy history to export.");
    return false;
  }

  const entries = history.map((item) => {
    try {
      return buildHarEntry(item);
    } catch (err) {
      log(`Skipping malformed history item (${item.host}${item.path}): ${err instanceof Error ? err.message : err}`);
      return buildHarEntry({ host: item.host, port: item.port, protocol: item.protocol, method: item.method, path: item.path, status: item.status });
    }
  });

  const har = {
    log: {
      version: "1.2",
      creator: { name: "burp-bridge", version: "1.0.0" },
      entries,
    },
  };

  try {
    await Bun.write(outputPath, JSON.stringify(har, null, 2));
    log(`HAR exported to ${outputPath} (${history.length} entries).`);
    return true;
  } catch (err) {
    log(`Failed to write HAR file: ${err instanceof Error ? err.message : err}`);
    return false;
  }
}

export async function getIssues(): Promise<ScannerIssue[]> {
  try {
    const resp = await fetch(`${burpConfig.apiUrl}/scan/issues`, { signal: AbortSignal.timeout(15000) });
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

export async function startScan(targetUrl: string): Promise<{ success: boolean; taskId?: string }> {
  try {
    // NOTE: this assumes the Burp REST API accepts POST /scan with a body of
    // `{ urls: [...], scope: { include: [{ rule }] } }` and returns the task
    // ID in a Location header. This request shape has NOT been verified
    // against a live Burp instance — verify before relying on it.
    const resp = await fetch(`${burpConfig.apiUrl}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: [targetUrl], scope: { include: [{ rule: targetUrl }] } }),
      signal: AbortSignal.timeout(10000),
    });

    if (resp.ok) {
      const taskId = resp.headers.get("location") ?? undefined;
      log(`Active scan started for ${targetUrl}${taskId ? ` (task: ${taskId})` : ""}`);
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

async function main(): Promise<void> {
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
      // Optional target-config JSON; when set, --start-scan URLs are scope-checked.
      "scope-config": { type: "string" },
      json: { type: "boolean", default: false },
    },
  });

  burpConfig.apiUrl = (args["api-url"] as string).replace(/\/+$/, "");
  burpConfig.proxyUrl = args["proxy-url"] as string;

  if (args.health) {
    const status = await isBurpAlive();
    output(status);
    if (!status.api && !status.proxy) {
      suggestMitmproxyFallback();
      process.exit(1);
    }
    return;
  }

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

  if (args.sitemap) {
    output(await getSitemap());
    return;
  }

  if (args.history) {
    output(await getHistory(parseFilter(args.filter as string)));
    return;
  }

  if (args["collaborator-poll"]) {
    const intervalMs = Number(args["poll-interval"]) || 5000;
    const maxPolls = Number(args["poll-max"]) || 60;
    log(`Polling Burp Collaborator every ${intervalMs}ms (max ${maxPolls} polls)...`);
    const interactions: CollaboratorInteraction[] = [];
    for await (const interaction of pollCollaborator(intervalMs, maxPolls)) {
      log(`Interaction received: ${interaction.type ?? "unknown"}`);
      interactions.push(interaction);
      console.log(JSON.stringify(interaction));
    }
    if (interactions.length === 0) log("No collaborator interactions detected.");
    return;
  }

  if (args["export-har"]) {
    const outputPath = (args.output as string) || "/tmp/burp-export.har";
    const success = await exportHar(outputPath);
    output({ success, path: outputPath });
    if (!success) process.exit(1);
    return;
  }

  if (args.issues) {
    output(await getIssues());
    return;
  }

  if (args["start-scan"]) {
    const target = args.target as string;
    if (!target) {
      log("ERROR: --start-scan requires --target URL");
      process.exit(1);
    }
    if (args["scope-config"]) {
      const scope = await loadScopeFromConfig(args["scope-config"] as string);
      const check = isInScope(target, scope);
      if (!check.inScope) {
        log("ERROR: scan target rejected by scope config. Rejected URLs:");
        log(`  ${target} — ${check.reason}`);
        process.exit(1);
      }
      log(`Scope check passed: ${check.reason}`);
    } else {
      log("WARNING: no --scope-config provided; scan target is NOT scope-checked.");
    }
    const result = await startScan(target);
    output(result);
    if (!result.success) process.exit(1);
    return;
  }

  console.log(`burp-bridge — Burp Suite REST API Bridge

Usage:
  burp-bridge --health
  burp-bridge --sync-scope --scope "*.example.com"
  burp-bridge --sitemap
  burp-bridge --history [--filter "status:200"]
  burp-bridge --collaborator-poll
  burp-bridge --export-har --output path.har
  burp-bridge --issues
  burp-bridge --start-scan --target URL [--scope-config target.json]`);
}

if (import.meta.main) {
  main().catch((err) => {
    log(`Fatal error: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  });
}
