/**
 * Shared parsing for repeatable `--header "Name: value"` CLI flags.
 * Each entry is split on the FIRST colon (values may contain colons, e.g.
 * URLs or JWTs); malformed entries throw with an actionable message.
 *
 * Also home to the origin-scoping decision for those headers: extra headers
 * (auth tokens, deployment-protection bypasses) must only be sent to the
 * target, never to off-scope origins (SSO walls, subresources, redirect hops).
 */

import type { BrowserContext } from "playwright";
import { isInScope, type Scope } from "./scope.ts";

export class HeaderParseError extends Error {}

/**
 * Parse raw `--header` flag values into a header map. Later entries with the
 * same name (case-insensitive) overwrite earlier ones.
 * @throws HeaderParseError on entries without a colon or with an empty name/value.
 */
export function parseExtraHeaders(values: string[]): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const raw of values) {
    const idx = raw.indexOf(":");
    if (idx === -1) {
      throw new HeaderParseError(`Malformed --header "${raw}": expected "Name: value" (missing colon)`);
    }
    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    if (!name) {
      throw new HeaderParseError(`Malformed --header "${raw}": header name is empty`);
    }
    if (!value) {
      throw new HeaderParseError(`Malformed --header "${raw}": value for "${name}" is empty`);
    }
    // Replace any earlier casing of the same header name.
    for (const existing of Object.keys(headers)) {
      if (existing.toLowerCase() === name.toLowerCase()) delete headers[existing];
    }
    headers[name] = value;
  }
  return headers;
}

/**
 * Decide whether a request to `url` may carry the extra auth/bypass headers:
 * only in-scope URLs when a scope is configured, else only URLs same-origin
 * with the target. Context-level extraHTTPHeaders would instead leak them to
 * EVERY origin — subresources, redirect hops, SSO walls (e.g. vercel.com).
 */
export function shouldSendExtraHeaders(url: string, target: string, scope?: Scope): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (scope && (scope.in.length > 0 || scope.out.length > 0)) {
    return isInScope(url, scope).inScope;
  }
  try {
    return parsed.origin === new URL(target).origin;
  } catch {
    return false;
  }
}

/**
 * Add the extra headers to a browser context scoped by origin: a route
 * interceptor appends them only to requests shouldSendExtraHeaders approves.
 * Replaces context-level extraHTTPHeaders, which goes with every request to
 * every origin. NOTE: routes do not intercept context.request API calls —
 * pass headers explicitly (scoped by shouldSendExtraHeaders) for those.
 */
export async function applyScopedExtraHeaders(
  context: BrowserContext,
  extraHeaders: Record<string, string>,
  target: string,
  scope?: Scope
): Promise<void> {
  if (Object.keys(extraHeaders).length === 0) return;
  await context.route("**/*", async (route) => {
    const request = route.request();
    if (shouldSendExtraHeaders(request.url(), target, scope)) {
      await route.continue({ headers: { ...request.headers(), ...extraHeaders } });
    } else {
      await route.continue();
    }
  });
}
