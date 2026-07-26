/**
 * Shared parsing for repeatable `--header "Name: value"` CLI flags.
 * Each entry is split on the FIRST colon (values may contain colons, e.g.
 * URLs or JWTs); malformed entries throw with an actionable message.
 */

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
