/**
 * BugHunter AI — Kimi port
 * Shared findings schema: single source of truth for the finding shape,
 * input normalization (bare array vs. `{findings: [...]}` wrapper),
 * severity ordering, and Bugcrowd VRT categorization.
 *
 * Producers currently disagree on output format:
 *  - playwright-harness.ts / appium-harness.ts write wrapper objects
 *    `{target, generated_at, findings: [...]}`
 *  - generate-report.ts / hunt-orchestrator.ts expect a bare JSON array
 * `normalizeFindings` accepts both so consumers stop caring.
 */

export interface Finding {
  id?: string;
  title: string;
  severity: string;
  cvss: number;
  cvss_vector?: string;
  vrt_category?: string;
  confirmed: boolean;
  url?: string;
  endpoint?: string;
  description: string;
  evidence?: string;
  poc?: string | { prompt_used?: string; response_received?: string };
  remediation?: string;
  agent?: string;
  timestamp?: string;
  // Optional fields some producers emit alongside the core shape.
  type?: string;
  subtype?: string;
  parameter?: string;
  steps_to_reproduce?: string[];
  impact?: string;
  cve?: string;
}

/**
 * Accepts a bare findings array or a wrapper object with a `findings` array
 * and returns the findings. Throws a clear error for anything else.
 */
export function normalizeFindings(raw: unknown): Finding[] {
  const arr: unknown = Array.isArray(raw)
    ? raw
    : raw !== null && typeof raw === "object" && Array.isArray((raw as { findings?: unknown }).findings)
      ? (raw as { findings: unknown[] }).findings
      : null;

  if (!arr) {
    throw new Error(
      "Findings input must be a JSON array of findings or an object with a 'findings' array"
    );
  }
  for (const item of arr as unknown[]) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("Findings array must contain finding objects");
    }
  }
  return arr as Finding[];
}

const SEVERITY_RANKS: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  moderate: 3,
  low: 2,
  informational: 1,
  info: 1,
  none: 0,
};

/** Numeric rank for a severity label (higher = more severe, unknown = -1). */
export function severityRank(severity: string): number {
  return SEVERITY_RANKS[(severity || "").trim().toLowerCase()] ?? -1;
}

/** Sort by severity descending, then CVSS score descending. Does not mutate. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (b.cvss ?? 0) - (a.cvss ?? 0)
  );
}

/** Bugcrowd priority band for a severity label. */
export const CVSS_TO_VRT: Record<string, string> = {
  critical: "P1",
  high: "P2",
  medium: "P3",
  low: "P4",
  info: "P5",
};

/** Keyword → Bugcrowd VRT category, matched against title/type/subtype. */
const VRT_KEYWORDS: Array<[RegExp, string]> = [
  [/cross[- ]site scripting|\bxss\b/i, "Cross-Site Scripting (XSS)"],
  [/\bsql\s*injection\b|\bsqli\b/i, "SQL Injection"],
  [/\bidor\b|insecure direct object/i, "Insecure Direct Object References (IDOR)"],
  [/\bssrf\b|server[- ]side request forgery/i, "Server-Side Request Forgery (SSRF)"],
  [/remote code execution|\brce\b|command injection/i, "Remote Code Execution (RCE)"],
  [/cross[- ]site request forgery|\bcsrf\b/i, "Cross-Site Request Forgery (CSRF)"],
  [/\bxxe\b|xml external entit/i, "XML External Entity (XXE) Injection"],
  [/open redirect|unvalidated redirect/i, "Open Redirect"],
  [/subdomain takeover/i, "Subdomain Takeover"],
  [/path traversal|directory traversal|\blfi\b|local file inclusion/i, "Path Traversal"],
  [/authentication bypass|auth[- ]bypass|broken authentication/i, "Authentication Bypass"],
  [/sensitive data|information disclosure|data exposure/i, "Sensitive Data Exposure"],
  [/security misconfiguration|misconfig/i, "Security Misconfiguration"],
  [/weak (password|credential)|brute[- ]force/i, "Weak Login Function"],
];

/**
 * Best-effort Bugcrowd VRT category for a finding, derived from keyword
 * matching on its title/type/subtype. Returns undefined when nothing matches.
 */
export function suggestVrtCategory(finding: Finding): string | undefined {
  const text = `${finding.title ?? ""} ${finding.type ?? ""} ${finding.subtype ?? ""}`;
  for (const [pattern, category] of VRT_KEYWORDS) {
    if (pattern.test(text)) return category;
  }
  return undefined;
}
