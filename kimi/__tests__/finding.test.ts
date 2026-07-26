import { describe, it, expect } from "bun:test";
import {
  normalizeFindings,
  severityRank,
  sortFindings,
  suggestVrtCategory,
  CVSS_TO_VRT,
  type Finding,
} from "../Tools/lib/finding.ts";

const base: Finding = {
  title: "Reflected XSS in search",
  severity: "high",
  cvss: 7.1,
  confirmed: true,
  description: "Reflected XSS via the q parameter.",
};

describe("normalizeFindings", () => {
  it("accepts a bare findings array", () => {
    const arr = [base];
    expect(normalizeFindings(arr)).toEqual(arr);
  });

  it("unwraps a {findings: [...]} wrapper object", () => {
    const wrapper = { target: "https://example.com", generated_at: "2026-01-01", findings: [base] };
    expect(normalizeFindings(wrapper)).toEqual([base]);
  });

  it("accepts an empty array", () => {
    expect(normalizeFindings([])).toEqual([]);
  });

  it("throws a clear error for garbage input", () => {
    expect(() => normalizeFindings(null)).toThrow(/findings/i);
    expect(() => normalizeFindings("not json findings")).toThrow(/findings/i);
    expect(() => normalizeFindings(42)).toThrow(/findings/i);
    expect(() => normalizeFindings({ target: "x" })).toThrow(/findings/i);
    expect(() => normalizeFindings({ findings: "nope" })).toThrow(/findings/i);
  });

  it("throws when the array contains non-objects", () => {
    expect(() => normalizeFindings([base, "oops"])).toThrow(/objects/i);
    expect(() => normalizeFindings([null])).toThrow(/objects/i);
  });
});

describe("severityRank", () => {
  it("ranks canonical severities in order", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
    expect(severityRank("medium")).toBeGreaterThan(severityRank("low"));
    expect(severityRank("low")).toBeGreaterThan(severityRank("info"));
  });

  it("is case-insensitive", () => {
    expect(severityRank("CRITICAL")).toBe(severityRank("critical"));
  });

  it("returns -1 for unknown severities", () => {
    expect(severityRank("bogus")).toBe(-1);
  });
});

describe("sortFindings", () => {
  it("sorts by severity desc, then cvss desc, without mutating input", () => {
    const low: Finding = { ...base, title: "low", severity: "low", cvss: 2.0 };
    const highA: Finding = { ...base, title: "high-a", severity: "high", cvss: 7.0 };
    const highB: Finding = { ...base, title: "high-b", severity: "high", cvss: 8.5 };
    const crit: Finding = { ...base, title: "crit", severity: "critical", cvss: 9.8 };
    const input = [low, highA, crit, highB];

    const sorted = sortFindings(input);
    expect(sorted.map((f) => f.title)).toEqual(["crit", "high-b", "high-a", "low"]);
    expect(input.map((f) => f.title)).toEqual(["low", "high-a", "crit", "high-b"]);
  });
});

describe("suggestVrtCategory", () => {
  it("maps canonical titles to Bugcrowd VRT categories", () => {
    const cases: Array<[string, string]> = [
      ["Reflected Cross-Site Scripting in search form", "Cross-Site Scripting (XSS)"],
      ["SQL injection in login parameter", "SQL Injection"],
      ["IDOR on /api/invoices/{id}", "Insecure Direct Object References (IDOR)"],
      ["SSRF via webhook URL", "Server-Side Request Forgery (SSRF)"],
      ["Remote code execution through template injection", "Remote Code Execution (RCE)"],
      ["CSRF on password change", "Cross-Site Request Forgery (CSRF)"],
      ["XXE in SVG upload", "XML External Entity (XXE) Injection"],
      ["Open redirect on /logout?next=", "Open Redirect"],
      ["Subdomain takeover of assets.example.com", "Subdomain Takeover"],
    ];
    for (const [title, expected] of cases) {
      expect(suggestVrtCategory({ ...base, title })).toBe(expected);
    }
  });

  it("also matches on the type field", () => {
    expect(suggestVrtCategory({ ...base, title: "Issue #12", type: "sqli" })).toBe("SQL Injection");
  });

  it("returns undefined when nothing matches", () => {
    expect(suggestVrtCategory({ ...base, title: "Verbose server banner" })).toBeUndefined();
  });
});

describe("CVSS_TO_VRT", () => {
  it("maps severity labels to Bugcrowd priority bands", () => {
    expect(CVSS_TO_VRT.critical).toBe("P1");
    expect(CVSS_TO_VRT.high).toBe("P2");
    expect(CVSS_TO_VRT.medium).toBe("P3");
  });
});
