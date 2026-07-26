import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { loadFindings, buildReport } from "../Tools/generate-report.ts";
import { TEMPLATES_DIR } from "../Tools/lib/paths.ts";
import type { Finding } from "../Tools/lib/finding.ts";

const GENERATE_REPORT = join(import.meta.dir, "..", "Tools", "generate-report.ts");
const DEFAULT_TEMPLATE = join(TEMPLATES_DIR, "BugReport.md");

const xss: Finding = {
  id: "BH-001",
  title: "Reflected XSS in search parameter",
  type: "xss",
  severity: "high",
  cvss: 7.1,
  confirmed: true,
  url: "https://target.example.com/search?q=x",
  parameter: "q",
  description: "The q parameter is reflected without encoding.",
  poc: "https://target.example.com/search?q=<script>alert(1)</script>",
  remediation: "Context-encode all reflected input.",
  agent: "xss-hunter",
  timestamp: "2026-07-01T00:00:00Z",
};

const idor: Finding = {
  id: "BH-002",
  title: "IDOR on invoice endpoint",
  type: "idor",
  severity: "critical",
  cvss: 9.1,
  confirmed: true,
  endpoint: "https://target.example.com/api/invoices/1234",
  description: "Any authenticated user can read any invoice by ID.",
  cve: "CVE-2026-0001",
};

const weakHeaders: Finding = {
  id: "BH-003",
  title: "Missing security headers",
  type: "misconfiguration",
  severity: "low",
  cvss: 3.1,
  confirmed: false,
  url: "https://target.example.com/",
  description: "CSP and X-Frame-Options are not set.",
};

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "bh-report-test-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

async function writeFixture(name: string, data: unknown): Promise<string> {
  const path = join(dir, name);
  await Bun.write(path, JSON.stringify(data));
  return path;
}

async function runCli(argv: string[]) {
  const proc = Bun.spawnSync([process.execPath, GENERATE_REPORT, ...argv], {
    cwd: join(import.meta.dir, ".."),
  });
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

describe("loadFindings", () => {
  it("accepts a bare findings array", async () => {
    const path = await writeFixture("findings.json", [xss]);
    expect(await loadFindings(path)).toEqual([xss]);
  });

  it("accepts a wrapper object with a findings array", async () => {
    const path = await writeFixture("playwright-findings.json", {
      target: "https://target.example.com",
      generated_at: "2026-07-01T00:00:00Z",
      findings: [xss, idor],
    });
    expect(await loadFindings(path)).toEqual([xss, idor]);
  });

  it("merges all *-findings.json files in a directory", async () => {
    await writeFixture("playwright-findings.json", { findings: [xss] });
    await writeFixture("appium-findings.json", [idor]);
    await writeFixture("unrelated.json", [weakHeaders]); // not matched

    // Merged in alphabetical filename order: appium- before playwright-.
    const loaded = await loadFindings(dir);
    expect(loaded).toEqual([idor, xss]);
  });

  it("throws on garbage input", async () => {
    const path = await writeFixture("findings.json", { nope: true });
    expect(loadFindings(path)).rejects.toThrow(/findings/i);
  });

  it("throws on a missing path", async () => {
    expect(loadFindings(join(dir, "missing.json"))).rejects.toThrow(/not found/i);
  });
});

describe("buildReport", () => {
  it("renders one section per finding, sorted by severity, with matching summary counts", async () => {
    const template = await Bun.file(DEFAULT_TEMPLATE).text();
    const report = buildReport({
      findings: [weakHeaders, xss, idor],
      target: "https://target.example.com",
      template,
      date: "2026-07-25",
    });

    // Sorted: critical (IDOR) first, then high (XSS), then low (headers).
    const iIdor = report.indexOf("Finding 1: [CRITICAL] IDOR on invoice endpoint");
    const iXss = report.indexOf("Finding 2: [HIGH] Reflected XSS in search parameter");
    const iLow = report.indexOf("Finding 3: [LOW] Missing security headers");
    expect(iIdor).toBeGreaterThan(-1);
    expect(iXss).toBeGreaterThan(iIdor);
    expect(iLow).toBeGreaterThan(iXss);

    // Summary counts the same population the body renders (all 3 findings).
    expect(report).toContain("**Total Findings:** 3 (2 confirmed, 1 unconfirmed)");
    expect(report).toContain("**Critical/High:** 2");
    expect(report).toContain("3 finding(s)");
    expect(report).toContain("2 confirmed and 1 unconfirmed");

    // Unconfirmed findings are still rendered in the body.
    expect(report).toContain("Unconfirmed — requires manual validation");
    expect(report).toContain("| **Validation Status** | Confirmed |");
  });

  it("enriches missing VRT categories and CVSS vectors, and advises on KEV/EPSS for CVEs", async () => {
    const template = await Bun.file(DEFAULT_TEMPLATE).text();
    const report = buildReport({
      findings: [xss, idor],
      target: "https://target.example.com",
      template,
      date: "2026-07-25",
    });

    expect(report).toContain("| **VRT Category** | Cross-Site Scripting (XSS) |");
    expect(report).toContain("| **VRT Category** | Insecure Direct Object References (IDOR) |");
    expect(report).toContain("`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` *(placeholder");
    expect(report).toContain("CVE-2026-0001 — check the CISA KEV catalog");
  });

  it("respects an existing cvss_vector instead of overwriting it", async () => {
    const template = await Bun.file(DEFAULT_TEMPLATE).text();
    const report = buildReport({
      findings: [{ ...xss, cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" }],
      target: "https://target.example.com",
      template,
      date: "2026-07-25",
    });
    expect(report).toContain("`CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`");
    expect(report).not.toContain("placeholder — verify");
  });
});

describe("generate-report CLI", () => {
  it("generates a multi-finding report end-to-end from a wrapper file", async () => {
    const findingsPath = await writeFixture("playwright-findings.json", {
      target: "https://target.example.com",
      findings: [weakHeaders, idor, xss],
    });
    const outputPath = join(dir, "report.md");

    const { exitCode, stderr } = await runCli([
      "--findings", findingsPath,
      "--target", "https://target.example.com",
      "--output", outputPath,
    ]);
    expect(exitCode).toBe(0);
    expect(stderr).toBe("");

    const report = await Bun.file(outputPath).text();
    expect(report.indexOf("Finding 1: [CRITICAL]")).toBeGreaterThan(-1);
    expect(report.indexOf("Finding 2: [HIGH]")).toBeGreaterThan(report.indexOf("Finding 1: [CRITICAL]"));
    expect(report.indexOf("Finding 3: [LOW]")).toBeGreaterThan(report.indexOf("Finding 2: [HIGH]"));
    expect(report).toContain("**Total Findings:** 3 (2 confirmed, 1 unconfirmed)");
  });

  it("merges a directory of *-findings.json files", async () => {
    await writeFixture("playwright-findings.json", { findings: [xss] });
    await writeFixture("appium-findings.json", { findings: [idor] });
    const outputPath = join(dir, "merged.md");

    const { exitCode } = await runCli([
      "--findings", dir,
      "--target", "https://target.example.com",
      "--output", outputPath,
    ]);
    expect(exitCode).toBe(0);

    const report = await Bun.file(outputPath).text();
    expect(report).toContain("**Total Findings:** 2");
    expect(report).toContain("IDOR on invoice endpoint");
    expect(report).toContain("Reflected XSS in search parameter");
  });

  it("exits non-zero on garbage findings input", async () => {
    const findingsPath = await writeFixture("findings.json", { nope: true });
    const { exitCode, stderr } = await runCli([
      "--findings", findingsPath,
      "--target", "https://target.example.com",
      "--output", join(dir, "never.md"),
    ]);
    expect(exitCode).toBe(1);
    expect(stderr).toMatch(/findings/i);
  });

  it("exits non-zero without required flags", async () => {
    const { exitCode, stderr } = await runCli([]);
    expect(exitCode).toBe(1);
    expect(stderr).toMatch(/Usage/);
  });
});
