#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Report generator: aggregates findings and applies the bug bounty report
 * template. Accepts a bare findings array, a wrapper object with a
 * `findings` array, or a directory of `*-findings.json` files (merged).
 * Produces multi-finding reports with one full section per finding,
 * sorted by severity.
 */

import { parseArgs } from "util";
import { readdirSync, statSync } from "fs";
import { join } from "path";
import { TEMPLATES_DIR } from "./lib/paths.ts";
import {
  normalizeFindings,
  sortFindings,
  suggestVrtCategory,
  type Finding,
} from "./lib/finding.ts";

/** Representative CVSS 4.0 base vectors per severity, used only as placeholders. */
const CVSS4_PLACEHOLDER_VECTORS: Record<string, string> = {
  CRITICAL: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
  HIGH: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
  MEDIUM: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  LOW: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
};

const KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

function severityLabel(f: Finding): string {
  const sev = (f.severity || "medium").toUpperCase();
  const cvss = f.cvss ?? 0;
  if (cvss >= 9.0 || sev === "CRITICAL") return "CRITICAL";
  if (cvss >= 7.0 || sev === "HIGH") return "HIGH";
  if (cvss >= 4.0 || sev === "MEDIUM") return "MEDIUM";
  return "LOW";
}

/**
 * Load findings from a file or directory. Files may contain a bare findings
 * array or a wrapper object with a `findings` array. Directories are scanned
 * for `*-findings.json` files, which are merged in alphabetical order.
 */
export async function loadFindings(path: string): Promise<Finding[]> {
  const stat = statSync(path, { throwIfNoEntry: false });
  if (!stat) {
    throw new Error(`Findings path not found: ${path}`);
  }

  if (stat.isDirectory()) {
    const files = readdirSync(path)
      .filter((name) => name.endsWith("-findings.json"))
      .sort();
    const merged: Finding[] = [];
    for (const name of files) {
      const filePath = join(path, name);
      let parsed: unknown;
      try {
        parsed = JSON.parse(await Bun.file(filePath).text());
      } catch {
        throw new Error(`Failed to parse findings JSON: ${filePath}`);
      }
      merged.push(...normalizeFindings(parsed));
    }
    return merged;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await Bun.file(path).text());
  } catch {
    throw new Error(`Failed to parse findings JSON: ${path}`);
  }
  return normalizeFindings(parsed);
}

interface EnrichedFinding extends Finding {
  severity_label: string;
  cvss_vector_placeholder: boolean;
}

/** Fill derived fields: severity label, CVSS vector placeholder, VRT category. */
function enrichFinding(f: Finding): EnrichedFinding {
  const enriched = { ...f, severity_label: severityLabel(f), cvss_vector_placeholder: false };
  if (!enriched.cvss_vector && typeof enriched.cvss === "number") {
    const placeholder = CVSS4_PLACEHOLDER_VECTORS[enriched.severity_label];
    if (placeholder) {
      enriched.cvss_vector = placeholder;
      enriched.cvss_vector_placeholder = true;
    }
  }
  if (!enriched.vrt_category) {
    const suggested = suggestVrtCategory(enriched);
    if (suggested) enriched.vrt_category = suggested;
  }
  return enriched;
}

function findingTitle(f: Finding): string {
  return (
    f.title ||
    `${f.type || "Vulnerability"} in ${f.endpoint || f.url || "unknown endpoint"}`
  );
}

function formatSteps(f: Finding): string {
  return Array.isArray(f.steps_to_reproduce) && f.steps_to_reproduce.length > 0
    ? f.steps_to_reproduce.map((s, i) => `${i + 1}. ${s}`).join("\n")
    : "1. Navigate to the affected URL\n2. Submit the payload\n3. Observe the result";
}

function formatPoc(f: Finding): string {
  let poc = "";
  if (typeof f.poc === "string") {
    poc = f.poc;
  } else if (f.poc && typeof f.poc === "object") {
    poc = `Prompt used: ${f.poc.prompt_used || "N/A"}\nResponse: ${f.poc.response_received || "N/A"}`;
  }
  if (f.evidence) {
    poc += (poc ? "\n\n" : "") + f.evidence;
  }
  return poc || "See reproduction steps above.";
}

function formatReferences(f: Finding): string {
  const refs: string[] = [];
  if (f.id) refs.push(`- Finding ID: ${f.id}`);
  if (f.agent) refs.push(`- Discovered by agent: ${f.agent}`);
  if (f.timestamp) refs.push(`- Timestamp: ${f.timestamp}`);
  if (f.cve) {
    refs.push(
      `- ${f.cve} — check the CISA KEV catalog (${KEV_URL}) and EPSS for current exploitation status.`
    );
  }
  return refs.length > 0 ? refs.join("\n") : "None.";
}

function fill(template: string, placeholder: string, value: string): string {
  // Function replacer so `$` sequences in finding data are inserted literally.
  return template.replaceAll(placeholder, () => value);
}

/** Per-finding section used when the template has a [FINDINGS] placeholder. */
const DEFAULT_FINDING_BLOCK = `
### Finding [FINDING NUMBER]: [[FINDING SEVERITY]] [FINDING TITLE]

| Field | Value |
|-------|-------|
| **Type** | [FINDING TYPE] |
| **Severity** | [FINDING SEVERITY] |
| **CVSS Score** | [CVSS SCORE] |
| **CVSS Vector** | [CVSS VECTOR] |
| **VRT Category** | [VRT CATEGORY] |
| **Validation Status** | [VALIDATION STATUS] |
| **Affected Component** | [COMPONENT] |
| **Parameter** | [PARAMETER] |

#### Description

[DESCRIPTION]

#### Steps to Reproduce

[STEPS TO REPRODUCE]

#### Proof of Concept

[PROOF OF CONCEPT]

#### Impact

[IMPACT]

#### Remediation

[REMEDIATION]

#### References

[REFERENCES]
`;

/** Render one finding into a per-finding template block. */
export function formatFinding(f: EnrichedFinding, index: number, block: string): string {
  const vector = f.cvss_vector
    ? `\`${f.cvss_vector}\`${f.cvss_vector_placeholder ? " *(placeholder — verify against actual metrics)*" : ""}`
    : "N/A";
  const validation = f.confirmed
    ? "Confirmed"
    : "Unconfirmed — requires manual validation";

  let out = block;
  out = fill(out, "[FINDING NUMBER]", String(index + 1));
  out = fill(out, "[FINDING TITLE]", findingTitle(f));
  out = fill(out, "[FINDING SEVERITY]", f.severity_label);
  out = fill(out, "[FINDING TYPE]", f.type || "N/A");
  out = fill(out, "[CVSS SCORE]", String(f.cvss ?? "N/A"));
  out = fill(out, "[CVSS VECTOR]", vector);
  out = fill(out, "[VRT CATEGORY]", f.vrt_category || "N/A");
  out = fill(out, "[VALIDATION STATUS]", validation);
  out = fill(out, "[COMPONENT]", `\`${f.url || f.endpoint || "N/A"}\``);
  out = fill(out, "[PARAMETER]", f.parameter || "N/A");
  out = fill(out, "[DESCRIPTION]", f.description || "No detailed description provided.");
  out = fill(out, "[STEPS TO REPRODUCE]", formatSteps(f));
  out = fill(out, "[PROOF OF CONCEPT]", `\`\`\`\n${formatPoc(f)}\n\`\`\``);
  out = fill(
    out,
    "[IMPACT]",
    f.impact ||
      "An attacker may be able to exploit this issue to compromise confidentiality, integrity, or availability."
  );
  out = fill(
    out,
    "[REMEDIATION]",
    f.remediation || "Apply defense-in-depth controls appropriate to the vulnerability class."
  );
  out = fill(out, "[REFERENCES]", formatReferences(f));
  return out;
}

const FINDING_BLOCK_RE = /<!--\s*BEGIN FINDING\s*-->([\s\S]*?)<!--\s*END FINDING\s*-->/;

export interface ReportOptions {
  findings: Finding[];
  target: string;
  program?: string;
  template: string;
  /** ISO date override (defaults to today); mainly for tests. */
  date?: string;
}

/** Render the full report for a set of findings. */
export function buildReport(options: ReportOptions): string {
  const { target, template } = options;
  const program = options.program || `${target} Bug Bounty`;
  const reportDate = options.date || new Date().toISOString().split("T")[0];

  // Body and summary count the same population: every finding, sorted.
  const findings = sortFindings(options.findings).map(enrichFinding);
  const total = findings.length;
  const confirmed = findings.filter((f) => f.confirmed).length;
  const unconfirmed = total - confirmed;
  const criticalHigh = findings.filter(
    (f) => f.severity_label === "CRITICAL" || f.severity_label === "HIGH"
  ).length;

  const summary =
    total === 0
      ? "No vulnerabilities were identified during this engagement."
      : `This assessment identified ${total} finding(s) in ${program}: ` +
        `${confirmed} confirmed and ${unconfirmed} unconfirmed, ` +
        `including ${criticalHigh} critical/high severity issue(s).`;

  let report = template;
  report = fill(report, "[TARGET PROGRAM]", program);
  report = fill(report, "[TARGET]", target);
  report = fill(report, "[DATE]", reportDate);
  report = fill(report, "[TOTAL FINDINGS]", String(total));
  report = fill(report, "[CRITICAL/HIGH]", String(criticalHigh));
  report = fill(report, "[CONFIRMED FINDINGS]", String(confirmed));
  report = fill(report, "[UNCONFIRMED FINDINGS]", String(unconfirmed));
  report = fill(report, "[SUMMARY SENTENCE]", summary);

  // Backward compatibility with the previous single-finding template shape.
  report = fill(report, "[IMPACT DESCRIPTION]", summary);
  report = fill(report, "[Summary sentence]", summary);
  report = fill(report, "[N]", String(total));
  const first = findings[0];
  report = fill(report, "[SEVERITY]", first ? first.severity_label : "INFO");
  report = fill(report, "[Vulnerability Type]", first?.type || "N/A");
  report = fill(report, "[Component]", first ? first.url || first.endpoint || "N/A" : "N/A");
  report = fill(report, "[Impact]", first?.impact || "N/A");

  const blockMatch = report.match(FINDING_BLOCK_RE);
  if (blockMatch) {
    const block = blockMatch[1];
    const sections = findings.map((f, i) => formatFinding(f, i, block));
    report = report.replace(FINDING_BLOCK_RE, () =>
      sections.length > 0 ? sections.join("\n---\n") : "No findings to report."
    );
  } else if (report.includes("[FINDINGS]")) {
    const sections = findings.map((f, i) => formatFinding(f, i, DEFAULT_FINDING_BLOCK));
    report = fill(
      report,
      "[FINDINGS]",
      sections.length > 0 ? sections.join("\n---\n") : "No findings to report."
    );
  } else if (findings.length > 0) {
    const sections = findings.map((f, i) => formatFinding(f, i, DEFAULT_FINDING_BLOCK));
    report += `\n\n${sections.join("\n---\n")}`;
  }

  return report;
}

async function main(): Promise<void> {
  const { values: args } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      findings: { type: "string" },
      template: { type: "string" },
      target: { type: "string" },
      program: { type: "string" },
      output: { type: "string" },
    },
  });

  if (!args.findings || !args.target) {
    console.error(
      "Usage: bun generate-report.ts --findings <path.json|dir> --target https://target.com [--template path.md] [--program 'Program Name'] --output report.md"
    );
    process.exit(1);
  }

  let findings: Finding[];
  try {
    findings = await loadFindings(args.findings);
  } catch (err) {
    console.error(`[report] ${(err as Error).message}`);
    process.exit(1);
  }

  const templatePath = args.template || `${TEMPLATES_DIR}/BugReport.md`;
  const templateFile = Bun.file(templatePath);
  if (!(await templateFile.exists())) {
    console.error(`[report] Template not found: ${templatePath}`);
    process.exit(1);
  }
  const template = await templateFile.text();

  const reportDate = new Date().toISOString().split("T")[0];
  const report = buildReport({
    findings,
    target: args.target,
    program: args.program,
    template,
    date: reportDate,
  });

  const outputPath = args.output || `kimi-data/bounty-report-${reportDate}.md`;
  await Bun.write(outputPath, report);
  console.log(`[report] Generated ${outputPath} (${findings.length} findings)`);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[report] Fatal: ${err.message}`);
    process.exit(1);
  });
}
