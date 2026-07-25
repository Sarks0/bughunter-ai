#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Report generator: aggregates findings and applies the bug bounty report template.
 */

import { parseArgs } from "util";
import { TEMPLATES_DIR } from "./lib/paths.ts";

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

interface Finding {
  id?: string;
  type?: string;
  subtype?: string;
  severity?: string;
  cvss?: number;
  title?: string;
  description?: string;
  endpoint?: string;
  url?: string;
  parameter?: string;
  poc?: string | { prompt_used?: string; response_received?: string };
  steps_to_reproduce?: string[];
  impact?: string;
  remediation?: string;
  confirmed?: boolean;
  timestamp?: string;
}

function severityLabel(f: Finding): string {
  const sev = (f.severity || "medium").toUpperCase();
  const cvss = f.cvss ?? 0;
  if (cvss >= 9.0 || sev === "CRITICAL") return "CRITICAL";
  if (cvss >= 7.0 || sev === "HIGH") return "HIGH";
  if (cvss >= 4.0 || sev === "MEDIUM") return "MEDIUM";
  return "LOW";
}

function formatFinding(f: Finding, index: number): string {
  const title = f.title || `${f.type || "Vulnerability"} in ${f.endpoint || f.url || "unknown endpoint"}`;
  const sev = severityLabel(f);
  const url = f.url || f.endpoint || "N/A";
  const param = f.parameter || "N/A";
  const auth = "See reproduction steps";

  let poc = "";
  if (typeof f.poc === "string") {
    poc = f.poc;
  } else if (f.poc && typeof f.poc === "object") {
    poc = `Prompt used: ${f.poc.prompt_used || "N/A"}\nResponse: ${f.poc.response_received || "N/A"}`;
  }

  const steps = Array.isArray(f.steps_to_reproduce) && f.steps_to_reproduce.length > 0
    ? f.steps_to_reproduce.map((s, i) => `${i + 1}. ${s}`).join("\n")
    : "1. Navigate to the affected URL\n2. Submit the payload\n3. Observe the result";

  return `
## Finding ${index + 1}: [${sev}] ${title}

| Field | Value |
|-------|-------|
| **Type** | ${f.type || "N/A"} |
| **Severity** | ${sev} |
| **CVSS Score** | ${f.cvss ?? "N/A"} |
| **Affected URL** | \`${url}\` |
| **Parameter** | ${param} |
| **Authentication** | ${auth} |

### Description
${f.description || "No detailed description provided."}

### Steps to Reproduce
${steps}

### Proof of Concept
\`\`\`
${poc || "See reproduction steps above."}
\`\`\`

### Impact
${f.impact || "An attacker may be able to exploit this issue to compromise confidentiality, integrity, or availability."}

### Remediation
${f.remediation || "Apply defense-in-depth controls appropriate to the vulnerability class."}

---
`;
}

async function main(): Promise<void> {
  if (!args.findings || !args.target) {
    console.error("Usage: bun generate-report.ts --findings path.json --target https://target.com [--template path.md] [--program 'Program Name'] --output report.md");
    process.exit(1);
  }

  const findingsFile = Bun.file(args.findings);
  if (!(await findingsFile.exists())) {
    console.error(`[report] Findings file not found: ${args.findings}`);
    process.exit(1);
  }

  let findings: Finding[];
  try {
    findings = JSON.parse(await findingsFile.text());
  } catch {
    console.error("[report] Failed to parse findings JSON");
    process.exit(1);
  }

  if (!Array.isArray(findings)) {
    console.error("[report] Findings file must contain a JSON array");
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
  const program = args.program || `${args.target} Bug Bounty`;

  const findingsBody = findings
    .filter((f) => f.confirmed !== false)
    .map((f, i) => formatFinding(f, i))
    .join("\n");

  const summary = findings.length === 0
    ? "No confirmed vulnerabilities were identified during this engagement."
    : `This assessment identified ${findings.length} finding(s) in ${program}.`;

  let report = template
    .replace(/\[TARGET PROGRAM\]/g, program)
    .replace(/\[TARGET\]/g, args.target)
    .replace(/\[DATE\]/g, reportDate)
    .replace(/\[IMPACT DESCRIPTION\]/g, summary)
    .replace(/\[SEVERITY\]/g, findings.length > 0 ? severityLabel(findings[0]) : "INFO")
    .replace(/\[Vulnerability Type\]/g, findings[0]?.type || "N/A")
    .replace(/\[Component\]/g, findings[0]?.endpoint || findings[0]?.url || "N/A")
    .replace(/\[Impact\]/g, findings[0]?.impact || "N/A");

  // Insert findings section after the Summary section if the template has a placeholder.
  if (report.includes("[FINDINGS]")) {
    report = report.replace("[FINDINGS]", findingsBody);
  } else {
    report += `\n\n${findingsBody}`;
  }

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
