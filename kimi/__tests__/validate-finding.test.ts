import { describe, it, expect, beforeAll, afterAll, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  applyVerdict,
  bodySimilarity,
  buildSummary,
  classifyFinding,
  compareIdorResponses,
  compareSqliResponses,
  containsSqlError,
  extractEvidenceMarker,
  extractPayload,
  injectPayloadIntoUrl,
  loadSessionAuth,
  oobEvidenceVerdict,
  runValidation,
  validateFinding,
  type ValidationContext,
  type ValidatorConfig,
} from "../Tools/validate-finding.ts";
import { getSessionDir } from "../Tools/lib/paths.ts";
import type { Finding } from "../Tools/lib/finding.ts";

const VALIDATE_FINDING = join(import.meta.dir, "..", "Tools", "validate-finding.ts");

// ---------------------------------------------------------------------------
// Fixture HTTP server — no external network
// ---------------------------------------------------------------------------

let server: ReturnType<typeof Bun.serve>;
let base: string;

function html(body: string, status = 200): Response {
  return new Response(`<html><body>${body}</body></html>`, {
    status,
    headers: { "content-type": "text/html" },
  });
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);
      const authed = (req.headers.get("cookie") ?? "").includes("session=valid");
      switch (url.pathname) {
        case "/echo":
          // Reflects the q parameter unencoded.
          return html(`<div>${url.searchParams.get("q") ?? ""}</div>`);
        case "/clean":
          return html("<div>nothing here</div>");
        case "/sqli": {
          const id = url.searchParams.get("id") ?? "";
          if (id.includes("'")) {
            return new Response(
              "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
              { status: 500 }
            );
          }
          return new Response("results: 1 row (user alice)");
        }
        case "/idor":
          // Broken: identical confidential body regardless of authentication.
          return new Response("INVOICE #42 — CONFIDENTIAL customer data");
        case "/idor-secure":
          // Correct: rejects unauthenticated requests.
          return authed
            ? new Response("INVOICE #42 — CONFIDENTIAL customer data")
            : new Response("Unauthorized", { status: 401 });
        default:
          return new Response("not found", { status: 404 });
      }
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

const SESSION_SLUG = `bh-validate-test-${process.pid}`;

function testConfig(overrides: Partial<ValidatorConfig> = {}): ValidatorConfig {
  return {
    timeoutMs: 3000,
    noBrowser: true,
    proxy: "",
    noSandbox: true,
    headless: true,
    requestDelayMs: 0,
    ...overrides,
  };
}

function makeCtx(overrides: Partial<ValidationContext> = {}): ValidationContext {
  return {
    target: base,
    sessionSlug: SESSION_SLUG,
    config: testConfig(),
    ...overrides,
  };
}

// Clean up the temporary session dir under kimi-data/Sessions (never a real session).
afterEach(() => {
  rmSync(getSessionDir(SESSION_SLUG), { recursive: true, force: true });
});

function finding(overrides: Partial<Finding>): Finding {
  return {
    title: "Test finding",
    severity: "medium",
    cvss: 5.0,
    confirmed: false,
    description: "test",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Pure decision logic
// ---------------------------------------------------------------------------

describe("classifyFinding", () => {
  it("dispatches on title/type keywords", () => {
    expect(classifyFinding(finding({ title: "Reflected XSS in search parameter" }))).toBe("xss");
    expect(classifyFinding(finding({ title: "Cross-site scripting via comment field" }))).toBe("xss");
    expect(classifyFinding(finding({ title: "SQL injection in id parameter" }))).toBe("sqli");
    expect(classifyFinding(finding({ title: "Error-based sqli", type: "sqli" }))).toBe("sqli");
    expect(classifyFinding(finding({ title: "IDOR on invoice endpoint" }))).toBe("idor");
    expect(classifyFinding(finding({ title: "Authentication bypass on admin panel" }))).toBe("idor");
    expect(classifyFinding(finding({ title: "SSRF via webhook URL" }))).toBe("oob");
    expect(classifyFinding(finding({ title: "XXE in SVG upload" }))).toBe("oob");
    expect(classifyFinding(finding({ title: "Blind command injection in ping form" }))).toBe("oob");
    expect(classifyFinding(finding({ title: "Missing security headers" }))).toBe("generic");
  });
});

describe("containsSqlError", () => {
  it("matches common database error signatures", () => {
    expect(containsSqlError("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")).toBe(true);
    expect(containsSqlError("ORA-00933: SQL command not properly ended")).toBe(true);
    expect(containsSqlError("unclosed quotation mark after the character string")).toBe(true);
    expect(containsSqlError("results: 1 row (user alice)")).toBe(false);
  });
});

describe("bodySimilarity", () => {
  it("is 1 for identical bodies and scales with length difference", () => {
    expect(bodySimilarity("abc", "abc")).toBe(1);
    expect(bodySimilarity("aaaa", "aa")).toBe(0.5);
    expect(bodySimilarity("", "")).toBe(1);
  });
});

describe("compareSqliResponses", () => {
  const control = { status: 200, body: "results: 1 row (user alice)" };

  it("validates when only the payload response shows a SQL error", () => {
    const verdict = compareSqliResponses(
      { status: 500, body: "You have an error in your SQL syntax; check the manual ..." },
      control
    );
    expect(verdict.status).toBe("validated");
  });

  it("is inconclusive when both responses show a SQL error", () => {
    const verdict = compareSqliResponses(
      { status: 500, body: "You have an error in your SQL syntax" },
      { status: 500, body: "You have an error in your SQL syntax near SELECT" }
    );
    expect(verdict.status).toBe("inconclusive");
  });

  it("refutes when the payload has no observable effect", () => {
    expect(compareSqliResponses(control, { ...control }).status).toBe("refuted");
  });

  it("validates on a large boolean/length differential", () => {
    const verdict = compareSqliResponses(
      { status: 200, body: "results: " + "x".repeat(500) },
      control
    );
    expect(verdict.status).toBe("validated");
  });

  it("is inconclusive on a minor difference", () => {
    const verdict = compareSqliResponses(
      { status: 200, body: "results: 1 row (user alice) " },
      control
    );
    expect(verdict.status).toBe("inconclusive");
  });
});

describe("compareIdorResponses", () => {
  const authed = { status: 200, body: "INVOICE #42 — CONFIDENTIAL customer data" };

  it("validates when unauthenticated access returns a near-identical 200", () => {
    expect(compareIdorResponses(authed, { ...authed }).status).toBe("validated");
  });

  it("refutes when unauthenticated access is rejected", () => {
    expect(compareIdorResponses(authed, { status: 401, body: "Unauthorized" }).status).toBe("refuted");
    expect(compareIdorResponses(authed, { status: 403, body: "Forbidden" }).status).toBe("refuted");
    expect(compareIdorResponses(authed, { status: 302, body: "" }).status).toBe("refuted");
  });

  it("is inconclusive when the authenticated baseline fails", () => {
    expect(compareIdorResponses({ status: 500, body: "err" }, { ...authed }).status).toBe("inconclusive");
  });

  it("is inconclusive when bodies diverge too much (possible error page)", () => {
    const verdict = compareIdorResponses(authed, { status: 200, body: "x".repeat(500) });
    expect(verdict.status).toBe("inconclusive");
  });
});

describe("oobEvidenceVerdict", () => {
  it("validates only with a documented received callback", () => {
    const verdict = oobEvidenceVerdict(
      finding({
        title: "SSRF via webhook URL",
        evidence: "Received DNS lookup callback on abc123.oast.fun from the target server",
      })
    );
    expect(verdict.status).toBe("validated");
  });

  it("is inconclusive with a callback token but no received interaction", () => {
    const verdict = oobEvidenceVerdict(
      finding({ title: "SSRF", evidence: "Payload fired at http://abc123.oast.fun/" })
    );
    expect(verdict.status).toBe("inconclusive");
  });

  it("is inconclusive with no callback evidence at all", () => {
    const verdict = oobEvidenceVerdict(finding({ title: "SSRF", evidence: "The server fetched the URL" }));
    expect(verdict.status).toBe("inconclusive");
    expect(verdict.evidence).toMatch(/never|credible|callback/i);
  });
});

describe("payload/marker extraction", () => {
  it("extractPayload prefers a non-URL poc, then the parameter value in the URL", () => {
    expect(extractPayload(finding({ poc: "' OR 1=1--" }))).toBe("' OR 1=1--");
    expect(
      extractPayload(
        finding({ url: "https://t.example/q?id=INJECTED&x=1", parameter: "id" })
      )
    ).toBe("INJECTED");
    expect(extractPayload(finding({ poc: "https://t.example/q?a=1&b=PAYLOAD" }))).toBe("PAYLOAD");
  });

  it("extractEvidenceMarker uses poc or the longest quoted token in evidence", () => {
    expect(extractEvidenceMarker(finding({ poc: "CANARY123" }))).toBe("CANARY123");
    expect(extractEvidenceMarker(finding({ evidence: 'Response contains "SECRET_TOKEN_XYZ" unmasked' }))).toBe(
      "SECRET_TOKEN_XYZ"
    );
    expect(extractEvidenceMarker(finding({}))).toBeNull();
  });

  it("injectPayloadIntoUrl replaces the named parameter", () => {
    const injected = new URL(injectPayloadIntoUrl("https://t.example/q?id=1&x=2", "id", "'"));
    expect(injected.searchParams.get("id")).toBe("'");
    expect(injected.searchParams.get("x")).toBe("2");
    expect(injected.searchParams.getAll("id")).toHaveLength(1);
  });
});

describe("applyVerdict", () => {
  it("sets confirmed only for validated findings and downgrades otherwise", () => {
    const f = finding({ confirmed: true });
    expect(applyVerdict(f, "validated", "ok", "now").confirmed).toBe(true);

    const downgraded = applyVerdict(f, "inconclusive", "meh", "now");
    expect(downgraded.confirmed).toBe(false);
    expect(downgraded.validation_evidence).toContain("downgraded");

    const refuted = applyVerdict(f, "refuted", "no", "now");
    expect(refuted.confirmed).toBe(false);

    const skipped = applyVerdict(f, "skipped_out_of_scope", "skip", "now");
    expect(skipped.confirmed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Strategies against the fixture server
// ---------------------------------------------------------------------------

describe("generic strategy (evidence re-check)", () => {
  it("validates when the key evidence string is still present", async () => {
    const f = finding({
      title: "Sensitive token exposed",
      url: `${base}/echo?q=CANARY123`,
      poc: "CANARY123",
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("validated");
    expect(result.confirmed).toBe(true);
    expect(result.validated_at).toBeTruthy();
  });

  it("refutes when the evidence string is absent", async () => {
    const f = finding({
      title: "Sensitive token exposed",
      url: `${base}/clean`,
      poc: "CANARY123",
      confirmed: true,
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("refuted");
    expect(result.confirmed).toBe(false);
  });

  it("is inconclusive when the request fails", async () => {
    const f = finding({
      title: "Sensitive token exposed",
      url: "http://127.0.0.1:1/unreachable",
      poc: "CANARY123",
      confirmed: true,
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("inconclusive");
    expect(result.confirmed).toBe(false);
    expect(result.validation_evidence).toContain("downgraded");
  });

  it("is inconclusive without a machine-checkable evidence string", async () => {
    const f = finding({ title: "Vague issue", url: `${base}/clean` });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("inconclusive");
  });
});

describe("sqli strategy (differential re-test)", () => {
  it("validates when only the payload triggers a SQL error", async () => {
    const f = finding({
      title: "SQL injection in id parameter",
      url: `${base}/sqli?id=1`,
      parameter: "id",
      poc: "'",
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("validated");
    expect(result.confirmed).toBe(true);
    expect(result.validation_evidence).toMatch(/SQL error/);
  });

  it("refutes when the payload has no effect", async () => {
    const f = finding({
      title: "SQL injection in id parameter",
      url: `${base}/sqli?id=1`,
      parameter: "id",
      poc: "1",
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("refuted");
  });
});

describe("idor strategy (authed vs unauthed)", () => {
  async function writeSessionState(): Promise<void> {
    const dir = getSessionDir(SESSION_SLUG);
    await Bun.write(
      join(dir, "storage-state.json"),
      JSON.stringify({
        cookies: [
          { name: "session", value: "valid", domain: "127.0.0.1", path: "/", expires: -1 },
        ],
        origins: [],
      })
    );
  }

  it("is inconclusive without session auth state", async () => {
    const f = finding({ title: "IDOR on invoice endpoint", url: `${base}/idor` });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("inconclusive");
    expect(result.validation_evidence).toMatch(/auth state/i);
  });

  it("validates when unauthenticated access returns the same resource", async () => {
    await writeSessionState();
    const auth = await loadSessionAuth(SESSION_SLUG, "127.0.0.1");
    expect(auth.cookieHeader).toContain("session=valid");

    const f = finding({ title: "IDOR on invoice endpoint", url: `${base}/idor` });
    const result = await validateFinding(f, makeCtx({ cookieHeader: auth.cookieHeader }));
    expect(result.validation_status).toBe("validated");
    expect(result.confirmed).toBe(true);
  });

  it("refutes when unauthenticated access is rejected", async () => {
    await writeSessionState();
    const auth = await loadSessionAuth(SESSION_SLUG, "127.0.0.1");
    const f = finding({ title: "IDOR on invoice endpoint", url: `${base}/idor-secure`, confirmed: true });
    const result = await validateFinding(f, makeCtx({ cookieHeader: auth.cookieHeader }));
    expect(result.validation_status).toBe("refuted");
    expect(result.confirmed).toBe(false);
  });
});

describe("oob strategy (evidence-based)", () => {
  it("validates documented callbacks without sending requests", async () => {
    const f = finding({
      title: "SSRF via webhook URL",
      url: `${base}/clean`,
      evidence: "HTTP interaction received on collaborator abc123.burpcollaborator.net from target",
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("validated");
    expect(result.confirmed).toBe(true);
  });
});

describe("scope gate", () => {
  it("skips findings whose URL fails isInScope and sends no requests", async () => {
    const f = finding({
      title: "Sensitive token exposed",
      url: `${base}/echo?q=CANARY123`,
      poc: "CANARY123",
      confirmed: true,
    });
    const ctx = makeCtx({ scope: { in: ["example.com"], out: [] } });
    const result = await validateFinding(f, ctx);
    expect(result.validation_status).toBe("skipped_out_of_scope");
    expect(result.confirmed).toBe(false);
  });

  it("validates in-scope findings normally", async () => {
    const f = finding({
      title: "Sensitive token exposed",
      url: `${base}/echo?q=CANARY123`,
      poc: "CANARY123",
    });
    const ctx = makeCtx({ scope: { in: ["127.0.0.1"], out: [] } });
    const result = await validateFinding(f, ctx);
    expect(result.validation_status).toBe("validated");
  });
});

describe("runValidation + buildSummary", () => {
  it("validates a batch sequentially and produces consistent counts", async () => {
    const findings: Finding[] = [
      finding({ title: "Token exposed", url: `${base}/echo?q=CANARY123`, poc: "CANARY123" }),
      finding({ title: "Token exposed 2", url: `${base}/clean`, poc: "CANARY123" }),
      finding({ title: "Token exposed 3", url: "http://127.0.0.1:1/x", poc: "CANARY123" }),
      finding({ title: "SSRF", url: `${base}/clean`, evidence: "no callback" }),
    ];
    const results = await runValidation(findings, makeCtx());
    expect(results).toHaveLength(4);
    const summary = buildSummary(results);
    expect(summary).toEqual({ total: 4, validated: 1, refuted: 1, inconclusive: 2, skipped: 0 });
  });

  it("keeps running when a finding has no usable URL", async () => {
    const findings: Finding[] = [
      finding({ title: "No URL at all" }),
      finding({ title: "Token exposed", url: `${base}/echo?q=CANARY123`, poc: "CANARY123" }),
    ];
    const results = await runValidation(findings, makeCtx());
    expect(results[0].validation_status).toBe("inconclusive");
    expect(results[1].validation_status).toBe("validated");
  });
});

// ---------------------------------------------------------------------------
// XSS browser strategy (gated on chromium availability)
// ---------------------------------------------------------------------------

let chromiumAvailable = false;

beforeAll(async () => {
  try {
    const { chromium } = await import("playwright");
    const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
    await browser.close();
    chromiumAvailable = true;
  } catch {
    chromiumAvailable = false;
  }
});

describe("xss strategy (browser)", () => {
  it("validates an executing payload via the __xss_confirmed marker", async () => {
    if (!chromiumAvailable) {
      console.log("[skip] chromium not available — XSS browser test not run");
      return;
    }
    const payload = `<img src=x onerror="window.__xss_confirmed=true">`;
    const f = finding({
      title: "Reflected XSS in q parameter",
      url: `${base}/echo?q=${encodeURIComponent(payload)}`,
      parameter: "q",
      poc: payload,
    });
    const result = await validateFinding(f, makeCtx({ config: testConfig({ noBrowser: false }) }));
    expect(result.validation_status).toBe("validated");
    expect(result.confirmed).toBe(true);
  });

  it("falls back to inconclusive with --no-browser", async () => {
    const f = finding({
      title: "Reflected XSS in q parameter",
      url: `${base}/echo?q=x`,
      poc: "<script>alert(1)</script>",
    });
    const result = await validateFinding(f, makeCtx());
    expect(result.validation_status).toBe("inconclusive");
    expect(result.validation_evidence).toMatch(/--no-browser/);
  });
});

// ---------------------------------------------------------------------------
// CLI end-to-end
// ---------------------------------------------------------------------------

let tmpDir: string;

// NOTE: must be async — spawnSync would block the event loop and starve the
// in-process fixture server the CLI subprocess talks to.
async function runCli(argv: string[]) {
  const proc = Bun.spawn([process.execPath, VALIDATE_FINDING, ...argv], {
    cwd: join(import.meta.dir, ".."),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe("validate-finding CLI", () => {
  afterEach(() => {
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });
  });

  async function writeFixture(name: string, data: unknown): Promise<string> {
    tmpDir = mkdtempSync(join(tmpdir(), "bh-validate-test-"));
    const path = join(tmpDir, name);
    await Bun.write(path, JSON.stringify(data));
    return path;
  }

  const generic = (suffix: string, url: string): Finding =>
    finding({ title: `Token exposed ${suffix}`, url, poc: "CANARY123" });

  it("validates a wrapper file and writes the output wrapper with consistent summary", async () => {
    const findingsPath = await writeFixture("input-findings.json", {
      target: base,
      findings: [generic("a", `${base}/echo?q=CANARY123`), generic("b", `${base}/clean`)],
    });
    const outputPath = join(tmpDir, "out.json");
    const { exitCode } = await runCli([
      "--findings", findingsPath,
      "--target", base,
      "--output", outputPath,
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);

    const report = JSON.parse(await Bun.file(outputPath).text());
    expect(report.target).toBe(base);
    expect(report.generated_at).toBeTruthy();
    expect(report.summary).toEqual({ total: 2, validated: 1, refuted: 1, inconclusive: 0, skipped: 0 });
    expect(report.findings).toHaveLength(2);
    expect(report.findings[0].validation_status).toBe("validated");
    expect(report.findings[0].confirmed).toBe(true);
    expect(report.findings[1].validation_status).toBe("refuted");
    expect(report.findings[1].confirmed).toBe(false);
  });

  it("accepts a bare findings array", async () => {
    const findingsPath = await writeFixture("bare.json", [generic("a", `${base}/echo?q=CANARY123`)]);
    const outputPath = join(tmpDir, "out.json");
    const { exitCode } = await runCli([
      "--findings", findingsPath,
      "--target", base,
      "--output", outputPath,
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);
    const report = JSON.parse(await Bun.file(outputPath).text());
    expect(report.summary.validated).toBe(1);
  });

  it("merges a directory of *-findings.json files", async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "bh-validate-test-"));
    await Bun.write(join(tmpDir, "a-findings.json"), JSON.stringify([generic("a", `${base}/echo?q=CANARY123`)]));
    await Bun.write(join(tmpDir, "b-findings.json"), JSON.stringify({ findings: [generic("b", `${base}/clean`)] }));
    await Bun.write(join(tmpDir, "unrelated.json"), JSON.stringify([generic("c", `${base}/clean`)]));

    const outputPath = join(tmpDir, "out.json");
    const { exitCode } = await runCli([
      "--findings", tmpDir,
      "--target", base,
      "--output", outputPath,
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);
    const report = JSON.parse(await Bun.file(outputPath).text());
    expect(report.summary.total).toBe(2);
  });

  it("writes to the default session findings path when --output is omitted", async () => {
    const findingsPath = await writeFixture("input.json", [generic("a", `${base}/echo?q=CANARY123`)]);
    const { exitCode } = await runCli([
      "--findings", findingsPath,
      "--target", base,
      "--session", SESSION_SLUG,
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);
    const expected = join(getSessionDir(SESSION_SLUG), "findings", "validated-findings.json");
    const report = JSON.parse(await Bun.file(expected).text());
    expect(report.summary.validated).toBe(1);
  });

  it("warns on stderr when no --scope-config is provided", async () => {
    const findingsPath = await writeFixture("input.json", [generic("a", `${base}/echo?q=CANARY123`)]);
    const { exitCode, stderr } = await runCli([
      "--findings", findingsPath,
      "--target", base,
      "--output", join(tmpDir, "out.json"),
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);
    expect(stderr).toMatch(/WARNING: no --scope-config/);
  });

  it("skips out-of-scope findings when a scope config is supplied", async () => {
    const findingsPath = await writeFixture("input.json", [generic("a", `${base}/echo?q=CANARY123`)]);
    const scopePath = join(tmpDir, "scope.json");
    await Bun.write(scopePath, JSON.stringify({ scope_in: ["example.com"], scope_out: [] }));

    const outputPath = join(tmpDir, "out.json");
    const { exitCode, stdout } = await runCli([
      "--findings", findingsPath,
      "--target", base,
      "--output", outputPath,
      "--scope-config", scopePath,
      "--no-browser",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/Scope enforcement active/);
    const report = JSON.parse(await Bun.file(outputPath).text());
    expect(report.summary).toEqual({ total: 1, validated: 0, refuted: 0, inconclusive: 0, skipped: 1 });
    expect(report.findings[0].validation_status).toBe("skipped_out_of_scope");
  });

  it("exits non-zero without required flags", async () => {
    const { exitCode, stderr } = await runCli([]);
    expect(exitCode).toBe(1);
    expect(stderr).toMatch(/Usage/);
  });
});
