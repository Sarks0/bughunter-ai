import { describe, it, expect } from "bun:test";
import { isInScope, parseBurpScope, loadScopeFromConfig, type Scope } from "../Tools/lib/scope.ts";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

describe("isInScope", () => {
  const scope: Scope = {
    in: ["*.example.com", "https://api.example.com/*", "example.io"],
    out: ["blog.example.com", "https://api.example.com/admin/*"],
  };

  it("allows subdomains matching *.example.com", () => {
    expect(isInScope("https://api.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://foo.bar.example.com/path", scope).inScope).toBe(true);
  });

  it("rejects out-of-scope hosts", () => {
    const result = isInScope("https://blog.example.com/", scope);
    expect(result.inScope).toBe(false);
    expect(result.reason).toContain("OUT OF SCOPE");
  });

  it("rejects hosts not in scope list", () => {
    const result = isInScope("https://evil.com/", scope);
    expect(result.inScope).toBe(false);
    expect(result.reason).toContain("NOT IN SCOPE");
  });

  it("matches URL globs", () => {
    expect(isInScope("https://api.example.com/v1/users", scope).inScope).toBe(true);
  });

  it("respects out-of-scope URL globs", () => {
    const result = isInScope("https://api.example.com/admin/dashboard", scope);
    expect(result.inScope).toBe(false);
    expect(result.reason).toContain("OUT OF SCOPE");
  });

  it("matches exact host", () => {
    expect(isInScope("https://example.io/", scope).inScope).toBe(true);
  });

  it("supports regex literals", () => {
    const regexScope: Scope = { in: ["/.*\\.example\\.com$/"], out: [] };
    expect(isInScope("https://api.example.com/", regexScope).inScope).toBe(true);
    expect(isInScope("https://example.com/", regexScope).inScope).toBe(false);
  });

  it("returns in-scope when no scope is configured", () => {
    const result = isInScope("https://anything.com/", undefined);
    expect(result.inScope).toBe(true);
  });
});

describe("parseBurpScope", () => {
  it("parses simple-mode URL strings", () => {
    const burp = {
      target: {
        scope: {
          advanced_mode: false,
          include: ["https://api.example.com/", "https://app.example.com/"],
          exclude: ["https://admin.example.com/"],
        },
      },
    };
    const scope = parseBurpScope(burp);
    expect(scope.in).toEqual(["https://api.example.com/", "https://app.example.com/"]);
    expect(scope.out).toEqual(["https://admin.example.com/"]);
  });

  it("parses advanced-mode objects", () => {
    const burp = {
      target: {
        scope: {
          advanced_mode: true,
          include: [
            { enabled: true, protocol: "https", host: "api.example.com", port: "443", file: "/v1/*" },
            { enabled: false, protocol: "https", host: "ignored.example.com", port: "443", file: "/*" },
          ],
          exclude: [{ enabled: true, protocol: "https", host: "admin.example.com", port: "443", file: "/" }],
        },
      },
    };
    const scope = parseBurpScope(burp);
    expect(scope.in).toEqual(["https://api.example.com:443/v1/*"]);
    expect(scope.out).toEqual(["https://admin.example.com:443/"]);
  });

  it("handles regex hosts from advanced mode", () => {
    const burp = {
      target: {
        scope: {
          advanced_mode: true,
          include: [{ enabled: true, protocol: "any", host: "^.*\\.example\\.com$", file: "/" }],
          exclude: [],
        },
      },
    };
    const scope = parseBurpScope(burp);
    expect(scope.in).toEqual(["/^.*\\.example\\.com$/"]);
  });
});

describe("loadScopeFromConfig", () => {
  let tmpDir: string;

  it("loads scope_in/scope_out from a config file", async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "bh-scope-"));
    const configPath = join(tmpDir, "target.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        program_name: "Test",
        scope_in: ["*.example.com"],
        scope_out: ["blog.example.com"],
      })
    );

    const scope = await loadScopeFromConfig(configPath);
    expect(scope.in).toEqual(["*.example.com"]);
    expect(scope.out).toEqual(["blog.example.com"]);
    expect(scope.source).toBe(configPath);

    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("merges a burp_scope_file when present", async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "bh-scope-"));
    const configPath = join(tmpDir, "target.json");
    const burpPath = join(tmpDir, "burp.json");

    writeFileSync(
      configPath,
      JSON.stringify({
        scope_in: ["example.com"],
        burp_scope_file: "burp.json",
      })
    );
    writeFileSync(
      burpPath,
      JSON.stringify({
        target: {
          scope: {
            include: ["https://api.example.com/"],
            exclude: ["https://admin.example.com/"],
          },
        },
      })
    );

    const scope = await loadScopeFromConfig(configPath);
    expect(scope.in).toContain("example.com");
    expect(scope.in).toContain("https://api.example.com/");
    expect(scope.out).toContain("https://admin.example.com/");

    rmSync(tmpDir, { recursive: true, force: true });
  });
});
