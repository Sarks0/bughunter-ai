import { describe, it, expect } from "bun:test";
import { isInScope, assertInScope, ScopeError, parseBurpScope, loadScopeFromConfig, type Scope } from "../Tools/lib/scope.ts";
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

describe("host glob semantics", () => {
  it("apex pattern matches the apex host only, not subdomains", () => {
    const scope: Scope = { in: ["example.com"], out: [] };
    expect(isInScope("https://example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://www.example.com/", scope).inScope).toBe(false);
    expect(isInScope("https://deep.sub.example.com/", scope).inScope).toBe(false);
  });

  it("*.example.com matches the apex AND any depth of subdomain", () => {
    const scope: Scope = { in: ["*.example.com"], out: [] };
    expect(isInScope("https://example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://www.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://a.b.c.example.com/", scope).inScope).toBe(true);
  });

  it("in-label * matches within a single label only (regression: cdn*.example.com)", () => {
    const scope: Scope = { in: ["cdn*.example.com"], out: [] };
    expect(isInScope("https://cdn1.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://cdn-eu.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://cdn.example.com/", scope).inScope).toBe(true);
    // Must not cross a dot boundary.
    expect(isInScope("https://cdn.foo.example.com/", scope).inScope).toBe(false);
    expect(isInScope("https://other.example.com/", scope).inScope).toBe(false);
  });

  it("in-label ? matches exactly one character within a label", () => {
    const scope: Scope = { in: ["api?.example.com"], out: [] };
    expect(isInScope("https://api1.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://api2.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://api12.example.com/", scope).inScope).toBe(false);
    expect(isInScope("https://api.example.com/", scope).inScope).toBe(false);
    expect(isInScope("https://api1.foo.example.com/", scope).inScope).toBe(false);
  });

  it("matching is case-insensitive on the host", () => {
    const scope: Scope = { in: ["*.Example.COM"], out: [] };
    expect(isInScope("https://WWW.EXAMPLE.COM/", scope).inScope).toBe(true);
  });

  it("rejects evil-suffix hosts for both apex and wildcard patterns", () => {
    const apexScope: Scope = { in: ["example.com"], out: [] };
    const wildScope: Scope = { in: ["*.example.com"], out: [] };
    expect(isInScope("https://example.com.evil.com/", apexScope).inScope).toBe(false);
    expect(isInScope("https://example.com.evil.com/", wildScope).inScope).toBe(false);
    expect(isInScope("https://www.example.com.evil.com/", wildScope).inScope).toBe(false);
  });
});

describe("URL glob semantics", () => {
  const scope: Scope = { in: ["https://api.example.com/*"], out: [] };

  it("matches any path on the origin", () => {
    expect(isInScope("https://api.example.com/", scope).inScope).toBe(true);
    expect(isInScope("https://api.example.com/v1/users", scope).inScope).toBe(true);
    expect(isInScope("https://api.example.com/a/b/c?x=1", scope).inScope).toBe(true);
  });

  it("does not match an evil-suffix host", () => {
    expect(isInScope("https://api.example.com.evil.com/x", scope).inScope).toBe(false);
  });

  it("does not match a different scheme or host", () => {
    expect(isInScope("https://other.example.com/v1", scope).inScope).toBe(false);
    expect(isInScope("http://api.example.com/v1", scope).inScope).toBe(false);
  });

  it("anchored URL pattern without trailing glob still rejects host extension", () => {
    const bareScope: Scope = { in: ["https://api.example.com"], out: [] };
    expect(isInScope("https://api.example.com/", bareScope).inScope).toBe(true);
    expect(isInScope("https://api.example.com/path", bareScope).inScope).toBe(true);
    expect(isInScope("https://api.example.com.evil.com/x", bareScope).inScope).toBe(false);
  });
});

describe("out-of-scope precedence", () => {
  it("out patterns win even when an in pattern also matches", () => {
    const scope: Scope = { in: ["*.example.com"], out: ["example.com"] };
    expect(isInScope("https://example.com/", scope).inScope).toBe(false);
    expect(isInScope("https://www.example.com/", scope).inScope).toBe(true);
  });

  it("out URL globs win over broader in host globs", () => {
    const scope: Scope = { in: ["*.example.com"], out: ["https://api.example.com/admin/*"] };
    const result = isInScope("https://api.example.com/admin/panel", scope);
    expect(result.inScope).toBe(false);
    expect(result.reason).toContain("OUT OF SCOPE");
    expect(isInScope("https://api.example.com/public", scope).inScope).toBe(true);
  });
});

describe("assertInScope", () => {
  const scope: Scope = { in: ["*.example.com"], out: ["blog.example.com"] };

  it("returns normally for in-scope URLs", () => {
    expect(() => assertInScope("https://api.example.com/v1", scope)).not.toThrow();
    expect(() => assertInScope("https://example.com/", scope)).not.toThrow();
  });

  it("throws ScopeError for URLs matching no in-scope pattern", () => {
    expect(() => assertInScope("https://evil.com/", scope)).toThrow(ScopeError);
    expect(() => assertInScope("https://evil.com/", scope)).toThrow(/NOT IN SCOPE/);
  });

  it("throws ScopeError for out-of-scope URLs, with target and reason attached", () => {
    try {
      assertInScope("https://blog.example.com/", scope);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ScopeError);
      expect(err).toBeInstanceOf(Error);
      const scopeErr = err as ScopeError;
      expect(scopeErr.name).toBe("ScopeError");
      expect(scopeErr.target).toBe("https://blog.example.com/");
      expect(scopeErr.reason).toContain("OUT OF SCOPE");
      expect(scopeErr.message).toContain("blog.example.com");
    }
  });

  it("does not throw when no scope is configured", () => {
    expect(() => assertInScope("https://anything.example/", { in: [], out: [] })).not.toThrow();
  });
});
