import { describe, it, expect } from "bun:test";
import { isSameOrigin, isOffScopeNavigation, detectAiFeatures, parseExtraHeaders, shouldSendExtraHeaders } from "../Tools/playwright-harness.ts";
import type { Scope } from "../Tools/lib/scope.ts";

describe("playwright-harness isSameOrigin", () => {
  it("accepts URLs on the same origin", () => {
    expect(isSameOrigin("https://example.com/a/b?x=1", "https://example.com")).toBe(true);
  });

  it("rejects lookalike hosts that only share a prefix", () => {
    expect(isSameOrigin("https://example.com.evil.com/x", "https://example.com")).toBe(false);
  });

  it("rejects different schemes and ports", () => {
    expect(isSameOrigin("http://example.com/", "https://example.com")).toBe(false);
    expect(isSameOrigin("https://example.com:8443/", "https://example.com")).toBe(false);
  });

  it("rejects unparseable URLs", () => {
    expect(isSameOrigin("not a url", "https://example.com")).toBe(false);
  });
});

describe("playwright-harness isOffScopeNavigation", () => {
  const scope: Scope = { in: ["dev.example.com"], out: [] };

  it("flags cross-origin redirects (SSO wall scenario)", () => {
    // dev.example.com 302 -> vercel.com/sso-api must be treated as off-scope
    expect(isOffScopeNavigation("https://vercel.com/sso-api?url=x", "https://dev.example.com/new", scope)).toBe(true);
  });

  it("allows same-origin landings", () => {
    expect(isOffScopeNavigation("https://dev.example.com/dashboard", "https://dev.example.com/new", scope)).toBe(false);
  });

  it("respects scope_out even on the same registrable domain", () => {
    const s: Scope = { in: ["*.example.com"], out: ["admin.example.com"] };
    expect(isOffScopeNavigation("https://admin.example.com/panel", "https://example.com", s)).toBe(true);
    expect(isOffScopeNavigation("https://app.example.com/", "https://example.com", s)).toBe(false);
  });

  it("falls back to origin comparison when no scope is configured", () => {
    expect(isOffScopeNavigation("https://evil.com/x", "https://example.com")).toBe(true);
    expect(isOffScopeNavigation("https://example.com/x", "https://example.com")).toBe(false);
  });

  it("ignores about:blank", () => {
    expect(isOffScopeNavigation("about:blank", "https://example.com", scope)).toBe(false);
  });
});

describe("playwright-harness detectAiFeatures", () => {
  it("detects LLM endpoint and provider signatures", () => {
    const html = `<script src="https://cdn.example.com/openai-sdk.js"></script>
      fetch("/v1/chat/completions") // langchain powered`;
    const features = detectAiFeatures(html);
    expect(features).toContain("OpenAI integration");
    expect(features).toContain("LLM chat-completions endpoint");
    expect(features).toContain("LangChain framework");
  });

  it("detects copilot widgets", () => {
    expect(detectAiFeatures('<div class="github-copilot-chat"></div>')).toContain("Copilot widget");
  });

  it("returns an empty list for plain pages", () => {
    expect(detectAiFeatures("<html><body>Hello world</body></html>")).toEqual([]);
  });
});

describe("playwright-harness shouldSendExtraHeaders (origin-scoped header injection)", () => {
  const target = "https://dev.example.com";

  it("allows same-origin URLs when no scope is configured", () => {
    expect(shouldSendExtraHeaders("https://dev.example.com/api/me", target)).toBe(true);
  });

  it("rejects lookalike origins and other hosts (SSO-wall scenario)", () => {
    expect(shouldSendExtraHeaders("https://dev.example.com.evil.com/x", target)).toBe(false);
    expect(shouldSendExtraHeaders("https://vercel.com/sso-api?url=x", target)).toBe(false);
    expect(shouldSendExtraHeaders("http://dev.example.com/x", target)).toBe(false); // different scheme
  });

  it("uses scope when configured: in-scope yes, scope_out no", () => {
    const scope: Scope = { in: ["*.example.com"], out: ["admin.example.com"] };
    expect(shouldSendExtraHeaders("https://app.example.com/x", target, scope)).toBe(true);
    expect(shouldSendExtraHeaders("https://admin.example.com/panel", target, scope)).toBe(false);
    expect(shouldSendExtraHeaders("https://other.org/x", target, scope)).toBe(false);
  });

  it("rejects unparseable URLs", () => {
    expect(shouldSendExtraHeaders("not a url", target)).toBe(false);
  });
});

describe("playwright-harness --header parsing", () => {
  it("splits name/value on the FIRST colon (values may contain colons)", () => {
    expect(parseExtraHeaders(["Authorization: Bearer eyJ:a:b"])).toEqual({ Authorization: "Bearer eyJ:a:b" });
  });

  it("accepts multiple headers and trims whitespace", () => {
    expect(parseExtraHeaders(["X-One: 1", " X-Two : two "])).toEqual({ "X-One": "1", "X-Two": "two" });
  });

  it("rejects entries without a colon", () => {
    expect(() => parseExtraHeaders(["no-colon-here"])).toThrow(/missing colon/);
  });

  it("rejects empty names and empty values", () => {
    expect(() => parseExtraHeaders([": value"])).toThrow(/name is empty/);
    expect(() => parseExtraHeaders(["X-Empty:"])).toThrow(/empty/);
  });

  it("lets a later entry overwrite an earlier one case-insensitively", () => {
    expect(parseExtraHeaders(["x-token: old", "X-Token: new"])).toEqual({ "X-Token": "new" });
  });
});
