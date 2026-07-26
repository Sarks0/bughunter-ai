import { describe, it, expect } from "bun:test";
import { isSameOrigin, detectAiFeatures } from "../Tools/playwright-harness.ts";

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
