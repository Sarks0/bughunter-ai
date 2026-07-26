import { describe, it, expect } from "bun:test";
import { parseFilter, filterNewInteractions, interactionId } from "../Tools/burp-bridge.ts";

describe("burp-bridge", () => {
  it("parses empty filter", () => {
    expect(parseFilter("")).toEqual({});
  });

  it("parses string filters", () => {
    expect(parseFilter("method:POST,url:/api")).toEqual({ method: "POST", url: "/api" });
  });

  it("parses numeric status filter", () => {
    expect(parseFilter("status:200")).toEqual({ status: 200 });
  });

  it("trims whitespace", () => {
    expect(parseFilter(" method: POST , status: 404 ")).toEqual({ method: "POST", status: 404 });
  });

  it("splits on the first colon only, keeping colons in values", () => {
    expect(parseFilter("url:http://example.com:8080/api")).toEqual({ url: "http://example.com:8080/api" });
    expect(parseFilter("method:POST,url:https://x/y")).toEqual({ method: "POST", url: "https://x/y" });
  });
});

describe("collaborator dedup", () => {
  it("prefers the interaction id field for identity", () => {
    expect(interactionId({ type: "dns", id: "abc123" })).toBe("abc123");
    expect(interactionId({ type: "http", interaction_id: 42 })).toBe("42");
  });

  it("falls back to content identity when no id is present", () => {
    const a = { type: "dns", client_ip: "1.2.3.4" };
    expect(interactionId(a)).toBe(JSON.stringify(a));
  });

  it("yields only interactions not seen in earlier polls", () => {
    const seen = new Set<string>();
    const i1 = { type: "dns", id: "1" };
    const i2 = { type: "http", id: "2" };
    const i3 = { type: "smtp", id: "3" };

    // First poll returns everything.
    expect(filterNewInteractions([i1, i2], seen)).toEqual([i1, i2]);
    // Second poll returns ALL interactions again plus one new one.
    expect(filterNewInteractions([i1, i2, i3], seen)).toEqual([i3]);
    // Third poll with nothing new yields nothing.
    expect(filterNewInteractions([i1, i2, i3], seen)).toEqual([]);
  });
});
