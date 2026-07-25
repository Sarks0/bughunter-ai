import { describe, it, expect } from "bun:test";
import { parseFilter } from "../Tools/burp-bridge.ts";

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
});
