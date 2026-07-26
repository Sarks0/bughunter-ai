import { describe, it, expect } from "bun:test";
import { severityFromCvss, toSharedFinding } from "../Tools/appium-harness.ts";
import { toSlug } from "../Tools/lib/paths.ts";

describe("appium-harness severityFromCvss (same bands as generate-report)", () => {
  it("maps CVSS scores to severity labels", () => {
    expect(severityFromCvss(9.8)).toBe("critical");
    expect(severityFromCvss(9.0)).toBe("critical");
    expect(severityFromCvss(8.1)).toBe("high");
    expect(severityFromCvss(7.0)).toBe("high");
    expect(severityFromCvss(5.3)).toBe("medium");
    expect(severityFromCvss(4.0)).toBe("medium");
    expect(severityFromCvss(2.0)).toBe("low");
  });
});

describe("appium-harness toSharedFinding", () => {
  it("maps MobileFinding to the shared Finding fields (title, severity, cvss)", () => {
    const shared = toSharedFinding({
      type: "INSECURE_CONTENT_PROVIDER",
      platform: "android",
      component: "com.example.provider",
      description: "Exported content provider allows unauthenticated data access",
      cvss_estimate: 8.1,
      poc: 'adb shell content query --uri "content://com.example/"',
      confirmed: true,
    });
    expect(shared.title).toBe("Insecure Content Provider");
    expect(shared.severity).toBe("high");
    expect(shared.cvss).toBe(8.1);
    // Mobile-specific fields survive the mapping.
    expect(shared.cvss_estimate).toBe(8.1);
    expect(shared.platform).toBe("android");
    expect(shared.component).toBe("com.example.provider");
  });
});

describe("appium-harness slug (canonical paths.toSlug)", () => {
  it("strips trailing dashes (the old local copy did not)", () => {
    expect(toSlug("https://example.com/")).toBe("example-com");
  });
});
