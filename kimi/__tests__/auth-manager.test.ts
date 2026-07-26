import { describe, it, expect } from "bun:test";
import { join } from "node:path";

const CLI = join(import.meta.dir, "..", "Tools", "auth-manager.ts");

function runCli(argv: string[]) {
  const proc = Bun.spawnSync([process.execPath, CLI, ...argv], {
    cwd: join(import.meta.dir, ".."),
  });
  return {
    exitCode: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

describe("auth-manager CLI", () => {
  it("--check with no stored session reports it and exits non-zero (no fetch)", () => {
    // Unique target slug: no auth-state.json / storage-state.json can exist.
    const { exitCode, stdout } = runCli(["--target", "http://no-session-bh-regtest.invalid", "--check"]);
    expect(exitCode).toBe(1);
    expect(stdout).toContain("[AUTH CHECK] No stored session");
    expect(stdout).not.toContain("Session valid: true");
  });

  it("--check with an explicit cookie still evaluates the session", async () => {
    // A dead target makes isSessionValid return false — the point is the run
    // is NOT short-circuited by the no-session gate when a cookie is passed.
    const { exitCode, stdout } = runCli([
      "--target",
      "http://no-session-bh-regtest.invalid",
      "--check",
      "--cookie",
      "sid=abc",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("[AUTH CHECK] Session valid: false");
  });
});
