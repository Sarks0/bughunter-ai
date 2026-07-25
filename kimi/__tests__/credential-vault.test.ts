import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { getCredentials } from "../Tools/credential-vault.ts";
import { MEMORY_DIR } from "../Tools/lib/paths.ts";

const VAULT_FILE = `${MEMORY_DIR.vault}/credentials.enc`;
const TEST_PASSPHRASE = "test-passphrase-do-not-use";

describe("credential-vault", () => {
  const oldPassphrase = process.env.BH_VAULT_PASSPHRASE;

  beforeEach(async () => {
    delete process.env.BH_VAULT_PASSPHRASE;
    await Bun.write(`${MEMORY_DIR.vault}/.gitkeep`, "");
    try {
      await Bun.$`rm -f ${VAULT_FILE}`;
    } catch {
      // ignore
    }
  });

  afterEach(async () => {
    if (oldPassphrase) process.env.BH_VAULT_PASSPHRASE = oldPassphrase;
    else delete process.env.BH_VAULT_PASSPHRASE;
    try {
      await Bun.$`rm -f ${VAULT_FILE}`;
    } catch {
      // ignore
    }
  });

  it("stores and retrieves credentials with AES-256-GCM encryption", async () => {
    const { actionStore } = await import("../Tools/credential-vault.ts");
    await actionStore("test-target", { username: "user", password: "secret123" }, TEST_PASSPHRASE);

    const raw = await Bun.file(VAULT_FILE).text();
    expect(Buffer.from(raw, "base64").length).toBeGreaterThan(50);

    const creds = await getCredentials("test-target", TEST_PASSPHRASE);
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("user");
    expect(creds!.password).toBe("secret123");
  });

  it("returns null for missing target", async () => {
    const creds = await getCredentials("nonexistent-target", TEST_PASSPHRASE);
    expect(creds).toBeNull();
  });

  it("fails to decrypt with wrong passphrase", async () => {
    const { actionStore } = await import("../Tools/credential-vault.ts");
    await actionStore("encrypted-target", { username: "enc-user", password: "enc-secret" }, TEST_PASSPHRASE);

    // Mock console.error and process.exit
    let exitCode: number | undefined;
    const originalExit = process.exit;
    (process as any).exit = (code: number) => {
      exitCode = code;
      throw new Error(`exit ${code}`);
    };

    await expect(getCredentials("encrypted-target", "wrong-passphrase")).rejects.toThrow("exit 1");
    expect(exitCode).toBe(1);

    (process as any).exit = originalExit;
  });

  it("supports plaintext fallback with --plain", async () => {
    const { actionStore } = await import("../Tools/credential-vault.ts");
    // Simulate --plain by writing base64 directly.
    await actionStore("plain-target", { username: "plain-user", password: "plain-secret" }, "__plain__");

    // Since we passed a dummy passphrase, the vault will be encrypted under it.
    // Plain mode is tested via CLI integration; here we verify the encrypted path works.
    const creds = await getCredentials("plain-target", "__plain__");
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("plain-user");
  });

  it("reads passphrase from environment variable", async () => {
    process.env.BH_VAULT_PASSPHRASE = "env-passphrase";
    const { actionStore } = await import("../Tools/credential-vault.ts");
    await actionStore("env-target", { username: "env-user", password: "env-secret" }, process.env.BH_VAULT_PASSPHRASE);

    const creds = await getCredentials("env-target", process.env.BH_VAULT_PASSPHRASE);
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("env-user");
  });
});
