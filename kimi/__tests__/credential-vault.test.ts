import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  getCredentials,
  actionStore,
  actionGet,
  encryptedBackend,
  plainBackend,
  resolvePassphrase,
  VaultError,
} from "../Tools/credential-vault.ts";

const TEST_PASSPHRASE = "test-passphrase-do-not-use";

/** Build a legacy v1 vault blob: base64 of salt(16) || iv(12) || ciphertext, 100k PBKDF2 iterations. */
async function makeV1VaultBlob(data: object, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 100_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return Buffer.concat([Buffer.from(salt), Buffer.from(iv), Buffer.from(ciphertext)]).toString("base64");
}

/** Capture console.log output produced by fn. */
async function captureStdout(fn: () => Promise<void>): Promise<string> {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    await fn();
  } finally {
    console.log = original;
  }
  return lines.join("\n");
}

describe("credential-vault", () => {
  const savedVaultPath = process.env.BH_VAULT_PATH;
  const savedPassphrase = process.env.BH_VAULT_PASSPHRASE;
  let tempDir: string;
  let vaultFile: string;

  beforeEach(() => {
    // Never touch the real vault: redirect to a fresh temp dir.
    tempDir = mkdtempSync(join(tmpdir(), "bh-vault-test-"));
    vaultFile = join(tempDir, "credentials.enc");
    process.env.BH_VAULT_PATH = vaultFile;
    delete process.env.BH_VAULT_PASSPHRASE;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (savedVaultPath === undefined) delete process.env.BH_VAULT_PATH;
    else process.env.BH_VAULT_PATH = savedVaultPath;
    if (savedPassphrase === undefined) delete process.env.BH_VAULT_PASSPHRASE;
    else process.env.BH_VAULT_PASSPHRASE = savedPassphrase;
  });

  it("stores and retrieves credentials with AES-256-GCM encryption (v2 format)", async () => {
    await actionStore("test-target", { username: "user", password: "secret123" }, encryptedBackend(TEST_PASSPHRASE));

    const envelope = JSON.parse(await Bun.file(vaultFile).text());
    expect(envelope.version).toBe(2);
    expect(envelope.iterations).toBe(210_000);
    expect(typeof envelope.salt).toBe("string");
    expect(typeof envelope.iv).toBe("string");
    expect(typeof envelope.data).toBe("string");
    expect(JSON.stringify(envelope)).not.toContain("secret123");

    const creds = await getCredentials("test-target", TEST_PASSPHRASE);
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("user");
    expect(creds!.password).toBe("secret123");
  });

  it("sets restrictive permissions on the vault file and directory", async () => {
    await actionStore("perm-target", { username: "u", password: "p" }, encryptedBackend(TEST_PASSPHRASE));
    expect(statSync(vaultFile).mode & 0o777).toBe(0o600);
    expect(statSync(tempDir).mode & 0o777).toBe(0o700);
  });

  it("returns null for missing target", async () => {
    const creds = await getCredentials("nonexistent-target", TEST_PASSPHRASE);
    expect(creds).toBeNull();
  });

  it("throws VaultError on wrong passphrase", async () => {
    await actionStore("encrypted-target", { username: "enc-user", password: "enc-secret" }, encryptedBackend(TEST_PASSPHRASE));

    await expect(getCredentials("encrypted-target", "wrong-passphrase")).rejects.toThrow(VaultError);
    await expect(getCredentials("encrypted-target", "wrong-passphrase")).rejects.toThrow(/wrong passphrase/);
  });

  it("reads legacy v1-format vaults (100k iterations)", async () => {
    const blob = await makeV1VaultBlob(
      { "legacy-target": { username: "legacy-user", password: "legacy-secret", updatedAt: new Date().toISOString() } },
      TEST_PASSPHRASE
    );
    await Bun.write(vaultFile, blob);

    const creds = await getCredentials("legacy-target", TEST_PASSPHRASE);
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("legacy-user");
    expect(creds!.password).toBe("legacy-secret");
  });

  it("supports the plaintext backend explicitly", async () => {
    await actionStore("plain-target", { username: "plain-user", password: "plain-secret" }, plainBackend());

    // Plain vaults are readable without a passphrase.
    const creds = await getCredentials("plain-target");
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("plain-user");

    // In encrypted mode the plaintext format is detected and reported
    // distinctly — not misreported as "wrong passphrase".
    await expect(getCredentials("plain-target", TEST_PASSPHRASE)).rejects.toThrow(/plaintext/);
  });

  it("masks secret fields on get by default and reveals them with show", async () => {
    await actionStore("mask-target", { username: "user", password: "hunter2secret3" }, encryptedBackend(TEST_PASSPHRASE));
    const backend = encryptedBackend(TEST_PASSPHRASE);

    const masked = await captureStdout(() => actionGet("mask-target", backend));
    expect(masked).not.toContain("hunter2secret3");
    expect(masked).toContain("h********3"); // first char + mask + last char
    expect(masked).toContain("user"); // non-secret fields stay visible

    const revealed = await captureStdout(() => actionGet("mask-target", backend, { show: true }));
    expect(revealed).toContain("hunter2secret3");
  });

  it("rejects an empty passphrase", async () => {
    await expect(resolvePassphrase({ passphrase: "" })).rejects.toThrow(VaultError);
    await expect(resolvePassphrase({ passphrase: "" })).rejects.toThrow(/may not be empty/);
  });

  it("reads passphrase from environment variable", async () => {
    process.env.BH_VAULT_PASSPHRASE = "env-passphrase";
    await actionStore("env-target", { username: "env-user", password: "env-secret" }, encryptedBackend(process.env.BH_VAULT_PASSPHRASE));

    const creds = await getCredentials("env-target", process.env.BH_VAULT_PASSPHRASE);
    expect(creds).not.toBeNull();
    expect(creds!.username).toBe("env-user");
  });
});
