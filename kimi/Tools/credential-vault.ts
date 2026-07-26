#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Secure credential vault.
 *
 * Credentials are encrypted by default using AES-256-GCM with a key derived
 * from a user passphrase via PBKDF2-SHA-256. New vaults are written in
 * format version 2 (210,000 KDF iterations, per the OWASP 2024
 * recommendation); legacy version-1 vaults (100,000 iterations, raw
 * base64 salt||iv||ciphertext layout) remain readable.
 *
 * Vault location:
 *   Default: <repo-root>/kimi-data/Vault/credentials.enc
 *   Override the file with BH_VAULT_PATH (absolute path) or the directory
 *   with BH_VAULT_DIR. Tests MUST set one of these so they never touch the
 *   real vault. After each write the file is chmod 600 and the directory
 *   chmod 700 (best-effort; a warning is printed on non-POSIX systems).
 *
 * Passphrase sources (in order of precedence):
 *   1. --passphrase flag (not recommended; leaks to shell history)
 *   2. --passphrase-file <path>
 *   3. BH_VAULT_PASSPHRASE environment variable
 *   4. Interactive prompt (if stdin is a TTY)
 *
 * Use --plain only as an explicit insecure fallback for testing/legacy.
 *
 * Library use: all exported functions throw VaultError on failure instead
 * of exiting the process. Only the CLI entry point (main) calls
 * process.exit.
 */

import { parseArgs } from "util";
import { existsSync, mkdirSync } from "fs";
import { chmod } from "fs/promises";
import { dirname, join } from "path";
import { MEMORY_DIR } from "./lib/paths.ts";

const PASSPHRASE_ENV = "BH_VAULT_PASSPHRASE";
const VAULT_PATH_ENV = "BH_VAULT_PATH";
const VAULT_DIR_ENV = "BH_VAULT_DIR";

const FORMAT_VERSION = 2;
const KDF_ITERATIONS = 210_000;
const V1_KDF_ITERATIONS = 100_000;

/** Error type thrown by all vault operations. The CLI catches it and exits 1. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

interface Credential {
  username?: string;
  password?: string;
  cookie?: string;
  apiKey?: string;
  jwt?: string;
  otpSeed?: string;
  creditCard?: string;
  updatedAt: string;
}

type VaultData = Record<string, Credential>;

const SECRET_FIELDS = ["password", "cookie", "apiKey", "jwt", "otpSeed", "creditCard"] as const;

function vaultDir(): string {
  const fileOverride = process.env[VAULT_PATH_ENV];
  if (fileOverride) return dirname(fileOverride);
  return process.env[VAULT_DIR_ENV] || MEMORY_DIR.vault;
}

function vaultFile(): string {
  return process.env[VAULT_PATH_ENV] || join(vaultDir(), "credentials.enc");
}

async function deriveKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function encodePlain(data: VaultData): string {
  return Buffer.from(JSON.stringify(data, null, 2), "utf-8").toString("base64");
}

function decodePlain(raw: string): VaultData {
  return JSON.parse(Buffer.from(raw, "base64").toString("utf-8")) as VaultData;
}

async function encodeEncrypted(data: VaultData, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, KDF_ITERATIONS);
  const encoder = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(data)));
  return JSON.stringify({
    version: FORMAT_VERSION,
    iterations: KDF_ITERATIONS,
    salt: Buffer.from(salt).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    data: Buffer.from(ciphertext).toString("base64"),
  });
}

async function decodeEncrypted(raw: string, passphrase: string): Promise<VaultData> {
  // Version 2: JSON envelope with explicit KDF parameters.
  let envelope: unknown;
  try {
    envelope = JSON.parse(raw);
  } catch {
    envelope = undefined;
  }
  if (envelope && typeof envelope === "object" && "version" in envelope) {
    const env = envelope as Record<string, unknown>;
    if (
      env.version !== FORMAT_VERSION ||
      typeof env.iterations !== "number" ||
      typeof env.salt !== "string" ||
      typeof env.iv !== "string" ||
      typeof env.data !== "string"
    ) {
      throw new VaultError("corrupt vault: unrecognized or malformed versioned format");
    }
    const key = await deriveKey(
      passphrase,
      new Uint8Array(Buffer.from(env.salt, "base64")),
      env.iterations
    );
    let decrypted: ArrayBuffer;
    try {
      decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(Buffer.from(env.iv, "base64")) },
        key,
        new Uint8Array(Buffer.from(env.data, "base64"))
      );
    } catch {
      throw new VaultError("failed to decrypt vault: wrong passphrase");
    }
    try {
      return JSON.parse(new TextDecoder().decode(decrypted)) as VaultData;
    } catch {
      throw new VaultError("corrupt vault: decrypted payload is not valid JSON");
    }
  }

  // A plaintext (--plain) vault is base64-encoded JSON; detect it explicitly
  // so it is not misreported as "wrong passphrase".
  try {
    decodePlain(raw);
    throw new VaultError(
      "vault file is in plaintext (--plain) format; re-run with --plain to read it or store fresh credentials to migrate"
    );
  } catch (err) {
    if (err instanceof VaultError) throw err;
    // Not plaintext — fall through to the legacy encrypted layout.
  }

  // Version 1 (legacy): base64 of salt(16) || iv(12) || ciphertext, 100k iterations.
  const buf = Buffer.from(raw, "base64");
  if (buf.length < 29) {
    throw new VaultError("corrupt vault: file is too short to be an encrypted vault");
  }
  const salt = buf.subarray(0, 16);
  const iv = buf.subarray(16, 28);
  const ciphertext = buf.subarray(28);
  const key = await deriveKey(passphrase, new Uint8Array(salt), V1_KDF_ITERATIONS);
  let decrypted: ArrayBuffer;
  try {
    decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, key, new Uint8Array(ciphertext));
  } catch {
    throw new VaultError("failed to decrypt vault: wrong passphrase or corrupt vault file");
  }
  try {
    return JSON.parse(new TextDecoder().decode(decrypted)) as VaultData;
  } catch {
    throw new VaultError("corrupt vault: decrypted payload is not valid JSON");
  }
}

function ensureVaultDir(): void {
  const dir = vaultDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/** Best-effort POSIX hardening: 700 on the vault dir, 600 on the vault file. */
async function secureVaultPermissions(): Promise<void> {
  try {
    await chmod(vaultFile(), 0o600);
    await chmod(vaultDir(), 0o700);
  } catch (err) {
    console.error(
      `[vault] WARNING: could not set restrictive permissions on the vault (non-POSIX system?): ${
        err instanceof Error ? err.message : err
      }`
    );
  }
}

async function readPassphraseFromFile(filePath: string): Promise<string> {
  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    throw new VaultError(`Passphrase file not found: ${filePath}`);
  }
  return (await file.text()).trim();
}

async function promptPassphrase(prompt = "Vault passphrase: "): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new VaultError(
      "Cannot prompt for passphrase in non-interactive mode. " +
        "Set BH_VAULT_PASSPHRASE, use --passphrase-file, or pass --passphrase."
    );
  }

  process.stdout.write(prompt);

  return new Promise((resolve, reject) => {
    try {
      process.stdin.setRawMode(true);
    } catch (err) {
      reject(new VaultError(`Failed to set raw mode on stdin: ${err instanceof Error ? err.message : err}`));
      return;
    }
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    let input = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (code === 3) {
          // Ctrl+C (interactive CLI prompt — exiting here is intentional)
          process.stdout.write("\n");
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off("data", onData);
          process.exit(130);
        }
        if (code === 13 || code === 10) {
          // Enter
          process.stdout.write("\n");
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off("data", onData);
          resolve(input);
          return;
        }
        if (code === 127) {
          // Backspace
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write("\b \b");
          }
          continue;
        }
        input += ch;
        process.stdout.write("*");
      }
    };

    process.stdin.on("data", onData);
  });
}

export async function resolvePassphrase(values: {
  passphrase?: string;
  "passphrase-file"?: string;
}): Promise<string> {
  if (values.passphrase !== undefined) {
    if (values.passphrase === "") {
      throw new VaultError("passphrase may not be empty");
    }
    console.error(
      "[vault] WARNING: --passphrase exposes the secret in shell history. Prefer BH_VAULT_PASSPHRASE or --passphrase-file."
    );
    return values.passphrase;
  }
  if (values["passphrase-file"]) {
    const fromFile = await readPassphraseFromFile(values["passphrase-file"]);
    if (fromFile === "") {
      throw new VaultError("passphrase may not be empty");
    }
    return fromFile;
  }
  const env = process.env[PASSPHRASE_ENV];
  if (env) return env;
  return promptPassphrase();
}

/**
 * A storage backend for the vault. Every operation (store/get/list/delete/
 * redact) is implemented once and parameterized by a backend.
 */
export interface VaultBackend {
  read(): Promise<VaultData>;
  write(data: VaultData): Promise<void>;
}

/** Default encrypted backend (AES-256-GCM, passphrase-derived key). */
export function encryptedBackend(passphrase: string): VaultBackend {
  return {
    read: () => readVault(passphrase),
    write: (data) => writeVault(data, passphrase),
  };
}

/** Insecure plaintext (base64-only) backend — explicit testing/legacy fallback. */
export function plainBackend(): VaultBackend {
  return {
    read: () => readVault(),
    write: async (data) => {
      ensureVaultDir();
      await Bun.write(vaultFile(), encodePlain(data));
      await secureVaultPermissions();
    },
  };
}

async function readVault(passphrase?: string): Promise<VaultData> {
  ensureVaultDir();
  const file = Bun.file(vaultFile());
  if (!(await file.exists())) return {};
  const raw = await file.text();
  if (!raw.trim()) return {};

  if (passphrase) {
    return decodeEncrypted(raw.trim(), passphrase);
  }

  // Without a passphrase, only plaintext (legacy --plain) files are readable.
  try {
    return decodePlain(raw.trim());
  } catch {
    throw new VaultError("vault appears encrypted but no passphrase was provided");
  }
}

async function writeVault(data: VaultData, passphrase: string): Promise<void> {
  ensureVaultDir();
  const encoded = await encodeEncrypted(data, passphrase);
  await Bun.write(vaultFile(), encoded);
  await secureVaultPermissions();
}

async function pull1PasswordItem(itemName: string): Promise<Partial<Credential>> {
  const which = Bun.spawnSync(["which", "op"]);
  if (which.exitCode !== 0) {
    throw new VaultError("`op` CLI not found. Install 1Password CLI to use --op-item.");
  }

  const proc = Bun.spawnSync(["op", "item", "get", itemName, "--format", "json"]);
  if (proc.exitCode !== 0) {
    const stderr = proc.stderr.toString().trim();
    throw new VaultError(`1Password lookup failed: ${stderr || "unknown error"}`);
  }

  const item = JSON.parse(proc.stdout.toString());
  const cred: Partial<Credential> = {};

  for (const field of item.fields ?? []) {
    const label = (field.label ?? "").toLowerCase();
    const value = field.value ?? "";
    if (!value) continue;

    if (label === "username") cred.username = value;
    else if (label === "password") cred.password = value;
    else if (label === "cookie") cred.cookie = value;
    else if (label.includes("api") && label.includes("key")) cred.apiKey = value;
    else if (label === "jwt" || label === "token") cred.jwt = value;
    else if (label.includes("otp") || label.includes("totp")) cred.otpSeed = value;
    else if (label.includes("credit") && label.includes("card")) cred.creditCard = value;
  }

  return cred;
}

function applyEnvOverrides(cred: Credential): Credential {
  const env = process.env;
  return {
    ...cred,
    username: env.HUNT_USER ?? cred.username,
    password: env.HUNT_PASS ?? cred.password,
    cookie: env.HUNT_COOKIE ?? cred.cookie,
    apiKey: env.HUNT_API_KEY ?? cred.apiKey,
  };
}

function warnIfExposed(cred: Credential): void {
  const secrets = SECRET_FIELDS.map((f) => cred[f]).filter(Boolean) as string[];
  if (secrets.length > 0) {
    console.error(
      "[vault] WARNING: Credential values returned. Ensure they do not leak into logs, prompts, or reports. Use --redact to sanitize files."
    );
  }
}

/** Mask a secret value, keeping only the first and last character: `h********3`. */
function maskSecret(value: string): string {
  if (value.length <= 2) return "*".repeat(8);
  return `${value[0]}${"*".repeat(8)}${value[value.length - 1]}`;
}

function maskCredential(cred: Credential): Credential {
  const masked = { ...cred };
  for (const field of SECRET_FIELDS) {
    const value = masked[field];
    if (value) masked[field] = maskSecret(value);
  }
  return masked;
}

export async function getCredentials(targetSlug: string, passphrase?: string): Promise<Credential | null> {
  const vault = await readVault(passphrase);
  const cred = vault[targetSlug];
  if (!cred) return null;
  const resolved = applyEnvOverrides(cred);
  warnIfExposed(resolved);
  return resolved;
}

export async function actionStore(
  target: string,
  fields: Partial<Credential>,
  backend: VaultBackend,
  opItem?: string
): Promise<void> {
  const vault = await backend.read();
  const existing = vault[target] ?? ({} as Credential);

  let opCreds: Partial<Credential> = {};
  if (opItem) {
    opCreds = await pull1PasswordItem(opItem);
  }

  vault[target] = {
    username: fields.username ?? opCreds.username ?? existing.username,
    password: fields.password ?? opCreds.password ?? existing.password,
    cookie: fields.cookie ?? opCreds.cookie ?? existing.cookie,
    apiKey: fields.apiKey ?? opCreds.apiKey ?? existing.apiKey,
    jwt: fields.jwt ?? opCreds.jwt ?? existing.jwt,
    otpSeed: fields.otpSeed ?? opCreds.otpSeed ?? existing.otpSeed,
    creditCard: fields.creditCard ?? opCreds.creditCard ?? existing.creditCard,
    updatedAt: new Date().toISOString(),
  };

  await backend.write(vault);
  console.log(`[vault] Stored credentials for "${target}"`);
}

export async function actionGet(
  target: string,
  backend: VaultBackend,
  options: { field?: keyof Credential; show?: boolean } = {}
): Promise<void> {
  const vault = await backend.read();
  const cred = vault[target];
  if (!cred) {
    throw new VaultError(`No credentials found for "${target}"`);
  }
  const resolved = applyEnvOverrides(cred);
  if (options.field) {
    // An explicit --field request prints the raw value.
    warnIfExposed(resolved);
    console.log(resolved[options.field] ?? "");
  } else if (options.show) {
    warnIfExposed(resolved);
    console.log(JSON.stringify(resolved, null, 2));
  } else {
    // Default: show keys, mask secret values.
    console.log(JSON.stringify(maskCredential(resolved), null, 2));
  }
}

export async function actionList(backend: VaultBackend): Promise<void> {
  const vault = await backend.read();
  const targets = Object.keys(vault);
  if (targets.length === 0) {
    console.log("[vault] No stored targets.");
    return;
  }
  console.log("[vault] Stored targets:");
  for (const t of targets) {
    console.log(`  - ${t}  (updated: ${vault[t].updatedAt})`);
  }
}

export async function actionDelete(target: string, backend: VaultBackend): Promise<void> {
  const vault = await backend.read();
  if (!(target in vault)) {
    throw new VaultError(`Target "${target}" not found.`);
  }
  delete vault[target];
  await backend.write(vault);
  console.log(`[vault] Deleted credentials for "${target}"`);
}

/** Replace every stored secret value in `content` with [REDACTED]. */
function redactContent(content: string, vault: VaultData): { content: string; replacements: number } {
  let replacements = 0;
  for (const cred of Object.values(vault)) {
    const secrets = SECRET_FIELDS.map((f) => cred[f]).filter(Boolean) as string[];
    for (const secret of secrets) {
      if (secret.length < 4) continue;
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(escaped, "g");
      const matches = content.match(regex);
      if (matches) {
        replacements += matches.length;
        content = content.replace(regex, "[REDACTED]");
      }
    }
  }
  return { content, replacements };
}

export async function actionRedact(filePath: string, backend: VaultBackend): Promise<void> {
  const vault = await backend.read();
  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    throw new VaultError(`File not found: ${filePath}`);
  }

  const { content, replacements } = redactContent(await file.text(), vault);
  await Bun.write(filePath, content);
  console.log(`[vault] Redacted ${replacements} secret(s) in ${filePath}`);
}

async function actionRotate(oldPassphrase: string, newPassphrase: string): Promise<void> {
  ensureVaultDir();
  const file = Bun.file(vaultFile());
  if (!(await file.exists())) {
    throw new VaultError("No vault file to rotate.");
  }

  const raw = await file.text();
  if (!raw.trim()) {
    throw new VaultError("Vault is empty.");
  }

  const data = await decodeEncrypted(raw.trim(), oldPassphrase);
  await writeVault(data, newPassphrase);
  console.log("[vault] Vault re-encrypted with new passphrase");
}

function usage(): string {
  return `credential-vault — BugHunter AI Credential Manager

Usage:
  --store   --target <name> [--username <u>] [--password <p>] [--cookie <c>]
            [--api-key <k>] [--jwt <j>] [--otp-seed <s>] [--credit-card <cc>]
            [--op-item <item>]
  --get     --target <name> [--field <field>] [--show]
  --list
  --delete  --target <name>
  --redact  --file <path>
  --rotate  [--old-passphrase <p>] [--new-passphrase <p>]

Encryption options (in order of precedence):
  --passphrase <string>              # least secure (shell history)
  --passphrase-file <path>           # read from file
  BH_VAULT_PASSPHRASE env var        # recommended for scripts
  interactive prompt                 # default when no other source given

Vault location:
  BH_VAULT_PATH env var              # absolute path to the vault file
  BH_VAULT_DIR env var               # vault directory (default: kimi-data/Vault)

Insecure fallback:
  --plain                            # base64-only storage (not recommended)

Environment overrides: HUNT_USER, HUNT_PASS, HUNT_COOKIE, HUNT_API_KEY`;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      store: { type: "boolean", default: false },
      get: { type: "boolean", default: false },
      list: { type: "boolean", default: false },
      delete: { type: "boolean", default: false },
      redact: { type: "boolean", default: false },
      rotate: { type: "boolean", default: false },
      plain: { type: "boolean", default: false },
      show: { type: "boolean", default: false },
      target: { type: "string" },
      username: { type: "string" },
      password: { type: "string" },
      cookie: { type: "string" },
      "api-key": { type: "string" },
      jwt: { type: "string" },
      "otp-seed": { type: "string" },
      "credit-card": { type: "string" },
      "op-item": { type: "string" },
      file: { type: "string" },
      field: { type: "string" },
      passphrase: { type: "string" },
      "passphrase-file": { type: "string" },
      "old-passphrase": { type: "string" },
      "new-passphrase": { type: "string" },
    },
    strict: true,
  });

  const needsTarget = values.store || values.get || values.delete;
  if (needsTarget && !values.target) {
    throw new VaultError("--target is required for --store, --get, and --delete");
  }
  if (values.redact && !values.file) {
    throw new VaultError("--file is required for --redact");
  }

  // Rotate uses explicit old/new passphrases, not a backend — handle it
  // before any passphrase resolution.
  if (values.rotate) {
    if (values.plain) {
      throw new VaultError("--rotate is only supported for encrypted vaults");
    }
    const oldPassphrase = values["old-passphrase"] ?? (await promptPassphrase("Old vault passphrase: "));
    const newPassphrase = values["new-passphrase"] ?? (await promptPassphrase("New vault passphrase: "));
    if (oldPassphrase === "" || newPassphrase === "") {
      throw new VaultError("passphrase may not be empty");
    }
    await actionRotate(oldPassphrase, newPassphrase);
    return;
  }

  // Select the backend: encrypted by default, --plain as an explicit
  // insecure fallback. All operations are backend-agnostic.
  let backend: VaultBackend;
  if (values.plain) {
    console.error(
      "[vault] SECURITY WARNING: --plain stores credentials with base64 encoding only. " +
        "This is not secure and should only be used for testing."
    );
    backend = plainBackend();
  } else {
    const passphrase = await resolvePassphrase(values);
    backend = encryptedBackend(passphrase);
  }

  if (values.store) {
    await actionStore(
      values.target!,
      {
        username: values.username,
        password: values.password,
        cookie: values.cookie,
        apiKey: values["api-key"],
        jwt: values.jwt,
        otpSeed: values["otp-seed"],
        creditCard: values["credit-card"],
      },
      backend,
      values["op-item"]
    );
  } else if (values.get) {
    await actionGet(values.target!, backend, {
      field: values.field as keyof Credential | undefined,
      show: values.show,
    });
  } else if (values.list) {
    await actionList(backend);
  } else if (values.delete) {
    await actionDelete(values.target!, backend);
  } else if (values.redact) {
    await actionRedact(values.file!, backend);
  } else {
    console.log(usage());
  }
}

if (import.meta.main) {
  main().catch((err) => {
    if (err instanceof VaultError) {
      console.error(`[vault] ERROR: ${err.message}`);
    } else {
      console.error(`[vault] Fatal: ${err instanceof Error ? err.message : err}`);
    }
    process.exit(1);
  });
}
