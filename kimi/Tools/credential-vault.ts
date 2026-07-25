#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Secure credential vault.
 *
 * Credentials are encrypted by default using AES-256-GCM with a key derived
 * from a user passphrase via PBKDF2 (100k iterations, SHA-256).
 *
 * Passphrase sources (in order of precedence):
 *   1. --passphrase flag (not recommended; leaks to shell history)
 *   2. --passphrase-file <path>
 *   3. BH_VAULT_PASSPHRASE environment variable
 *   4. Interactive prompt (if stdin is a TTY)
 *
 * Use --plain only as an explicit insecure fallback for testing/legacy.
 */

import { parseArgs } from "util";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import { MEMORY_DIR } from "./lib/paths.ts";

const VAULT_DIR = MEMORY_DIR.vault;
const VAULT_FILE = join(VAULT_DIR, "credentials.enc");
const PASSPHRASE_ENV = "BH_VAULT_PASSPHRASE";

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

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 100_000, hash: "SHA-256" },
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
  const key = await deriveKey(passphrase, salt);
  const encoder = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(data)));
  const payload = Buffer.concat([Buffer.from(salt), Buffer.from(iv), Buffer.from(ciphertext)]);
  return payload.toString("base64");
}

async function decodeEncrypted(raw: string, passphrase: string): Promise<VaultData> {
  const buf = Buffer.from(raw, "base64");
  const salt = buf.subarray(0, 16);
  const iv = buf.subarray(16, 28);
  const ciphertext = buf.subarray(28);
  const key = await deriveKey(passphrase, salt);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(decrypted)) as VaultData;
}

function ensureVaultDir(): void {
  if (!existsSync(VAULT_DIR)) {
    mkdirSync(VAULT_DIR, { recursive: true });
  }
}

async function readPassphraseFromFile(filePath: string): Promise<string> {
  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    throw new Error(`Passphrase file not found: ${filePath}`);
  }
  return (await file.text()).trim();
}

async function promptPassphrase(prompt = "Vault passphrase: "): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      "Cannot prompt for passphrase in non-interactive mode. " +
        "Set BH_VAULT_PASSPHRASE, use --passphrase-file, or pass --passphrase."
    );
  }

  process.stdout.write(prompt);

  return new Promise((resolve, reject) => {
    try {
      process.stdin.setRawMode(true);
    } catch (err) {
      reject(new Error(`Failed to set raw mode on stdin: ${err instanceof Error ? err.message : err}`));
      return;
    }
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    let input = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (code === 3) {
          // Ctrl+C
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

async function resolvePassphrase(values: {
  passphrase?: string;
  "passphrase-file"?: string;
  "old-passphrase"?: string;
  "new-passphrase"?: string;
}): Promise<string> {
  if (values.passphrase) {
    console.error(
      "[vault] WARNING: --passphrase exposes the secret in shell history. Prefer BH_VAULT_PASSPHRASE or --passphrase-file."
    );
    return values.passphrase;
  }
  if (values["passphrase-file"]) {
    return readPassphraseFromFile(values["passphrase-file"]);
  }
  const env = process.env[PASSPHRASE_ENV];
  if (env) return env;
  return promptPassphrase();
}

async function readVault(passphrase?: string): Promise<VaultData> {
  ensureVaultDir();
  const file = Bun.file(VAULT_FILE);
  if (!(await file.exists())) return {};
  const raw = await file.text();
  if (!raw.trim()) return {};

  if (passphrase) {
    try {
      return await decodeEncrypted(raw.trim(), passphrase);
    } catch {
      console.error("[vault] ERROR: failed to decrypt vault (wrong passphrase or corrupt file)");
      process.exit(1);
    }
  }

  // Without a passphrase, attempt plaintext for legacy files.
  try {
    return decodePlain(raw.trim());
  } catch {
    console.error("[vault] ERROR: vault appears encrypted but no passphrase was provided");
    process.exit(1);
  }
}

async function writeVault(data: VaultData, passphrase: string): Promise<void> {
  ensureVaultDir();
  const encoded = await encodeEncrypted(data, passphrase);
  await Bun.write(VAULT_FILE, encoded);
}

async function pull1PasswordItem(itemName: string): Promise<Partial<Credential>> {
  const which = Bun.spawnSync(["which", "op"]);
  if (which.exitCode !== 0) {
    throw new Error("`op` CLI not found. Install 1Password CLI to use --op-item.");
  }

  const proc = Bun.spawnSync(["op", "item", "get", itemName, "--format", "json"]);
  if (proc.exitCode !== 0) {
    const stderr = proc.stderr.toString().trim();
    throw new Error(`1Password lookup failed: ${stderr || "unknown error"}`);
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
    else if (label.includes("credit") || label.includes("card")) cred.creditCard = value;
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
  const secrets = [cred.password, cred.cookie, cred.apiKey, cred.jwt, cred.otpSeed, cred.creditCard].filter(
    Boolean
  ) as string[];
  if (secrets.length > 0) {
    console.error(
      "[vault] WARNING: Credential values returned. Ensure they do not leak into logs, prompts, or reports. Use --redact to sanitize files."
    );
  }
}

async function buildCredential(
  target: string,
  fields: Partial<Credential>,
  opItem?: string
): Promise<Credential> {
  let opCreds: Partial<Credential> = {};
  if (opItem) {
    opCreds = await pull1PasswordItem(opItem);
  }

  // Load existing only if vault already exists.
  let existing: Partial<Credential> = {};
  const file = Bun.file(VAULT_FILE);
  if (await file.exists()) {
    // We cannot decrypt here without passphrase; existing merge is done by caller.
  }

  return {
    username: fields.username ?? opCreds.username ?? existing.username,
    password: fields.password ?? opCreds.password ?? existing.password,
    cookie: fields.cookie ?? opCreds.cookie ?? existing.cookie,
    apiKey: fields.apiKey ?? opCreds.apiKey ?? existing.apiKey,
    jwt: fields.jwt ?? opCreds.jwt ?? existing.jwt,
    otpSeed: fields.otpSeed ?? opCreds.otpSeed ?? existing.otpSeed,
    creditCard: fields.creditCard ?? opCreds.creditCard ?? existing.creditCard,
    updatedAt: new Date().toISOString(),
  };
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
  passphrase: string,
  opItem?: string
): Promise<void> {
  const vault = await readVault(passphrase);
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

  await writeVault(vault, passphrase);
  console.log(`[vault] Stored encrypted credentials for "${target}"`);
}

async function actionGet(target: string, passphrase: string, field?: keyof Credential): Promise<void> {
  const cred = await getCredentials(target, passphrase);
  if (!cred) {
    console.error(`[vault] No credentials found for "${target}"`);
    process.exit(1);
  }
  if (field) {
    console.log(cred[field] ?? "");
  } else {
    console.log(JSON.stringify(cred, null, 2));
  }
}

async function actionList(passphrase: string): Promise<void> {
  const vault = await readVault(passphrase);
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

async function actionDelete(target: string, passphrase: string): Promise<void> {
  const vault = await readVault(passphrase);
  if (!(target in vault)) {
    console.error(`[vault] Target "${target}" not found.`);
    process.exit(1);
  }
  delete vault[target];
  await writeVault(vault, passphrase);
  console.log(`[vault] Deleted credentials for "${target}"`);
}

async function actionRedact(filePath: string, passphrase: string): Promise<void> {
  const vault = await readVault(passphrase);
  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    console.error(`[vault] File not found: ${filePath}`);
    process.exit(1);
  }

  let content = await file.text();
  let replacements = 0;

  for (const cred of Object.values(vault)) {
    const secrets = [cred.password, cred.cookie, cred.apiKey, cred.jwt, cred.otpSeed, cred.creditCard].filter(
      Boolean
    ) as string[];

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

  await Bun.write(filePath, content);
  console.log(`[vault] Redacted ${replacements} secret(s) in ${filePath}`);
}

async function actionRotate(oldPassphrase: string, newPassphrase: string): Promise<void> {
  ensureVaultDir();
  const file = Bun.file(VAULT_FILE);
  if (!(await file.exists())) {
    console.error("[vault] No vault file to rotate.");
    process.exit(1);
  }

  const raw = await file.text();
  if (!raw.trim()) {
    console.error("[vault] Vault is empty.");
    process.exit(1);
  }

  let data: VaultData;
  try {
    data = await decodeEncrypted(raw.trim(), oldPassphrase);
  } catch {
    console.error("[vault] ERROR: failed to decrypt vault with old passphrase");
    process.exit(1);
  }

  await writeVault(data, newPassphrase);
  console.log("[vault] Vault re-encrypted with new passphrase");
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

  // Plaintext legacy mode
  if (values.plain) {
    console.error(
      "[vault] SECURITY WARNING: --plain stores credentials with base64 encoding only. " +
        "This is not secure and should only be used for testing."
    );

    const runPlain = async (operation: () => Promise<void>) => {
      // Temporarily disable encryption by using an empty passphrase handler.
      await operation();
    };

    if (values.store) {
      if (!values.target) {
        console.error("[vault] --target is required for --store");
        process.exit(1);
      }
      const vault = await readVault();
      const existing = vault[values.target] ?? ({} as Credential);
      vault[values.target] = {
        username: values.username ?? existing.username,
        password: values.password ?? existing.password,
        cookie: values.cookie ?? existing.cookie,
        apiKey: values["api-key"] ?? existing.apiKey,
        jwt: values.jwt ?? existing.jwt,
        otpSeed: values["otp-seed"] ?? existing.otpSeed,
        creditCard: values["credit-card"] ?? existing.creditCard,
        updatedAt: new Date().toISOString(),
      };
      ensureVaultDir();
      await Bun.write(VAULT_FILE, encodePlain(vault));
      console.log(`[vault] Stored plaintext credentials for "${values.target}"`);
      return;
    }

    if (values.get) {
      if (!values.target) {
        console.error("[vault] --target is required for --get");
        process.exit(1);
      }
      const vault = await readVault();
      const cred = vault[values.target];
      if (!cred) {
        console.error(`[vault] No credentials found for "${values.target}"`);
        process.exit(1);
      }
      if (values.field) {
        console.log(cred[values.field as keyof Credential] ?? "");
      } else {
        console.log(JSON.stringify(cred, null, 2));
      }
      return;
    }

    if (values.list) {
      const vault = await readVault();
      const targets = Object.keys(vault);
      if (targets.length === 0) {
        console.log("[vault] No stored targets.");
        return;
      }
      console.log("[vault] Stored targets:");
      for (const t of targets) {
        console.log(`  - ${t}  (updated: ${vault[t].updatedAt})`);
      }
      return;
    }

    if (values.delete) {
      if (!values.target) {
        console.error("[vault] --target is required for --delete");
        process.exit(1);
      }
      const vault = await readVault();
      if (!(values.target in vault)) {
        console.error(`[vault] Target "${values.target}" not found.`);
        process.exit(1);
      }
      delete vault[values.target];
      ensureVaultDir();
      await Bun.write(VAULT_FILE, encodePlain(vault));
      console.log(`[vault] Deleted credentials for "${values.target}"`);
      return;
    }

    if (values.redact) {
      if (!values.file) {
        console.error("[vault] --file is required for --redact");
        process.exit(1);
      }
      const vault = await readVault();
      const file = Bun.file(values.file);
      if (!(await file.exists())) {
        console.error(`[vault] File not found: ${values.file}`);
        process.exit(1);
      }
      let content = await file.text();
      let replacements = 0;
      for (const cred of Object.values(vault)) {
        const secrets = [cred.password, cred.cookie, cred.apiKey, cred.jwt, cred.otpSeed, cred.creditCard].filter(
          Boolean
        ) as string[];
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
      await Bun.write(values.file, content);
      console.log(`[vault] Redacted ${replacements} secret(s) in ${values.file}`);
      return;
    }

    console.error("[vault] --plain requires --store, --get, --list, --delete, or --redact");
    process.exit(1);
  }

  // Encrypted mode (default)
  const passphrase = await resolvePassphrase(values);

  if (values.store) {
    if (!values.target) {
      console.error("[vault] --target is required for --store");
      process.exit(1);
    }
    await actionStore(
      values.target,
      {
        username: values.username,
        password: values.password,
        cookie: values.cookie,
        apiKey: values["api-key"],
        jwt: values.jwt,
        otpSeed: values["otp-seed"],
        creditCard: values["credit-card"],
      },
      passphrase,
      values["op-item"]
    );
  } else if (values.get) {
    if (!values.target) {
      console.error("[vault] --target is required for --get");
      process.exit(1);
    }
    await actionGet(values.target, passphrase, values.field as keyof Credential | undefined);
  } else if (values.list) {
    await actionList(passphrase);
  } else if (values.delete) {
    if (!values.target) {
      console.error("[vault] --target is required for --delete");
      process.exit(1);
    }
    await actionDelete(values.target, passphrase);
  } else if (values.redact) {
    if (!values.file) {
      console.error("[vault] --file is required for --redact");
      process.exit(1);
    }
    await actionRedact(values.file, passphrase);
  } else if (values.rotate) {
    const oldPassphrase = values["old-passphrase"] ?? (await promptPassphrase("Old vault passphrase: "));
    const newPassphrase = values["new-passphrase"] ?? (await promptPassphrase("New vault passphrase: "));
    await actionRotate(oldPassphrase, newPassphrase);
  } else {
    console.log(`credential-vault — BugHunter AI Credential Manager

Usage:
  --store   --target <name> [--username <u>] [--password <p>] [--cookie <c>]
            [--api-key <k>] [--jwt <j>] [--otp-seed <s>] [--credit-card <cc>]
            [--op-item <item>]
  --get     --target <name> [--field <field>]
  --list
  --delete  --target <name>
  --redact  --file <path>
  --rotate  [--old-passphrase <p>] [--new-passphrase <p>]

Encryption options (in order of precedence):
  --passphrase <string>              # least secure (shell history)
  --passphrase-file <path>           # read from file
  BH_VAULT_PASSPHRASE env var        # recommended for scripts
  interactive prompt                 # default when no other source given

Insecure fallback:
  --plain                            # base64-only storage (not recommended)

Environment overrides: HUNT_USER, HUNT_PASS, HUNT_COOKIE, HUNT_API_KEY`);
  }
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[vault] Fatal: ${err.message}`);
    process.exit(1);
  });
}
