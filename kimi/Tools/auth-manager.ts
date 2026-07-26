#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Auth manager: authentication flows, session persistence, and auto-refresh.
 *
 * This file is import-safe: argument parsing happens inside main(), so
 * importing it as a library never touches process argv. Library callers can
 * tune behavior via the exported `authConfig` object (or CLI flags when run
 * directly).
 */

import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { parseArgs } from "util";
import { getSessionDir, toSlug } from "./lib/paths.ts";

export type AuthStrategy = "basic" | "b2c" | "oauth" | "saml" | "api" | "cookie" | "token";

export interface AuthState {
  target: string;
  strategy: AuthStrategy;
  cookies: Array<{ name: string; value: string; domain: string; path: string; expires: number }>;
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  tokenExpiry: string | null;
  lastAuthenticated: string;
  lastChecked: string;
  isValid: boolean;
}

export interface AuthManagerConfig {
  target?: string;
  strategy: string;
  cookie?: string;
  token?: string;
  protectedPage?: string;
  proxy?: string;
  /** Headless by default; --headful on the CLI sets this to false. */
  headless: boolean;
  /** Chromium sandbox is ON by default; --no-sandbox opts out (needed as root). */
  noSandbox: boolean;
}

/** Mutable configuration; the CLI populates it in main(), library callers may set it directly. */
export const authConfig: AuthManagerConfig = {
  strategy: "basic",
  proxy: "http://127.0.0.1:8080",
  headless: true,
  noSandbox: false,
};

function getAuthStatePath(target: string): string {
  return `${getSessionDir(toSlug(target))}/auth-state.json`;
}

function getStorageStatePath(target: string): string {
  return `${getSessionDir(toSlug(target))}/storage-state.json`;
}

async function loadCredsFromVault(targetName: string): Promise<{ username?: string; password?: string; cookie?: string; token?: string }> {
  const { getCredentials, VaultError } = await import("./credential-vault.ts");
  try {
    const cred = await getCredentials(targetName, process.env.BH_VAULT_PASSPHRASE);
    if (!cred) return {};
    return {
      username: cred.username,
      password: cred.password,
      cookie: cred.cookie,
      token: cred.jwt || cred.apiKey,
    };
  } catch (err) {
    if (err instanceof VaultError) {
      console.error(`[AUTH] Vault error: ${err.message}`);
      process.exit(1);
    }
    return {};
  }
}

async function createBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: authConfig.headless,
    proxy: authConfig.proxy ? { server: authConfig.proxy } : undefined,
    args: ["--ignore-certificate-errors", ...(authConfig.noSandbox ? ["--no-sandbox"] : [])],
  });
}

async function authBasic(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: basic (form login)");
  await page.goto(authConfig.target!, { waitUntil: "networkidle", timeout: 15000 });

  const usernameField = await page.$('input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"], input[name="username"], input[id*="user"], input[id*="email"]');
  const passwordField = await page.$('input[type="password"]');
  const submitButton = await page.$('button[type="submit"], input[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")');

  if (!usernameField || !passwordField) {
    console.log("[AUTH] Could not find login form fields.");
    return false;
  }

  await usernameField.fill(username);
  await passwordField.fill(password);
  await page.waitForTimeout(500);

  if (submitButton) {
    await submitButton.click();
  } else {
    await passwordField.press("Enter");
  }

  await page.waitForTimeout(3000);
  await page.waitForLoadState("networkidle").catch(() => {});

  const hasLoginIndicators = await page.$('input[type="password"]');
  const success = !hasLoginIndicators;
  console.log(success ? "[AUTH] Login successful" : "[AUTH] Login may have failed");
  return success;
}

async function authB2C(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: b2c (Azure AD B2C popup flow)");
  await page.goto(authConfig.target!, { waitUntil: "domcontentloaded", timeout: 15000 });

  const popupPromise = page.context().waitForEvent("page", { timeout: 10000 }).catch(() => null);
  const loginBtn = await page.$('button:has-text("Sign in"), button:has-text("Log in"), a:has-text("Sign in"), a:has-text("Log in"), [data-testid*="login"], [data-testid*="signin"]');
  if (loginBtn) await loginBtn.click();

  const popup = await popupPromise;
  const authPage = popup || page;
  await authPage.waitForTimeout(3000);

  const emailField = await authPage.$('#email, #signInName, input[name="loginfmt"], input[type="email"]');
  if (emailField) {
    await emailField.fill(username);
    const nextBtn = await authPage.$('#next, button:has-text("Next"), button:has-text("Continue"), input[type="submit"]');
    if (nextBtn) await nextBtn.click();
    await authPage.waitForTimeout(2000);
  }

  const passField = await authPage.$('#password, #passwordInput, input[type="password"]');
  if (passField) {
    await passField.fill(password);
    const signInBtn = await authPage.$('#idSIButton9, #submitButton, button:has-text("Sign in"), button:has-text("Submit"), input[type="submit"]');
    if (signInBtn) await signInBtn.click();
  }

  await page.waitForTimeout(5000);
  await page.waitForLoadState("networkidle").catch(() => {});

  const mfaPrompt = await page.$('[data-testid*="mfa"], [data-testid*="otp"], input[name*="otp"], input[name*="code"]');
  if (mfaPrompt) {
    console.log("[AUTH] MFA/OTP prompt detected — manual input required (waiting 30s)");
    await page.waitForTimeout(30000);
  }

  const success = !page.url().includes("login") && !page.url().includes("signin");
  console.log(success ? "[AUTH] B2C login successful" : "[AUTH] B2C login may have failed");
  return success;
}

async function authOAuth(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: oauth");
  await page.goto(authConfig.target!, { waitUntil: "domcontentloaded", timeout: 15000 });

  const oauthBtn = await page.$('a:has-text("Login with"), button:has-text("Login with"), a:has-text("Continue with"), button:has-text("Continue with"), [data-testid*="oauth"], [data-testid*="sso"]');
  if (oauthBtn) await oauthBtn.click();

  await page.waitForTimeout(3000);

  const emailField = await page.$('input[type="email"], input[name="login"], input[id="login_field"]');
  if (emailField) {
    await emailField.fill(username);
    const nextBtn = await page.$('#identifierNext, button:has-text("Next"), input[type="submit"]');
    if (nextBtn) {
      await nextBtn.click();
      await page.waitForTimeout(2000);
    }
  }

  const passField = await page.$('input[type="password"]');
  if (passField) {
    await passField.fill(password);
    const signInBtn = await page.$('#passwordNext, button:has-text("Sign in"), input[type="submit"]');
    if (signInBtn) await signInBtn.click();
  }

  await page.waitForTimeout(5000);
  await page.waitForLoadState("networkidle").catch(() => {});

  const success = page.url().includes(new URL(authConfig.target!).hostname);
  console.log(success ? "[AUTH] OAuth login successful" : "[AUTH] OAuth login may have failed");
  return success;
}

async function authCookie(context: BrowserContext): Promise<boolean> {
  console.log("[AUTH] Strategy: cookie");
  const cookieStr = authConfig.cookie;
  if (!cookieStr) {
    console.log("[AUTH] No cookie provided");
    return false;
  }

  const domain = new URL(authConfig.target!).hostname;
  const cookies = cookieStr.split(";").map((c) => {
    const [name, ...valueParts] = c.trim().split("=");
    return { name: name.trim(), value: valueParts.join("=").trim(), domain, path: "/" };
  });

  await context.addCookies(cookies);
  console.log(`[AUTH] Injected ${cookies.length} cookies`);
  return true;
}

async function authToken(page: Page): Promise<boolean> {
  console.log("[AUTH] Strategy: token");
  const token = authConfig.token;
  if (!token) {
    console.log("[AUTH] No token provided");
    return false;
  }

  await page.setExtraHTTPHeaders({ Authorization: `Bearer ${token}` });
  console.log("[AUTH] Bearer token set in headers");
  return true;
}

async function authAPI(username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: api");
  const target = authConfig.target!;

  const loginEndpoints = [
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/login",
    "/auth/token",
    "/oauth/token",
    "/api/v1/sessions",
    "/api/authenticate",
    "/login",
  ];

  for (const endpoint of loginEndpoints) {
    const url = new URL(endpoint, target).href;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: username, username, password }),
      });

      if (res.ok) {
        const data = await res.json();
        console.log(`[AUTH] API login successful at ${endpoint}`);
        const token = data.token || data.access_token || data.jwt || data.session_token;
        if (token) {
          console.log(`[AUTH] Token obtained (length: ${String(token).length})`);
        }
        return true;
      }
    } catch {
      // try next endpoint
    }
  }

  console.log("[AUTH] No API login endpoint responded successfully");
  return false;
}

export async function isSessionValid(target: string, cookie?: string): Promise<boolean> {
  const protectedPage = authConfig.protectedPage || target;
  try {
    const headers: Record<string, string> = {};
    if (cookie) headers["Cookie"] = cookie;
    if (authConfig.token) headers["Authorization"] = `Bearer ${authConfig.token}`;

    const res = await fetch(protectedPage, { headers, redirect: "manual" });
    if (res.status >= 200 && res.status < 300) return true;
    if (res.status === 401 || res.status === 403) return false;
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location") || "";
      return !location.includes("login") && !location.includes("signin") && !location.includes("auth");
    }
    return false;
  } catch {
    return false;
  }
}

/** Decode a base64url segment (JWT payloads use base64url without padding). */
function decodeBase64Url(segment: string): string {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf-8");
}

async function saveAuthState(target: string, context: BrowserContext): Promise<void> {
  const storageStatePath = getStorageStatePath(target);
  const authStatePath = getAuthStatePath(target);

  const storageState = await context.storageState();
  await Bun.write(storageStatePath, JSON.stringify(storageState, null, 2));

  const authState: AuthState = {
    target,
    strategy: authConfig.strategy as AuthStrategy,
    cookies: storageState.cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      expires: c.expires,
    })),
    localStorage: {},
    sessionStorage: {},
    tokenExpiry: null,
    lastAuthenticated: new Date().toISOString(),
    lastChecked: new Date().toISOString(),
    isValid: true,
  };

  for (const cookie of storageState.cookies) {
    if (cookie.value.split(".").length === 3) {
      try {
        const payload = JSON.parse(decodeBase64Url(cookie.value.split(".")[1]));
        if (payload.exp) {
          authState.tokenExpiry = new Date(payload.exp * 1000).toISOString();
          console.log(`[AUTH] Token expires: ${authState.tokenExpiry}`);
        }
      } catch {
        /* not a JWT */
      }
    }
  }

  await Bun.write(authStatePath, JSON.stringify(authState, null, 2));
  console.log(`[AUTH] State saved to ${authStatePath}`);
}

async function loadAuthState(target: string): Promise<AuthState | null> {
  const path = getAuthStatePath(target);
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  return JSON.parse(await file.text());
}

/** Build a Cookie header from a saved auth state, if one exists. */
function cookieHeaderFromState(state: AuthState | null): string | undefined {
  if (!state || !state.cookies || state.cookies.length === 0) return undefined;
  return state.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

async function newContextWithSavedState(browser: Browser, target: string): Promise<BrowserContext> {
  const storageFile = Bun.file(getStorageStatePath(target));
  if (await storageFile.exists()) {
    console.log("[AUTH] Loading saved browser state...");
    const storageState = JSON.parse(await storageFile.text());
    return browser.newContext({ storageState, ignoreHTTPSErrors: true });
  }
  return browser.newContext({ ignoreHTTPSErrors: true });
}

export async function authenticate(
  target: string,
  strategy: AuthStrategy,
  creds: { username?: string; password?: string }
): Promise<boolean> {
  const browser = await createBrowser();
  const context = await newContextWithSavedState(browser, target);

  const page = await context.newPage();
  let success = false;

  switch (strategy) {
    case "basic":
      success = await authBasic(page, creds.username || "", creds.password || "");
      break;
    case "b2c":
      success = await authB2C(page, creds.username || "", creds.password || "");
      break;
    case "oauth":
    case "saml":
      success = await authOAuth(page, creds.username || "", creds.password || "");
      break;
    case "api":
      success = await authAPI(creds.username || "", creds.password || "");
      break;
    case "cookie":
      success = await authCookie(context);
      break;
    case "token":
      success = await authToken(page);
      break;
  }

  if (success) {
    await saveAuthState(target, context);
  }

  await browser.close();
  return success;
}

async function main() {
  const { values: args } = parseArgs({
    args: Bun.argv.slice(2),
    options: {
      target: { type: "string" },
      strategy: { type: "string", default: "basic" },
      username: { type: "string" },
      password: { type: "string" },
      cookie: { type: "string" },
      token: { type: "string" },
      "creds-from": { type: "string" },
      "protected-page": { type: "string" },
      proxy: { type: "string", default: "http://127.0.0.1:8080" },
      // Headless is the default; --headful shows the browser.
      // --headless is kept as a backwards-compatible alias (now a no-op).
      headful: { type: "boolean", default: false },
      headless: { type: "boolean", default: false },
      // Chromium sandbox is on by default; --no-sandbox opts out (e.g. as root).
      "no-sandbox": { type: "boolean", default: false },
      authenticate: { type: "boolean", default: false },
      check: { type: "boolean", default: false },
      refresh: { type: "boolean", default: false },
      "save-state": { type: "boolean", default: false },
      "load-state": { type: "boolean", default: false },
    },
  });

  authConfig.target = args.target;
  authConfig.strategy = args.strategy;
  authConfig.cookie = args.cookie;
  authConfig.token = args.token;
  authConfig.protectedPage = args["protected-page"];
  authConfig.proxy = args.proxy;
  authConfig.headless = !args.headful;
  authConfig.noSandbox = args["no-sandbox"];

  if (!args.target) {
    console.log(`auth-manager — BugHunter AI Authentication Manager

Usage:
  auth-manager --target URL --authenticate --strategy basic --username X --password Y
  auth-manager --target URL --authenticate --strategy b2c --creds-from vault:target-name
  auth-manager --target URL --authenticate --strategy cookie --cookie 'name=value'
  auth-manager --target URL --authenticate --strategy token --token 'xxx'
  auth-manager --target URL --check [--protected-page URL]
  auth-manager --target URL --refresh
  auth-manager --target URL --save-state [--cookie 'name=value']
  auth-manager --target URL --load-state

Options:
  --headful      Show the browser (headless is the default; --headless is kept as an alias)
  --no-sandbox   Disable the Chromium sandbox (needed when running as root)`);
    return;
  }

  let username = args.username;
  let password = args.password;
  if (args["creds-from"]?.startsWith("vault:")) {
    const vaultTarget = args["creds-from"].replace("vault:", "");
    console.log(`[AUTH] Loading credentials from vault: ${vaultTarget}`);
    const creds = await loadCredsFromVault(vaultTarget);
    username = username || creds.username;
    password = password || creds.password;
  }

  if (args.check) {
    const state = await loadAuthState(args.target!);
    const hasStorageState = await Bun.file(getStorageStatePath(args.target!)).exists();
    const hasExplicitCreds = Boolean(args.cookie || args.token);
    if (!state && !hasStorageState && !hasExplicitCreds) {
      console.log(
        `[AUTH CHECK] No stored session for ${args.target} — run --authenticate first or pass --cookie/--token`
      );
      process.exit(1);
    }
    const valid = await isSessionValid(args.target!, cookieHeaderFromState(state));
    console.log(`[AUTH CHECK] Session valid: ${valid}`);
    if (state?.tokenExpiry) {
      const expires = new Date(state.tokenExpiry);
      const minutesLeft = Math.round((expires.getTime() - Date.now()) / 60000);
      console.log(`[AUTH CHECK] Token expires in ${minutesLeft} minutes`);
      if (minutesLeft < 5) console.log("[AUTH CHECK] WARNING: Token expiring soon");
    }
    return;
  }

  if (args.refresh) {
    const state = await loadAuthState(args.target!);
    if (!state) {
      console.log("[AUTH] No saved auth state — performing fresh authentication");
    } else {
      console.log(`[AUTH] Refreshing using strategy: ${state.strategy}`);
    }
    const strategy = (state?.strategy || args.strategy) as AuthStrategy;
    const success = await authenticate(args.target!, strategy, { username, password });
    console.log(success ? "[AUTH] Session refreshed successfully" : "[AUTH] Refresh failed");
    return;
  }

  if (args.authenticate) {
    const strategy = args.strategy as AuthStrategy;
    const success = await authenticate(args.target!, strategy, { username, password });
    console.log(success ? "[AUTH] Authentication complete" : "[AUTH] Authentication failed");
    process.exit(success ? 0 : 1);
  }

  if (args["save-state"]) {
    // Persist the current auth state (existing storage state plus any
    // cookies passed on the command line) to the session dir — the same
    // files that --load-state and --check read.
    const browser = await createBrowser();
    const context = await newContextWithSavedState(browser, args.target!);
    if (args.cookie) {
      await authCookie(context);
    }
    await saveAuthState(args.target!, context);
    await browser.close();
    return;
  }

  if (args["load-state"]) {
    const state = await loadAuthState(args.target!);
    if (state) {
      console.log(JSON.stringify(state, null, 2));
    } else {
      console.log("[AUTH] No saved state for this target");
    }
  }
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[AUTH] Fatal: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  });
}
