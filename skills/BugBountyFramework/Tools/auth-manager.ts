#!/usr/bin/env bun
/**
 * BugBountyFramework — Auth Manager (ENH-4)
 * Manages authentication flows, session persistence, and auto-refresh for hunt targets.
 * Solves B2C/SSO login blocking and token expiry issues.
 */

import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { parseArgs } from "util";
import { homedir } from "os";

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    target: { type: "string" },
    strategy: { type: "string", default: "basic" }, // basic|b2c|oauth|saml|api|cookie|token
    username: { type: "string" },
    password: { type: "string" },
    cookie: { type: "string" },
    token: { type: "string" },
    "creds-from": { type: "string" }, // vault:target-name
    "protected-page": { type: "string" }, // URL to check if session is valid
    proxy: { type: "string", default: "http://127.0.0.1:8080" },
    headless: { type: "boolean", default: false },
    // Commands
    authenticate: { type: "boolean", default: false },
    check: { type: "boolean", default: false },
    refresh: { type: "boolean", default: false },
    "save-state": { type: "boolean", default: false },
    "load-state": { type: "boolean", default: false },
  },
});

// --- Types ---

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

// --- Helpers ---

function toSlug(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/[^a-z0-9]/gi, "-").replace(/-+/g, "-").toLowerCase();
}

function getAuthStatePath(target: string): string {
  return `${homedir()}/.claude/MEMORY/BugBounty/Sessions/${toSlug(target)}/auth-state.json`;
}

function getStorageStatePath(target: string): string {
  return `${homedir()}/.claude/MEMORY/BugBounty/Sessions/${toSlug(target)}/storage-state.json`;
}

async function loadCredsFromVault(targetName: string): Promise<{ username?: string; password?: string; cookie?: string; token?: string }> {
  const vaultPath = `${homedir()}/.claude/MEMORY/BugBounty/Vault/credentials.enc`;
  const file = Bun.file(vaultPath);
  if (!(await file.exists())) return {};
  const data = JSON.parse(Buffer.from(await file.text(), "base64").toString("utf-8"));
  const entry = data[targetName];
  if (!entry) return {};
  return {
    username: entry.username,
    password: entry.password,
    cookie: entry.cookie,
    token: entry.jwt || entry.api_key,
  };
}

// --- Browser Setup ---

async function createBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: args.headless,
    proxy: { server: args.proxy },
    args: ["--ignore-certificate-errors", "--no-sandbox"],
  });
}

// --- Auth Strategies ---

async function authBasic(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: basic (form login)");
  await page.goto(args.target!, { waitUntil: "networkidle", timeout: 15000 });

  // Find login form
  const usernameField = await page.$('input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"], input[name="username"], input[id*="user"], input[id*="email"]');
  const passwordField = await page.$('input[type="password"]');
  const submitButton = await page.$('button[type="submit"], input[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")');

  if (!usernameField || !passwordField) {
    console.log("[AUTH] Could not find login form fields. Trying alternative selectors...");
    // Try clicking a "Log in" link first
    const loginLink = await page.$('a:has-text("Log in"), a:has-text("Sign in"), a:has-text("Login")');
    if (loginLink) {
      await loginLink.click();
      await page.waitForTimeout(2000);
    }
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

  // Check if login succeeded (not still on login page)
  const currentUrl = page.url();
  const hasLoginIndicators = await page.$('input[type="password"]');
  const success = !hasLoginIndicators || currentUrl !== args.target;

  console.log(success ? "[AUTH] Login successful" : "[AUTH] Login may have failed — still on login page");
  return success;
}

async function authB2C(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: b2c (Azure AD B2C popup flow)");
  await page.goto(args.target!, { waitUntil: "domcontentloaded", timeout: 15000 });

  // Wait for B2C redirect or popup
  const popupPromise = page.context().waitForEvent("page", { timeout: 10000 }).catch(() => null);

  // Click login button if present
  const loginBtn = await page.$('button:has-text("Sign in"), button:has-text("Log in"), a:has-text("Sign in"), a:has-text("Log in"), [data-testid*="login"], [data-testid*="signin"]');
  if (loginBtn) await loginBtn.click();

  // Handle popup or redirect
  const popup = await popupPromise;
  const authPage = popup || page;

  // Wait for B2C form to load
  await authPage.waitForTimeout(3000);

  // B2C typically has email first, then password on next screen
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

  // Wait for redirect back to app
  await page.waitForTimeout(5000);
  await page.waitForLoadState("networkidle").catch(() => {});

  // Check for MFA prompt
  const mfaPrompt = await page.$('[data-testid*="mfa"], [data-testid*="otp"], input[name*="otp"], input[name*="code"]');
  if (mfaPrompt) {
    console.log("[AUTH] MFA/OTP prompt detected — manual input required");
    console.log("[AUTH] Waiting 30s for manual MFA entry...");
    await page.waitForTimeout(30000);
  }

  const success = !page.url().includes("login") && !page.url().includes("signin");
  console.log(success ? "[AUTH] B2C login successful" : "[AUTH] B2C login may have failed");
  return success;
}

async function authOAuth(page: Page, username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: oauth (OAuth2 authorization code flow)");
  await page.goto(args.target!, { waitUntil: "domcontentloaded", timeout: 15000 });

  // Click OAuth login button
  const oauthBtn = await page.$('a:has-text("Login with"), button:has-text("Login with"), a:has-text("Continue with"), button:has-text("Continue with"), [data-testid*="oauth"], [data-testid*="sso"]');
  if (oauthBtn) await oauthBtn.click();

  await page.waitForTimeout(3000);

  // Fill OAuth provider form (Google, GitHub, etc.)
  const emailField = await page.$('input[type="email"], input[name="login"], input[id="login_field"]');
  if (emailField) {
    await emailField.fill(username);
    const nextBtn = await page.$('#identifierNext, button:has-text("Next"), input[type="submit"]');
    if (nextBtn) { await nextBtn.click(); await page.waitForTimeout(2000); }
  }

  const passField = await page.$('input[type="password"]');
  if (passField) {
    await passField.fill(password);
    const signInBtn = await page.$('#passwordNext, button:has-text("Sign in"), input[type="submit"]');
    if (signInBtn) await signInBtn.click();
  }

  await page.waitForTimeout(5000);
  await page.waitForLoadState("networkidle").catch(() => {});

  const success = page.url().includes(new URL(args.target!).hostname);
  console.log(success ? "[AUTH] OAuth login successful" : "[AUTH] OAuth login may have failed");
  return success;
}

async function authCookie(context: BrowserContext): Promise<boolean> {
  console.log("[AUTH] Strategy: cookie (manual injection)");
  const cookieStr = args.cookie;
  if (!cookieStr) { console.log("[AUTH] No cookie provided"); return false; }

  const domain = new URL(args.target!).hostname;
  const cookies = cookieStr.split(";").map(c => {
    const [name, ...valueParts] = c.trim().split("=");
    return { name: name.trim(), value: valueParts.join("=").trim(), domain, path: "/" };
  });

  await context.addCookies(cookies);
  console.log(`[AUTH] Injected ${cookies.length} cookies`);
  return true;
}

async function authToken(page: Page): Promise<boolean> {
  console.log("[AUTH] Strategy: token (Bearer token injection)");
  const token = args.token;
  if (!token) { console.log("[AUTH] No token provided"); return false; }

  await page.setExtraHTTPHeaders({ Authorization: `Bearer ${token}` });
  console.log("[AUTH] Bearer token set in headers");
  return true;
}

async function authAPI(username: string, password: string): Promise<boolean> {
  console.log("[AUTH] Strategy: api (direct API authentication — bypass UI)");
  const target = args.target!;

  // Try common API login endpoints
  const loginEndpoints = [
    "/api/auth/login", "/api/v1/auth/login", "/api/login",
    "/auth/token", "/oauth/token", "/api/v1/sessions",
    "/api/authenticate", "/login",
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
        console.log(`[AUTH] Response keys: ${Object.keys(data).join(", ")}`);

        // Extract token
        const token = data.token || data.access_token || data.jwt || data.session_token;
        if (token) {
          console.log(`[AUTH] Token obtained: ${token.slice(0, 20)}...`);
        }
        return true;
      }
    } catch {
      // Try next endpoint
    }
  }

  console.log("[AUTH] No API login endpoint responded successfully");
  return false;
}

// --- Session Validation ---

export async function isSessionValid(target: string, cookie?: string): Promise<boolean> {
  const protectedPage = args["protected-page"] || target;
  try {
    const headers: Record<string, string> = {};
    if (cookie) headers["Cookie"] = cookie;
    if (args.token) headers["Authorization"] = `Bearer ${args.token}`;

    const res = await fetch(protectedPage, {
      headers,
      redirect: "manual",
    });

    // Valid if 200-299, invalid if 401/403/redirect to login
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

// --- State Persistence ---

async function saveAuthState(target: string, context: BrowserContext): Promise<void> {
  const storageStatePath = getStorageStatePath(target);
  const authStatePath = getAuthStatePath(target);

  // Save Playwright storage state (cookies + localStorage)
  const storageState = await context.storageState();
  await Bun.write(storageStatePath, JSON.stringify(storageState, null, 2));

  // Save our auth state
  const authState: AuthState = {
    target,
    strategy: args.strategy as AuthStrategy,
    cookies: storageState.cookies.map(c => ({
      name: c.name, value: c.value, domain: c.domain, path: c.path,
      expires: c.expires,
    })),
    localStorage: {},
    sessionStorage: {},
    tokenExpiry: null,
    lastAuthenticated: new Date().toISOString(),
    lastChecked: new Date().toISOString(),
    isValid: true,
  };

  // Check for JWT expiry
  for (const cookie of storageState.cookies) {
    if (cookie.value.split(".").length === 3) {
      try {
        const payload = JSON.parse(Buffer.from(cookie.value.split(".")[1], "base64").toString());
        if (payload.exp) {
          authState.tokenExpiry = new Date(payload.exp * 1000).toISOString();
          console.log(`[AUTH] Token expires: ${authState.tokenExpiry}`);
        }
      } catch { /* not a JWT */ }
    }
  }

  await Bun.write(authStatePath, JSON.stringify(authState, null, 2));
  console.log(`[AUTH] State saved to ${authStatePath}`);
  console.log(`[AUTH] Storage state saved to ${storageStatePath}`);
}

async function loadAuthState(target: string): Promise<AuthState | null> {
  const path = getAuthStatePath(target);
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  return JSON.parse(await file.text());
}

// --- Main Orchestration ---

export async function authenticate(target: string, strategy: AuthStrategy, creds: { username?: string; password?: string }): Promise<boolean> {
  const browser = await createBrowser();
  const storageStatePath = getStorageStatePath(target);
  const storageFile = Bun.file(storageStatePath);

  // Load existing storage state if available
  let context: BrowserContext;
  if (await storageFile.exists()) {
    console.log("[AUTH] Loading saved browser state...");
    const storageState = JSON.parse(await storageFile.text());
    context = await browser.newContext({ storageState, ignoreHTTPSErrors: true });
  } else {
    context = await browser.newContext({ ignoreHTTPSErrors: true });
  }

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
    case "saml":
      // SAML uses similar flow to OAuth — redirect-based
      success = await authOAuth(page, creds.username || "", creds.password || "");
      break;
  }

  if (success) {
    await saveAuthState(target, context);
  }

  await browser.close();
  return success;
}

// --- CLI ---

async function main() {
  if (!args.target) {
    console.log("Usage:");
    console.log("  auth-manager --target URL --authenticate --strategy basic --username X --password Y");
    console.log("  auth-manager --target URL --authenticate --strategy b2c --creds-from vault:target-name");
    console.log("  auth-manager --target URL --authenticate --strategy cookie --cookie 'name=value'");
    console.log("  auth-manager --target URL --authenticate --strategy token --token 'Bearer xxx'");
    console.log("  auth-manager --target URL --check [--protected-page URL]");
    console.log("  auth-manager --target URL --refresh");
    console.log("  auth-manager --target URL --save-state");
    console.log("  auth-manager --target URL --load-state");
    return;
  }

  // Load creds from vault if specified
  let username = args.username;
  let password = args.password;
  if (args["creds-from"]?.startsWith("vault:")) {
    const vaultTarget = args["creds-from"].replace("vault:", "");
    console.log(`[AUTH] Loading credentials from vault: ${vaultTarget}`);
    const creds = await loadCredsFromVault(vaultTarget);
    username = username || creds.username;
    password = password || creds.password;
  }

  // Check session validity
  if (args.check) {
    const valid = await isSessionValid(args.target!);
    const state = await loadAuthState(args.target!);
    console.log(`[AUTH CHECK] Session valid: ${valid}`);
    if (state?.tokenExpiry) {
      const expires = new Date(state.tokenExpiry);
      const now = new Date();
      const minutesLeft = Math.round((expires.getTime() - now.getTime()) / 60000);
      console.log(`[AUTH CHECK] Token expires in ${minutesLeft} minutes`);
      if (minutesLeft < 5) console.log("[AUTH CHECK] WARNING: Token expiring soon — consider refresh");
    }
    return;
  }

  // Refresh session
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

  // Authenticate
  if (args.authenticate) {
    const strategy = args.strategy as AuthStrategy;
    const success = await authenticate(args.target!, strategy, { username, password });
    console.log(success ? "[AUTH] Authentication complete" : "[AUTH] Authentication failed");
    return;
  }

  // Save/Load state (for manual use)
  if (args["save-state"] || args["load-state"]) {
    const state = await loadAuthState(args.target!);
    if (args["load-state"]) {
      if (state) {
        console.log(JSON.stringify(state, null, 2));
      } else {
        console.log("[AUTH] No saved state for this target");
      }
    }
  }
}

main().catch(console.error);
