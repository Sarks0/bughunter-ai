#!/usr/bin/env bun
/**
 * BugHunter AI — Kimi port
 * Appium mobile testing harness (Android focused, iOS stubbed).
 *
 * Security notes — every string parsed out of the APK (package name,
 * activities, provider authorities, deep-link schemes/hosts) is adversarial
 * input from a potentially malicious app:
 * - Local processes are spawned as argv arrays (no local shell), so APK-
 *   derived strings can never reach bash on the analyst's machine.
 * - The package name is validated against a strict regex before use.
 * - Anything else interpolated into a device-side `adb shell` command is
 *   single-quote escaped via sq().
 *
 * Decompiled artifacts persist in a per-run directory: under the session
 * artifacts dir when --target is given, else an fs.mkdtempSync() dir under
 * the OS temp dir. The path is logged at startup.
 */

import { parseArgs } from "util";
import { mkdtempSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { getSessionDir } from "./lib/paths.ts";

interface HarnessOptions {
  platform?: string;
  apk?: string;
  ipa?: string;
  proxy: string;
  device: string;
  target?: string;
  testSslPinningBypass: boolean;
  testDeepLinks: boolean;
  testExportedComponents: boolean;
  testStorage: boolean;
  output: string;
}

interface MobileFinding {
  type: string;
  platform: "android" | "ios";
  component?: string;
  description: string;
  cvss_estimate: number;
  poc: string;
  confirmed: boolean;
}

const findings: MobileFinding[] = [];

/** CVSS threshold at which a finding is reported as critical. */
const CRITICAL_CVSS_THRESHOLD = 8.0;

/** Valid Android/Java package name (e.g. com.example.app). */
const PACKAGE_NAME_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

/** Tools this harness shells out to, with install hints for the startup check. */
const REQUIRED_TOOLS: Array<{ command: string; hint: string }> = [
  { command: "adb", hint: "sudo apt install adb  (or Android SDK platform-tools)" },
  { command: "aapt", hint: "sudo apt install aapt  (or Android SDK build-tools)" },
  { command: "apktool", hint: "sudo apt install apktool" },
  { command: "frida", hint: "pip install frida-tools" },
];

/**
 * Single-quote a string for safe interpolation into a device-side shell
 * command string passed to `adb shell`.
 */
function sq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function toSlug(target: string): string {
  return target.replace(/^https?:\/\//, "").replace(/[^a-z0-9]/gi, "-").replace(/-+/g, "-").toLowerCase();
}

function parseCliArgs(argv: string[]): HarnessOptions {
  const { values } = parseArgs({
    args: argv,
    options: {
      platform: { type: "string" },
      apk: { type: "string" },
      ipa: { type: "string" },
      proxy: { type: "string", default: "http://127.0.0.1:8080" },
      device: { type: "string", default: "emulator-5554" },
      target: { type: "string" },
      "test-ssl-pinning-bypass": { type: "boolean", default: true },
      "test-deep-links": { type: "boolean", default: true },
      "test-exported-components": { type: "boolean", default: true },
      "test-storage": { type: "boolean", default: true },
      output: { type: "string", default: "" },
    },
  });
  return {
    platform: values.platform,
    apk: values.apk,
    ipa: values.ipa,
    proxy: values.proxy ?? "http://127.0.0.1:8080",
    device: values.device ?? "emulator-5554",
    target: values.target,
    testSslPinningBypass: values["test-ssl-pinning-bypass"] ?? true,
    testDeepLinks: values["test-deep-links"] ?? true,
    testExportedComponents: values["test-exported-components"] ?? true,
    testStorage: values["test-storage"] ?? true,
    output: values.output ?? "",
  };
}

/** Verify required external tools are on PATH; report missing ones with install hints. */
function checkRequiredTools(options: HarnessOptions): void {
  const needed = REQUIRED_TOOLS.filter(({ command }) => {
    if (command === "frida") return options.testSslPinningBypass;
    if (command === "apktool") return options.testExportedComponents || options.testDeepLinks;
    return true;
  });
  const missing = needed.filter(
    ({ command }) => Bun.spawnSync(["which", command], { stdout: "pipe", stderr: "pipe" }).exitCode !== 0
  );
  for (const { command, hint } of missing) {
    console.error(`[!] Missing required tool: ${command} — install: ${hint}`);
  }
  if (missing.length > 0) {
    throw new Error(`Missing required tools: ${missing.map((m) => m.command).join(", ")}`);
  }
}

/**
 * Per-run working directory for decompiled artifacts and helper scripts.
 * Artifacts persist after the run (they are evidence); the path is logged.
 */
function createWorkDir(options: HarnessOptions): string {
  if (options.target) {
    const dir = join(getSessionDir(toSlug(options.target)), "artifacts", `appium-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    return dir;
  }
  return mkdtempSync(join(tmpdir(), "appium-harness-"));
}

interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Spawn a process as an argv array — never through a local shell. */
async function run(argv: string[]): Promise<RunResult> {
  try {
    const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" });
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    const exitCode = await proc.exited;
    return { stdout, stderr, exitCode };
  } catch (e) {
    return { stdout: "", stderr: String(e), exitCode: 127 };
  }
}

function adb(options: HarnessOptions, ...args: string[]): Promise<RunResult> {
  return run(["adb", "-s", options.device, ...args]);
}

async function testAndroid(options: HarnessOptions): Promise<void> {
  const apk = options.apk;
  if (!apk) {
    throw new Error("--apk required for Android testing");
  }

  const workDir = createWorkDir(options);
  console.log(`[*] Android testing — APK: ${apk}`);
  console.log(`[*] Work dir (decompiled artifacts persist here): ${workDir}`);

  const install = await adb(options, "install", "-r", apk);
  if (install.exitCode !== 0) {
    console.error(`[!] adb install failed: ${(install.stderr || install.stdout).trim()}`);
  }

  const packageName = await getPackageName(apk);
  console.log(`[+] Package: ${packageName}`);

  let manifest: string | null = null;
  if (options.testExportedComponents || options.testDeepLinks) {
    manifest = await decompileManifest(apk, workDir);
  }

  if (options.testExportedComponents && manifest) await testExportedComponents(options, packageName, manifest);
  if (options.testDeepLinks && manifest) await testAndroidDeepLinks(options, manifest);
  if (options.testStorage) await testAndroidStorage(options, packageName);
  if (options.testSslPinningBypass) await bypassAndroidSSLPinning(options, packageName, workDir);
}

async function getPackageName(apkPath: string): Promise<string> {
  const result = await run(["aapt", "dump", "badging", apkPath]);
  const name = result.stdout.match(/package: name='([^']+)'/)?.[1];
  if (!name) {
    throw new Error(
      `Could not determine package name from APK (aapt exit ${result.exitCode}): ${apkPath}. ` +
        `Refusing to continue against an unknown package.`
    );
  }
  if (!PACKAGE_NAME_RE.test(name)) {
    throw new Error(
      `APK declares an invalid package name ${JSON.stringify(name)} — refusing to continue (possible malicious APK).`
    );
  }
  return name;
}

/** Decompile the APK with apktool into the per-run work dir and return the manifest text. */
async function decompileManifest(apkPath: string, workDir: string): Promise<string | null> {
  const outDir = join(workDir, "decompiled");
  const result = await run(["apktool", "d", "-f", apkPath, "-o", outDir]);
  if (result.exitCode !== 0) {
    console.error(`[!] apktool decompile failed: ${(result.stderr || result.stdout).trim()}`);
    return null;
  }
  const manifestFile = Bun.file(join(outDir, "AndroidManifest.xml"));
  if (!(await manifestFile.exists())) {
    console.error("[!] AndroidManifest.xml not found after decompile");
    return null;
  }
  return manifestFile.text();
}

/** Extract android:name from manifest elements matching `pattern`. */
function extractAttr(elements: RegExpMatchArray | null, attr: string): string[] {
  const values: string[] = [];
  for (const el of elements ?? []) {
    const value = el.match(new RegExp(`android:${attr}="([^"]+)"`))?.[1];
    if (value) values.push(value);
  }
  return values;
}

async function testExportedComponents(options: HarnessOptions, packageName: string, manifest: string): Promise<void> {
  console.log("[*] Testing exported components...");

  const activities = extractAttr(manifest.match(/<activity\b[^>]*android:exported="true"[^>]*>/g), "name");
  for (const activityName of activities.slice(0, 10)) {
    const component = `${packageName}/${activityName}`;
    const launch = await adb(options, "shell", `am start -n ${sq(component)}`);
    const out = launch.stdout + launch.stderr;
    if (!out.includes("Error") && !out.includes("Permission denied")) {
      findings.push({
        type: "EXPORTED_ACTIVITY",
        platform: "android",
        component: activityName,
        description: "Exported activity accessible without authentication",
        cvss_estimate: 7.5,
        poc: `adb shell am start -n "${component}"`,
        confirmed: true,
      });
    }
  }

  const providers = extractAttr(
    manifest.match(/<provider\b[^>]*android:exported="true"[^>]*>/g),
    "authorities"
  );
  for (const authority of providers.slice(0, 5)) {
    const uri = `content://${authority}/`;
    const query = await adb(options, "shell", `content query --uri ${sq(uri)}`);
    const out = query.stdout + query.stderr;
    if (out.includes("Row:") || out.includes("_id")) {
      findings.push({
        type: "INSECURE_CONTENT_PROVIDER",
        platform: "android",
        component: authority,
        description: "Exported content provider allows unauthenticated data access",
        cvss_estimate: 8.1,
        poc: `adb shell content query --uri "${uri}"`,
        confirmed: true,
      });
    }
  }
}

async function testAndroidDeepLinks(options: HarnessOptions, manifest: string): Promise<void> {
  console.log("[*] Testing deep links...");

  const schemes = extractAttr(manifest.match(/android:scheme="[^"]+"/g), "scheme");
  const hosts = extractAttr(manifest.match(/android:host="[^"]+"/g), "host");

  const injectionPayloads = [
    "javascript:alert(1)",
    "' OR 1=1--",
    "../../etc/passwd",
    "${7*7}",
  ];

  for (const scheme of schemes.slice(0, 3)) {
    for (const host of hosts.slice(0, 3)) {
      for (const payload of injectionPayloads) {
        const uri = `${scheme}://${host}?redirect=${encodeURIComponent(payload)}`;
        await adb(options, "shell", `am start -a android.intent.action.VIEW -d ${sq(uri)}`);
      }
    }
  }
}

async function testAndroidStorage(options: HarnessOptions, packageName: string): Promise<void> {
  console.log("[*] Testing insecure storage...");

  const prefsDir = `/data/data/${packageName}/shared_prefs/`;
  const prefs = await adb(options, "shell", `run-as ${packageName} ls ${sq(prefsDir)}`);
  if (prefs.exitCode !== 0) {
    console.log(`[-] run-as shared_prefs listing failed (exit ${prefs.exitCode}): ${prefs.stderr.trim()}`);
  } else {
    const prefsFiles = prefs.stdout.split("\n").map((f) => f.trim()).filter((f) => f.endsWith(".xml") && !f.includes("/"));
    for (const prefsFile of prefsFiles.slice(0, 5)) {
      const filePath = `${prefsDir}${prefsFile}`;
      const content = await adb(options, "shell", `run-as ${packageName} cat ${sq(filePath)}`);
      if (content.exitCode === 0 && /token|password|secret|api_key|session/i.test(content.stdout)) {
        findings.push({
          type: "INSECURE_STORAGE",
          platform: "android",
          component: prefsFile,
          description: "Sensitive data found in SharedPreferences",
          cvss_estimate: 8.0,
          poc: `adb shell run-as ${packageName} cat ${filePath}`,
          confirmed: true,
        });
      }
    }
  }

  const dbDir = `/data/data/${packageName}/databases/`;
  const db = await adb(options, "shell", `run-as ${packageName} ls ${sq(dbDir)}`);
  if (db.exitCode !== 0) {
    console.log(`[-] run-as databases listing failed (exit ${db.exitCode}): ${db.stderr.trim()}`);
  } else if (db.stdout.trim()) {
    console.log(`[+] Databases found: ${db.stdout.trim()}`);
  }

  const logcat = await adb(options, "logcat", "-d", "-t", "200");
  const hits = logcat.stdout
    .split("\n")
    .filter((line) => /token|password|secret|api_key/i.test(line))
    .slice(0, 20);
  if (hits.length > 0) {
    findings.push({
      type: "LOG_LEAKAGE",
      platform: "android",
      description: "Sensitive data exposed in Android logs",
      cvss_estimate: 7.5,
      poc: `adb logcat -d | grep -iE "token|password|secret"`,
      confirmed: true,
    });
  }
}

async function bypassAndroidSSLPinning(options: HarnessOptions, packageName: string, workDir: string): Promise<void> {
  console.log("[*] Bypassing SSL pinning via Frida...");
  const sslBypassScript = `
Java.perform(function() {
  try {
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    Builder.certificatePinner.implementation = function() { return this; };
  } catch(e) {}
  try {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function() { return true; };
  } catch(e) {}
  try {
    var CertificateTransparency = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
    CertificateTransparency.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
  } catch(e) {}
  console.log("[+] SSL pinning bypass active");
});
  `;

  const scriptPath = join(workDir, "ssl-bypass.js");
  await Bun.write(scriptPath, sslBypassScript);

  const frida = Bun.spawn(["frida", "-U", "-f", packageName, "-l", scriptPath, "--no-pause"], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
  });
  try {
    // Give Frida a moment to spawn the app and attach; detect early crashes.
    const earlyExit = await Promise.race([frida.exited, Bun.sleep(3000).then(() => null)]);
    if (earlyExit !== null) {
      const stderr = await new Response(frida.stderr).text();
      console.error(`[!] Frida exited early (code ${earlyExit}): ${stderr.trim().slice(0, 200)}`);
    } else {
      console.log(`[+] Frida launched (pid ${frida.pid}) — SSL pinning bypass active`);
      const reverse = await adb(options, "reverse", "tcp:8080", "tcp:8080");
      if (reverse.exitCode === 0) {
        console.log("[+] Proxy redirect: device port 8080 → localhost 8080");
      } else {
        console.error(`[!] adb reverse failed: ${reverse.stderr.trim()}`);
      }
    }
  } finally {
    // Never leave a backgrounded frida process running after the harness exits.
    if (frida.exitCode === null) {
      frida.kill();
      await frida.exited;
      console.log("[*] Frida process terminated (re-run manually to keep the bypass active)");
    }
  }
}

function resolveOutputPath(options: HarnessOptions): string {
  if (options.output) return options.output;
  return "kimi-data/mobile-findings.json";
}

async function main(): Promise<void> {
  const options = parseCliArgs(Bun.argv.slice(2));
  if (!options.platform) {
    console.error("Usage: bun appium-harness.ts --platform android|ios [options]");
    process.exit(1);
  }

  try {
    if (options.platform === "android") {
      checkRequiredTools(options);
      await testAndroid(options);
    } else if (options.platform === "ios") {
      console.log("[*] iOS testing — use objection/frida manually with IPA");
      console.log("[*] Run: objection -g com.target.app explore");
      console.log("[*] Then: ios sslpinning disable && ios keychain dump");
    }
  } catch (e) {
    console.error(`[!] ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  }

  const criticalFindings = findings.filter((f) => f.cvss_estimate >= CRITICAL_CVSS_THRESHOLD);
  const outputPath = resolveOutputPath(options);
  await Bun.write(
    outputPath,
    JSON.stringify(
      {
        target: options.apk ?? options.ipa ?? options.platform,
        generated_at: new Date().toISOString(),
        total_findings: findings.length,
        findings,
        critical_findings: criticalFindings,
      },
      null,
      2
    )
  );

  console.log(
    `[+] Mobile testing complete. ${findings.length} findings (${criticalFindings.length} critical) → ${outputPath}`
  );
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(`[appium] Fatal: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
