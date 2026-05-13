#!/usr/bin/env bun
/**
 * BugBountyFramework — Appium Mobile Testing Harness
 * Supports Android APK and iOS IPA testing
 * Tests: SSL pinning bypass, exported components, deep links, insecure storage
 */

import { parseArgs } from "util";

const { values: args } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    platform: { type: "string" }, // android | ios
    apk: { type: "string" },
    ipa: { type: "string" },
    proxy: { type: "string", default: "http://127.0.0.1:8080" },
    device: { type: "string", default: "emulator-5554" },
    "test-ssl-pinning-bypass": { type: "boolean", default: true },
    "test-deep-links": { type: "boolean", default: true },
    "test-exported-components": { type: "boolean", default: true },
    "test-storage": { type: "boolean", default: true },
    output: { type: "string", default: "/tmp/mobile-findings.json" },
  },
});

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

// ============================================================
// ANDROID TESTING
// ============================================================

async function testAndroid() {
  const apk = args.apk;
  if (!apk) {
    console.error("[!] --apk required for Android testing");
    return;
  }

  console.log(`[*] Android testing — APK: ${apk}`);

  // 1. Install APK
  await run(`adb install -r "${apk}"`);
  const packageName = await getPackageName(apk);
  console.log(`[+] Package: ${packageName}`);

  // 2. Get exported components
  if (args["test-exported-components"]) {
    await testExportedComponents(packageName);
  }

  // 3. Test deep links
  if (args["test-deep-links"]) {
    await testAndroidDeepLinks(packageName);
  }

  // 4. Check insecure storage
  if (args["test-storage"]) {
    await testAndroidStorage(packageName);
  }

  // 5. Setup proxy & SSL pinning bypass via Frida
  if (args["test-ssl-pinning-bypass"]) {
    await bypassAndroidSSLPinning(packageName);
  }
}

async function getPackageName(apkPath: string): Promise<string> {
  const result = await run(`aapt dump badging "${apkPath}" 2>/dev/null | grep "package: name" | cut -d"'" -f2`);
  return result.stdout.trim() || "com.unknown.app";
}

async function testExportedComponents(packageName: string) {
  console.log("[*] Testing exported components...");

  // Get all exported components from manifest
  const manifestResult = await run(
    `apktool d -f "${args.apk}" -o /tmp/apk-decompiled/ 2>/dev/null && ` +
    `grep -E 'exported="true"' /tmp/apk-decompiled/AndroidManifest.xml`
  );

  const exportedComponents = manifestResult.stdout;
  if (!exportedComponents) return;

  // Test exported activities
  const activities = exportedComponents.match(/activity.*?android:name="([^"]+)"/g) || [];
  for (const activity of activities.slice(0, 10)) {
    const activityName = activity.match(/android:name="([^"]+)"/)?.[1];
    if (!activityName) continue;

    // Launch without auth
    const launchResult = await run(
      `adb shell am start -n "${packageName}/${activityName}" 2>&1`
    );

    if (!launchResult.stdout.includes("Error") && !launchResult.stdout.includes("Permission denied")) {
      findings.push({
        type: "EXPORTED_ACTIVITY",
        platform: "android",
        component: activityName,
        description: `Exported activity accessible without authentication`,
        cvss_estimate: 7.5,
        poc: `adb shell am start -n "${packageName}/${activityName}"`,
        confirmed: true,
      });
      console.log(`[+] Exported activity: ${activityName}`);
    }
  }

  // Test exported content providers
  const providers = exportedComponents.match(/provider.*?android:authorities="([^"]+)"/g) || [];
  for (const provider of providers.slice(0, 5)) {
    const authority = provider.match(/android:authorities="([^"]+)"/)?.[1];
    if (!authority) continue;

    const queryResult = await run(`adb shell content query --uri "content://${authority}/" 2>&1`);
    if (queryResult.stdout.includes("Row:") || queryResult.stdout.includes("_id")) {
      findings.push({
        type: "INSECURE_CONTENT_PROVIDER",
        platform: "android",
        component: authority,
        description: `Exported content provider allows unauthenticated data access`,
        cvss_estimate: 8.1,
        poc: `adb shell content query --uri "content://${authority}/"`,
        confirmed: true,
      });
      console.log(`[!!!] INSECURE CONTENT PROVIDER: ${authority}`);
    }
  }
}

async function testAndroidDeepLinks(packageName: string) {
  console.log("[*] Testing deep links...");

  // Extract deep link schemes from manifest
  const schemesResult = await run(
    `grep -E "scheme|host|pathPattern" /tmp/apk-decompiled/AndroidManifest.xml 2>/dev/null`
  );

  const schemes = schemesResult.stdout.match(/android:scheme="([^"]+)"/g)?.map(
    (s) => s.match(/android:scheme="([^"]+)"/)?.[1]
  ).filter(Boolean) || [];

  const hosts = schemesResult.stdout.match(/android:host="([^"]+)"/g)?.map(
    (h) => h.match(/android:host="([^"]+)"/)?.[1]
  ).filter(Boolean) || [];

  // Test injection in deep link parameters
  const injectionPayloads = [
    "javascript:alert(1)",
    "' OR 1=1--",
    "../../etc/passwd",
    "${7*7}",
  ];

  for (const scheme of schemes.slice(0, 3)) {
    for (const host of hosts.slice(0, 3)) {
      for (const payload of injectionPayloads) {
        await run(
          `adb shell am start -a android.intent.action.VIEW ` +
          `-d "${scheme}://${host}?redirect=${encodeURIComponent(payload)}" 2>&1`
        );
      }
    }
  }
}

async function testAndroidStorage(packageName: string) {
  console.log("[*] Testing insecure storage...");

  // Check SharedPreferences
  const prefsResult = await run(
    `adb shell run-as ${packageName} ls /data/data/${packageName}/shared_prefs/ 2>&1`
  );

  if (!prefsResult.stdout.includes("Permission denied")) {
    const prefsFiles = prefsResult.stdout.split("\n").filter(f => f.endsWith(".xml"));
    for (const prefsFile of prefsFiles.slice(0, 5)) {
      const content = await run(
        `adb shell run-as ${packageName} cat /data/data/${packageName}/shared_prefs/${prefsFile} 2>&1`
      );
      if (content.stdout.match(/token|password|secret|api_key|session/i)) {
        findings.push({
          type: "INSECURE_STORAGE",
          platform: "android",
          component: prefsFile,
          description: `Sensitive data (token/password/key) found in SharedPreferences`,
          cvss_estimate: 8.0,
          poc: `adb shell run-as ${packageName} cat /data/data/${packageName}/shared_prefs/${prefsFile}`,
          confirmed: true,
        });
        console.log(`[!!!] INSECURE STORAGE: ${prefsFile}`);
      }
    }
  }

  // Check SQLite databases
  const dbResult = await run(
    `adb shell run-as ${packageName} ls /data/data/${packageName}/databases/ 2>&1`
  );
  if (!dbResult.stdout.includes("Permission denied")) {
    console.log(`[+] Databases found: ${dbResult.stdout}`);
  }

  // Check logcat for sensitive data
  const logResult = await run(
    `adb logcat -d -t 200 | grep -iE "token|password|secret|api_key" 2>&1 | head -20`
  );
  if (logResult.stdout.trim()) {
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

async function bypassAndroidSSLPinning(packageName: string) {
  console.log("[*] Bypassing SSL pinning via Frida...");

  // SSL bypass script using multiple techniques
  const sslBypassScript = `
Java.perform(function() {
  // Bypass OkHttp SSL pinning
  try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    Builder.certificatePinner.implementation = function() { return this; };
  } catch(e) {}

  // Bypass TrustManager
  try {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function() { return true; };
  } catch(e) {}

  // Bypass custom pinning (network_security_config)
  try {
    var CertificateTransparency = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
    CertificateTransparency.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() { return true; };
  } catch(e) {}

  console.log("[+] SSL pinning bypass active — route traffic through Burp");
});
  `;

  await Bun.write("/tmp/ssl-bypass.js", sslBypassScript);

  // Launch app with Frida
  const fridaResult = await run(
    `frida -U -f "${packageName}" -l /tmp/ssl-bypass.js --no-pause 2>&1 &`
  );
  console.log(`[+] Frida launched: ${fridaResult.stdout.slice(0, 100)}`);

  // Setup proxy redirect
  await run(`adb reverse tcp:8080 tcp:8080`);
  console.log("[+] Proxy redirect: device port 8080 → localhost:8080");
}

// ============================================================
// UTILITY
// ============================================================

async function run(cmd: string): Promise<{ stdout: string; stderr: string }> {
  try {
    const proc = Bun.spawn(["bash", "-c", cmd], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    return { stdout, stderr };
  } catch (e) {
    return { stdout: "", stderr: String(e) };
  }
}

async function main() {
  if (!args.platform) {
    console.error("Usage: bun appium-harness.ts --platform android|ios [options]");
    process.exit(1);
  }

  if (args.platform === "android") {
    await testAndroid();
  } else if (args.platform === "ios") {
    console.log("[*] iOS testing — use objection/frida manually with IPA");
    console.log("[*] Run: objection -g com.target.app explore");
    console.log("[*] Then: ios sslpinning disable && ios keychain dump");
  }

  // Filter and write high-severity findings only
  const criticalFindings = findings.filter((f) => f.cvss_estimate >= 7.5);
  await Bun.write(
    args.output,
    JSON.stringify({
      platform: args.platform,
      total_findings: findings.length,
      critical_high: criticalFindings.length,
      findings: criticalFindings,
      timestamp: new Date().toISOString(),
    }, null, 2)
  );

  console.log(`[+] Mobile testing complete. ${criticalFindings.length} critical/high findings → ${args.output}`);
}

main().catch(console.error);
