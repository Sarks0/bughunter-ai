/*
 * ssl-bypass.js — universal Android SSL-pinning bypass (Frida)
 *
 * Hooks the common certificate-validation paths so HTTPS traffic can be
 * intercepted with a proxy (Burp, mitmproxy) during authorized testing:
 *   - OkHttp3 CertificatePinner.check (all known overloads)
 *   - javax.net.ssl.X509TrustManager / conscrypt TrustManagerImpl
 *   - SSLContext.init with a permissive trust manager
 *   - Apache AbstractVerifier hostname verification
 *
 * Usage: frida -U -f com.target.app -l kimi/Tools/ssl-bypass.js
 */
Java.perform(function () {
  function log(msg) { console.log("[ssl-bypass] " + msg); }

  // Permissive X509TrustManager used to replace pinned/strict managers.
  var TrustAll = Java.registerClass({
    name: "com.bughunter.TrustAll",
    implements: [Java.use("javax.net.ssl.X509TrustManager")],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });

  // 1. OkHttp3 CertificatePinner.check — every overload.
  try {
    var Pinner = Java.use("okhttp3.CertificatePinner");
    Pinner.check.overloads.forEach(function (ov) {
      ov.implementation = function () { log("OkHttp3 CertificatePinner.check bypassed"); };
    });
  } catch (e) { log("OkHttp3 CertificatePinner not present"); }

  // 2. Conscrypt TrustManagerImpl.checkServerTrusted.
  try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TMI.checkServerTrusted.overloads.forEach(function (ov) {
      ov.implementation = function (chain) {
        log("TrustManagerImpl.checkServerTrusted bypassed");
        return chain;
      };
    });
  } catch (e) { log("TrustManagerImpl not present"); }

  // 3. Any X509TrustManager.checkServerTrusted registered at runtime.
  try {
    var X509 = Java.use("javax.net.ssl.X509TrustManager");
    X509.checkServerTrusted.overloads.forEach(function (ov) {
      ov.implementation = function () { log("X509TrustManager.checkServerTrusted bypassed"); };
    });
  } catch (e) { log("X509TrustManager hook failed"); }

  // 4. SSLContext.init — install the permissive trust manager.
  try {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var managers = Java.array("Ljavax.net.ssl.TrustManager;", [TrustAll.$new()]);
    SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
    ).implementation = function (km, tm, sr) {
      log("SSLContext.init trust managers replaced");
      this.init(km, managers, sr);
    };
  } catch (e) { log("SSLContext.init hook failed"); }

  // 5. Apache AbstractVerifier hostname verification.
  try {
    var Verifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
    Verifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;")
      .implementation = function () { log("AbstractVerifier.verify bypassed"); };
  } catch (e) { log("Apache AbstractVerifier not present"); }

  log("all hooks installed");
});
