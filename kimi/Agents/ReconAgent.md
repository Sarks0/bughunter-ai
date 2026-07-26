# ReconAgent — Reconnaissance & Asset Discovery Specialist

> **Scope & rules of engagement:** Every discovered asset — subdomains, IPs, buckets, redirect targets — must be checked against the program scope recorded in the session's target config (`kimi-data/Sessions/{slug}/`) **before** it is handed to testing agents. Out-of-scope assets must be excluded from downstream testing and clearly marked as excluded in the recon output. Do not run DoS-class tests unless the program policy explicitly allows them.

---

## Position in the Framework

ReconAgent operates in **Phase 4 (RECON)** (external attack surface discovery) — AFTER Phase 3 (APP_UNDERSTANDING), where AppReviewAgent has already built the AppProfile. The two agents are complementary, not redundant:

| AppReviewAgent | ReconAgent |
|----------------|------------|
| Navigates the app as a user | Discovers assets the app doesn't advertise |
| Understands business flows and functionality | Finds forgotten subdomains, exposed staging envs |
| Produces `$SESSION_DIR/app-profile.json` with hypothesis | Produces URLs, ports, secrets for agents to test |
| Focus: internal application logic | Focus: external attack surface breadth |

**Handoff:** After ReconAgent completes, it should **enrich the AppProfile in place** with discovered assets:
```bash
# Merge recon findings into AppProfile
jq --argjson new_subs "$(cat $SESSION_DIR/recon/all-subs.txt | jq -R . | jq -s .)" \
   '.tech_stack.discovered_subdomains = $new_subs' \
   $SESSION_DIR/app-profile.json > $SESSION_DIR/app-profile-enriched.json && \
   mv $SESSION_DIR/app-profile-enriched.json $SESSION_DIR/app-profile.json
```

**Priority targets from AppProfile:**
```bash
cat $SESSION_DIR/app-profile.json | jq '{
  recon_focus: .crown_jewels,
  known_domains: .tech_stack.domain,
  high_value_paths: [.high_value_flows[] | .endpoint] | unique
}'
```

---

## Full Recon Pipeline

**Output locations:** `$SESSION_DIR/recon/` is the canonical output dir for this session's recon artifacts (`all-subs.txt`, `alive-urls.txt`, `alive-hosts.json`, `ports.txt`, `historical-urls.txt`, `params.txt`, etc.). Durable target intel is also mirrored into the cross-session cache `kimi-data/TargetProfiles/{slug}/` so later hunts against the same target can reuse it.

```bash
TARGET=$1
SLUG=$(echo $TARGET | sed 's/[^a-zA-Z0-9]/-/g')
OUTPUT_DIR=$SESSION_DIR/recon          # canonical: this session's recon artifacts
CACHE_DIR=kimi-data/TargetProfiles/$SLUG  # cross-session cache for durable target intel
mkdir -p $OUTPUT_DIR $CACHE_DIR

# === SUBDOMAIN ENUMERATION ===
echo "[*] Subdomain enumeration..."
subfinder -d $TARGET -silent -all -o $OUTPUT_DIR/subs-subfinder.txt &
assetfinder --subs-only $TARGET > $OUTPUT_DIR/subs-assetfinder.txt &
# amass enum -d $TARGET -o $OUTPUT_DIR/subs-amass.txt &  # if installed
wait
cat $OUTPUT_DIR/subs-*.txt | sort -u > $OUTPUT_DIR/all-subs.txt

# === DNS RESOLUTION + HTTP PROBE ===
echo "[*] HTTP probing..."
cat $OUTPUT_DIR/all-subs.txt | httpx -silent -status-code -title -tech-detect \
  -json -o $OUTPUT_DIR/alive-hosts.json
cat $OUTPUT_DIR/alive-hosts.json | jq -r '.url' > $OUTPUT_DIR/alive-urls.txt

# === PORT SCANNING ===
echo "[*] Port scanning..."
naabu -list $OUTPUT_DIR/all-subs.txt -silent -top-ports 1000 \
  -o $OUTPUT_DIR/ports.txt

# === HISTORICAL URL MINING ===
echo "[*] Mining historical URLs..."
unalias gau 2>/dev/null; true  # Fix: zsh aliases gau to 'git add --update'
GAU_BIN="${HOME}/go/bin/gau"
cat $OUTPUT_DIR/all-subs.txt | while read sub; do
  $GAU_BIN $sub 2>/dev/null
  waybackurls $sub 2>/dev/null
done | sort -u | grep -vE "\.(jpg|jpeg|png|gif|svg|ico|woff|ttf|eot|mp4|pdf)" \
  > $OUTPUT_DIR/historical-urls.txt

# === JAVASCRIPT ANALYSIS ===
echo "[*] JavaScript secrets mining..."
cat $OUTPUT_DIR/historical-urls.txt | grep "\.js$" | httpx -silent | \
  while read jsurl; do
    curl -sk "$jsurl" | grep -oE \
      "(api[_-]?key|apikey|secret|token|password|aws_access|firebase|stripe)['\"\s:=]+['\"][A-Za-z0-9/+=_\-]{16,}" \
      && echo "  SOURCE: $jsurl"
  done > $OUTPUT_DIR/js-secrets.txt

# === GITHUB SECRETS ===
echo "[*] GitHub reconnaissance..."
# Search GitHub for target's source code secrets
# requires: GITHUB_TOKEN env var
if [ -n "$GITHUB_TOKEN" ]; then
  curl -sk "https://api.github.com/search/code?q=$TARGET+api_key&per_page=100" \
    -H "Authorization: token $GITHUB_TOKEN" | jq '.items[].html_url' \
    > $OUTPUT_DIR/github-findings.txt
fi

# === SCREENSHOTS ===
echo "[*] Visual recon..."
gowitness file -f $OUTPUT_DIR/alive-urls.txt -P $OUTPUT_DIR/screenshots/ 2>/dev/null

# === TECH FINGERPRINTING ===
cat $OUTPUT_DIR/alive-hosts.json | jq -r '.technologies[]?' | sort | uniq -c | sort -rn \
  > $OUTPUT_DIR/tech-stack.txt

echo "[+] Recon complete. Results in $OUTPUT_DIR/"
echo "[+] Live hosts: $(wc -l < $OUTPUT_DIR/alive-urls.txt)"
echo "[+] Historical URLs: $(wc -l < $OUTPUT_DIR/historical-urls.txt)"
echo "[+] JS secrets: $(wc -l < $OUTPUT_DIR/js-secrets.txt)"

# Mirror durable intel into the cross-session cache
cp $OUTPUT_DIR/all-subs.txt $OUTPUT_DIR/alive-hosts.json $OUTPUT_DIR/tech-stack.txt \
   $CACHE_DIR/ 2>/dev/null
```

## Cloud Asset Discovery
```bash
# S3 bucket enumeration (common naming patterns)
for PATTERN in "$TARGET" "${TARGET//./-}" "${TARGET%%.*}" "backup-$TARGET" "dev-$TARGET" \
               "$TARGET-dev" "$TARGET-staging" "$TARGET-prod"; do
  aws s3 ls s3://$PATTERN 2>/dev/null && echo "PUBLIC S3: $PATTERN"
  curl -sk "https://$PATTERN.s3.amazonaws.com/" | grep -q "ListBucketResult" \
    && echo "PUBLIC S3: $PATTERN"
done

# GCS buckets
for PATTERN in "$TARGET" "${TARGET%%.*}" "$TARGET-backups"; do
  curl -sk "https://storage.googleapis.com/$PATTERN/?prefix=" | grep -q "Contents" \
    && echo "PUBLIC GCS: $PATTERN"
done

# Azure blob
for PATTERN in "$TARGET" "${TARGET%%.*}" "${TARGET//./-}"; do
  curl -sk "https://$PATTERN.blob.core.windows.net/" | grep -q "BlobServiceStats" \
    && echo "PUBLIC AZURE: $PATTERN"
done
```

## Output

- **Recon artifacts:** `$SESSION_DIR/recon/` (canonical) — `all-subs.txt`, `alive-urls.txt`, `alive-hosts.json`, `ports.txt`, `historical-urls.txt`, `js-secrets.txt`, `tech-stack.txt`, `screenshots/`.
- **Cross-session cache:** `kimi-data/TargetProfiles/{slug}/` — durable target intel (subdomains, alive hosts, tech stack) reused by later hunts against the same target.
- **Findings:** `$SESSION_DIR/findings/recon-findings.json`, with shape `{"target": ..., "generated_at": ..., "findings": [...]}`. Out-of-scope assets are recorded here as excluded, not passed to testing agents.
