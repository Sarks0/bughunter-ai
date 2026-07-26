# W_RECON — Standalone Reconnaissance

Workflow definition: `W_RECON.json`

## Trigger

User asks for reconnaissance only.

## Phases

1. **RECON** — Subdomain enumeration, port scanning, tech fingerprinting, screenshotting. Produce the standard recon artifacts: `recon/subs.txt`, `recon/alive-hosts.json`, `recon/alive-urls.txt`, `recon/urls.txt`, `recon/params.txt`.
2. **VALIDATION** — Validate findings with `validate-finding.ts`; update target profile and pattern DB from the results.
3. **REPORT** — Generate recon report.

## Agents

- ReconAgent
- SubdomainTakeoverAgent
