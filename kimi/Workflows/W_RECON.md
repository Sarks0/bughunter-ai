# W_RECON — Standalone Reconnaissance

Workflow definition: `W_RECON.json`

## Trigger

User asks for reconnaissance only.

## Phases

1. **RECON** — Subdomain enumeration, port scanning, tech fingerprinting, screenshotting.
2. **LEARNING** — Update target profile and pattern DB.
3. **REPORT** — Generate recon report.

## Agents

- ReconAgent
- SubdomainTakeoverAgent
