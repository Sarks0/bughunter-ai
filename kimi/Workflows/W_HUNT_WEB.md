# W_HUNT_WEB — Web Application Assessment

Workflow definition: `W_HUNT_WEB.json`

## Trigger

Target is an HTTP/HTTPS URL responding with 200/301/302/403.

## Pre-flight

```bash
bun kimi/Tools/hunt-orchestrator.ts --target "$TARGET" --workflow W_HUNT_WEB --mode "$MODE"
bun kimi/Tools/credential-vault.ts --get --target "$TARGET_SLUG"
bun kimi/Tools/auth-manager.ts --target "$TARGET" --check
bun kimi/Tools/burp-bridge.ts --health
```

## Phases

1. **RECON** — subdomain enum, port scan, URL discovery, tech fingerprinting.
2. **APP_UNDERSTANDING** — Playwright map-flows, AppProfile generation.
3. **AUTH_TESTING** — AuthAgent (JWT, OAuth, session, password reset).
4. **INJECTION** — SQLi, XSS, XXE, RCE agents in parallel.
5. **ACCESS_CONTROL** — IDOR, CORS, CSRF agents in parallel.
6. **BUSINESS_LOGIC** — Business logic and race condition testing.
7. **ADVANCED** — SSRF, cache poisoning, HTTP smuggling, prototype pollution.
8. **API_PROTOCOL** — GraphQL, WebSocket, API agents (conditional).
9. **FILE_HANDLING** — File upload testing (conditional).
10. **REPORT** — Aggregate, deduplicate, generate report.

## Agent dispatch

Use Kimi `Agent` or `AgentSwarm` to run agents in parallel. Each agent reads `kimi/Agents/{Name}.md` and the AppProfile at `kimi-data/Sessions/{slug}/app-profile.json`.
