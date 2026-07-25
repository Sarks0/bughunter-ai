# W_HUNT_API — API Assessment

Workflow definition: `W_HUNT_API.json`

## Trigger

Target is an API endpoint, Swagger/OpenAPI URL, or GraphQL endpoint.

## Pre-flight

```bash
bun kimi/Tools/hunt-orchestrator.ts --target "$TARGET" --workflow W_HUNT_API --mode "$MODE"
```

## Phases

1. **RECON** — Discover API endpoints, versions, docs.
2. **APP_UNDERSTANDING** — APIAgent + AppReviewAgent map the API surface.
3. **AUTH_TESTING** — Token, OAuth, API key testing.
4. **INJECTION** — SQLi, RCE via API inputs.
5. **ACCESS_CONTROL** — IDOR, CORS.
6. **API_PROTOCOL** — GraphQL introspection, batch abuse, WebSocket auth.
7. **BUSINESS_LOGIC** — Race conditions, mass assignment.
8. **REPORT**.
