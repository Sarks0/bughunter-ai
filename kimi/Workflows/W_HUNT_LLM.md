# W_HUNT_LLM — AI/LLM Application Assessment

Workflow definition: `W_HUNT_LLM.json`

## Trigger

Target is an AI chatbot, copilot, RAG system, or LLM-powered app.

## Pre-flight

```bash
bun kimi/Tools/hunt-orchestrator.ts --target "$TARGET" --workflow W_HUNT_LLM --mode "$MODE"
```

## Phases

1. **RECON** — Identify AI endpoints (`/api/chat`, `/api/completion`).
2. **APP_UNDERSTANDING** — Detect AI features, map flows.
3. **AUTH_TESTING** — Session handling between users.
4. **LLM_SECURITY** — System prompt extraction, prompt injection, cross-user data, RAG poisoning.
5. **INJECTION** — XSS/SSRF via AI output, RCE via generated code.
6. **ACCESS_CONTROL** — Cross-user data access.
7. **FILE_HANDLING** — Document upload for RAG poisoning.
8. **LEARNING**.
9. **REPORT**.

Primary agent: `kimi/Agents/LLMSecurityAgent.md`.
