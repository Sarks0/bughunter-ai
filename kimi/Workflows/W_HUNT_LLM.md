# W_HUNT_LLM — AI/LLM Application Assessment

Workflow definition: `W_HUNT_LLM.json`

## Trigger

Target is an AI chatbot, copilot, RAG system, or LLM-powered app.

## Pre-flight

```bash
bun kimi/Tools/hunt-orchestrator.ts --target "$TARGET" --workflow W_HUNT_LLM --mode "$MODE" \
  --config kimi-data/TargetProfiles/program.json
```

Pass `--scope-config` (the same target-config JSON) to playwright-harness, burp-bridge, and validate-finding on every run.

## Phases

1. **RECON** — Identify AI endpoints (`/api/chat`, `/api/completion`).
2. **APP_UNDERSTANDING** — Detect AI features, map flows.
3. **AUTH_TESTING** — Session handling between users.
4. **LLM_SECURITY** — System prompt extraction, prompt injection, cross-user data, RAG poisoning.
5. **INJECTION** — XSS/SSRF via AI output, RCE via generated code.
6. **ACCESS_CONTROL** — Cross-user data access.
7. **FILE_HANDLING** — Document upload for RAG poisoning.
8. **VALIDATION** — Validate findings with `validate-finding.ts`; only `validated` findings are reported as confirmed. Refuted findings go to the learning log.
9. **REPORT** — Generate the report from validated findings.

Primary agent: `kimi/Agents/LLMSecurityAgent.md` (the former standalone LLM agent was merged into it).
