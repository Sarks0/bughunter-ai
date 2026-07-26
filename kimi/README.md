# BugHunter AI — Kimi Code CLI Port

This directory contains a Kimi-compatible version of BugHunter AI. It preserves the same 10-phase hunt model, agent army, and tooling as the original Claude Code skill, but uses Kimi Code CLI conventions, paths, and tools.

## Status

This is a **port** of the original `skills/BugBountyFramework/` skill. The original Claude skill remains in `skills/BugBountyFramework/` and is untouched.

## Quick start

1. Install dependencies:

   ```bash
   cd kimi
   bun install
   ```

2. Run a hunt:

   ```bash
   cd ..
   bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --mode bounty
   ```

   Or ask Kimi:

   ```
   hunt https://target.example.com
   ```

3. Check status:

   ```bash
   bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --status
   ```

## Differences from the Claude version

| Aspect | Claude version | Kimi port |
|--------|---------------|-----------|
| Skill location | `~/.claude/skills/BugBountyFramework/` | `kimi/` in this repo |
| Data directory | `~/.claude/MEMORY/BugBounty/` | `kimi-data/` (project-local) |
| Voice notifications | Hardcoded localhost server | Removed (configurable later) |
| Agent execution | Claude `Agent` tool | Kimi `Agent` / `AgentSwarm` tools |
| Cross-session memory | `claude-mem` plugin | Kimi memory + local learning logs |
| Dependency metadata | Inherited from PAI | `package.json` + `tsconfig.json` |

## Tools

| Tool | Purpose |
|------|---------|
| `Tools/hunt-orchestrator.ts` | State machine, phase tracking, resume |
| `Tools/credential-vault.ts` | Credential storage and redaction |
| `Tools/auth-manager.ts` | Authentication flow automation |
| `Tools/burp-bridge.ts` | Burp Suite REST API integration |
| `Tools/playwright-harness.ts` | Browser automation and app profiling |
| `Tools/appium-harness.ts` | Mobile app testing harness |
| `Tools/generate-report.ts` | Report generation from findings |

The orchestrator can also health-check the external toolset used by the agents
(`subfinder`, `httpx`, `naabu`, `nuclei`, `ffuf`, `katana`, `gau`, `waymore`,
`jsluice`, `arjun`, `kiterunner`/`kr`, `trufflehog`, `interactsh-client`,
`graphql-cop`, `grpc_cli`, `garak`, `pyrit`, `promptfoo`, `adb`/`aapt`/`frida`,
and more — see `Tools/lib/tool-validator.ts`):

```bash
bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --validate-tools
```

See `SETUP.md` for install notes.

## Agents

All 27 specialized agent prompts live in `kimi/Agents/`. They are derived from the original Claude agent files with Claude-specific references removed.

## Testing

```bash
cd kimi
bun test
```

## TODO / known gaps

- The credential vault encrypts with AES-256-GCM by default (passphrase via interactive prompt, `BH_VAULT_PASSPHRASE`, `--passphrase-file`, or `--passphrase`); `--plain` is an explicit insecure fallback for testing only. A 1Password `op` CLI integration is also available via `--op-item`.
- iOS mobile testing is stubbed; Android dynamic analysis requires a rooted/debuggable device or emulator.
- External recon tools are not auto-installed; run the dependency check in `SETUP.md`.
