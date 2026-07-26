# BugHunter AI — Project Guide for Kimi Code CLI

This repository is **BugHunter AI**, an autonomous bug bounty and offensive-security testing framework. The original code is a Claude Code skill located in `skills/BugBountyFramework/`. This fork also contains a **Kimi Code CLI port** in `kimi/`.

## How to invoke (Kimi)

From the repo root, ask Kimi to run a hunt:

```
hunt https://target.example.com
```

Kimi loads the framework from `kimi/BugBountyFramework.md`. The framework then:

1. Creates a hunt session under `kimi-data/Sessions/{target-slug}/`.
2. Loads credentials from the vault (`kimi-data/Vault/credentials.enc`).
3. Authenticates via `kimi/Tools/auth-manager.ts`.
4. Profiles the app via `kimi/Tools/playwright-harness.ts`.
5. Runs reconnaissance.
6. Dispatches specialized agents in parallel from `kimi/Agents/`.
7. Performs dynamic testing and generates a report.

## Safety rules (non-negotiable)

- Only test targets you have **written authorization** to test.
- Respect program scope. Out-of-scope targets must be rejected immediately.
- Never embed credentials in prompts or logs; use the credential vault.
- Redact session artifacts before sharing reports.
- Stop and ask the user if a command would affect systems outside the declared scope.

## Directory layout

```
├── skills/BugBountyFramework/   # Original Claude Code skill (kept intact)
├── kimi/                        # Kimi Code CLI port
│   ├── BugBountyFramework.md    # Top-level skill prompt
│   ├── commands.md              # User-facing commands
│   ├── Tools/                   # TypeScript tooling
│   ├── Agents/                  # Specialized agent prompts
│   ├── Workflows/               # Hunt workflows
│   └── Templates/               # Report and config templates
├── kimi-data/                   # Runtime data (sessions, findings, vault)
├── README.md                    # Project overview
└── AGENTS.md                    # This file
```

## Development

- Tools are TypeScript/Bun. Run one with `bun kimi/Tools/<tool>.ts` (no arguments) to print its usage.
- Tests live in `kimi/__tests__/` and run with `bun test` from `kimi/`.
- The original Claude skill is preserved; changes to `kimi/` should not modify `skills/`.
- `./install.sh` is the unified installer for both CLIs (flags: `--kimi-only`, `--claude-only`, `--with-mcp`, `--skip-browser`).

## MCP servers

Configured for both Kimi Code CLI (`~/.kimi-code/mcp.json`) and Claude Code (user scope in `~/.claude.json`, managed with `claude mcp add/list`). No API keys are stored in config files — export them in `~/.zshrc`; stdio child processes inherit the shell environment.

Fresh clones: run `./scripts/setup-mcp.sh` to reproduce this setup (template in `config/mcp.servers.json`; see `kimi/SETUP.md` → "MCP servers (optional)").

| Server | Status | Notes |
|--------|--------|-------|
| `filesystem` | enabled | `npx @modelcontextprotocol/server-filesystem@2026.7.10`; allowlist: `~/bughunter-ai`, `~/Projects` |
| `vuln-intel` | enabled | thinkchainai/vulnerability-intelligence-mcp in `~/venvs/vulnerability-intelligence-mcp/venv`; CISA KEV + EPSS + NVD are keyless (optional `NIST_NVD_API_KEY` raises NVD rate limits) |
| `github` | disabled | HTTP `https://api.githubcopilot.com/mcp/`; needs `GITHUB_PERSONAL_ACCESS_TOKEN` (Kimi uses `bearerTokenEnvVar`) |
| `shodan` | disabled | `npx @burtthecoder/mcp-shodan@1.0.22`; needs `SHODAN_API_KEY` |
| `virustotal` | disabled | `uvx gti_mcp` (Google GTI MCP); needs `VT_APIKEY` (a free VT key works) |
| `burp` | disabled | SSE `http://127.0.0.1:9876`; needs the Burp BApp (below) |

To activate a key-gated server: export the key in `~/.zshrc`, then set `"enabled": true` in `~/.kimi-code/mcp.json` (Claude picks it up automatically once the env var exists).

**Burp BApp install:** in Burp Suite (Community works), go to Extensions → BApp Store, install the official PortSwigger **MCP Server** extension (BApp id `9952290f04ed4f628e624d0aa9dccebc`), then enable it under Extensions → MCP. It serves SSE on `127.0.0.1:9876`. Collaborator payloads and active scanning require Burp Pro. Caveat: the SSE port is unauthenticated localhost — only enable it while testing.

## Dependencies

Required:

- [Bun](https://bun.sh)
- [Node.js 18+](https://nodejs.org) (for MCP servers)
- [Playwright](https://playwright.dev)

Recommended:

- Burp Suite Professional (for Burp MCP bridge)
- ProjectDiscovery recon stack: `subfinder`, `httpx`, `naabu`, `dnsx`, `nuclei`, `katana`, `interactsh-client` (install via `pdtm`)
- Content discovery / secrets: `ffuf`, `gau`, `waymore`, `jsluice`, `arjun`, `kiterunner` (`kr`), `trufflehog`
- Python tools: `sqlmap`, `jwt_tool.py`
- API / LLM testing: `graphql-cop`, `grpc_cli`, `garak`, `pyrit`, `promptfoo`
- Mobile (Android): `adb`, `aapt`, `apktool`, `jadx`, `frida`

See `kimi/SETUP.md` for a complete installation guide.
