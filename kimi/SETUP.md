# BugHunter AI — Kimi Code CLI Setup Guide

This guide walks through installing and running the Kimi port of BugHunter AI.

## Prerequisites

- [Bun](https://bun.sh) (v1.0+)
- [Node.js 18+](https://nodejs.org) (for MCP servers)
- [Git](https://git-scm.com)

## Optional but recommended

- [Playwright](https://playwright.dev) browsers: `bunx playwright install chromium`
- [Burp Suite Professional](https://portswigger.net/burp) with REST API enabled on port 1337
- ProjectDiscovery recon stack: `subfinder`, `httpx`, `naabu`, `dnsx`, `nuclei`, `katana`, `interactsh-client`.
  The easy path is their installer [pdtm](https://github.com/projectdiscovery/pdtm):
  `go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest`, then `pdtm -install-all`
- Other Go-based content-discovery/recon tools:
  - `ffuf`: `go install github.com/ffuf/ffuf/v2@latest`
  - `gau`: `go install github.com/lc/gau/v2/cmd/gau@latest`
  - `jsluice`: `go install github.com/BishopFox/jsluice/cmd/jsluice@latest`
  - `kiterunner` (binary is `kr`): build from [assetnote/kiterunner](https://github.com/assetnote/kiterunner)
  - `trufflehog`: `go install github.com/trufflesecurity/trufflehog/v3@latest`
- Python tools:
  - `sqlmap`
  - `waymore`: `pip install waymore`
  - `arjun`: `pip install arjun`
- API testing:
  - `graphql-cop`: `pip install graphql-cop`
  - `grpc_cli`: build from the [grpc](https://github.com/grpc/grpc) repo (`bazel build //test/cpp/util:grpc_cli`)
- LLM security (used by LLMSecurityAgent):
  - `garak`: `pip install garak`
  - Microsoft [PyRIT](https://github.com/Azure/PyRIT): `pip install pyrit`
  - `promptfoo`: `npm install -g promptfoo`
- Mobile testing (Android, used by `appium-harness.ts`):
  - `adb` and `aapt`: install the Android SDK platform-tools / build-tools
  - `apktool`, `jadx`
  - `frida`: `pip install frida-tools`

Run `bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --validate-tools`
to health-check everything on your PATH (see `kimi/Tools/lib/tool-validator.ts`
for the full list of known tools).

## Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/Sarks0/bughunter-ai.git
   cd bughunter-ai
   ```

2. Install the Kimi port dependencies:

   ```bash
   cd kimi
   bun install
   cd ..
   ```

3. (Optional) Install Playwright browsers:

   ```bash
   bunx playwright install chromium
   ```

## Verify the installation

```bash
cd kimi
bun test
bun run lint
```

Both should pass.

## Run your first hunt

```bash
# Start a hunt
bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --mode bounty

# Store credentials first (recommended)
bun kimi/Tools/credential-vault.ts --store --target target-example-com \
  --username user@example.com --password "SuperSecret123!"

# Check status
bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --status

# Resume
bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --resume
```

## Credential vault encryption

By default, the vault encrypts credentials using **AES-256-GCM** with a passphrase-derived key (PBKDF2, 100k iterations).

Provide the passphrase via one of these methods (in order of precedence):

1. `--passphrase` flag (not recommended — leaks to shell history)
2. `--passphrase-file /path/to/passphrase.txt`
3. `BH_VAULT_PASSPHRASE` environment variable
4. Interactive prompt (default if no other source is given)

Example with env var:

```bash
export BH_VAULT_PASSPHRASE="a-strong-passphrase"
bun kimi/Tools/credential-vault.ts --store --target target-example-com \
  --username user@example.com --password "SuperSecret123!"
```

Example with interactive prompt:

```bash
bun kimi/Tools/credential-vault.ts --store --target target-example-com \
  --username user@example.com --password "SuperSecret123!"
# Prompts: Vault passphrase: ***
```

### Rotate passphrase

```bash
bun kimi/Tools/credential-vault.ts --rotate
```

### Insecure plaintext fallback

For testing only:

```bash
bun kimi/Tools/credential-vault.ts --store --target test --username u --password p --plain
```

## Use a target config file

Create `kimi-data/TargetProfiles/example-corp.json` (see `kimi/Templates/TargetConfig.md`) and run:

```bash
bun kimi/Tools/hunt-orchestrator.ts --config kimi-data/TargetProfiles/example-corp.json
```

## Project layout

```
kimi/
├── BugBountyFramework.md   # Top-level skill prompt
├── commands.md             # Command reference
├── Tools/                  # TypeScript tooling
├── Agents/                 # 27 specialized agent prompts
├── Workflows/              # Hunt workflows (JSON + Markdown)
├── Templates/              # Report and config templates
├── __tests__/              # Unit tests
└── package.json

kimi-data/                  # Runtime data (gitignored)
├── Sessions/
├── Findings/
├── LearningLogs/
├── PatternDB/
├── TargetProfiles/
└── Vault/
```

## Troubleshooting

### `playwright` module not found

Run `bun install` from inside the `kimi/` directory.

### Burp bridge health check fails

Ensure Burp Suite is running and the REST API is enabled on `http://127.0.0.1:1337/v0.1`. The framework can run without Burp using direct Playwright testing.

### Vault corrupt / wrong passphrase

If you forget the passphrase, delete `kimi-data/Vault/credentials.enc` and re-store credentials. There is no recovery mechanism.
