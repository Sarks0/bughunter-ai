# BugHunter AI — Kimi Commands

These are the user-facing commands the Kimi port recognizes.

## Core commands

### Start a hunt

```
hunt https://target.example.com
hunt https://target.example.com --mode pentest
hunt https://target.example.com --mode comprehensive
hunt https://target.example.com --creds-from vault:my-target
```

### Resume or check status

```
hunt https://target.example.com --resume
hunt https://target.example.com --status
```

### Use a config file

```
hunt --config kimi-data/TargetProfiles/example-corp.json
```

### Mobile hunt

Mobile hunts don't go through `hunt-orchestrator` — there is no `--apk` flag.
Run the mobile harness directly (the `W_HUNT_MOBILE` workflow gates on the APK
existing):

```bash
bun kimi/Tools/appium-harness.ts --platform android --apk /path/to/app.apk --target https://api.example.com
```

## Direct tool usage

You can also run the underlying tools directly:

```bash
bun kimi/Tools/hunt-orchestrator.ts --target https://target.example.com --mode bounty
bun kimi/Tools/credential-vault.ts --store --target example --username user --password pass
bun kimi/Tools/auth-manager.ts --target https://target.example.com --authenticate --strategy basic --username user --password pass
bun kimi/Tools/auth-manager.ts --target https://target.example.com --authenticate --strategy basic --creds-from vault:my-target
bun kimi/Tools/burp-bridge.ts --health
bun kimi/Tools/playwright-harness.ts --target https://target.example.com --mode map-flows
bun kimi/Tools/generate-report.ts --findings kimi-data/Sessions/target-slug/findings/all-findings.json --target https://target.example.com --output report.md
```

## Safety reminders

- Only authorized targets.
- Store credentials in the vault, never inline.
- Review findings before reporting.
