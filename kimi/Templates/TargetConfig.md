# Target Configuration Guide

Create a JSON config file at `kimi-data/TargetProfiles/{program-name}.json`.

## Full schema

```json
{
  "program_name": "ExampleCorp Bug Bounty",
  "platform": "hackerone",
  "program_url": "https://hackerone.com/examplecorp",
  "target": "https://api.example.com",
  "scope_in": ["*.example.com", "api.example.com", "app.example.com"],
  "scope_out": ["blog.example.com", "status.example.com"],
  "burp_scope_file": "hackerone-burp-scope.json",
  "target_types": ["web", "api"],
  "artifacts": {
    "apk_path": "",
    "ipa_path": "",
    "swagger_url": "https://api.example.com/swagger.json"
  },
  "authentication": {
    "regular_user": {
      "username": "test@example.com",
      "password": "",
      "session_cookie": "",
      "jwt": "",
      "api_key": ""
    },
    "admin_user": {
      "note": "Create admin account if possible"
    }
  },
  "burp": {
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,
    "rest_api_url": "http://127.0.0.1:1337/v0.1"
  },
  "known_endpoints": ["/admin", "/api/v1", "/graphql", "/upload"],
  "tech_hints": "Laravel 9, MySQL 8, Redis, Nginx",
  "prior_findings": "XSS found in search in 2024, since patched",
  "max_requests_per_second": 10,
  "severity_filter": "critical_high",
  "report_format": "hackerone",
  "notes": "Admin panel at /dashboard. Multi-tenant SaaS."
}
```

## Scope pattern syntax

- `*.example.com` — any subdomain of `example.com`.
- `example.com` — the exact host.
- `https://api.example.com/*` — URLs under that path.
- `/^.*\.example\.com$/` — regex literal (wrap in `/.../`).

Out-of-scope patterns take precedence over in-scope patterns.

## HackerOne Burp Suite scope import

If a program provides a Burp Suite Project Configuration JSON from the HackerOne Scope tab, reference it with `burp_scope_file`. The path is resolved relative to the config file unless absolute.

```json
{
  "program_name": "ExampleCorp",
  "target": "https://api.example.com",
  "scope_in": [],
  "scope_out": [],
  "burp_scope_file": "hackerone-burp-scope.json"
}
```

The importer understands both simple-mode URL strings and advanced-mode objects with `protocol`, `host`, `port`, `file`, and `enabled` fields.

## Minimal config

```json
{
  "program_name": "Quick Hunt",
  "target": "https://target.com",
  "scope_in": ["https://target.com"],
  "scope_out": [],
  "target_types": ["web"],
  "severity_filter": "critical_high"
}
```

## Usage

Start a hunt from a config file:

```bash
bun kimi/Tools/hunt-orchestrator.ts --config kimi-data/TargetProfiles/example-corp.json
```

Check whether a target is in scope without starting a hunt:

```bash
bun kimi/Tools/hunt-orchestrator.ts --config kimi-data/TargetProfiles/example-corp.json --scope-check
bun kimi/Tools/hunt-orchestrator.ts --config kimi-data/TargetProfiles/example-corp.json --target https://api.example.com --scope-check
```

Validate external tools for the selected mode:

```bash
bun kimi/Tools/hunt-orchestrator.ts --validate-tools
bun kimi/Tools/hunt-orchestrator.ts --validate-tools --mode pentest
```
