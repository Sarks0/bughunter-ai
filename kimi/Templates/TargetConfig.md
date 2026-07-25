# Target Configuration Guide

Create a JSON config file at `kimi-data/TargetProfiles/{program-name}.json`.

## Full schema

```json
{
  "program_name": "ExampleCorp Bug Bounty",
  "platform": "hackerone",
  "program_url": "https://hackerone.com/examplecorp",
  "scope_in": ["*.example.com", "api.example.com", "app.example.com"],
  "scope_out": ["blog.example.com", "status.example.com"],
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

## Minimal config

```json
{
  "program_name": "Quick Hunt",
  "scope_in": ["https://target.com"],
  "scope_out": [],
  "target_types": ["web"],
  "severity_filter": "critical_high"
}
```

## Usage

```bash
bun kimi/Tools/hunt-orchestrator.ts --config kimi-data/TargetProfiles/example-corp.json
```
