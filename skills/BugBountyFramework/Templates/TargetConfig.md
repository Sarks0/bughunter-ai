# Target Configuration Guide

## Quick Start

Create a target config JSON file and place it at:
`~/.claude/MEMORY/BugBounty/TargetProfiles/{program-name}.json`

Then invoke: `hunt --config ~/.claude/MEMORY/BugBounty/TargetProfiles/{program-name}.json`

## Full Config Schema

```json
{
  "program_name": "ExampleCorp Bug Bounty",
  "platform": "hackerone",
  "program_url": "https://hackerone.com/examplecorp",

  "scope_in": [
    "*.example.com",
    "api.example.com",
    "app.example.com",
    "192.168.1.0/24"
  ],

  "scope_out": [
    "blog.example.com",
    "status.example.com",
    "docs.example.com"
  ],

  "target_types": ["web", "api", "android", "ios"],

  "artifacts": {
    "apk_path": "/tmp/example-app.apk",
    "ipa_path": "/tmp/example-app.ipa",
    "swagger_url": "https://api.example.com/swagger.json",
    "source_code": null
  },

  "authentication": {
    "regular_user": {
      "session_cookie": "session=abc123; csrf=xyz456",
      "api_key": "",
      "jwt": "eyJ...",
      "username": "test@example.com",
      "password": "TestPassword123!"
    },
    "admin_user": {
      "session_cookie": "",
      "note": "Create admin account if possible for privilege escalation testing"
    }
  },

  "burp": {
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,
    "project_file": "~/.claude/MEMORY/BugBounty/TargetProfiles/example-burp.burp",
    "rest_api_url": "http://127.0.0.1:1337/v0.1"
  },

  "known_endpoints": [
    "/admin",
    "/api/v1",
    "/graphql",
    "/upload",
    "/export"
  ],

  "tech_hints": "Laravel 9, MySQL 8, Redis, Nginx",

  "prior_findings": "XSS found in search in 2024, since patched",

  "max_requests_per_second": 10,

  "severity_filter": "critical_high",

  "report_format": "hackerone",

  "notes": "Admin panel confirmed at /dashboard. Multi-tenant SaaS."
}
```

## Minimal Config (Quick Start)

```json
{
  "program_name": "Quick Hunt",
  "scope_in": ["https://target.com"],
  "scope_out": [],
  "target_types": ["web"],
  "severity_filter": "critical_high"
}
```
