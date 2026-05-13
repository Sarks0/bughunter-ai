# Sample Hunt Prompts

Copy-paste these into Claude Code to start hunting.

---

## Basic Web Application Hunt

```
hunt https://app.example.com
```

## Hunt with Credentials from Vault

```
hunt https://app.example.com --creds vault:example-corp
```

## Pentest Mode (Lower Severity Threshold)

```
hunt https://app.example.com --mode pentest
```

## Comprehensive Assessment (Everything)

```
hunt https://staging.example.com --mode comprehensive
```

## Resume an Interrupted Hunt

```
hunt https://app.example.com --resume
```

## Check Hunt Progress

```
hunt https://app.example.com --status
```

## Hunt with Full Context (Recommended First Run)

```
hunt https://app.example.com using username test@example.com and password TestPass123

Use all available tools, skills, workflows, and MCPs.
Use Playwright and Burp MCPs to perform dynamic analysis.
Map the entire application attack surface first.
Understand the application before attacking.
Find 10 high-severity vulnerabilities.
Don't stop until done.
```

## API-Only Hunt

```
hunt https://api.example.com/v1 --type api --swagger /tmp/swagger.json
```

## Hunt AI/LLM Application

```
hunt https://ai-app.example.com --mode pentest

Focus on:
- System prompt extraction
- Cross-user data access
- Prompt injection (direct + indirect)
- RAG poisoning via document upload
- OWASP LLM Top 10
```

## Mobile App Hunt

```
hunt --apk /path/to/app.apk --proxy

Test for:
- SSL pinning bypass
- Exported components
- Deep link injection
- Insecure storage
- API security through intercepted traffic
```

## Full Program Hunt (Config File)

```
hunt --config ~/.claude/MEMORY/BugBounty/TargetProfiles/example-corp.json
```

---

## Pro Tips

1. **Always store creds in vault first:**
   ```
   Store credentials for example-corp: username test@example.com, password TestPass123, cookie session=abc
   ```

2. **Check Burp is running before hunt:**
   ```
   Check if Burp Suite proxy is running and healthy
   ```

3. **After hunt, review findings:**
   ```
   Show me the hunt status and all findings for app.example.com
   ```
