#!/bin/bash
# BugHunter AI — MCP server setup for fresh clones
#
# Merges the six canonical MCP server definitions (config/mcp.servers.json)
# into the Kimi Code CLI config (~/.kimi-code/mcp.json) and, when available,
# registers them with the Claude Code CLI (user scope). Idempotent: existing
# entries with the same name are updated to the template version, all other
# entries are preserved, and any existing config is backed up first.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }
err()  { echo -e "  ${RED}[ERROR]${NC} $1"; }
info() { echo -e "  ${CYAN}[..]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TEMPLATE="$REPO_ROOT/config/mcp.servers.json"
KIMI_HOME="${KIMI_CODE_HOME:-$HOME/.kimi-code}"
CLAUDE_JSON_DIR=""

DO_KIMI=1
DO_CLAUDE=1
DO_VULN_INTEL=1

VULN_INTEL_HOME="${VULN_INTEL_HOME:-$HOME/venvs/vulnerability-intelligence-mcp}"
VULN_INTEL_REPO="https://github.com/thinkchainai/vulnerability-intelligence-mcp"
VULN_INTEL_BIN="$VULN_INTEL_HOME/venv/bin/vulnerability-intelligence-mcp"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Configure BugHunter AI's MCP servers for Kimi Code CLI and Claude Code.

Options:
  --kimi-only        Only update the Kimi Code CLI config (mcp.json)
  --claude-only      Only register servers with the Claude Code CLI
  --skip-vuln-intel  Do not clone/install the vulnerability-intelligence-mcp
                     server (its config entry is still merged)
  --help             Show this help

Environment:
  KIMI_CODE_HOME     Kimi config dir (default: ~/.kimi-code)
  VULN_INTEL_HOME    vuln-intel install dir (default: ~/venvs/vulnerability-intelligence-mcp)
  BH_PROJECTS_DIR    Extra filesystem allowlist dir (default: ~/Projects)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --kimi-only)       DO_CLAUDE=0 ;;
        --claude-only)     DO_KIMI=0 ;;
        --skip-vuln-intel) DO_VULN_INTEL=0 ;;
        --help|-h)         usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

echo ""
echo -e "${CYAN}${BOLD}BugHunter AI — MCP server setup${NC}"
echo ""

if [ ! -f "$TEMPLATE" ]; then
    err "Template not found: $TEMPLATE"
    exit 1
fi

# ---------------------------------------------------------------------------
# Dependency checks (degrade per server, don't die)
# ---------------------------------------------------------------------------
echo -e "${BOLD}Checking dependencies...${NC}"

HAVE_NPX=0; HAVE_UVX=0; HAVE_GIT=0; HAVE_PY=0
command -v npx      >/dev/null 2>&1 && HAVE_NPX=1
command -v uvx      >/dev/null 2>&1 && HAVE_UVX=1
command -v git      >/dev/null 2>&1 && HAVE_GIT=1
command -v python3  >/dev/null 2>&1 && HAVE_PY=1

if [ $HAVE_NPX -eq 1 ]; then ok "npx (filesystem, shodan)"; else warn "npx missing — filesystem and shodan servers will not run (install Node.js 18+)"; fi
if [ $HAVE_UVX -eq 1 ]; then ok "uvx (virustotal)"; else warn "uvx missing — virustotal server will not run (install uv: https://docs.astral.sh/uv/)"; fi
if [ $HAVE_GIT -eq 1 ]; then ok "git"; else warn "git missing — cannot install vuln-intel"; fi
if [ $HAVE_PY  -eq 1 ]; then ok "python3"; else warn "python3 missing — cannot merge JSON config or install vuln-intel"; fi

if [ $DO_KIMI -eq 1 ] && [ $HAVE_PY -eq 0 ]; then
    err "python3 is required to merge the Kimi mcp.json. Install python3 and re-run."
    exit 1
fi

# ---------------------------------------------------------------------------
# vuln-intel install
# ---------------------------------------------------------------------------
if [ $DO_VULN_INTEL -eq 1 ]; then
    echo ""
    echo -e "${BOLD}Installing vuln-intel (vulnerability-intelligence-mcp)...${NC}"
    if [ $HAVE_GIT -eq 0 ] || [ $HAVE_PY -eq 0 ]; then
        warn "git/python3 missing — skipping vuln-intel install"
    else
        if [ -d "$VULN_INTEL_HOME/src/.git" ]; then
            info "Repo already present at $VULN_INTEL_HOME/src — pulling (ff-only)"
            git -C "$VULN_INTEL_HOME/src" pull --ff-only || warn "Pull failed — keeping existing checkout"
        elif [ -e "$VULN_INTEL_HOME/src" ]; then
            warn "$VULN_INTEL_HOME/src exists but is not a git checkout — leaving it alone"
        else
            mkdir -p "$VULN_INTEL_HOME"
            git clone --depth 1 "$VULN_INTEL_REPO" "$VULN_INTEL_HOME/src"
            ok "Cloned $VULN_INTEL_REPO"
        fi

        if [ ! -x "$VULN_INTEL_HOME/venv/bin/python" ]; then
            python3 -m venv "$VULN_INTEL_HOME/venv"
            ok "Created venv at $VULN_INTEL_HOME/venv"
        else
            info "venv already exists at $VULN_INTEL_HOME/venv"
        fi

        if [ -d "$VULN_INTEL_HOME/src" ]; then
            "$VULN_INTEL_HOME/venv/bin/pip" install --quiet "$VULN_INTEL_HOME/src"
            ok "Installed vulnerability-intelligence-mcp into the venv"
        fi
    fi
else
    echo ""
    warn "Skipping vuln-intel install (--skip-vuln-intel)"
    if [ ! -x "$VULN_INTEL_BIN" ]; then
        warn "vuln-intel binary not found at $VULN_INTEL_BIN — the server will fail until installed"
    fi
fi

# ---------------------------------------------------------------------------
# Build the substituted template (tokens -> real paths)
# ---------------------------------------------------------------------------
BH_PROJECTS_DIR="${BH_PROJECTS_DIR:-$HOME/Projects}"
SUBSTITUTED="$(mktemp)"
trap 'rm -f "$SUBSTITUTED"; [ -n "$CLAUDE_JSON_DIR" ] && rm -rf "$CLAUDE_JSON_DIR"' EXIT

sed -e "s|\$BH_REPO_ROOT|$REPO_ROOT|g" \
    -e "s|\$BH_PROJECTS_DIR|$BH_PROJECTS_DIR|g" \
    -e "s|\$VULN_INTEL_BIN|$VULN_INTEL_BIN|g" \
    "$TEMPLATE" > "$SUBSTITUTED"

# ---------------------------------------------------------------------------
# Kimi target: merge into mcp.json
# ---------------------------------------------------------------------------
if [ $DO_KIMI -eq 1 ]; then
    echo ""
    echo -e "${BOLD}Configuring Kimi Code CLI...${NC}"
    KIMI_MCP="$KIMI_HOME/mcp.json"
    mkdir -p "$KIMI_HOME"

    if [ -f "$KIMI_MCP" ]; then
        BACKUP="$KIMI_MCP.bak.$(date +%Y%m%d%H%M%S)"
        cp "$KIMI_MCP" "$BACKUP"
        info "Backed up existing config to $BACKUP"
    fi

    MERGED="$(mktemp)"
    python3 - "$SUBSTITUTED" "$KIMI_MCP" "$MERGED" <<'PYEOF'
import json, sys

tpl_path, target_path, out_path = sys.argv[1:4]
with open(tpl_path) as f:
    tpl = json.load(f)["mcpServers"]
try:
    with open(target_path) as f:
        existing = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    existing = {}
existing.setdefault("mcpServers", {})
existing["mcpServers"].update(tpl)
with open(out_path, "w") as f:
    json.dump(existing, f, indent=2)
    f.write("\n")
PYEOF
    mv "$MERGED" "$KIMI_MCP"
    ok "Merged 6 server definitions into $KIMI_MCP"
fi

# ---------------------------------------------------------------------------
# Claude target: claude mcp add-json --scope user
# ---------------------------------------------------------------------------
if [ $DO_CLAUDE -eq 1 ]; then
    echo ""
    echo -e "${BOLD}Configuring Claude Code CLI...${NC}"
    if ! command -v claude >/dev/null 2>&1; then
        warn "claude CLI not on PATH — skipping Claude registration"
    elif [ $HAVE_PY -eq 0 ]; then
        warn "python3 missing — cannot build Claude server JSON, skipping"
    else
        CLAUDE_JSON_DIR="$(mktemp -d)"
        python3 - "$SUBSTITUTED" "$CLAUDE_JSON_DIR" <<'PYEOF'
import json, os, sys

tpl_path, out_dir = sys.argv[1:3]
with open(tpl_path) as f:
    servers = json.load(f)["mcpServers"]
for name, s in servers.items():
    if "command" in s:
        c = {"type": "stdio", "command": s["command"]}
        if s.get("args"):
            c["args"] = s["args"]
    elif s.get("transport") == "sse":
        c = {"type": "sse", "url": s["url"]}
    else:
        c = {"type": "http", "url": s["url"]}
        if "bearerTokenEnvVar" in s:
            c["headers"] = {"Authorization": "Bearer ${%s}" % s["bearerTokenEnvVar"]}
    with open(os.path.join(out_dir, name + ".json"), "w") as f:
        json.dump(c, f)
PYEOF
        for name in filesystem github burp shodan virustotal vuln-intel; do
            if claude mcp get "$name" >/dev/null 2>&1; then
                info "$name already registered — leaving existing entry"
            else
                claude mcp add-json --scope user "$name" "$(cat "$CLAUDE_JSON_DIR/$name.json")" >/dev/null
                ok "$name registered (user scope)"
            fi
        done
    fi
fi

# ---------------------------------------------------------------------------
# Pre-warm package downloads (non-fatal)
# ---------------------------------------------------------------------------
# The goal is to warm the npx/uvx package cache. Servers may exit non-zero
# once downloaded (missing API keys, --help parsed as an arg) or be killed by
# `timeout` (124) after starting — all of those mean the download succeeded.
# Only a launcher-level failure (127) counts as a real pre-warm failure.
prewarm() {
    local desc="$1"; shift
    local rc=0
    timeout 60 "$@" </dev/null >/dev/null 2>&1 || rc=$?
    case $rc in
        0)   ok "$desc cached" ;;
        124) ok "$desc cached (server started; timed out waiting as expected)" ;;
        127) warn "$desc pre-warm failed (launcher error; will download on first use)" ;;
        *)   ok "$desc downloaded (server exited rc=$rc — expected without keys/args)" ;;
    esac
}

echo ""
echo -e "${BOLD}Pre-warming package downloads...${NC}"
if [ $HAVE_NPX -eq 1 ]; then
    prewarm "server-filesystem@2026.7.10" npx -y @modelcontextprotocol/server-filesystem@2026.7.10 --help
    prewarm "mcp-shodan@1.0.22" npx -y @burtthecoder/mcp-shodan@1.0.22 --help
fi
if [ $HAVE_UVX -eq 1 ]; then
    prewarm "gti_mcp" uvx gti_mcp --help
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}MCP setup complete.${NC}"
echo ""
echo -e "${BOLD}Servers:${NC}"
echo -e "  ${GREEN}enabled${NC}  filesystem     (keyless; allowlist: $REPO_ROOT, $BH_PROJECTS_DIR)"
echo -e "  ${GREEN}enabled${NC}  vuln-intel     (keyless; CISA KEV + EPSS + NVD — optional NIST_NVD_API_KEY raises NVD rate limits)"
echo -e "  ${YELLOW}disabled${NC} github         pending: export GITHUB_PERSONAL_ACCESS_TOKEN in ~/.zshrc"
echo -e "  ${YELLOW}disabled${NC} shodan         pending: export SHODAN_API_KEY in ~/.zshrc"
echo -e "  ${YELLOW}disabled${NC} virustotal     pending: export VT_APIKEY in ~/.zshrc (a free VT key works)"
echo -e "  ${YELLOW}disabled${NC} burp           pending: install the official PortSwigger \"MCP Server\" BApp"
echo -e "           (Extensions -> BApp Store -> MCP Server, then enable under Extensions -> MCP;"
echo -e "           it serves SSE on 127.0.0.1:9876. Caveat: that port is UNAUTHENTICATED"
echo -e "           localhost — only enable it while testing.)"
echo ""
echo -e "${BOLD}To activate a key-gated server:${NC} export the key in ~/.zshrc, then set"
echo -e "\"enabled\": true for that server in $KIMI_HOME/mcp.json."
echo -e "Claude Code picks servers up automatically once the env var exists."
echo ""
