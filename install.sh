#!/bin/bash
# BugHunter AI — Unified installer (Claude Code + Kimi Code CLI)
#
# Claude Code side:  copies skills/BugBountyFramework to ~/.claude/skills/,
#                    creates ~/.claude/MEMORY/BugBounty/ runtime dirs.
# Kimi Code CLI side: bun install in kimi/, creates kimi-data/ runtime dirs,
#                    downloads the Playwright chromium headless shell,
#                    prints a tool-health report.
#
# Idempotent: safe to re-run. Anything already installed is backed up with a
# timestamp before being overwritten; seed files are never clobbered.
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
cd "$SCRIPT_DIR"

DO_KIMI=1
DO_CLAUDE=1
WITH_MCP=0
SKIP_BROWSER=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install BugHunter AI for Claude Code and/or Kimi Code CLI.

Options:
  --kimi-only     Install only the Kimi Code CLI side (kimi/ deps + kimi-data/)
  --claude-only   Install only the Claude Code side (~/.claude/skills + MEMORY)
  --with-mcp      Chain into ./scripts/setup-mcp.sh at the end
  --skip-browser  Skip the Playwright chromium download (Kimi side)
  --help          Show this help

Default (no flags): install BOTH sides, no MCP setup, browser included.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --kimi-only)    DO_CLAUDE=0 ;;
        --claude-only)  DO_KIMI=0 ;;
        --with-mcp)     WITH_MCP=1 ;;
        --skip-browser) SKIP_BROWSER=1 ;;
        --help|-h)      usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

echo ""
echo -e "${CYAN}${BOLD}"
echo "  ____              _   _             _              _    ___ "
echo " | __ ) _   _  __ _| | | |_   _ _ __ | |_ ___ _ __  / \  |_ _|"
echo " |  _ \| | | |/ _\` | |_| | | | | '_ \| __/ _ \ '__// _ \  | | "
echo " | |_) | |_| | (_| |  _  | |_| | | | | ||  __/ | / ___ \ | | "
echo " |____/ \__,_|\__, |_| |_|\__,_|_| |_|\__\___|_|/_/   \_\___|"
echo "              |___/                                            "
echo -e "${NC}"
echo -e "${BOLD}  Autonomous Bug Bounty Hunting Framework${NC}"
echo -e "  For Claude Code & Kimi Code CLI"
echo ""

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
echo -e "${BOLD}Checking prerequisites...${NC}"

check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        ok "$1"
        return 0
    else
        echo -e "  ${RED}[MISSING]${NC} $1 — $2"
        return 1
    fi
}

# Warn-only variant for optional tooling.
opt_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        ok "$1"
    else
        warn "$1 missing — $2"
    fi
}

KIMI_PREREQ_OK=1
CLAUDE_PREREQ_OK=1

if [ $DO_CLAUDE -eq 1 ]; then
    check_tool "claude" "npm install -g @anthropic-ai/claude-code" || CLAUDE_PREREQ_OK=0
fi

if [ $DO_KIMI -eq 1 ]; then
    # bun is a hard requirement for the Kimi side.
    check_tool "bun" "curl -fsSL https://bun.sh/install | bash" || KIMI_PREREQ_OK=0
    # Warn-only: npx is needed by the MCP servers, python3 by sqlmap/jwt_tool
    # and scripts/setup-mcp.sh.
    opt_tool "npx" "install Node.js 18+ (needed by the MCP servers)"
    opt_tool "python3" "needed by sqlmap/jwt_tool and ./scripts/setup-mcp.sh"
fi

echo ""
echo -e "${BOLD}Optional tools:${NC}"
opt_tool "burpsuite" "https://portswigger.net/burp"
opt_tool "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
opt_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
opt_tool "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
opt_tool "ffuf" "go install github.com/ffuf/ffuf/v2@latest"
opt_tool "sqlmap" "pip install sqlmap"
opt_tool "op" "brew install 1password-cli (for credential vault)"

# ---------------------------------------------------------------------------
# Claude Code side
# ---------------------------------------------------------------------------
install_claude() {
    echo ""
    echo -e "${BOLD}Installing Claude Code side...${NC}"

    SKILL_DIR="$HOME/.claude/skills/BugBountyFramework"
    if [ -d "$SKILL_DIR" ]; then
        BACKUP="${SKILL_DIR}.bak.$(date +%Y%m%d%H%M%S)"
        warn "Existing installation found — backing up to $BACKUP"
        if ! cp -r "$SKILL_DIR" "$BACKUP"; then
            err "Backup of $SKILL_DIR failed — refusing to overwrite it"
            return 1
        fi
        # Remove the old copy so `cp -r` below replaces it instead of
        # nesting the skill inside itself.
        rm -rf "$SKILL_DIR"
    fi

    if ! mkdir -p "$HOME/.claude/skills"; then
        err "Could not create $HOME/.claude/skills"
        return 1
    fi
    if ! cp -r skills/BugBountyFramework "$SKILL_DIR"; then
        err "Failed to copy skills/BugBountyFramework to $SKILL_DIR"
        return 1
    fi
    ok "Skill installed to $SKILL_DIR"

    # Create memory directories
    MEMORY_DIR="$HOME/.claude/MEMORY/BugBounty"
    if ! mkdir -p "$MEMORY_DIR"/{Findings,LearningLogs,PatternDB,TargetProfiles,Sessions,Vault}; then
        err "Could not create memory directories under $MEMORY_DIR"
        return 1
    fi
    ok "Memory directories created"

    # Initialize databases (don't overwrite existing)
    if [ ! -f "$MEMORY_DIR/PatternDB/master-patterns.md" ]; then
        echo "# Master Patterns" > "$MEMORY_DIR/PatternDB/master-patterns.md"
        echo "" >> "$MEMORY_DIR/PatternDB/master-patterns.md"
        echo "Patterns accumulate as you hunt. Each session adds what worked." >> "$MEMORY_DIR/PatternDB/master-patterns.md"
    fi

    if [ ! -f "$MEMORY_DIR/LearningLogs/effective-techniques.md" ]; then
        echo "# Effective Techniques" > "$MEMORY_DIR/LearningLogs/effective-techniques.md"
        echo "" >> "$MEMORY_DIR/LearningLogs/effective-techniques.md"
        echo "Techniques that confirmed vulnerabilities across engagements." >> "$MEMORY_DIR/LearningLogs/effective-techniques.md"
    fi
    ok "Pattern databases initialized"

    # Make tools executable
    chmod +x "$SKILL_DIR/Tools/"*.ts 2>/dev/null || true
    ok "Tools marked executable"

    echo ""
    echo -e "  ${YELLOW}${BOLD}Note:${NC} the installed Claude skill is the preserved ORIGINAL upstream"
    echo -e "  version. The hardened/remediated agent prompts and tooling live in the"
    echo -e "  Kimi port (kimi/). Parity sync back into the Claude skill is a"
    echo -e "  deliberate choice — ask for it if you want the Kimi-side fixes there too."
}

# ---------------------------------------------------------------------------
# Kimi Code CLI side
# ---------------------------------------------------------------------------
install_kimi() {
    echo ""
    echo -e "${BOLD}Installing Kimi Code CLI side...${NC}"

    info "Installing dependencies (kimi/bun install)..."
    if ! (cd kimi && bun install); then
        err "bun install failed — fix the error above and re-run"
        return 1
    fi
    ok "Dependencies installed"

    # Runtime data dirs — match kimi/Tools/lib/paths.ts. No seed files are
    # needed: the Kimi tools create everything they read at runtime
    # (ensureDataDirs() writes .gitkeep; sessions/logs are appended on use).
    DATA_DIR="kimi-data"
    if ! mkdir -p "$DATA_DIR"/{Sessions,Findings,LearningLogs,PatternDB,TargetProfiles,Vault}; then
        err "Could not create runtime directories under $DATA_DIR"
        return 1
    fi
    chmod 700 "$DATA_DIR/Vault"
    ok "Runtime data directories ready under $DATA_DIR/ (Vault chmod 700)"

    # Playwright browser. Playwright itself detects already-downloaded
    # browsers and skips them, so re-runs are cheap.
    if [ $SKIP_BROWSER -eq 1 ]; then
        warn "Skipping Playwright browser download (--skip-browser)"
    else
        info "Installing Playwright chromium headless shell (existing downloads are skipped)..."
        if (cd kimi && bunx playwright install chromium-headless-shell); then
            ok "Playwright chromium headless shell ready"
        else
            warn "Playwright download failed (non-fatal) — retry with: cd kimi && bunx playwright install chromium-headless-shell"
        fi
    fi

    # Tool-health summary (informational — missing optional tools are fine).
    echo ""
    echo -e "${BOLD}Tool health (bounty mode):${NC}"
    bun kimi/Tools/hunt-orchestrator.ts --validate-tools --mode bounty \
        || warn "Tool health check failed to run — try: bun kimi/Tools/hunt-orchestrator.ts --validate-tools --mode bounty"
}

# ---------------------------------------------------------------------------
# Run the requested sides
# ---------------------------------------------------------------------------
KIMI_STATUS="skipped"
CLAUDE_STATUS="skipped"

if [ $DO_CLAUDE -eq 1 ]; then
    if [ $CLAUDE_PREREQ_OK -eq 0 ]; then
        err "claude CLI is required for the Claude side — install it and re-run."
        CLAUDE_STATUS="failed"
    elif install_claude; then
        CLAUDE_STATUS="installed"
    else
        CLAUDE_STATUS="failed"
    fi
fi

if [ $DO_KIMI -eq 1 ]; then
    if [ $KIMI_PREREQ_OK -eq 0 ]; then
        err "bun is required for the Kimi side — install it (curl -fsSL https://bun.sh/install | bash) and re-run."
        KIMI_STATUS="failed"
    elif install_kimi; then
        KIMI_STATUS="installed"
    else
        KIMI_STATUS="failed"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_status() {
    case "$2" in
        installed) echo -e "  ${GREEN}[installed]${NC} $1" ;;
        skipped)   echo -e "  ${YELLOW}[skipped]${NC}   $1" ;;
        failed)    echo -e "  ${RED}[failed]${NC}    $1" ;;
    esac
}

echo ""
if [ "$KIMI_STATUS" = "failed" ] || [ "$CLAUDE_STATUS" = "failed" ]; then
    echo -e "${YELLOW}${BOLD}BugHunter AI install finished with errors:${NC}"
else
    echo -e "${GREEN}${BOLD}BugHunter AI installed successfully!${NC}"
fi
echo ""
print_status "Claude Code   (~/.claude/skills/BugBountyFramework)" "$CLAUDE_STATUS"
print_status "Kimi Code CLI (kimi/ + kimi-data/)" "$KIMI_STATUS"

echo ""
echo -e "${BOLD}Quick Start:${NC}"
echo ""
if [ "$CLAUDE_STATUS" = "installed" ]; then
    echo -e "  ${CYAN}Claude Code:${NC} open ${BOLD}claude${NC}, then:"
    echo -e "     ${BOLD}hunt https://your-target.com${NC}"
    echo -e "     (loads the installed skill from ~/.claude/skills/BugBountyFramework)"
    echo ""
fi
if [ "$KIMI_STATUS" = "installed" ]; then
    echo -e "  ${CYAN}Kimi Code CLI:${NC} open ${BOLD}kimi${NC} in this repo, then:"
    echo -e "     ${BOLD}hunt https://your-target.com${NC}"
    echo -e "     (loads the framework from kimi/BugBountyFramework.md)"
    echo ""
fi

# ---------------------------------------------------------------------------
# MCP setup (opt-in)
# ---------------------------------------------------------------------------
if [ $WITH_MCP -eq 1 ]; then
    echo -e "${BOLD}Running MCP server setup (./scripts/setup-mcp.sh)...${NC}"
    echo ""
    ./scripts/setup-mcp.sh || warn "setup-mcp.sh exited non-zero — re-run it manually later"
else
    echo -e "${BOLD}Optional:${NC} To set up the MCP servers (Kimi + Claude), run:"
    echo -e "     ${BOLD}./scripts/setup-mcp.sh${NC}"
    echo -e "  (Not run automatically — it writes to your home directory and needs your consent."
    echo -e "   Re-run this installer with --with-mcp to chain it.)"
    echo ""
fi

echo -e "${YELLOW}${BOLD}Remember:${NC} Only test targets you have authorization to test."
echo ""

if [ "$KIMI_STATUS" = "failed" ] || [ "$CLAUDE_STATUS" = "failed" ]; then
    exit 1
fi
