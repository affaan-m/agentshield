#!/bin/bash
# ============================================================
# AgentShield Demo Recording Script
# ============================================================
# Modes:
#   bash scripts/record-demo.sh           # Interactive (ENTER to advance)
#   bash scripts/record-demo.sh --auto    # Auto-advance with timed pauses
#
# Before running:
#   export ANTHROPIC_API_KEY=your-key     # Required for --opus beat
#   export PS1='$ '                       # Clean prompt
# ============================================================

set +e  # Don't exit on non-zero — agentshield exits 2 on critical findings

cd "$(dirname "$0")/.."

AGENTSHIELD="node $(pwd)/dist/index.js"
VULN_PATH="$(pwd)/examples/vulnerable"
AUTO_MODE=false
[[ "$1" == "--auto" ]] && AUTO_MODE=true

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

pause() {
  local seconds="${1:-5}"
  if $AUTO_MODE; then
    sleep "$seconds"
    clear
  else
    echo ""
    echo -e "${DIM}── Press ENTER for next step ──${RESET}"
    read -r
    clear
  fi
}

typeout() {
  local text="$1"
  echo -n -e "${BOLD}$ ${RESET}"
  for ((i=0; i<${#text}; i++)); do
    echo -n "${text:$i:1}"
    sleep 0.03
  done
  echo ""
}

section() {
  echo ""
  echo -e "${DIM}─────────────────────────────────────────${RESET}"
  echo ""
}

# ============================================================
# PRE-FLIGHT
# ============================================================
if [[ ! -f "$(pwd)/dist/index.js" ]]; then
  echo "Error: dist/index.js not found. Run 'npm run build' first."
  exit 1
fi

# ============================================================
# COLD OPEN — One command, full scan
# ============================================================
clear
sleep 2
typeout "agentshield scan --path examples/vulnerable"
sleep 0.5
$AGENTSHIELD scan --path "$VULN_PATH" 2>/dev/null
pause 6

# ============================================================
# BEAT 1 — Show the vulnerable config
# ============================================================
typeout "cat examples/vulnerable/CLAUDE.md"
sleep 0.5
echo ""
cat "$VULN_PATH/CLAUDE.md"
sleep 4
section
typeout "cat examples/vulnerable/settings.json"
sleep 0.5
echo ""
cat "$VULN_PATH/settings.json"
sleep 4
section
typeout "cat examples/vulnerable/mcp.json"
sleep 0.5
echo ""
cat "$VULN_PATH/mcp.json"
pause 5

# ============================================================
# BEAT 2 — Full security scan (the main demo)
# ============================================================
typeout "agentshield scan --path examples/vulnerable"
sleep 0.5
$AGENTSHIELD scan --path "$VULN_PATH" 2>/dev/null
pause 8

# ============================================================
# BEAT 3 — JSON output for CI pipelines
# ============================================================
typeout "agentshield scan --path examples/vulnerable --format json | head -20"
sleep 0.5
$AGENTSHIELD scan --path "$VULN_PATH" --format json 2>/dev/null | head -20
sleep 3
section
typeout "agentshield scan --path examples/vulnerable > /dev/null 2>&1; echo \"Exit code: \$?\""
sleep 0.3
$AGENTSHIELD scan --path "$VULN_PATH" > /dev/null 2>&1
local_exit=$?
echo "Exit code: $local_exit"
pause 4

# ============================================================
# BEAT 4 — Auto-fix
# ============================================================
rm -rf /tmp/vuln-demo-test 2>/dev/null || true
cp -r "$VULN_PATH" /tmp/vuln-demo-test
typeout "agentshield scan --path examples/vulnerable --fix"
sleep 0.5
$AGENTSHIELD scan --path /tmp/vuln-demo-test --fix 2>/dev/null
rm -rf /tmp/vuln-demo-test 2>/dev/null || true
pause 5

# ============================================================
# BEAT 5 — Scan your own config
# ============================================================
typeout "agentshield scan"
sleep 0.5
$AGENTSHIELD scan 2>/dev/null
pause 5

# ============================================================
# BEAT 6 — Opus three-agent pipeline (FLAGSHIP)
# ============================================================
if [[ -z "$ANTHROPIC_API_KEY" ]]; then
  echo -e "${YELLOW}Skipping --opus (ANTHROPIC_API_KEY not set)${RESET}"
  pause 2
else
  typeout "agentshield scan --path examples/vulnerable --opus --stream"
  sleep 0.5
  $AGENTSHIELD scan --path "$VULN_PATH" --opus --stream 2>/dev/null
  pause 6
fi

# ============================================================
# CLOSING CARD
# ============================================================
clear
echo ""
echo ""
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║   AgentShield                                         ║"
echo "  ║   Security auditor for AI agent configurations        ║"
echo "  ║                                                       ║"
echo "  ║   github.com/affaan-m/agentshield                     ║"
echo "  ║                                                       ║"
echo "  ║   npm install -g ecc-agentshield                      ║"
echo "  ║   npx ecc-agentshield scan                            ║"
echo "  ║                                                       ║"
echo "  ║   520 tests · 98% coverage · MIT licensed             ║"
echo "  ║   Part of ECC (42K+ stars)                            ║"
echo "  ║                                                       ║"
echo "  ║   Built at the Claude Code Hackathon                  ║"
echo "  ║   Cerebral Valley × Anthropic — Feb 2026              ║"
echo "  ║                                                       ║"
echo "  ║   @affaanmustafa                                      ║"
echo "  ║                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo ""

if $AUTO_MODE; then
  sleep 8
else
  echo -e "${DIM}Demo complete. Stop recording now.${RESET}"
  read -r
fi
