#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# Chainsmith Recon - Reset Range
#
# Stops scenario services and clears session state.
#
# Usage:
#   ./reset-range.sh <scenario>   Reset a specific scenario
#   ./reset-range.sh --all        Reset all scenarios
#
# Examples:
#   ./reset-range.sh fakobanko
#   ./reset-range.sh --all
# ─────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIOS_DIR="$REPO_ROOT/scenarios"

# ─── Usage ───────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <scenario> | --all"
    echo ""
    echo "Options:"
    echo "  <scenario>    Reset a specific scenario"
    echo "  --all         Reset all scenarios"
    echo "  --help        Show this help message"
    echo ""
    echo "Available scenarios:"
    for dir in "$SCENARIOS_DIR"/*/; do
        if [ -f "$dir/docker-compose.yml" ]; then
            name=$(basename "$dir")
            echo "  $name"
        fi
    done
    exit 1
}

# ─── Reset Scenario ──────────────────────────────────────────────
reset_scenario() {
    local scenario="$1"
    local scenario_dir="$SCENARIOS_DIR/$scenario"
    
    echo "[+] Resetting $scenario..."
    
    # Stop services if running
    if [ -f "$scenario_dir/docker-compose.yml" ]; then
        cd "$scenario_dir"
        docker compose \
            --profile all \
            --profile ml \
            --profile internal \
            --profile admin \
            --profile vector \
            --profile agent \
            --profile mcp \
            down 2>/dev/null || docker compose down 2>/dev/null || true
    fi
    
    # Clear session state
    if [ -d "$scenario_dir/data" ]; then
        echo "    Clearing session state..."
        rm -f "$scenario_dir/data/session.json"
        # Keep .gitkeep and any other non-session files
    fi
    
    echo "    ✓ $scenario reset"
}

# ─── Main ────────────────────────────────────────────────────────
if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
fi

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Chainsmith Recon - Reset Range               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

if [ "$1" = "--all" ]; then
    # Reset all scenarios
    echo "[+] Resetting all scenarios..."
    echo ""
    
    for dir in "$SCENARIOS_DIR"/*/; do
        scenario=$(basename "$dir")
        # Skip template directory
        if [ "$scenario" = "_template" ]; then
            continue
        fi
        if [ -f "$dir/docker-compose.yml" ]; then
            reset_scenario "$scenario"
        fi
    done
else
    # Reset specific scenario
    SCENARIO="$1"
    
    if [ ! -d "$SCENARIOS_DIR/$SCENARIO" ]; then
        echo "Error: Scenario '$SCENARIO' not found"
        echo ""
        echo "Available scenarios:"
        ls -1 "$SCENARIOS_DIR" | while read name; do
            [ -f "$SCENARIOS_DIR/$name/docker-compose.yml" ] && echo "  $name"
        done
        exit 1
    fi
    
    reset_scenario "$SCENARIO"
fi

echo ""
echo "[✓] Reset complete!"
echo ""
echo "Run ./start-range.sh <scenario> to start fresh."
echo "Use --randomize flag to apply new randomization."
