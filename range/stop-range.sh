#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# Chainsmith Recon - Stop Range
#
# Usage:
#   ./stop-range.sh              Stop all running scenarios
#   ./stop-range.sh <scenario>   Stop a specific scenario
#
# Examples:
#   ./stop-range.sh
#   ./stop-range.sh fakobanko
# ─────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIOS_DIR="$REPO_ROOT/scenarios"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Chainsmith Recon - Stop Range                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ─── Stop Specific Scenario ──────────────────────────────────────
stop_scenario() {
    local scenario="$1"
    local scenario_dir="$SCENARIOS_DIR/$scenario"
    
    if [ ! -f "$scenario_dir/docker-compose.yml" ]; then
        echo "Warning: $scenario has no docker-compose.yml, skipping"
        return
    fi
    
    echo "[+] Stopping $scenario..."
    cd "$scenario_dir"
    
    # Stop with all profiles to ensure everything shuts down
    docker compose \
        --profile all \
        --profile ml \
        --profile internal \
        --profile admin \
        --profile vector \
        --profile agent \
        --profile mcp \
        down 2>/dev/null || docker compose down 2>/dev/null || true
}

# ─── Main ────────────────────────────────────────────────────────
if [ $# -ge 1 ]; then
    # Stop specific scenario
    SCENARIO="$1"
    
    if [ ! -d "$SCENARIOS_DIR/$SCENARIO" ]; then
        echo "Error: Scenario '$SCENARIO' not found"
        exit 1
    fi
    
    stop_scenario "$SCENARIO"
else
    # Stop all scenarios that have running containers
    echo "[+] Checking for running scenarios..."
    
    found_running=false
    for dir in "$SCENARIOS_DIR"/*/; do
        scenario=$(basename "$dir")
        if [ -f "$dir/docker-compose.yml" ]; then
            cd "$dir"
            # Check if any containers are running
            if docker compose ps -q 2>/dev/null | grep -q .; then
                found_running=true
                stop_scenario "$scenario"
            fi
        fi
    done
    
    if [ "$found_running" = false ]; then
        echo "[*] No running scenarios found"
    fi
fi

echo ""
echo "[✓] Range stopped."
echo ""
echo "    Session state is preserved in each scenario's data/ directory."
echo "    Run ./start-range.sh <scenario> to resume."
echo "    Run ./reset-range.sh <scenario> to clear state and re-randomize."
