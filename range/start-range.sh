#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# Chainsmith Recon - Range Launcher
#
# Usage:
#   ./start-range.sh <scenario>              Start scenario as-is
#   ./start-range.sh <scenario> --randomize  Start with randomization
#   ./start-range.sh <scenario> --profile X  Start with specific profile
#   ./start-range.sh <scenario> --all        Start all services
#
# Examples:
#   ./start-range.sh fakobanko
#   ./start-range.sh fakobanko --randomize
#   ./start-range.sh fakobanko --profile ml --profile agent
#   ./start-range.sh demo-domain
# ─────────────────────────────────────────────────────────────────

set -e

# Compose settings inherited from the caller's shell would point `docker compose`
# at a different project or file than the scenario's own (lab backport 1e).
unset COMPOSE_FILE COMPOSE_PROJECT_NAME

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCENARIOS_DIR="$REPO_ROOT/scenarios"

# ─── Usage ───────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <scenario> [options]"
    echo ""
    echo "Options:"
    echo "  --randomize       Apply randomization from scenario's randomize.json"
    echo "  --profile <name>  Enable a specific service profile"
    echo "  --all             Enable all optional services"
    echo "  --help            Show this help message"
    echo ""
    echo "Available scenarios:"
    for dir in "$SCENARIOS_DIR"/*/; do
        if [ -f "$dir/docker-compose.yml" ]; then
            name=$(basename "$dir")
            desc=""
            if [ -f "$dir/scenario.json" ] && command -v jq &> /dev/null; then
                desc=$(jq -r '.description // ""' "$dir/scenario.json" 2>/dev/null | head -c 50)
                [ -n "$desc" ] && desc=" - $desc"
            fi
            echo "  $name$desc"
        fi
    done
    exit 1
}

# ─── Parse Arguments ─────────────────────────────────────────────
if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
fi

SCENARIO="$1"
shift

RANDOMIZE=false
PROFILE_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --randomize)
            RANDOMIZE=true
            shift
            ;;
        --profile)
            PROFILE_ARGS="$PROFILE_ARGS --profile $2"
            shift 2
            ;;
        --all)
            PROFILE_ARGS="$PROFILE_ARGS --profile all"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# ─── Validate Scenario ───────────────────────────────────────────
SCENARIO_DIR="$SCENARIOS_DIR/$SCENARIO"

if [ ! -d "$SCENARIO_DIR" ]; then
    echo "Error: Scenario '$SCENARIO' not found"
    echo ""
    echo "Available scenarios:"
    ls -1 "$SCENARIOS_DIR" | while read name; do
        [ -f "$SCENARIOS_DIR/$name/docker-compose.yml" ] && echo "  $name"
    done
    exit 1
fi

if [ ! -f "$SCENARIO_DIR/docker-compose.yml" ]; then
    echo "Error: Scenario '$SCENARIO' has no docker-compose.yml"
    exit 1
fi

# ─── Banner ──────────────────────────────────────────────────────
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Chainsmith Recon - Range                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ─── Check Port Availability ─────────────────────────────────────
check_ports() {
    local compose_file="$1"
    local conflicts=""
    
    # Extract ports from compose file
    if command -v grep &> /dev/null; then
        ports=$(grep -oP '127\.0\.0\.1:\K[0-9]+(?=:)' "$compose_file" 2>/dev/null || true)
        
        for port in $ports; do
            if command -v ss &> /dev/null; then
                if ss -tuln 2>/dev/null | grep -q ":$port "; then
                    conflicts="$conflicts $port"
                fi
            elif command -v netstat &> /dev/null; then
                if netstat -tuln 2>/dev/null | grep -q ":$port "; then
                    conflicts="$conflicts $port"
                fi
            elif command -v lsof &> /dev/null; then
                if lsof -i ":$port" &> /dev/null; then
                    conflicts="$conflicts $port"
                fi
            fi
        done
    fi
    
    if [ -n "$conflicts" ]; then
        echo "⚠️  Warning: The following ports are already in use:$conflicts"
        echo "   This may cause conflicts when starting the scenario."
        echo ""
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 1
        fi
    fi
}

echo "[*] Scenario: $SCENARIO"
if [ -f "$SCENARIO_DIR/scenario.json" ] && command -v jq &> /dev/null; then
    desc=$(jq -r '.description // ""' "$SCENARIO_DIR/scenario.json")
    [ -n "$desc" ] && echo "    $desc"
fi
echo ""

# ─── Check Ports ─────────────────────────────────────────────────
echo "[+] Checking port availability..."
check_ports "$SCENARIO_DIR/docker-compose.yml"

# ─── Ensure Network Exists ───────────────────────────────────────
echo "[+] Ensuring chainsmith-shared network exists..."
docker network create chainsmith-shared 2>/dev/null || true

# ─── Session ─────────────────────────────────────────────────────
# The session file is the one source of truth every container reads. It holds
# the session id, the selected chain packages and the services they need, and
# nothing else: each service derives its active observations from the id
# (`resolve_active_observations` in app/scenario_services/common/config.py),
# seeded, so they all agree without a lock.
#
# An existing session is resumed, not re-rolled. Use ./range/reset-range.sh to
# start a new one. The file is created here, before any container starts, so two
# containers can never race to create different sessions.
SESSION_FILE="$SCENARIO_DIR/data/session.json"
RANDOMIZE_FILE="$SCENARIO_DIR/randomize.json"
mkdir -p "$SCENARIO_DIR/data"

if [ -f "$SESSION_FILE" ]; then
    echo "[+] Resuming existing session ($SESSION_FILE)"
    if [ "$RANDOMIZE" = true ]; then
        echo "    --randomize ignored: a session already exists."
        echo "    Run ./range/reset-range.sh $SCENARIO to roll a new one."
    fi
else
    if [ "$RANDOMIZE" = true ] && [ ! -f "$RANDOMIZE_FILE" ]; then
        echo "⚠️  Warning: No randomize.json found for $SCENARIO"
        echo "   Creating a session without chain packages."
    fi
    if [ "$RANDOMIZE" = true ] && [ -f "$RANDOMIZE_FILE" ]; then
        echo "[+] Creating a randomized session..."
    else
        echo "[+] Creating a session..."
    fi

    RANGE_RANDOMIZE="$RANDOMIZE" RANGE_RANDOMIZE_FILE="$RANDOMIZE_FILE" \
    RANGE_SESSION_FILE="$SESSION_FILE" RANGE_SCENARIO="$SCENARIO" \
    python3 << 'EOF'
import json
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

randomize_file = Path(os.environ["RANGE_RANDOMIZE_FILE"])
session_file = Path(os.environ["RANGE_SESSION_FILE"])

selected = []
if os.environ["RANGE_RANDOMIZE"] == "true" and randomize_file.exists():
    config = json.loads(randomize_file.read_text())
    packages = config.get("chain_packages", [])
    rules = config.get("selection_rules", {})
    num_chains = random.randint(rules.get("min_chains", 2), rules.get("max_chains", 4))
    selected = random.sample(packages, min(num_chains, len(packages)))

services = sorted({svc for chain in selected for svc in chain.get("required_services", [])})

# No `active_observations` (and no `extra_findings`): the services derive the
# observations from the session id. See resolve_active_observations().
session = {
    "session_id": uuid.uuid4().hex[:16],
    "scenario": os.environ["RANGE_SCENARIO"],
    "created_at": datetime.now(timezone.utc).isoformat(),
    "selected_chains": selected,
    "active_services": services,
}
session_file.write_text(json.dumps(session, indent=2))

print(f"    Session ID: {session['session_id']}")
print(f"    Chains: {len(selected)}")
print(f"    Services: {', '.join(services) or 'base only'}")
EOF
fi

# Profiles for the session's services. Runs on resume too, so a resumed
# randomized session brings back the services its chains need.
if [ -f "$SESSION_FILE" ] && command -v jq &> /dev/null; then
    SERVICES=$(jq -r '.active_services[]?' "$SESSION_FILE" 2>/dev/null || echo "")
    for svc in $SERVICES; do
        PROFILE_ARGS="$PROFILE_ARGS --profile $svc"
    done
fi
echo ""

# ─── Start Scenario ──────────────────────────────────────────────
echo "[+] Starting $SCENARIO services..."
cd "$SCENARIO_DIR"

if [ -n "$PROFILE_ARGS" ]; then
    echo "    Profiles:$PROFILE_ARGS"
    docker compose $PROFILE_ARGS up -d
else
    docker compose up -d
fi

# ─── Wait for Health ─────────────────────────────────────────────
echo ""
echo "[+] Waiting for scenario services to be healthy..."
sleep 3

# ─── Start/Reload Chainsmith ─────────────────────────────────────
cd "$REPO_ROOT"
CHAINSMITH_PORT="${CHAINSMITH_PORT:-8100}"
CHAINSMITH_URL="http://localhost:$CHAINSMITH_PORT"

echo ""
echo "[+] Starting Chainsmith..."

# Check if Chainsmith is already running
if curl -sf "$CHAINSMITH_URL/health" > /dev/null 2>&1; then
    echo "    Chainsmith already running"
else
    # Start Chainsmith
    if [ -x "./chainsmith.sh" ]; then
        ./chainsmith.sh start
        echo "    Waiting for Chainsmith to be ready..."
        
        # Wait for Chainsmith to be healthy (max 30 seconds)
        for i in $(seq 1 30); do
            if curl -sf "$CHAINSMITH_URL/health" > /dev/null 2>&1; then
                echo "    Chainsmith ready"
                break
            fi
            sleep 1
        done
        
        if ! curl -sf "$CHAINSMITH_URL/health" > /dev/null 2>&1; then
            echo "⚠️  Warning: Chainsmith did not become healthy in time"
            echo "    You may need to start it manually: ./chainsmith.sh start"
        fi
    else
        echo "⚠️  Warning: chainsmith.sh not found or not executable"
        echo "    Start Chainsmith manually: ./chainsmith.sh start"
    fi
fi

# ─── Load Scenario in Chainsmith ─────────────────────────────────
echo ""
echo "[+] Loading scenario '$SCENARIO' in Chainsmith..."

# Call the scenario load API
LOAD_RESPONSE=$(curl -sf -X POST "$CHAINSMITH_URL/api/v1/scenarios/load" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$SCENARIO\"}" 2>&1) || true

if echo "$LOAD_RESPONSE" | grep -q '"loaded": true\|"loaded":true'; then
    SIM_COUNT=$(echo "$LOAD_RESPONSE" | grep -o '"simulation_count":[0-9]*' | grep -o '[0-9]*' || echo "0")
    echo "    ✓ Scenario loaded with $SIM_COUNT simulated checks"
else
    echo "⚠️  Warning: Could not load scenario in Chainsmith"
    echo "    Response: $LOAD_RESPONSE"
    echo "    You can load it manually via the API or UI"
fi

# ─── Display Status ──────────────────────────────────────────────
cd "$SCENARIO_DIR"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Range Status                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Show running containers for this scenario
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || docker compose ps

# Show session info if randomized
SESSION_FILE="$SCENARIO_DIR/data/session.json"
if [ -f "$SESSION_FILE" ] && command -v jq &> /dev/null; then
    echo ""
    echo "Session: $(jq -r '.session_id' "$SESSION_FILE")"
    echo ""
    echo "Active Chains:"
    jq -r '.selected_chains[] | "  [\(.severity)] \(.chain_name // .name)"' "$SESSION_FILE" 2>/dev/null || true
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Access Points                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Chainsmith UI:  $CHAINSMITH_URL"
echo "  Scenario:       $SCENARIO (loaded)"
echo ""
echo "  Stop range:     ./range/stop-range.sh"
echo "  Reset range:    ./range/reset-range.sh $SCENARIO"
echo ""
echo "[✓] Range is ready!"
