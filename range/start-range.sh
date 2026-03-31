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

# ─── Apply Randomization ─────────────────────────────────────────
if [ "$RANDOMIZE" = true ]; then
    RANDOMIZE_FILE="$SCENARIO_DIR/randomize.json"
    SESSION_FILE="$SCENARIO_DIR/data/session.json"
    
    if [ ! -f "$RANDOMIZE_FILE" ]; then
        echo "⚠️  Warning: No randomize.json found for $SCENARIO"
        echo "   Skipping randomization."
    else
        echo "[+] Applying randomization..."
        mkdir -p "$SCENARIO_DIR/data"
        
        # Generate randomized session using Python
        python3 << EOF
import json
import random
import uuid
from datetime import datetime
from pathlib import Path

randomize_file = Path("$RANDOMIZE_FILE")
session_file = Path("$SESSION_FILE")

with open(randomize_file) as f:
    config = json.load(f)

packages = config.get('chain_packages', [])
rules = config.get('selection_rules', {})

# Select random chains
min_chains = rules.get('min_chains', 2)
max_chains = rules.get('max_chains', 4)
num_chains = random.randint(min_chains, max_chains)
selected = random.sample(packages, min(num_chains, len(packages)))

# Determine required services
services = set()
for chain in selected:
    services.update(chain.get('required_services', []))

# Add random extra findings
pool = config.get('random_findings_pool', [])
extra_min = rules.get('extra_findings_min', 0)
extra_max = rules.get('extra_findings_max', 3)
num_extra = random.randint(extra_min, min(extra_max, len(pool)))
extra_findings = random.sample(pool, num_extra) if pool else []

session = {
    'session_id': str(uuid.uuid4())[:8],
    'scenario': "$SCENARIO",
    'created_at': datetime.now().isoformat(),
    'selected_chains': selected,
    'active_services': sorted(services),
    'extra_findings': extra_findings
}

with open(session_file, 'w') as f:
    json.dump(session, f, indent=2)

print(f"    Session ID: {session['session_id']}")
print(f"    Chains: {len(selected)}")
print(f"    Services: {', '.join(sorted(services)) or 'base only'}")
EOF
        
        # Read profiles from session
        if [ -f "$SESSION_FILE" ] && command -v jq &> /dev/null; then
            SERVICES=$(jq -r '.active_services[]' "$SESSION_FILE" 2>/dev/null || echo "")
            for svc in $SERVICES; do
                PROFILE_ARGS="$PROFILE_ARGS --profile $svc"
            done
        fi
        echo ""
    fi
fi

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
