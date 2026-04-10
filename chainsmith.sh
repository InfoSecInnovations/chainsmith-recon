#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# chainsmith.sh — Chainsmith Recon standalone launcher
#
# Usage:
#   ./chainsmith.sh start [--profile|--provider <openai|anthropic|ollama|litellm>]
#   ./chainsmith.sh stop
#   ./chainsmith.sh restart [--profile|--provider ...]
#   ./chainsmith.sh status
#   ./chainsmith.sh logs [service]
#   ./chainsmith.sh teardown
#
# Profiles:
#   openai     OpenAI API          — requires OPENAI_API_KEY in .env
#   anthropic  Anthropic API       — requires ANTHROPIC_API_KEY in .env
#   ollama     Local Ollama        — no key required; OLLAMA_MODEL sets model
#   litellm    External LiteLLM    — requires LITELLM_BASE_URL in .env
#
# --profile overrides LLM_PROFILE in .env for this run.
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.chainsmith.yml"
ENV_FILE="${SCRIPT_DIR}/.env"
PROJECT_NAME="chainsmith"
SHARED_NETWORK="chainsmith-shared"

HEALTH_RETRIES=30
HEALTH_INTERVAL=3

CORE_SERVICES=("chainsmith-recon")

# ── Colors ────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

info()    { echo -e "${CYAN}[chainsmith]${RESET} $*"; }
success() { echo -e "${GREEN}[chainsmith]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[chainsmith]${RESET} $*"; }
error()   { echo -e "${RED}[chainsmith]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
step()    { echo -e "${BOLD}──${RESET} $*"; }

# ── OS detection ──────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux*)               OS="linux"   ;;
        Darwin*)              OS="macos"   ;;
        CYGWIN*|MINGW*|MSYS*) OS="windows" ;;
        *)                    OS="unknown" ;;
    esac
}

# ── Parse --profile before anything else ─────────────────────────
# Called first so the CLI value is exported before check_env sources .env.
parse_profile_flag() {
    PROFILE_OVERRIDE=""
    local args=("$@")
    local i=0
    while [ $i -lt ${#args[@]} ]; do
        case "${args[$i]}" in
            --profile|--provider|-p)
                i=$(( i + 1 ))
                PROFILE_OVERRIDE="${args[$i]:-}"
                ;;
        esac
        i=$(( i + 1 ))
    done

    if [ -n "$PROFILE_OVERRIDE" ]; then
        # Normalize to lowercase so --profile Anthropic works
        PROFILE_OVERRIDE="$(echo "$PROFILE_OVERRIDE" | tr '[:upper:]' '[:lower:]')"
        case "$PROFILE_OVERRIDE" in
            openai|anthropic|ollama|litellm) ;;
            *) die "Unknown profile '${PROFILE_OVERRIDE}'. Valid: openai, anthropic, ollama, litellm" ;;
        esac
        export LLM_PROFILE="$PROFILE_OVERRIDE"
    fi
}

# ── Docker check ──────────────────────────────────────────────────
check_docker() {
    step "Checking Docker"

    if ! command -v docker &>/dev/null; then
        die "Docker not found in PATH.\n  Install: https://docs.docker.com/get-docker/"
    fi

    if ! docker info &>/dev/null 2>&1; then
        case "$OS" in
            macos|windows) die "Docker daemon is not running. Start Docker Desktop and try again." ;;
            *)             die "Docker daemon is not running.\n  Try: sudo systemctl start docker" ;;
        esac
    fi

    if docker compose version &>/dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
    elif command -v docker-compose &>/dev/null; then
        warn "Using legacy docker-compose (v1). Upgrading to Compose v2 is recommended."
        DOCKER_COMPOSE="docker-compose"
    else
        die "docker compose plugin not found.\n  Install: https://docs.docker.com/compose/install/"
    fi

    success "Docker $(docker --version | awk '{print $3}' | tr -d ',') — OK"
}

# ── Shared network ────────────────────────────────────────────────
ensure_shared_network() {
    step "Shared network"
    if ! docker network inspect "$SHARED_NETWORK" &>/dev/null 2>&1; then
        docker network create "$SHARED_NETWORK" &>/dev/null
        success "Created: ${SHARED_NETWORK}"
    else
        success "${SHARED_NETWORK} — exists"
    fi
}

# ── .env check and key validation ────────────────────────────────
check_env() {
    step "Checking environment"

    if [ ! -f "$ENV_FILE" ]; then
        error ".env file not found."
        echo
        echo "  Create one from the template:"
        echo "    cp .env.example .env"
        echo "    # fill in required values for your chosen profile"
        echo
        echo "  Required per profile:"
        echo "    openai     →  OPENAI_API_KEY"
        echo "    anthropic  →  ANTHROPIC_API_KEY"
        echo "    litellm    →  LITELLM_BASE_URL, LITELLM_API_KEY"
        echo "    ollama     →  no key required"
        echo
        exit 1
    fi

    # Source .env — skip comments and blank lines.
    # LLM_PROFILE from CLI (parse_profile_flag) is already exported and
    # will not be overwritten by the source below because we export it first.
    set -a
    # shellcheck disable=SC1090
    source <(grep -v '^\s*#' "$ENV_FILE" | grep -v '^\s*$')
    set +a

    # Re-apply CLI override in case .env stomped it
    [ -n "${PROFILE_OVERRIDE:-}" ] && export LLM_PROFILE="$PROFILE_OVERRIDE"

    # Default if still unset
    LLM_PROFILE="${LLM_PROFILE:-openai}"

    case "$LLM_PROFILE" in
        openai)
            [ -z "${OPENAI_API_KEY:-}" ] && prompt_for_key "OPENAI_API_KEY" "OpenAI API key"
            ;;
        anthropic)
            [ -z "${ANTHROPIC_API_KEY:-}" ] && prompt_for_key "ANTHROPIC_API_KEY" "Anthropic API key"
            ;;
        litellm)
            [ -z "${LITELLM_BASE_URL:-}" ] && die "LITELLM_BASE_URL not set in .env (required for litellm profile)."
            ;;
        ollama)
            info "Ollama profile — no API key required."
            ;;
    esac

    success "Environment — OK (profile: ${LLM_PROFILE})"
}

prompt_for_key() {
    local var_name="$1"
    local display_name="$2"

    warn "${var_name} is not set in .env."
    echo -n "  Enter your ${display_name} (or press Enter to abort): "
    read -r -s key
    echo

    [ -z "$key" ] && die "No key provided. Set ${var_name} in .env and try again."

    if grep -q "^${var_name}=" "$ENV_FILE"; then
        if [ "$OS" = "macos" ]; then
            sed -i '' "s|^${var_name}=.*|${var_name}=${key}|" "$ENV_FILE"
        else
            sed -i "s|^${var_name}=.*|${var_name}=${key}|" "$ENV_FILE"
        fi
    else
        echo "${var_name}=${key}" >> "$ENV_FILE"
    fi

    export "${var_name}=${key}"
    success "${var_name} saved to .env."
}

# ── Port conflict check ───────────────────────────────────────────
check_ports() {
    step "Checking ports"

    local ports=("${CHAINSMITH_PORT:-8100}")
    [ "${LLM_PROFILE:-openai}" = "ollama" ] && ports+=(11434)

    local conflicts=()
    for port in "${ports[@]}"; do
        port_in_use "$port" && conflicts+=("$port")
    done

    if [ ${#conflicts[@]} -gt 0 ]; then
        error "Port conflict(s): ${conflicts[*]}"
        echo "  Change CHAINSMITH_PORT in .env or free the port and retry."
        exit 1
    fi

    success "Ports clear — OK"
}

port_in_use() {
    local port="$1"
    if command -v nc &>/dev/null; then
        nc -z 127.0.0.1 "$port" &>/dev/null 2>&1; return $?
    elif [ -f /proc/net/tcp ]; then
        local hex_port; hex_port=$(printf '%04X' "$port")
        grep -q " 00000000:${hex_port} " /proc/net/tcp 2>/dev/null; return $?
    fi
    return 1
}

# ── Build ─────────────────────────────────────────────────────────
build_images() {
    step "Building runtime image"
    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        build --quiet \
        || die "Image build failed. Check output above."
    success "Image built — OK"
}

# ── Ollama model pull ─────────────────────────────────────────────
pull_ollama_model() {
    local model="${OLLAMA_MODEL:-mistral}"
    step "Pulling Ollama model: ${model}"
    warn "This may take several minutes on first run (mistral ~4 GB)."
    wait_healthy "chainsmith-ollama" 60 5
    docker exec chainsmith-ollama ollama pull "$model" \
        || die "Failed to pull Ollama model '${model}'."
    success "Model '${model}' ready."
}

# ── Start ─────────────────────────────────────────────────────────
start_services() {
    step "Starting Chainsmith"

    local compose_profiles=()
    [ "${LLM_PROFILE:-openai}" = "ollama" ] && compose_profiles=(--profile ollama)

    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        "${compose_profiles[@]}" \
        up -d --remove-orphans \
        || die "docker compose up failed. Check output above."

    [ "${LLM_PROFILE:-openai}" = "ollama" ] && pull_ollama_model
}

# ── Health polling ────────────────────────────────────────────────
wait_for_healthy() {
    step "Waiting for services"

    local failed=()
    for container in "${CORE_SERVICES[@]}"; do
        echo -n "  ${container}..."
        if wait_healthy "$container" "$HEALTH_RETRIES" "$HEALTH_INTERVAL"; then
            echo -e " ${GREEN}healthy${RESET}"
        else
            echo -e " ${RED}FAILED${RESET}"
            failed+=("$container")
        fi
    done

    if [ ${#failed[@]} -gt 0 ]; then
        echo
        error "Service did not become healthy: ${failed[*]}"
        echo "  Run: ./chainsmith.sh logs ${failed[0]}"
        exit 1
    fi

    success "All services healthy"
}

wait_healthy() {
    local container="$1" retries="$2" interval="$3"
    for (( i=0; i<retries; i++ )); do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")
        case "$status" in
            healthy)   return 0 ;;
            unhealthy) return 1 ;;
            *)         sleep "$interval" ;;
        esac
    done
    return 1
}

# ── Access info ───────────────────────────────────────────────────
print_access_info() {
    local port="${CHAINSMITH_PORT:-8100}"
    echo
    echo -e "${BOLD}────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}  Chainsmith Recon — Ready${RESET}"
    echo -e "${BOLD}────────────────────────────────────────────${RESET}"
    echo
    echo -e "  ${CYAN}UI${RESET}        http://localhost:${port}"
    echo -e "  ${DIM}Profile:  ${LLM_PROFILE:-openai}${RESET}"
    echo
    echo -e "  Stop:      ${BOLD}./chainsmith.sh stop${RESET}"
    echo -e "  Teardown:  ${BOLD}./chainsmith.sh teardown${RESET}"
    echo -e "  Logs:      ${BOLD}./chainsmith.sh logs${RESET}"
    echo -e "  Status:    ${BOLD}./chainsmith.sh status${RESET}"
    echo
    echo -e "  ${DIM}Start a target: ./target.sh start [--profile ...]${RESET}"
    echo
}

# ── Commands ──────────────────────────────────────────────────────
cmd_stop() {
    step "Stopping Chainsmith"
    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        down 2>&1 || true
    success "Stopped."
}

cmd_status() {
    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        ps
}

cmd_logs() {
    local service="${1:-}"
    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        logs --follow --tail=100 $service
}

cmd_teardown() {
    warn "Removes Chainsmith containers, volumes, and built image."
    echo -n "  Continue? [y/N] "
    read -r confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { info "Cancelled."; exit 0; }

    step "Tearing down"
    $DOCKER_COMPOSE \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        down -v --rmi local 2>&1 || true

    docker volume rm chainsmith-recon-data 2>/dev/null \
        && info "Removed volume: chainsmith-recon-data" || true

    # Remove shared network only if nothing else is using it
    local connected
    connected=$(docker network inspect "$SHARED_NETWORK" \
        --format '{{len .Containers}}' 2>/dev/null || echo "0")
    if [ "$connected" = "0" ]; then
        docker network rm "$SHARED_NETWORK" 2>/dev/null \
            && info "Removed network: ${SHARED_NETWORK}" || true
    else
        info "Shared network still in use by target — leaving it."
    fi

    success "Teardown complete."
}

cmd_help() {
    echo
    echo "  Usage: ./chainsmith.sh <command> [options]"
    echo
    echo "  Commands:"
    echo "    start [--profile|--provider <openai|anthropic|ollama|litellm>]"
    echo "      Preflight checks, build, and start Chainsmith."
    echo
    echo "    stop"
    echo "      Stop Chainsmith. Data volumes are preserved."
    echo
    echo "    restart [--profile ...]"
    echo "      Stop then start."
    echo
    echo "    status"
    echo "      Show container states."
    echo
    echo "    logs [service]"
    echo "      Tail logs. Omit service to follow all."
    echo
    echo "    teardown"
    echo "      Remove containers, volumes, and built image."
    echo
    echo "  Profiles:"
    echo "    openai     OPENAI_API_KEY in .env"
    echo "    anthropic  ANTHROPIC_API_KEY in .env"
    echo "    ollama     No key. OLLAMA_MODEL sets model (default: mistral)"
    echo "    litellm    LITELLM_BASE_URL + LITELLM_API_KEY in .env"
    echo
    echo "  See also: ./target.sh help"
    echo
}

# ── Entry point ───────────────────────────────────────────────────
main() {
    cd "$SCRIPT_DIR"
    local cmd="${1:-help}"; shift || true

    load_env() {
        detect_os
        check_docker
        if [ -f "$ENV_FILE" ]; then
            set -a
            source <(grep -v '^\s*#' "$ENV_FILE" | grep -v '^\s*$')
            set +a
        fi
    }

    case "$cmd" in
        start)
            parse_profile_flag "$@"
            detect_os
            check_docker
            ensure_shared_network
            check_env
            check_ports
            build_images
            start_services
            wait_for_healthy
            print_access_info
            ;;
        stop)
            load_env; cmd_stop ;;
        restart)
            parse_profile_flag "$@"
            load_env; cmd_stop
            ensure_shared_network
            check_env
            check_ports
            build_images
            start_services
            wait_for_healthy
            print_access_info
            ;;
        status)
            load_env; cmd_status ;;
        logs)
            load_env; cmd_logs "$@" ;;
        teardown)
            load_env; cmd_teardown ;;
        help|--help|-h)
            cmd_help ;;
        *)
            error "Unknown command: ${cmd}"
            echo "  Run './chainsmith.sh help'"
            exit 1
            ;;
    esac
}

main "$@"
