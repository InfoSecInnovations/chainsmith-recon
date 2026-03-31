# Scenario Template

This is a minimal scenario template. Copy this directory to create a new scenario.

## Quick Start

```bash
# 1. Copy template
cp -r scenarios/_template scenarios/my-scenario

# 2. Rename containers in docker-compose.yml
#    Change "template-" prefix to "my-scenario-"

# 3. Update scenario.json with your details

# 4. Implement services in services/

# 5. Test
./range/start-range.sh my-scenario
```

## Directory Structure

```
my-scenario/
├── scenario.json        # Scenario metadata and configuration
├── docker-compose.yml   # Service definitions
├── services/            # FastAPI service implementations
│   ├── __init__.py
│   ├── www.py          # Main service
│   └── extra.py        # Optional service (profile-activated)
├── data/               # Persistent state (session.json, etc.)
└── randomize.json      # Optional: randomization config
```

## scenario.json

```json
{
  "name": "my-scenario",
  "description": "Brief description of your scenario",
  "version": "1.0.0",
  "target": {
    "pattern": "*.my-scenario.local",
    "known_hosts": ["www", "api", "chat"],
    "ports": [9000, 9001, 9002]
  },
  "simulations": [
    "network/dns_my_scenario.yaml",
    "web/headers_my_scenario.yaml"
  ],
  "expected_findings": [
    "header_analysis-www.my-scenario.local-missing-security-headers"
  ],
  "expected_chains": [
    "my_attack_chain"
  ]
}
```

## docker-compose.yml

Key points:
- Build context is `../..` (repo root) so Dockerfile is accessible
- Mount `../../app:/app/app:ro` for Chainsmith libraries
- Mount `../:/app/scenarios:ro` for scenario code
- Mount `./data:/app/data` for persistent state
- Use `chainsmith-shared` external network
- Use profiles for optional services

## Services

Each service is a FastAPI app. Required endpoints:
- `GET /health` — returns `{"status": "ok"}` for Docker health checks

Common vulnerability patterns to implement:
- Missing security headers
- Version disclosure
- Sensitive paths in robots.txt
- CORS misconfiguration
- Exposed API documentation
- Debug endpoints
- Verbose error messages

## Simulations

If you want Chainsmith to find specific vulnerabilities in simulated mode,
create YAML files in `app/checks/simulator/simulations/` that reference
your scenario's hosts.

## Randomization (Optional)

To support `--randomize`, create `randomize.json`:

```json
{
  "chain_packages": [
    {
      "id": "my_chain",
      "chain_name": "My Attack Chain",
      "severity": "high",
      "required_services": ["api", "chat"],
      "required_findings": ["api_exposed", "chat_injection"]
    }
  ],
  "random_findings_pool": [
    "extra_finding_1",
    "extra_finding_2"
  ],
  "selection_rules": {
    "min_chains": 1,
    "max_chains": 2,
    "extra_findings_min": 0,
    "extra_findings_max": 2
  }
}
```

## Testing

```bash
# Start scenario
./range/start-range.sh my-scenario

# Start with all optional services
./range/start-range.sh my-scenario --all

# Start with specific profile
./range/start-range.sh my-scenario --profile extra

# Start with randomization
./range/start-range.sh my-scenario --randomize

# Check services
curl http://localhost:9000/health

# Stop
./range/stop-range.sh my-scenario

# Reset (clear session state)
./range/reset-range.sh my-scenario
```
