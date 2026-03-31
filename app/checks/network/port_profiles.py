"""
Port Profiles

Named sets of TCP ports organized by service category.
Used by PortScanCheck and the port_scan tool to select
which ports to scan based on engagement context.

Profiles:
    web  - Standard web and API gateway ports
    ai   - Web + AI/ML service ports
    full - Web + AI + database ports
    lab  - Everything above + container/dev server ports (default)
"""

# ── Port categories ──────────────────────────────────────────────

# Standard web servers and HTTPS
WEB = [
    80,    # HTTP
    443,   # HTTPS
    8080,  # Alt HTTP (Tomcat, proxies)
    8443,  # Alt HTTPS
    8000,  # Django, uvicorn
    8888,  # Jupyter, misc
    3000,  # Node/Express, Grafana
    5000,  # Flask
    9443,  # Alt HTTPS (WSO2, etc.)
]

# API gateways, proxies, management planes
API = [
    4000,   # LiteLLM, GraphQL servers
    8001,   # Kong admin
    8444,   # Kong admin SSL
    8090,   # Various API servers
    9080,   # API gateways (APISIX, etc.)
    5555,   # Flower (Celery), misc APIs
]

# AI / ML inference and tooling
AI = [
    11434,  # Ollama
    7860,   # Gradio
    8501,   # Streamlit
    5001,   # MLflow
    6333,   # Qdrant gRPC
    6334,   # Qdrant HTTP
    8265,   # Ray Dashboard
    19530,  # Milvus
    9090,   # Prometheus
    3100,   # Loki
]

# Databases commonly exposed alongside web services
DATA = [
    5432,   # PostgreSQL
    3306,   # MySQL / MariaDB
    27017,  # MongoDB
    6379,   # Redis
    9200,   # Elasticsearch
    8529,   # ArangoDB
]

# Lab / container range - dev servers, Docker-mapped services
LAB = [
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    3001,   # Dev servers (Next.js, etc.)
    4200,   # Angular CLI
    5173,   # Vite
]


# ── Named profiles ───────────────────────────────────────────────

PROFILES: dict[str, list[int]] = {
    "web":  sorted(set(WEB + API)),
    "ai":   sorted(set(WEB + API + AI)),
    "full": sorted(set(WEB + API + AI + DATA)),
    "lab":  sorted(set(WEB + API + AI + DATA + LAB)),
}

# Default profile when nothing is specified
DEFAULT_PROFILE = "lab"


def resolve_ports(
    profile: str | None = None,
    in_scope_ports: list[int] | None = None,
) -> list[int]:
    """
    Resolve the final port list for a scan.

    Priority (highest to lowest):
        1. in_scope_ports - hard ceiling; if set, intersect with profile
        2. profile - named profile ("web", "ai", "full", "lab")
        3. DEFAULT_PROFILE - fallback

    Args:
        profile: Profile name to use, or None for default.
        in_scope_ports: Hard filter from scope config. Empty list = no restriction.

    Returns:
        Sorted list of ports to scan.
    """
    name = profile or DEFAULT_PROFILE
    ports = list(PROFILES.get(name, PROFILES[DEFAULT_PROFILE]))

    if in_scope_ports:
        allowed = set(in_scope_ports)
        ports = sorted(p for p in ports if p in allowed)

    return ports
