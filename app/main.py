"""
Chainsmith Recon API

Modular web reconnaissance tool with:
- Check-based scanning pipeline
- Attack chain detection
- Proof of scope compliance
- Scenario simulation support
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import get_config
from app.db import init_db, close_db
from app.state import state
from app.routes import (
    scope_router,
    scan_router,
    scans_router,
    engagements_router,
    findings_router,
    checks_router,
    chains_router,
    scenarios_router,
    preferences_router,
    compliance_router,
    swarm_router,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Lifecycle ────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup, close on shutdown."""
    cfg = get_config()
    try:
        await init_db(
            backend=cfg.storage.backend,
            db_path=cfg.storage.db_path,
            postgresql_url=cfg.storage.postgresql_url,
        )
    except Exception:
        logger.warning(
            "Database initialization failed — persistence is disabled for this session. "
            "Scans will still work but results will not be saved.",
            exc_info=True,
        )
    yield
    await close_db()


# ─── App ──────────────────────────────────────────────────────

app = FastAPI(title="Chainsmith Recon", version="1.3.0", lifespan=lifespan)


# ─── Static Files ─────────────────────────────────────────────

def _get_static_dir() -> str:
    """Get static files directory, checking Docker path first."""
    docker_path = Path("/app/static")
    local_path = Path(__file__).parent.parent / "static"
    if docker_path.exists():
        return str(docker_path)
    elif local_path.exists():
        return str(local_path)
    return str(local_path)


_static_dir = _get_static_dir()
if Path(_static_dir).exists():
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")
    logger.info(f"Static files mounted from {_static_dir}")


# ─── Include Routers ──────────────────────────────────────────

app.include_router(scope_router)
app.include_router(scan_router)
app.include_router(scans_router)
app.include_router(engagements_router)
app.include_router(findings_router)
app.include_router(checks_router)
app.include_router(chains_router)
app.include_router(scenarios_router)
app.include_router(preferences_router)
app.include_router(compliance_router)
app.include_router(swarm_router)


# ─── Static Page Routes ───────────────────────────────────────

@app.get("/")
async def root():
    """Serve main UI."""
    return FileResponse(f"{_static_dir}/index.html")


@app.get("/index.html")
async def index_page():
    """Serve index page."""
    return FileResponse(f"{_static_dir}/index.html")


@app.get("/scan.html")
async def scan_page():
    """Serve scan page."""
    return FileResponse(f"{_static_dir}/scan.html")


@app.get("/findings.html")
async def findings_page():
    """Serve findings page."""
    return FileResponse(f"{_static_dir}/findings.html")


@app.get("/settings.html")
async def settings_page():
    """Serve settings page."""
    return FileResponse(f"{_static_dir}/settings.html")


@app.get("/profiles.html")
async def profiles_page():
    """Serve profiles page."""
    return FileResponse(f"{_static_dir}/profiles.html")


@app.get("/trend.html")
async def trend_page():
    """Serve trend analysis page."""
    return FileResponse(f"{_static_dir}/trend.html")


@app.get("/reports.html")
async def reports_page():
    """Serve report generation page."""
    return FileResponse(f"{_static_dir}/reports.html")


@app.get("/engagements.html")
async def engagements_page():
    """Serve engagements management page."""
    return FileResponse(f"{_static_dir}/engagements.html")


# ─── Health ───────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "session_id": state.session_id
    }
