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
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_config
from app.db import close_db, init_db
from app.routes import (
    adjudication_router,
    advisor_router,
    chains_router,
    chainsmith_router,
    chat_router,
    checks_router,
    compliance_router,
    customizations_router,
    engagements_router,
    observations_router,
    preferences_router,
    scan_history_router,
    scan_router,
    scenarios_router,
    scope_router,
    swarm_router,
)
from app.state import state

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

    # Initialize chat dispatcher with prompt router
    try:
        from app.engine.chat import chat_dispatcher
        from app.engine.prompt_router import PromptRouter
        from app.lib.llm import get_llm_client

        client = get_llm_client()
        router = PromptRouter(client)
        chat_dispatcher.set_router(router)
        logger.info("Chat dispatcher initialized with prompt router")
    except Exception:
        logger.warning(
            "Chat dispatcher initialization failed — chat will be unavailable.",
            exc_info=True,
        )

    yield
    await close_db()


# ─── App ──────────────────────────────────────────────────────

app = FastAPI(title="Chainsmith Recon", version="1.3.0", lifespan=lifespan)

# ─── CORS ─────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
app.include_router(scan_history_router)
app.include_router(engagements_router)
app.include_router(observations_router)
app.include_router(checks_router)
app.include_router(chains_router)
app.include_router(adjudication_router)
app.include_router(scenarios_router)
app.include_router(preferences_router)
app.include_router(compliance_router)
app.include_router(swarm_router)
app.include_router(customizations_router)
app.include_router(advisor_router)
app.include_router(chat_router)
app.include_router(chainsmith_router)


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


@app.get("/observations.html")
async def observations_page():
    """Serve observations page."""
    return FileResponse(f"{_static_dir}/observations.html")


@app.get("/settings.html")
async def settings_page():
    """Serve settings page."""
    return FileResponse(f"{_static_dir}/settings.html")


@app.get("/profiles.html")
async def profiles_page():
    """Serve profiles page."""
    return FileResponse(f"{_static_dir}/profiles.html")


@app.get("/guided-quickstart.html")
async def guided_quickstart_page():
    """Serve Guided Mode quick start page."""
    return FileResponse(f"{_static_dir}/guided-quickstart.html")


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
    return {"status": "healthy", "session_id": state.session_id}
