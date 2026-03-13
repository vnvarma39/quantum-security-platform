"""
Quantum Security Intelligence Platform — Backend API
FastAPI application entry point.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from .routers import graph, paths, patches, quantum, validation
from .core.config import settings
from .core.graph_store import GraphStore

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    log.info("qsip.startup", version="1.0.0", quantum_backend=settings.QUANTUM_BACKEND)
    app.state.graph_store = GraphStore()
    await app.state.graph_store.initialize()
    yield
    log.info("qsip.shutdown")


app = FastAPI(
    title="Quantum Security Intelligence Platform",
    description=(
        "Quantum-Assisted Vulnerability Graph Analysis + "
        "Quantum-Inspired Automated Patch Synthesis"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────
app.include_router(graph.router,      prefix="/api/graph",      tags=["Graph"])
app.include_router(paths.router,      prefix="/api/paths",      tags=["Attack Paths"])
app.include_router(patches.router,    prefix="/api/patches",    tags=["Patches"])
app.include_router(quantum.router,    prefix="/api/quantum",    tags=["Quantum State"])
app.include_router(validation.router, prefix="/api/validation", tags=["Validation"])


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "version": "1.0.0"})
