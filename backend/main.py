"""NetMapper backend: FastAPI + WebSocket.

Expone redes, dispositivos y el grafo de topología vía REST, y
retransmite el estado actual del grafo por WebSocket cada pocos
segundos. El pipeline de discovery/analysis (discovery/main.py)
escribe en la base de datos; el backend solo lee y difunde — ambos
procesos quedan desacoplados y se pueden desplegar por separado.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from common.config import settings
from common.db import get_repository
from routes import devices, graph, networks, reports, ws
from ws_manager import manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netmapper.backend")

POLL_INTERVAL_SECONDS = 5


async def _broadcast_graph_loop() -> None:
    """Difunde el estado actual del grafo a todos los clientes conectados.

    A diferencia de un log de eventos append-only, el grafo es estado
    mutable (un dispositivo puede desaparecer, una relación puede
    cambiar de peso), así que se retransmite el snapshot completo en
    cada vuelta en vez de intentar diffs incrementales — a la escala
    de un homelab (decenas/cientos de dispositivos) es más simple y
    barato que llevar la contabilidad de qué cambió.
    """
    repo = get_repository()
    while True:
        try:
            await manager.broadcast(
                {
                    "type": "graph_update",
                    "data": {
                        "devices": repo.list_devices(active_only=True),
                        "relations": repo.list_relations(),
                        "snapshot": repo.get_latest_graph_snapshot(),
                    },
                }
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Error en el bucle de difusión del grafo")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_repository()  # crea el esquema si no existe todavía
    task = asyncio.create_task(_broadcast_graph_loop())
    logger.info("NetMapper backend arrancado")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="NetMapper API",
    description=(
        "Descubrimiento y mapeo automático de redes multi-segmento. "
        "Expone redes, dispositivos y el grafo de topología, con "
        "streaming en tiempo real por WebSocket. Documentación "
        "interactiva en /docs."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(networks.router)
app.include_router(devices.router)
app.include_router(graph.router)
app.include_router(reports.router)
app.include_router(ws.router)


@app.get("/api/health", tags=["health"])
async def health() -> dict:
    """Incluye la salud del propio pipeline de escaneo (discovery/main.py),
    no solo la del proceso del backend: si el sensor murió en silencio,
    esto lo hace visible en vez de que el panel se quede simplemente
    "sin novedades" sin que nadie sepa por qué."""
    repo = get_repository()
    pipeline_status = repo.get_pipeline_status() or {}
    last_discovery = pipeline_status.get("last_discovery_pass_at")

    stale_after = settings.scan_interval_seconds * 3
    sensor_healthy = last_discovery is not None and (time.time() - last_discovery) < stale_after

    return {
        "status": "ok",
        "websocket_clients": manager.active_connections,
        "sensor_healthy": sensor_healthy,
        "last_discovery_pass_at": last_discovery,
        "last_analysis_pass_at": pipeline_status.get("last_analysis_pass_at"),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.api_host, port=settings.api_port, reload=True)
