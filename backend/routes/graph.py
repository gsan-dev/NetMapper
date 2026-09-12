"""Endpoints REST del grafo de topología (Fase 4-5)."""
from __future__ import annotations

from fastapi import APIRouter

from common.db import get_repository

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
async def get_graph():
    """Estado actual del grafo: dispositivos activos, relaciones y el
    último análisis (comunidades/centralidad/capas) calculado."""
    repo = get_repository()
    return {
        "devices": repo.list_devices(active_only=True),
        "relations": repo.list_relations(),
        "snapshot": repo.get_latest_graph_snapshot(),
    }


@router.get("/snapshots")
async def list_snapshots(limit: int = 50):
    """Histórico de análisis del grafo, para el modo time-lapse del frontend."""
    repo = get_repository()
    return repo.list_graph_snapshots(limit=limit)
