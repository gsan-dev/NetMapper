"""Endpoints REST de dispositivos descubiertos (Fase 1-2)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from common.db import get_repository

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("")
async def list_devices(active_only: bool = True):
    repo = get_repository()
    return repo.list_devices(active_only=active_only)


@router.get("/{mac}")
async def get_device(mac: str):
    repo = get_repository()
    device = repo.get_device_by_mac(mac)
    if device is None:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    return device


@router.get("/{mac}/history")
async def get_device_history(mac: str, limit: int = 200):
    """Huella histórica del dispositivo: su estado en cada análisis de
    grafo pasado en el que apareció (mejora futura del README)."""
    repo = get_repository()
    return repo.get_device_history(mac, limit=limit)
