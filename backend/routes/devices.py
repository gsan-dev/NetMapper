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


@router.post("/{mac}/traceroute", status_code=202)
async def request_traceroute(mac: str):
    """Mejora futura ya implementada: traceroute bajo demanda.

    El backend solo encola la petición: no tiene privilegios de socket
    crudo (ni tendría sentido dárselos solo para esto). El pipeline de
    discovery la resuelve en su siguiente pasada.
    """
    repo = get_repository()
    device = repo.get_device_by_mac(mac)
    if device is None:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    if not device["ips"]:
        raise HTTPException(status_code=400, detail="El dispositivo no tiene ninguna IP conocida")

    target_ip = device["ips"][0]
    request_id = repo.create_traceroute_request(mac, target_ip)
    return {"id": request_id, "status": "pending", "target_ip": target_ip}


@router.get("/{mac}/traceroute")
async def get_traceroute(mac: str):
    repo = get_repository()
    result = repo.get_latest_traceroute_for_mac(mac)
    if result is None:
        raise HTTPException(status_code=404, detail="No se ha solicitado ningún traceroute para este dispositivo")
    return result
