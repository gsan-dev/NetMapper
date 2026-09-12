"""Endpoint REST de redes descubiertas (Fase 0)."""
from __future__ import annotations

from fastapi import APIRouter

from common.db import get_repository

router = APIRouter(prefix="/api/networks", tags=["networks"])


@router.get("")
async def list_networks():
    repo = get_repository()
    return repo.list_networks()
