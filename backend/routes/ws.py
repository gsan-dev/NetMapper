"""Endpoint WebSocket: difusión en vivo del estado del grafo."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ws_manager import manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # No esperamos mensajes del cliente; solo mantenemos la
            # conexión viva y detectamos la desconexión.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
