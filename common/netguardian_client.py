"""Cliente para integrarse con NetGuardian (mejora futura del README ya
implementada).

NetGuardian es un IDS con detección de anomalías (otro proyecto
propio): aprende el comportamiento normal de una red y genera alertas
cuando detecta tráfico anómalo desde una IP. Este cliente sondea su
API REST para traer esas alertas y correlacionarlas con los
dispositivos que NetMapper ya conoce por esa misma IP — así el mapa de
topología puede resaltar qué dispositivo está siendo flaggeado como
anómalo, sin que NetMapper tenga que reimplementar ninguna detección
de anomalías propia.

Diseño desacoplado a propósito: si NetGuardian no está desplegado o
NETGUARDIAN_ENABLED=false, este módulo simplemente no se usa — el
resto del pipeline funciona exactamente igual.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger("netmapper.netguardian_client")


@dataclass(frozen=True)
class SecurityAlert:
    alert_id: int
    source_ip: str
    severity: str
    reason: str
    created_at: float


class NetGuardianClient:
    def __init__(self, base_url: str, username: str, password: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    def _login(self) -> str | None:
        try:
            response = requests.post(
                f"{self.base_url}/api/auth/login",
                json={"username": self.username, "password": self.password},
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.warning(
                "No se pudo autenticar contra NetGuardian en %s (¿AUTH_ENABLED=false allí? "
                "en ese caso no hace falta token y esto es solo informativo)",
                self.base_url,
            )
            return None

        data = response.json()
        self._token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 600) - 30
        return self._token

    def _get_token(self) -> str | None:
        if self._token and time.time() < self._token_expires_at:
            return self._token
        return self._login()

    def fetch_recent_alerts(self, limit: int = 100, since_id: int = 0) -> list[SecurityAlert]:
        """Trae hasta `limit` alertas recientes de NetGuardian, descartando
        las que ya se procesaron en una vuelta anterior (id <= since_id)."""
        token = self._get_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        try:
            response = requests.get(
                f"{self.base_url}/api/alerts",
                params={"limit": limit},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.exception("Error consultando alertas de NetGuardian en %s", self.base_url)
            return []

        alerts = []
        for item in response.json():
            if item.get("id", 0) <= since_id or not item.get("source_ip"):
                continue
            alerts.append(
                SecurityAlert(
                    alert_id=item["id"],
                    source_ip=item["source_ip"],
                    severity=item.get("severity", "unknown"),
                    reason=item.get("reason", ""),
                    created_at=item.get("created_at", time.time()),
                )
            )
        return alerts
