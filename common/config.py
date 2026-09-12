"""Carga centralizada de configuración desde variables de entorno / .env.

discovery, analysis y backend importan `settings` desde aquí para no
duplicar lógica de parseo.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _list(name: str, default: list[str] | None = None) -> list[str]:
    val = os.getenv(name)
    if not val:
        return default or []
    return [item.strip() for item in val.split(",") if item.strip()]


def _networks(name: str, default: list[str] | None = None) -> list[ipaddress.IPv4Network]:
    result = []
    for item in _list(name, default):
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return result


@dataclass
class Settings:
    # Descubrimiento de redes
    allowed_networks: list[ipaddress.IPv4Network] = field(
        default_factory=lambda: _networks("ALLOWED_NETWORKS")
    )

    snmp_enabled: bool = field(default_factory=lambda: _bool("SNMP_ENABLED", False))
    snmp_community: str = os.getenv("SNMP_COMMUNITY", "public")
    snmp_timeout_seconds: int = field(
        default_factory=lambda: _int("SNMP_TIMEOUT_SECONDS", 2)
    )

    # Descubrimiento de hosts
    arp_timeout_seconds: int = field(default_factory=lambda: _int("ARP_TIMEOUT_SECONDS", 3))
    remote_scan_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("REMOTE_SCAN_TIMEOUT_SECONDS", "1"))
    )
    remote_scan_concurrency: int = field(
        default_factory=lambda: _int("REMOTE_SCAN_CONCURRENCY", 100)
    )

    # Caracterización de dispositivos
    port_scan_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("PORT_SCAN_TIMEOUT_SECONDS", "1"))
    )
    port_scan_concurrency: int = field(
        default_factory=lambda: _int("PORT_SCAN_CONCURRENCY", 50)
    )
    mdns_enabled: bool = field(default_factory=lambda: _bool("MDNS_ENABLED", True))
    mdns_listen_seconds: int = field(default_factory=lambda: _int("MDNS_LISTEN_SECONDS", 5))

    # Descubrimiento pasivo
    passive_capture_enabled: bool = field(
        default_factory=lambda: _bool("PASSIVE_CAPTURE_ENABLED", True)
    )
    passive_capture_interface: str = os.getenv("PASSIVE_CAPTURE_INTERFACE", "eth0")
    passive_capture_window_seconds: int = field(
        default_factory=lambda: _int("PASSIVE_CAPTURE_WINDOW_SECONDS", 30)
    )

    # Orquestación
    scan_interval_seconds: int = field(
        default_factory=lambda: _int("SCAN_INTERVAL_SECONDS", 300)
    )

    # Base de datos
    db_backend: str = os.getenv("DB_BACKEND", "sqlite")
    db_path: str = os.getenv("DB_PATH", "./data/netmapper.db")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "")

    # Análisis de grafo
    gateway_ip: str = os.getenv("GATEWAY_IP", "")
    graph_analysis_interval_seconds: int = field(
        default_factory=lambda: _int("GRAPH_ANALYSIS_INTERVAL_SECONDS", 300)
    )

    # Backend / API
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = field(default_factory=lambda: _int("API_PORT", 8100))
    cors_origins: list[str] = field(
        default_factory=lambda: _list("CORS_ORIGINS", ["http://localhost:5174"])
    )

    @property
    def db_path_absolute(self) -> Path:
        path = Path(self.db_path)
        if not path.is_absolute():
            path = REPO_ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def is_network_allowed(self, network: ipaddress.IPv4Network) -> bool:
        """True si `network` está cubierta por alguna entrada de ALLOWED_NETWORKS."""
        return any(
            network.subnet_of(allowed) or network == allowed
            for allowed in self.allowed_networks
        )


settings = Settings()
