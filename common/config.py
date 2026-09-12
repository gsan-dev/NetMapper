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


def _networks(name: str, default: list[str] | None = None):
    """Acepta CIDRs IPv4 e IPv6 indistintamente en la misma variable."""
    result = []
    for item in _list(name, default):
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return result


def _mac_set(name: str) -> set[str]:
    """Normaliza una lista de MACs a minúsculas para comparación case-insensitive."""
    return {mac.lower() for mac in _list(name)}


@dataclass
class Settings:
    # Descubrimiento de redes (admite CIDRs IPv4 e IPv6 mezclados)
    allowed_networks: list = field(default_factory=lambda: _networks("ALLOWED_NETWORKS"))

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

    # Integración con NetGuardian (mejora futura ya implementada): sondea
    # el backend de NetGuardian para correlacionar sus alertas de
    # anomalías de red con los dispositivos que NetMapper ya conoce.
    netguardian_enabled: bool = field(
        default_factory=lambda: _bool("NETGUARDIAN_ENABLED", False)
    )
    netguardian_api_url: str = os.getenv("NETGUARDIAN_API_URL", "http://localhost:8000")
    netguardian_username: str = os.getenv("NETGUARDIAN_USERNAME", "admin")
    netguardian_password: str = os.getenv("NETGUARDIAN_PASSWORD", "")
    netguardian_poll_interval_seconds: int = field(
        default_factory=lambda: _int("NETGUARDIAN_POLL_INTERVAL_SECONDS", 60)
    )

    # Detección de dispositivos no autorizados (mejora futura ya
    # implementada): lista blanca opcional de MACs conocidas. Vacía por
    # defecto -> nada se marca como no autorizado (evita falsos positivos
    # hasta que el usuario decide activar la comprobación).
    allowed_devices: set[str] = field(default_factory=lambda: _mac_set("ALLOWED_DEVICES"))

    # Identidad del sensor (para desplegar varios en segmentos/VLANs
    # aislados que comparten backend + base de datos). Cada sensor solo
    # puede marcar inactivos los dispositivos que él mismo vio por última
    # vez, nunca los que reportó otro sensor.
    sensor_id: str = os.getenv("SENSOR_ID", "default")

    # Retención de snapshots del análisis de grafo: sin esto,
    # graph_snapshots crece para siempre en modo --continuous. Se
    # conserva siempre el más reciente aunque sea más antiguo que esto.
    graph_snapshot_retention_seconds: int = field(
        default_factory=lambda: _int("GRAPH_SNAPSHOT_RETENTION_SECONDS", 30 * 24 * 3600)
    )

    # Banner grabbing: lee el saludo/cabecera inicial de cada puerto
    # abierto (versión de servicio), base para la correlación con CVEs.
    banner_grab_enabled: bool = field(
        default_factory=lambda: _bool("BANNER_GRAB_ENABLED", True)
    )
    banner_grab_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("BANNER_GRAB_TIMEOUT_SECONDS", "1.5"))
    )

    # Inspección de certificados TLS en puertos HTTPS-like.
    tls_inspect_enabled: bool = field(
        default_factory=lambda: _bool("TLS_INSPECT_ENABLED", True)
    )
    tls_inspect_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("TLS_INSPECT_TIMEOUT_SECONDS", "2.0"))
    )

    # Correlación con CVEs (NVD): desactivada por defecto porque hace
    # peticiones salientes a un servicio externo y está sujeta a límites
    # de tasa — es un opt-in explícito, no algo que se active solo.
    cve_lookup_enabled: bool = field(
        default_factory=lambda: _bool("CVE_LOOKUP_ENABLED", False)
    )
    cve_lookup_interval_seconds: int = field(
        default_factory=lambda: _int("CVE_LOOKUP_INTERVAL_SECONDS", 86400)
    )
    nvd_api_key: str = os.getenv("NVD_API_KEY", "")

    # Detección de ARP/DHCP spoofing (pasiva, sin riesgo): activada por
    # defecto, igual que el resto de descubrimiento pasivo.
    arp_spoof_detection_enabled: bool = field(
        default_factory=lambda: _bool("ARP_SPOOF_DETECTION_ENABLED", True)
    )

    # Traceroute bajo demanda (Fase de diagnóstico).
    traceroute_max_hops: int = field(
        default_factory=lambda: _int("TRACEROUTE_MAX_HOPS", 30)
    )
    traceroute_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("TRACEROUTE_TIMEOUT_SECONDS", "2.0"))
    )

    # Descubrimiento de topología física vía LLDP (pasivo).
    lldp_discovery_enabled: bool = field(
        default_factory=lambda: _bool("LLDP_DISCOVERY_ENABLED", True)
    )

    @property
    def db_path_absolute(self) -> Path:
        path = Path(self.db_path)
        if not path.is_absolute():
            path = REPO_ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def is_network_allowed(self, network) -> bool:
        """True si `network` está cubierta por alguna entrada de ALLOWED_NETWORKS.

        Compara solo contra entradas de la misma familia (IPv4/IPv6):
        `subnet_of()` lanza TypeError si se comparan versiones distintas.
        """
        return any(
            allowed.version == network.version
            and (network.subnet_of(allowed) or network == allowed)
            for allowed in self.allowed_networks
        )


settings = Settings()
