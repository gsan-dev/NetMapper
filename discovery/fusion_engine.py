"""Motor de fusión de datos multi-fuente (Fase 4).

Es el módulo más delicado del proyecto: recibe datos de las fuentes
activas (`host_discovery` + `device_fingerprint`) y pasivas
(`passive_capture`), que pueden llegar en momentos distintos y con
inconsistencias, y mantiene un modelo de grafo coherente a lo largo
del tiempo.

Decisiones de diseño clave:

- La **MAC** es el identificador estable de un dispositivo, no la IP
  (que puede cambiar por DHCP). Los hosts sin MAC real (descubiertos
  por sondeo TCP remoto, fuera del segmento L2 local) usan
  `"unknown-<ip>"` como identidad de repuesto.
- Si una IP que antes pertenecía a un dispositivo aparece ahora
  reportada por otro, se reasigna al nuevo dispositivo y se retira del
  anterior (reasignación DHCP).
- Las aristas pasivas llegan como pares de IP; se resuelven a MAC en
  el momento de fusionarlas usando el mapa IP -> MAC ya conocido. Una
  IP que no pertenece a ningún dispositivo conocido (p. ej. un
  servidor de Internet) se usa tal cual como nodo "externo" del grafo.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("netmapper.fusion_engine")


@dataclass
class Device:
    mac: str
    ips: set[str] = field(default_factory=set)
    vendor: str | None = None
    device_type: str = "unknown"
    open_ports: set[int] = field(default_factory=set)
    mdns_services: list[str] = field(default_factory=list)
    dns_queries: dict[str, int] = field(default_factory=dict)  # dominio -> nº consultas
    subnet_cidrs: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    # Mejora futura ya implementada: detección de dispositivos no
    # autorizados. True por defecto — solo se recalcula si el usuario ha
    # configurado ALLOWED_DEVICES (ver Pipeline._apply_device_authorization
    # en discovery/main.py). El FusionEngine en sí no conoce la whitelist,
    # para mantenerlo desacoplado de la configuración global.
    is_authorized: bool = True

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ips": sorted(self.ips),
            "vendor": self.vendor,
            "device_type": self.device_type,
            "open_ports": sorted(self.open_ports),
            "mdns_services": self.mdns_services,
            "dns_queries": self.dns_queries,
            "subnet_cidrs": sorted(self.subnet_cidrs),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_authorized": self.is_authorized,
        }


@dataclass
class Relation:
    src_mac: str
    dst_mac: str
    bytes_total: int = 0
    connections: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_mac, self.dst_mac)

    def to_dict(self) -> dict:
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "bytes_total": self.bytes_total,
            "connections": self.connections,
        }


class FusionEngine:
    """Mantiene el estado fusionado (dispositivos + relaciones) a lo largo del tiempo."""

    def __init__(self):
        self.devices: dict[str, Device] = {}  # mac -> Device
        self.ip_to_mac: dict[str, str] = {}  # ip -> mac (para resolver aristas pasivas)
        self.relations: dict[tuple[str, str], Relation] = {}

    def _get_or_create_device(self, mac: str, now: float) -> Device:
        device = self.devices.get(mac)
        if device is None:
            device = Device(mac=mac, first_seen=now, last_seen=now)
            self.devices[mac] = device
        else:
            device.last_seen = now
        return device

    def _assign_ip(self, ip: str, mac: str) -> None:
        """Asocia `ip` a `mac`, retirándola de cualquier otro dispositivo (DHCP)."""
        previous_mac = self.ip_to_mac.get(ip)
        if previous_mac is not None and previous_mac != mac:
            previous_device = self.devices.get(previous_mac)
            if previous_device is not None:
                previous_device.ips.discard(ip)
                logger.info("IP %s reasignada de %s a %s (DHCP)", ip, previous_mac, mac)
        self.ip_to_mac[ip] = mac

    def ingest_host(self, host, subnet_cidr: str, now: float | None = None) -> Device:
        """Registra un Host (de host_discovery) — descubrimiento activo."""
        now = now if now is not None else time.time()
        mac = host.mac or f"unknown-{host.ip}"
        device = self._get_or_create_device(mac, now)
        device.ips.add(host.ip)
        device.subnet_cidrs.add(subnet_cidr)
        self._assign_ip(host.ip, mac)
        return device

    def ingest_fingerprint(self, profile, now: float | None = None) -> Device:
        """Enriquece un dispositivo con su DeviceProfile (Fase 2). Lo crea si hace falta."""
        now = now if now is not None else time.time()
        device = self._get_or_create_device(profile.mac, now)
        device.ips.add(profile.ip)
        self._assign_ip(profile.ip, profile.mac)
        if profile.vendor:
            device.vendor = profile.vendor
        device.open_ports |= profile.open_ports
        device.device_type = profile.device_type
        if profile.mdns_services:
            device.mdns_services = sorted(
                set(device.mdns_services) | set(profile.mdns_services)
            )
        return device

    def _resolve_mac(self, ip: str) -> str:
        """MAC conocida para `ip`, o la propia IP como nodo "externo" si no se conoce."""
        return self.ip_to_mac.get(ip, ip)

    def ingest_edge(self, edge, now: float | None = None) -> Relation:
        """Registra una Edge (de passive_capture) — descubrimiento pasivo."""
        src_mac = self._resolve_mac(edge.src_ip)
        dst_mac = self._resolve_mac(edge.dst_ip)
        key = (src_mac, dst_mac)

        relation = self.relations.get(key)
        if relation is None:
            relation = Relation(src_mac=src_mac, dst_mac=dst_mac)
            self.relations[key] = relation
        relation.bytes_total += edge.bytes_total
        relation.connections += edge.connections
        return relation

    def ingest_dns_queries(self, dns_queries: dict[str, dict[str, int]]) -> None:
        """Añade el recuento de consultas DNS por IP origen a su dispositivo conocido."""
        for ip, queries in dns_queries.items():
            mac = self.ip_to_mac.get(ip)
            if mac is None:
                continue
            device = self.devices.get(mac)
            if device is None:
                continue
            for domain, count in queries.items():
                device.dns_queries[domain] = device.dns_queries.get(domain, 0) + count

    def prune_stale_devices(self, max_age_seconds: float, now: float | None = None) -> list[str]:
        """Elimina dispositivos no vistos en `max_age_seconds`; devuelve sus MACs."""
        now = now if now is not None else time.time()
        stale = [mac for mac, d in self.devices.items() if now - d.last_seen > max_age_seconds]
        for mac in stale:
            device = self.devices.pop(mac)
            for ip in device.ips:
                if self.ip_to_mac.get(ip) == mac:
                    del self.ip_to_mac[ip]
        return stale

    def snapshot(self) -> tuple[list[Device], list[Relation]]:
        """Copia superficial del estado actual, lista para persistir o analizar."""
        return list(self.devices.values()), list(self.relations.values())
