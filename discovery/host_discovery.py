"""Descubrimiento de hosts vivos por subred (Fase 1).

- Redes **directamente conectadas**: ARP scan (capa 2) — casi
  instantáneo y muy fiable dentro del mismo segmento físico.
- Redes **remotas** (solo alcanzables vía routing): ARP no funciona más
  allá del segmento local, así que se usa un sondeo TCP asíncrono sobre
  puertos comunes (más fiable que ICMP, que muchos firewalls filtran).

`discover_hosts()` decide automáticamente qué técnica usar según el
`discovery_method` de la subred, en vez de aplicar la misma técnica a
todo — evita ser agresivo en redes remotas donde ARP ni siquiera
llegaría.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from network_discovery import Subnet

logger = logging.getLogger("netmapper.host_discovery")

try:
    from scapy.all import ARP, Ether, srp

    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    ARP = Ether = srp = None  # noqa: N816
    _SCAPY_AVAILABLE = False

# Puertos habituales para el sondeo TCP de redes remotas: si cualquiera
# responde (abierto o con RST), el host está vivo.
PROBE_PORTS = (80, 443, 22, 445, 3389)

# Por encima de esto, un sondeo TCP activo sería demasiado lento/agresivo
# para una subred "remota" descubierta automáticamente; se omite.
MAX_ADDRESSES_TO_PROBE = 4096


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str | None
    subnet_cidr: str
    discovery_method: str  # "arp" | "tcp_probe"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "subnet_cidr": self.subnet_cidr,
            "discovery_method": self.discovery_method,
        }


def arp_scan(subnet: Subnet, timeout: int = 3) -> list[Host]:
    """Escanea una red directamente conectada con ARP (requiere permisos root)."""
    if not _SCAPY_AVAILABLE:
        logger.warning("Scapy no disponible; no se puede hacer ARP scan")
        return []

    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet.cidr)
        answered, _unanswered = srp(request, timeout=timeout, verbose=False)
    except Exception:
        logger.exception("Error haciendo ARP scan de %s", subnet.cidr)
        return []

    hosts = []
    for _sent, received in answered:
        hosts.append(
            Host(
                ip=received.psrc,
                mac=received.hwsrc,
                subnet_cidr=subnet.cidr,
                discovery_method="arp",
            )
        )
    return hosts


async def _probe_host(ip: str, ports: tuple[int, ...], timeout: float) -> bool:
    """True si al menos un puerto responde (abierto o RST) -> hay un host vivo."""
    for port in ports:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except ConnectionRefusedError:
            return True  # RST: el host existe aunque el puerto esté cerrado
        except (TimeoutError, OSError):
            continue
    return False


async def tcp_probe_sweep_async(
    subnet: Subnet,
    ports: tuple[int, ...] = PROBE_PORTS,
    timeout: float = 1.0,
    concurrency: int = 100,
) -> list[Host]:
    """Sondeo TCP asíncrono para redes remotas."""
    network = subnet.network
    if network.num_addresses > MAX_ADDRESSES_TO_PROBE:
        logger.warning(
            "Subred %s demasiado grande (%d direcciones); se omite el sondeo activo",
            subnet.cidr,
            network.num_addresses,
        )
        return []

    host_ips = [str(ip) for ip in network.hosts()]
    semaphore = asyncio.Semaphore(concurrency)

    async def check(ip: str) -> Host | None:
        async with semaphore:
            alive = await _probe_host(ip, ports, timeout)
        return (
            Host(ip=ip, mac=None, subnet_cidr=subnet.cidr, discovery_method="tcp_probe")
            if alive
            else None
        )

    results = await asyncio.gather(*(check(ip) for ip in host_ips))
    return [h for h in results if h is not None]


def tcp_probe_sweep(subnet: Subnet, **kwargs) -> list[Host]:
    """Versión síncrona de `tcp_probe_sweep_async`, para llamadores no-async."""
    return asyncio.run(tcp_probe_sweep_async(subnet, **kwargs))


def discover_hosts(
    subnet: Subnet,
    arp_timeout: int = 3,
    tcp_timeout: float = 1.0,
    tcp_concurrency: int = 100,
) -> list[Host]:
    """Elige ARP o sondeo TCP según si la subred es directamente conectada."""
    if subnet.discovery_method == "direct":
        return arp_scan(subnet, timeout=arp_timeout)
    return tcp_probe_sweep(subnet, timeout=tcp_timeout, concurrency=tcp_concurrency)
