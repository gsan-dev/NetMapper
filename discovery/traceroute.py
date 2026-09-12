"""Traceroute bajo demanda (mejora futura ya implementada).

El backend no tiene privilegios de socket crudo (ni falta que le
hace para servir el resto de la API), así que solo encola la petición
en `traceroute_requests`; este módulo la resuelve desde el pipeline de
discovery, que sí corre con los privilegios necesarios para enviar
sondas IP con TTL creciente (la técnica clásica de traceroute).
"""
from __future__ import annotations

import logging
import time

logger = logging.getLogger("netmapper.traceroute")

try:
    from scapy.all import ICMP, IP, sr1

    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    ICMP = IP = sr1 = None
    _SCAPY_AVAILABLE = False


def run_traceroute(target_ip: str, max_hops: int = 30, timeout: float = 2.0) -> list[dict]:
    """Traceroute clásico por TTL creciente hasta `max_hops` o llegar al destino.

    Cada salto que no responde a tiempo se registra igualmente (con
    ip/rtt_ms a None) en vez de omitirse: un "*" también es información
    (ese salto filtra ICMP, algo habitual en muchos routers).
    """
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("Scapy no disponible; no se puede ejecutar traceroute")

    hops: list[dict] = []
    for ttl in range(1, max_hops + 1):
        probe = IP(dst=target_ip, ttl=ttl) / ICMP()
        sent_at = time.time()
        reply = sr1(probe, timeout=timeout, verbose=0)
        rtt_ms = (time.time() - sent_at) * 1000 if reply is not None else None

        hops.append({"ttl": ttl, "ip": reply.src if reply is not None else None, "rtt_ms": rtt_ms})

        if reply is not None and (reply.src == target_ip or _is_echo_reply(reply)):
            break

    return hops


def _is_echo_reply(reply) -> bool:
    return reply.haslayer(ICMP) and reply[ICMP].type == 0
