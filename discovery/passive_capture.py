"""Descubrimiento pasivo mediante captura de tráfico (Fase 3).

Agrupa paquetes observados por pares de IPs en ventanas de tiempo,
generando aristas `(origen, destino, bytes, nº_paquetes)` — esto es lo
que permite mostrar relaciones **reales** de comunicación, no solo
presencia.

También extrae las consultas DNS resueltas por cada IP origen: qué
dominios resuelve un dispositivo es una pista de fingerprinting
gratuita (p. ej. un dispositivo que solo resuelve dominios de Apple
probablemente sea un iPhone/Mac).
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("netmapper.passive_capture")

try:
    from scapy.all import DNS, DNSQR, IP, AsyncSniffer

    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    DNS = DNSQR = IP = AsyncSniffer = None  # noqa: N816
    _SCAPY_AVAILABLE = False


@dataclass(frozen=True)
class PacketObservation:
    src_ip: str
    dst_ip: str
    length: int
    dns_query: str | None = None


def parse_packet(pkt) -> PacketObservation | None:
    """Convierte un paquete de Scapy en una PacketObservation, o None si no es IP."""
    if IP is None or IP not in pkt:
        return None

    ip_layer = pkt[IP]
    dns_query = None
    if DNS is not None and DNS in pkt and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
        try:
            dns_query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except Exception:
            dns_query = None

    return PacketObservation(
        src_ip=ip_layer.src, dst_ip=ip_layer.dst, length=len(pkt), dns_query=dns_query
    )


@dataclass
class Edge:
    src_ip: str
    dst_ip: str
    bytes_total: int = 0
    connections: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.dst_ip)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "bytes_total": self.bytes_total,
            "connections": self.connections,
        }


class WindowAggregator:
    """Acumula PacketObservation y las agrega en aristas por ventana de tiempo.

    Thread-safe: `add()` se llama desde el hilo de captura de Scapy y
    `flush()` desde un hilo temporizador independiente.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._edges: dict[tuple[str, str], Edge] = {}
        self._dns_queries: dict[str, Counter] = defaultdict(Counter)
        self._window_start = time.time()

    def add(self, obs: PacketObservation) -> None:
        with self._lock:
            key = (obs.src_ip, obs.dst_ip)
            edge = self._edges.get(key)
            if edge is None:
                edge = Edge(src_ip=obs.src_ip, dst_ip=obs.dst_ip)
                self._edges[key] = edge
            edge.bytes_total += obs.length
            edge.connections += 1
            if obs.dns_query:
                self._dns_queries[obs.src_ip][obs.dns_query] += 1

    def should_flush(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self._window_start) >= self.window_seconds

    def flush(
        self, now: float | None = None
    ) -> tuple[float, float, list[Edge], dict[str, dict[str, int]]]:
        """Devuelve (window_start, window_end, edges, dns_queries) y reinicia el buffer."""
        now = now if now is not None else time.time()
        with self._lock:
            edges = list(self._edges.values())
            dns_queries = {ip: dict(counter) for ip, counter in self._dns_queries.items()}
            window_start = self._window_start
            self._edges = {}
            self._dns_queries = defaultdict(Counter)
            self._window_start = now
        return window_start, now, edges, dns_queries

    def __len__(self) -> int:
        with self._lock:
            return len(self._edges)


WindowCallback = Callable[[float, float, list[Edge], dict[str, dict[str, int]]], None]


class PassiveCapture:
    """Captura pasiva en vivo con Scapy; entrega cada ventana cerrada vía callback."""

    def __init__(
        self,
        interface: str,
        window_seconds: int,
        on_window: WindowCallback,
        bpf_filter: str = "ip",
    ):
        self.interface = interface
        self.on_window = on_window
        self.aggregator = WindowAggregator(window_seconds)
        self.bpf_filter = bpf_filter
        self._sniffer: AsyncSniffer | None = None
        self._timer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def _handle_packet(self, pkt) -> None:
        obs = parse_packet(pkt)
        if obs is not None:
            self.aggregator.add(obs)

    def _timer_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(1)
            if self.aggregator.should_flush():
                window_start, window_end, edges, dns_queries = self.aggregator.flush()
                try:
                    self.on_window(window_start, window_end, edges, dns_queries)
                except Exception:
                    logger.exception("Error procesando ventana de captura pasiva")

    def start(self) -> None:
        if not _SCAPY_AVAILABLE:
            logger.warning("Scapy no disponible; no se puede iniciar la captura pasiva")
            return

        logger.info(
            "Iniciando captura pasiva en '%s' (ventana=%ss)",
            self.interface,
            self.aggregator.window_seconds,
        )
        self._sniffer = AsyncSniffer(
            iface=self.interface, filter=self.bpf_filter, prn=self._handle_packet, store=False
        )
        self._sniffer.start()
        self._stop_event.clear()
        self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
        self._timer_thread.start()

    def stop(self) -> None:
        logger.info("Deteniendo captura pasiva")
        self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self._timer_thread is not None:
            self._timer_thread.join(timeout=2)
