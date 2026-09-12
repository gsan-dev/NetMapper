"""Descubrimiento pasivo mediante captura de tráfico (Fase 3).

Agrupa paquetes observados por pares de IPs en ventanas de tiempo,
generando aristas `(origen, destino, bytes, nº_paquetes)` — esto es lo
que permite mostrar relaciones **reales** de comunicación, no solo
presencia.

También extrae las consultas DNS resueltas por cada IP origen: qué
dominios resuelve un dispositivo es una pista de fingerprinting
gratuita (p. ej. un dispositivo que solo resuelve dominios de Apple
probablemente sea un iPhone/Mac).

Mejora futura ya implementada: detección de ARP/DHCP spoofing
(`ArpWatcher`) — vigila si una misma IP es reclamada por MACs
distintas en tramas ARP, señal habitual de un ataque de suplantación.

Mejora futura ya implementada: topología física parcial vía LLDP
(`LldpNeighborTracker`) — registra qué switches/APs gestionados se
anuncian a sí mismos (chassis ID, puerto, nombre de sistema) en el
segmento que este sensor alcanza a oír. No es la topología completa de
la red, solo lo que llega a esta interfaz.
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

try:
    from scapy.all import IPv6
except ImportError:  # pragma: no cover
    IPv6 = None  # noqa: N816

try:
    from scapy.all import ARP, Ether
except ImportError:  # pragma: no cover
    ARP = Ether = None

try:
    from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemName

    _LLDP_AVAILABLE = True
except ImportError:  # pragma: no cover
    LLDPDU = LLDPDUChassisID = LLDPDUPortID = LLDPDUSystemName = None
    _LLDP_AVAILABLE = False


@dataclass(frozen=True)
class PacketObservation:
    src_ip: str
    dst_ip: str
    length: int
    dns_query: str | None = None


def parse_packet(pkt) -> PacketObservation | None:
    """Convierte un paquete de Scapy en una PacketObservation, o None si no es IP/IPv6."""
    if IP is not None and IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 is not None and IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        return None

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


@dataclass(frozen=True)
class ArpClaim:
    ip: str
    mac: str


def parse_arp_packet(pkt) -> ArpClaim | None:
    """Extrae (IP, MAC) reclamada de un paquete ARP (who-has o is-at).

    Tanto una petición ("who-has") como una respuesta ("is-at") declaran
    qué MAC dice tener `psrc` — suficiente para detectar conflictos sin
    esperar a que alguien responda.
    """
    if ARP is None or ARP not in pkt:
        return None
    arp = pkt[ARP]
    if arp.op not in (1, 2) or not arp.psrc or not arp.hwsrc:
        return None
    return ArpClaim(ip=arp.psrc, mac=arp.hwsrc.lower())


@dataclass(frozen=True)
class ArpSpoofAlert:
    ip: str
    known_mac: str
    new_mac: str
    detected_at: float = field(default_factory=time.time)


class ArpWatcher:
    """Detecta la misma IP reclamada por MACs distintas (mejora futura ya
    implementada: detección de ARP/DHCP spoofing).

    No hay forma de saber, solo observando ARP, cuál de las dos MACs es
    la legítima y cuál la que suplanta — se limita a reportar el
    conflicto; la decisión de investigar es del usuario.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.ip_to_mac: dict[str, str] = {}

    def observe(self, claim: ArpClaim, now: float | None = None) -> ArpSpoofAlert | None:
        now = now if now is not None else time.time()
        with self._lock:
            known_mac = self.ip_to_mac.get(claim.ip)
            if known_mac is None or known_mac == claim.mac:
                self.ip_to_mac[claim.ip] = claim.mac
                return None
            self.ip_to_mac[claim.ip] = claim.mac
            return ArpSpoofAlert(
                ip=claim.ip, known_mac=known_mac, new_mac=claim.mac, detected_at=now
            )


def _lldp_str(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return str(value)


@dataclass(frozen=True)
class LldpNeighbor:
    mac: str
    chassis_id: str | None
    port_id: str | None
    system_name: str | None


def parse_lldp_packet(pkt) -> LldpNeighbor | None:
    """Extrae la identidad que un vecino LLDP anuncia de sí mismo.

    LLDP lo emiten típicamente switches/APs gestionados, anunciándose a
    los dispositivos conectados directamente a ellos — no es una
    topología completa de la red, solo lo que este sensor alcanza a
    oír en su propio segmento.
    """
    if not _LLDP_AVAILABLE or Ether is None or LLDPDU not in pkt:
        return None
    mac = pkt[Ether].src if Ether in pkt else None
    if not mac:
        return None

    chassis_id = _lldp_str(pkt[LLDPDUChassisID].id) if pkt.haslayer(LLDPDUChassisID) else None
    port_id = _lldp_str(pkt[LLDPDUPortID].id) if pkt.haslayer(LLDPDUPortID) else None
    system_name = (
        _lldp_str(pkt[LLDPDUSystemName].system_name) if pkt.haslayer(LLDPDUSystemName) else None
    )
    return LldpNeighbor(mac=mac.lower(), chassis_id=chassis_id, port_id=port_id, system_name=system_name)


class LldpNeighborTracker:
    """Acumula el último anuncio LLDP visto de cada MAC vecina."""

    def __init__(self):
        self._lock = threading.Lock()
        self._neighbors: dict[str, LldpNeighbor] = {}

    def observe(self, neighbor: LldpNeighbor) -> None:
        with self._lock:
            self._neighbors[neighbor.mac] = neighbor

    def snapshot(self) -> list[LldpNeighbor]:
        with self._lock:
            return list(self._neighbors.values())


class PassiveCapture:
    """Captura pasiva en vivo con Scapy; entrega cada ventana cerrada vía callback."""

    def __init__(
        self,
        interface: str,
        window_seconds: int,
        on_window: WindowCallback,
        bpf_filter: str | None = None,
        arp_spoof_detection_enabled: bool = False,
        on_arp_spoof_alert: Callable[[ArpSpoofAlert], None] | None = None,
        lldp_discovery_enabled: bool = False,
    ):
        self.interface = interface
        self.on_window = on_window
        self.aggregator = WindowAggregator(window_seconds)
        self.on_arp_spoof_alert = on_arp_spoof_alert
        self._arp_watcher = ArpWatcher() if arp_spoof_detection_enabled else None
        self._lldp_tracker = LldpNeighborTracker() if lldp_discovery_enabled else None
        if bpf_filter is not None:
            self.bpf_filter = bpf_filter
        else:
            # Sin detección/descubrimiento activados no hace falta
            # capturar ARP/LLDP: menos carga de captura para lo que de
            # verdad se usa.
            filters = ["ip"]
            if arp_spoof_detection_enabled:
                filters.append("arp")
            if lldp_discovery_enabled:
                filters.append("ether proto 0x88cc")
            self.bpf_filter = " or ".join(filters)
        self._sniffer: AsyncSniffer | None = None
        self._timer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def get_lldp_neighbors(self) -> list[LldpNeighbor]:
        return self._lldp_tracker.snapshot() if self._lldp_tracker is not None else []

    def _handle_packet(self, pkt) -> None:
        obs = parse_packet(pkt)
        if obs is not None:
            self.aggregator.add(obs)

        if self._arp_watcher is not None:
            claim = parse_arp_packet(pkt)
            if claim is not None:
                alert = self._arp_watcher.observe(claim)
                if alert is not None and self.on_arp_spoof_alert is not None:
                    try:
                        self.on_arp_spoof_alert(alert)
                    except Exception:
                        logger.exception("Error procesando alerta de ARP spoofing")

        if self._lldp_tracker is not None:
            neighbor = parse_lldp_packet(pkt)
            if neighbor is not None:
                self._lldp_tracker.observe(neighbor)

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
