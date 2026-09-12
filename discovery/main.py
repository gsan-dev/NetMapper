"""Orquestación del pipeline completo de NetMapper.

Uso:
    python3 main.py                 # una sola pasada completa (discovery + análisis)
    python3 main.py --continuous    # bucle cada SCAN_INTERVAL_SECONDS

Cada pasada de descubrimiento:

1. Descubre redes (Fase 0) y las contrasta con `ALLOWED_NETWORKS`: las
   autorizadas se escanean activamente; el resto se registran como
   "conocidas" pero **nunca** se escanean sin autorización explícita
   (ver Consideraciones legales y éticas en el README).
2. Para cada red autorizada, descubre hosts vivos (Fase 1) y los
   caracteriza (Fase 2), reutilizando una única ventana de escucha
   mDNS por pasada.
3. Fusiona todo en el `FusionEngine` (Fase 4), que se mantiene vivo
   entre pasadas para acumular el grafo a lo largo del tiempo.

La captura pasiva (Fase 3) se arranca una vez en modo continuo y
alimenta al mismo `FusionEngine` en segundo plano. Cada
`GRAPH_ANALYSIS_INTERVAL_SECONDS`, se ejecuta el análisis de grafo
(Fase 5) y se persiste todo (Fase 6).
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _extra_path in (REPO_ROOT, REPO_ROOT / "analysis"):
    if str(_extra_path) not in sys.path:
        sys.path.insert(0, str(_extra_path))

from common.config import settings
from common.db import get_repository
from device_fingerprint import fingerprint_host, listen_mdns
from fusion_engine import FusionEngine
from graph_analysis import analyze
from host_discovery import discover_hosts
from network_discovery import discover_networks
from passive_capture import PassiveCapture

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("netmapper.pipeline")


class Pipeline:
    def __init__(self) -> None:
        self.repo = get_repository()
        self.engine = FusionEngine()
        self._passive_capture: PassiveCapture | None = None

    def _start_passive_capture(self) -> None:
        if not settings.passive_capture_enabled:
            return

        def on_window(_window_start, _window_end, edges, dns_queries) -> None:
            for edge in edges:
                self.engine.ingest_edge(edge)
            self.engine.ingest_dns_queries(dns_queries)

        self._passive_capture = PassiveCapture(
            interface=settings.passive_capture_interface,
            window_seconds=settings.passive_capture_window_seconds,
            on_window=on_window,
        )
        self._passive_capture.start()

    def run_discovery_pass(self, device_stale_after_seconds: float | None = None) -> None:
        """Fases 0-1-2-4: descubre redes, hosts, los caracteriza y fusiona.

        Al final de cada pasada, se retiran del FusionEngine (y se marcan
        inactivos en la BD) los dispositivos no vistos en las últimas
        `device_stale_after_seconds` (por defecto, 3 ciclos de escaneo):
        un dispositivo que estuvo pero ya no responde no debería quedarse
        "activo" para siempre solo porque se vio una vez.
        """
        networks = discover_networks(
            router_ip=settings.gateway_ip or None,
            snmp_enabled=settings.snmp_enabled,
            snmp_community=settings.snmp_community,
            snmp_timeout=settings.snmp_timeout_seconds,
        )

        mdns_services: dict[str, list[str]] = {}
        if settings.mdns_enabled:
            mdns_services = listen_mdns(duration_seconds=settings.mdns_listen_seconds)

        for subnet in networks:
            allowed = settings.is_network_allowed(subnet.network)
            self.repo.upsert_network({**subnet.to_dict(), "reachable": allowed})

            if not allowed:
                logger.info(
                    "Red %s detectada pero no está en ALLOWED_NETWORKS; no se escanea",
                    subnet.cidr,
                )
                continue

            hosts = discover_hosts(
                subnet,
                arp_timeout=settings.arp_timeout_seconds,
                tcp_timeout=settings.remote_scan_timeout_seconds,
                tcp_concurrency=settings.remote_scan_concurrency,
            )
            logger.info("Red %s: %d hosts vivos", subnet.cidr, len(hosts))

            for host in hosts:
                self.engine.ingest_host(host, subnet.cidr)
                profile = fingerprint_host(
                    host,
                    mdns_services_by_ip=mdns_services,
                    port_scan_timeout=settings.port_scan_timeout_seconds,
                    port_scan_concurrency=settings.port_scan_concurrency,
                )
                self.engine.ingest_fingerprint(profile)

        stale_after = (
            device_stale_after_seconds
            if device_stale_after_seconds is not None
            else settings.scan_interval_seconds * 3
        )
        self.engine.prune_stale_devices(max_age_seconds=stale_after)
        self._apply_device_authorization()
        self.repo.mark_stale_devices_inactive(set(self.engine.devices.keys()))

    def _apply_device_authorization(self) -> None:
        """Mejora futura ya implementada: detección de dispositivos no
        autorizados. Sin ALLOWED_DEVICES configurada, no se toca nada (todo
        sigue autorizado por defecto) para no generar falsos positivos en
        quien no ha decidido activar esta comprobación."""
        if not settings.allowed_devices:
            return
        for mac, device in self.engine.devices.items():
            device.is_authorized = mac.lower() in settings.allowed_devices

    def persist_current_state(self) -> None:
        """Fase 6: escribe el estado acumulado del FusionEngine en la BD."""
        devices, relations = self.engine.snapshot()
        for device in devices:
            self.repo.upsert_device(device.to_dict())
        for relation in relations:
            self.repo.upsert_relation(relation.to_dict())

    def run_analysis_pass(self) -> None:
        """Fase 5: analiza el grafo actual y persiste el snapshot resultante."""
        devices, relations = self.engine.snapshot()
        gateway_mac = (
            self.engine.ip_to_mac.get(settings.gateway_ip) if settings.gateway_ip else None
        )
        result = analyze(devices, relations, gateway_mac=gateway_mac)
        result["devices"] = [d.to_dict() for d in devices]
        result["relations"] = [r.to_dict() for r in relations]
        self.repo.insert_graph_snapshot(result)
        logger.info(
            "Análisis de grafo: %d nodos, %d aristas, %d comunidades",
            result["node_count"],
            result["edge_count"],
            len(set(result["communities"].values())),
        )

    def run_once(self) -> None:
        self.run_discovery_pass()
        self.persist_current_state()
        self.run_analysis_pass()

    def run_continuous(self) -> None:
        self._start_passive_capture()
        last_analysis = 0.0
        try:
            while True:
                self.run_discovery_pass()
                self.persist_current_state()

                now = time.time()
                if now - last_analysis >= settings.graph_analysis_interval_seconds:
                    self.run_analysis_pass()
                    last_analysis = now

                time.sleep(settings.scan_interval_seconds)
        finally:
            if self._passive_capture is not None:
                self._passive_capture.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline de descubrimiento y mapeo de NetMapper"
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Deja el pipeline corriendo en bucle cada SCAN_INTERVAL_SECONDS",
    )
    args = parser.parse_args()

    pipeline = Pipeline()
    if args.continuous:
        pipeline.run_continuous()
    else:
        pipeline.run_once()


if __name__ == "__main__":
    main()
