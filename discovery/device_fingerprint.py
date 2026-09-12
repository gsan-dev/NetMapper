"""Caracterización de dispositivos (Fase 2).

Para cada host vivo:
- **Fabricante**: primeros bytes de la MAC (OUI del IEEE) vía `manuf`.
- **Puertos abiertos**: escaneo selectivo y asíncrono sobre una lista
  corta de puertos comunes — no exhaustivo, para no ser agresivo.
- **Banner grabbing** (mejora futura ya implementada): lee la
  versión de servicio de cada puerto abierto — base para la
  correlación con CVEs.
- **Inspección de certificados TLS** (mejora futura ya implementada):
  handshake TLS sin verificar la cadena de confianza para leer
  sujeto/emisor/caducidad de cada puerto TLS abierto.
- **Tipo de dispositivo**: motor de reglas (`common.device_types`) que
  combina fabricante + puertos abiertos.
- **mDNS/UPnP**: escucha pasiva de anuncios que muchos dispositivos
  domésticos emiten solos, dando información gratis sin escanear.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from common.device_types import infer_device_type
from host_discovery import Host

logger = logging.getLogger("netmapper.device_fingerprint")

try:
    from cryptography import x509

    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    x509 = None
    _CRYPTOGRAPHY_AVAILABLE = False

try:
    from manuf import manuf

    _mac_parser = manuf.MacParser(update=False)
    _MANUF_AVAILABLE = True
except ImportError:  # pragma: no cover
    _mac_parser = None
    _MANUF_AVAILABLE = False

try:
    from zeroconf import ServiceListener, Zeroconf
    from zeroconf import ServiceBrowser as _ServiceBrowser

    _ZEROCONF_AVAILABLE = True
except ImportError:  # pragma: no cover
    ServiceListener = object
    Zeroconf = _ServiceBrowser = None  # noqa: N816
    _ZEROCONF_AVAILABLE = False

# Puertos comunes a comprobar; deliberadamente no exhaustivo.
COMMON_PORTS = (22, 23, 53, 80, 139, 161, 443, 445, 554, 631, 3306, 3389, 5432, 5000, 8000, 8080, 9100)

# Puertos donde hay que "hablar primero" (petición HTTP mínima) para
# obtener un banner — el resto de servicios de texto plano suelen
# enviar su saludo nada más conectar, sin que el cliente diga nada.
HTTP_BANNER_PORTS = (80, 8000, 8080)

# Puertos donde probar un handshake TLS para inspeccionar el certificado
# (mejora futura ya implementada) — deliberadamente no exhaustivo.
TLS_PORTS = (443, 8443, 993, 995)

# Tipos de servicio mDNS más habituales en un homelab/red doméstica.
DEFAULT_MDNS_SERVICE_TYPES = (
    "_http._tcp.local.",
    "_ipp._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_device-info._tcp.local.",
)


@dataclass
class DeviceProfile:
    mac: str
    ip: str
    vendor: str | None = None
    open_ports: set[int] = field(default_factory=set)
    device_type: str = "unknown"
    mdns_services: list[str] = field(default_factory=list)
    # Mejora futura ya implementada: banner grabbing — versión de
    # servicio por puerto (p. ej. {22: "SSH-2.0-OpenSSH_8.9p1"}), base
    # para la correlación con CVEs.
    service_banners: dict[int, str] = field(default_factory=dict)
    # Mejora futura ya implementada: inspección de certificados TLS —
    # sujeto/emisor/caducidad por puerto TLS abierto, sin verificar la
    # cadena de confianza (muchos dispositivos domésticos usan
    # certificados autofirmados; el objetivo es informar, no validar).
    tls_certificates: dict[int, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "vendor": self.vendor,
            "open_ports": sorted(self.open_ports),
            "device_type": self.device_type,
            "mdns_services": self.mdns_services,
            "service_banners": self.service_banners,
            "tls_certificates": self.tls_certificates,
        }


def lookup_vendor(mac: str | None) -> str | None:
    """Fabricante a partir del OUI (primeros bytes de la MAC)."""
    if not _MANUF_AVAILABLE or not mac:
        return None
    try:
        return _mac_parser.get_manuf_long(mac) or _mac_parser.get_manuf(mac)
    except Exception:
        logger.exception("Error resolviendo fabricante para %s", mac)
        return None


async def _scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except ConnectionRefusedError:
        return False  # respondió, pero el puerto está cerrado
    except (TimeoutError, OSError):
        return False


async def scan_ports_async(
    ip: str,
    ports: tuple[int, ...] = COMMON_PORTS,
    timeout: float = 1.0,
    concurrency: int = 50,
) -> set[int]:
    """Escaneo de puertos selectivo (no exhaustivo) sobre `ports`."""
    semaphore = asyncio.Semaphore(concurrency)

    async def check(port: int) -> int | None:
        async with semaphore:
            is_open = await _scan_port(ip, port, timeout)
        return port if is_open else None

    results = await asyncio.gather(*(check(p) for p in ports))
    return {p for p in results if p is not None}


def scan_ports(ip: str, **kwargs) -> set[int]:
    """Versión síncrona de `scan_ports_async`."""
    return asyncio.run(scan_ports_async(ip, **kwargs))


async def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
    """Lee el saludo/cabecera inicial de un puerto ya confirmado abierto.

    SSH/FTP/SMTP/POP3/IMAP envían su banner nada más conectar. HTTP no
    lo hace por su cuenta: hay que enviar una petición mínima y leer la
    cabecera `Server:` de la respuesta.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (TimeoutError, OSError):
        return None

    try:
        if port in HTTP_BANNER_PORTS:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            await writer.drain()

        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        if not data:
            return None
        text = data.decode(errors="ignore").strip()

        if port in HTTP_BANNER_PORTS:
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return None  # respuesta HTTP sin cabecera Server: nada útil que guardar

        return text.splitlines()[0] if text else None
    except (TimeoutError, OSError):
        return None
    finally:
        writer.close()


async def grab_banners_async(
    ip: str, ports: set[int], timeout: float = 1.5, concurrency: int = 20
) -> dict[int, str]:
    """Banner grabbing sobre los puertos ya confirmados como abiertos."""
    semaphore = asyncio.Semaphore(concurrency)

    async def check(port: int) -> tuple[int, str] | None:
        async with semaphore:
            banner = await _grab_banner(ip, port, timeout)
        return (port, banner) if banner else None

    results = await asyncio.gather(*(check(p) for p in ports))
    return dict(r for r in results if r is not None)


def grab_banners(ip: str, ports: set[int], **kwargs) -> dict[int, str]:
    """Versión síncrona de `grab_banners_async`."""
    return asyncio.run(grab_banners_async(ip, ports, **kwargs))


def _build_insecure_tls_context() -> ssl.SSLContext:
    """Contexto TLS que no valida la cadena de confianza.

    El objetivo es *informar* sobre el certificado que presenta el
    dispositivo (para detectar caducidad o autofirmado), no decidir si
    confiar en él — muchos dispositivos domésticos (routers, cámaras,
    NAS) usan certificados autofirmados que rechazaría una verificación
    estricta.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _parse_certificate(der_bytes: bytes) -> dict | None:
    if not _CRYPTOGRAPHY_AVAILABLE:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc
        return {
            "subject": subject,
            "issuer": issuer,
            "not_after": not_after.isoformat(),
            "expired": not_after < datetime.now(timezone.utc),
            "self_signed": subject == issuer,
        }
    except Exception:
        logger.exception("Error parseando certificado TLS")
        return None


async def _inspect_tls(ip: str, port: int, timeout: float) -> dict | None:
    context = _build_insecure_tls_context()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context), timeout=timeout
        )
    except (TimeoutError, OSError, ssl.SSLError):
        return None

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        der_bytes = ssl_object.getpeercert(binary_form=True)
        if not der_bytes:
            return None
        return _parse_certificate(der_bytes)
    finally:
        writer.close()


async def inspect_tls_certificates_async(
    ip: str, ports: set[int], timeout: float = 2.0, concurrency: int = 10
) -> dict[int, dict]:
    """Inspecciona el certificado TLS de los puertos ya confirmados como abiertos."""
    semaphore = asyncio.Semaphore(concurrency)

    async def check(port: int) -> tuple[int, dict] | None:
        async with semaphore:
            cert = await _inspect_tls(ip, port, timeout)
        return (port, cert) if cert else None

    results = await asyncio.gather(*(check(p) for p in ports))
    return dict(r for r in results if r is not None)


def inspect_tls_certificates(ip: str, ports: set[int], **kwargs) -> dict[int, dict]:
    """Versión síncrona de `inspect_tls_certificates_async`."""
    return asyncio.run(inspect_tls_certificates_async(ip, ports, **kwargs))


class _MdnsCollector(ServiceListener):
    """Recoge anuncios mDNS por dirección IP durante una ventana de escucha."""

    def __init__(self):
        self.services_by_ip: dict[str, list[str]] = {}

    def add_service(self, zc, service_type, name):  # noqa: D102
        try:
            info = zc.get_service_info(service_type, name)
        except Exception:
            info = None
        if info is None or not info.addresses:
            return
        for raw_ip in info.addresses:
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            self.services_by_ip.setdefault(ip, []).append(name)

    def update_service(self, zc, service_type, name):  # noqa: D102
        pass

    def remove_service(self, zc, service_type, name):  # noqa: D102
        pass


def listen_mdns(
    duration_seconds: int = 5,
    service_types: tuple[str, ...] = DEFAULT_MDNS_SERVICE_TYPES,
) -> dict[str, list[str]]:
    """Escucha anuncios mDNS pasivamente durante `duration_seconds`.

    Devuelve un dict IP -> lista de nombres de servicio anunciados.
    """
    if not _ZEROCONF_AVAILABLE:
        logger.debug("zeroconf no disponible; se omite la escucha mDNS")
        return {}

    zc = Zeroconf()
    collector = _MdnsCollector()
    browsers = [_ServiceBrowser(zc, st, collector) for st in service_types]
    try:
        time.sleep(duration_seconds)
    finally:
        del browsers
        zc.close()

    return collector.services_by_ip


def fingerprint_host(
    host: Host,
    mdns_services_by_ip: dict[str, list[str]] | None = None,
    port_scan_timeout: float = 1.0,
    port_scan_concurrency: int = 50,
    banner_grab_enabled: bool = True,
    banner_grab_timeout: float = 1.5,
    tls_inspect_enabled: bool = True,
    tls_inspect_timeout: float = 2.0,
) -> DeviceProfile:
    """Combina vendor + puertos abiertos + mDNS + banners en un DeviceProfile.

    Si el host no tiene MAC (viene de un sondeo TCP remoto, no de ARP),
    se usa un identificador "unknown-<ip>" como MAC de repuesto: es
    menos estable frente a cambios de DHCP que una MAC real, pero es la
    mejor identidad disponible cuando el host está fuera del segmento
    L2 local y ARP no puede alcanzarlo.
    """
    vendor = lookup_vendor(host.mac)
    open_ports = scan_ports(
        host.ip, timeout=port_scan_timeout, concurrency=port_scan_concurrency
    )
    mdns_services = (mdns_services_by_ip or {}).get(host.ip, [])
    device_type = infer_device_type(vendor, open_ports)

    service_banners: dict[int, str] = {}
    if banner_grab_enabled and open_ports:
        service_banners = grab_banners(host.ip, open_ports, timeout=banner_grab_timeout)

    tls_certificates: dict[int, dict] = {}
    tls_ports = open_ports & set(TLS_PORTS)
    if tls_inspect_enabled and tls_ports:
        tls_certificates = inspect_tls_certificates(host.ip, tls_ports, timeout=tls_inspect_timeout)

    return DeviceProfile(
        mac=host.mac or f"unknown-{host.ip}",
        ip=host.ip,
        vendor=vendor,
        open_ports=open_ports,
        device_type=device_type,
        mdns_services=mdns_services,
        service_banners=service_banners,
        tls_certificates=tls_certificates,
    )
