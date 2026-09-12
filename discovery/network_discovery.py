"""Descubrimiento de redes accesibles (Fase 0 de la arquitectura).

Combina tres fuentes, de menos a más fiable:

- **Tabla de rutas** (`pyroute2`, solo Linux): redes alcanzables vía un
  gateway pero no conectadas directamente — esto es lo que permite ver
  un 10.0.0.x aunque la máquina esté físicamente en 192.168.1.x.
- **Interfaces locales** (`netifaces`): redes directamente conectadas.
- **SNMP a routers/switches gestionables** (opcional): la fuente más
  fiable cuando está disponible, porque el router conoce con certeza
  todas sus subredes/VLANs configuradas.

Cuando dos fuentes describen la misma red, gana la más fiable (SNMP >
interfaz local > tabla de rutas), pero todas se conservan si son CIDRs
distintos.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass

logger = logging.getLogger("netmapper.network_discovery")

try:
    import netifaces

    _NETIFACES_AVAILABLE = True
except ImportError:  # pragma: no cover
    netifaces = None  # noqa: N816 - placeholder para poder mockear en tests
    _NETIFACES_AVAILABLE = False

try:
    from pyroute2 import IPRoute

    _PYROUTE2_AVAILABLE = True
except ImportError:  # pragma: no cover - pyroute2 es Linux-only
    IPRoute = None  # noqa: N816 - placeholder para poder mockear en tests
    _PYROUTE2_AVAILABLE = False

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        walk_cmd,
    )

    _PYSNMP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYSNMP_AVAILABLE = False


# ipAddrTable.ipAdEntNetMask — para cada IP configurada en el router, su
# máscara. Es una tabla de MIB-II clásica y por tanto solo IPv4; el
# descubrimiento vía SNMP no cubre subredes IPv6 del router (para eso
# haría falta la tabla ipAddressTable de RFC 4293, no implementada aquí).
IP_ADDR_TABLE_NETMASK_OID = "1.3.6.1.2.1.4.20.1.3"

# rt_type de rtnetlink (ver <linux/rtnetlink.h>). Solo RTN_UNICAST
# representa una red real alcanzable — el kernel también expone, en la
# tabla "local" (255), una entrada RTN_LOCAL por cada IP propia y una
# RTN_BROADCAST por cada dirección de broadcast, ambas como rutas /32
# "hacia sí mismo" que no son redes a escanear. Sin este filtro,
# get_routes() devuelve dos entradas /32 de puro ruido por cada interfaz
# (su propia IP y su broadcast) — se vieron como decenas de "redes"
# fantasma en un despliegue real con varias interfaces Docker.
RTN_UNICAST = 1


@dataclass(frozen=True)
class Subnet:
    cidr: str  # p.ej. "192.168.1.0/24", ya normalizado (bits de host a 0)
    discovery_method: str  # "direct" | "route" | "router"
    interface: str | None = None
    gateway: str | None = None

    @property
    def network(self):
        """IPv4Network o IPv6Network, según el CIDR de esta subred."""
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def key(self) -> str:
        return self.cidr

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "discovery_method": self.discovery_method,
            "interface": self.interface,
            "gateway": self.gateway,
        }


def _make_subnet(ip: str, mask: str, method: str, **kwargs) -> Subnet | None:
    try:
        if ":" in mask:
            # netifaces da la máscara IPv6 en notación completa (p. ej.
            # "ffff:ffff:ffff:ffff::"), pero ipaddress.ip_network solo
            # acepta esa notación para IPv4 — para IPv6 exige longitud de
            # prefijo. La convertimos contando los bits altos a 1.
            prefixlen = bin(int(ipaddress.IPv6Address(mask))).count("1")
            network = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
        else:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    except ValueError:
        return None
    if network.is_loopback or network.is_link_local:
        return None
    return Subnet(cidr=str(network), discovery_method=method, **kwargs)


def discover_local_networks() -> list[Subnet]:
    """Redes directamente conectadas (IPv4 e IPv6), derivadas de cada interfaz local."""
    if not _NETIFACES_AVAILABLE:
        logger.warning("netifaces no disponible; no se pueden enumerar interfaces locales")
        return []

    subnets: dict[str, Subnet] = {}
    for iface in netifaces.interfaces():
        all_addrs = netifaces.ifaddresses(iface)
        for family in (netifaces.AF_INET, netifaces.AF_INET6):
            for addr in all_addrs.get(family, []):
                ip = addr.get("addr")
                # "netmask" es la clave del paquete netifaces original; el
                # fork netifaces2 (el que se instala aquí, ver
                # discovery/requirements.txt) usa "mask" en su lugar — sin
                # este fallback, discover_local_networks() no encontraba
                # NINGUNA red directamente conectada en un despliegue real
                # (netifaces2 instalado), aunque sí funcionaba en los tests
                # (que mockean netifaces con la clave clásica "netmask").
                netmask = addr.get("netmask") or addr.get("mask")
                if not ip or not netmask:
                    continue
                if family == netifaces.AF_INET6 and "%" in ip:
                    # netifaces incluye el scope id en direcciones IPv6
                    # link-local (p. ej. "fe80::1%eth0"); ipaddress no lo acepta.
                    ip = ip.split("%", 1)[0]
                subnet = _make_subnet(ip, netmask, "direct", interface=iface)
                if subnet is not None:
                    subnets[subnet.key] = subnet

    return list(subnets.values())


def discover_routed_networks(local_networks: list[Subnet] | None = None) -> list[Subnet]:
    """Redes no conectadas directamente pero alcanzables vía un gateway.

    Requiere pyroute2 (Linux). Filtra las rutas que ya coinciden con una
    red directamente conectada, para no duplicar información.
    """
    if not _PYROUTE2_AVAILABLE:
        logger.debug("pyroute2 no disponible (¿no estás en Linux?); se omite la tabla de rutas")
        return []

    local_cidrs = [s.network for s in (local_networks or [])]
    subnets: dict[str, Subnet] = {}

    try:
        with IPRoute() as ipr:
            for family in (2, 10):  # AF_INET, AF_INET6
                for route in ipr.get_routes(family=family):
                    if route.get("type") != RTN_UNICAST:
                        continue  # descarta entradas RTN_LOCAL/RTN_BROADCAST del kernel

                    dst = route.get_attr("RTA_DST")
                    dst_len = route.get("dst_len")
                    gateway = route.get_attr("RTA_GATEWAY")

                    if not dst or dst_len is None or dst_len == 0:
                        continue  # sin RTA_DST es la ruta por defecto

                    try:
                        network = ipaddress.ip_network(f"{dst}/{dst_len}", strict=False)
                    except ValueError:
                        continue

                    if any(
                        local.version == network.version
                        and (network.subnet_of(local) or network == local)
                        for local in local_cidrs
                    ):
                        continue

                    subnet = Subnet(cidr=str(network), discovery_method="route", gateway=gateway)
                    subnets[subnet.key] = subnet
    except Exception:
        logger.exception("Error leyendo la tabla de rutas del sistema")

    return list(subnets.values())


def _parse_snmp_netmask_walk(var_binds_iter) -> list[Subnet]:
    """Convierte las filas de ipAddrTable.ipAdEntNetMask en Subnet.

    Separado de la I/O de red para poder testear el parseo con datos
    sintéticos, sin necesitar un agente SNMP real.
    """
    subnets: dict[str, Subnet] = {}
    prefix = IP_ADDR_TABLE_NETMASK_OID + "."
    for oid, value in var_binds_iter:
        oid_str = str(oid)
        if not oid_str.startswith(prefix):
            continue
        ip = oid_str[len(prefix):]
        netmask = str(value)
        subnet = _make_subnet(ip, netmask, "router")
        if subnet is not None:
            subnets[subnet.key] = subnet
    return list(subnets.values())


async def discover_router_networks_async(
    router_ip: str, community: str = "public", timeout: int = 2
) -> list[Subnet]:
    """Consulta SNMP (GETNEXT sobre ipAddrTable) a un router/switch gestionable."""
    if not _PYSNMP_AVAILABLE:
        logger.debug("pysnmp no disponible; se omite el descubrimiento vía SNMP")
        return []

    subnets: list[Subnet] = []
    try:
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (router_ip, 161), timeout=timeout, retries=1
        )
        all_binds = []
        async for error_indication, error_status, _error_index, var_binds in walk_cmd(
            engine,
            CommunityData(community, mpModel=0),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(IP_ADDR_TABLE_NETMASK_OID)),
        ):
            if error_indication:
                logger.warning("SNMP a %s: %s", router_ip, error_indication)
                break
            if error_status:
                logger.warning("SNMP a %s: %s", router_ip, error_status.prettyPrint())
                break
            all_binds.extend(var_binds)
        subnets = _parse_snmp_netmask_walk(all_binds)
    except Exception:
        logger.exception("Error consultando SNMP a %s", router_ip)

    return subnets


def discover_router_networks(
    router_ip: str, community: str = "public", timeout: int = 2
) -> list[Subnet]:
    """Versión síncrona de `discover_router_networks_async`, para llamadores no-async."""
    return asyncio.run(discover_router_networks_async(router_ip, community, timeout))


def discover_networks(
    router_ip: str | None = None,
    snmp_enabled: bool = False,
    snmp_community: str = "public",
    snmp_timeout: int = 2,
) -> list[Subnet]:
    """Combina las tres fuentes en una lista única de subredes conocidas.

    Prioridad cuando coincide el mismo CIDR: SNMP > interfaz local > tabla
    de rutas (se procesan en ese orden, y el último en escribir gana).
    """
    local = discover_local_networks()
    routed = discover_routed_networks(local)

    router_nets: list[Subnet] = []
    if snmp_enabled and router_ip:
        router_nets = discover_router_networks(router_ip, snmp_community, snmp_timeout)

    merged: dict[str, Subnet] = {}
    for group in (routed, local, router_nets):
        for subnet in group:
            merged[subnet.key] = subnet

    return list(merged.values())


if __name__ == "__main__":
    # Paso de validación manual (ver "Pasos a seguir para ejecutarlo" en el
    # README): imprime las subredes detectadas y si están autorizadas para
    # escaneo activo, antes de lanzar el pipeline completo.
    import sys as _sys
    from pathlib import Path as _Path

    _REPO_ROOT = _Path(__file__).resolve().parent.parent
    if str(_REPO_ROOT) not in _sys.path:
        _sys.path.insert(0, str(_REPO_ROOT))

    from common.config import settings  # noqa: E402

    detected = discover_networks(
        router_ip=settings.gateway_ip or None,
        snmp_enabled=settings.snmp_enabled,
        snmp_community=settings.snmp_community,
        snmp_timeout=settings.snmp_timeout_seconds,
    )

    print(f"{len(detected)} subred(es) detectada(s):\n")
    for net in detected:
        allowed = settings.is_network_allowed(net.network)
        flag = "ESCANEABLE" if allowed else "solo conocida (no en ALLOWED_NETWORKS)"
        print(
            f"  {net.cidr:20s} método={net.discovery_method:8s} "
            f"interfaz={net.interface or '-':10s} gateway={net.gateway or '-':16s} [{flag}]"
        )
