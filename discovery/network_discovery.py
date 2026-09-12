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


# ipAddrTable.ipAdEntNetMask — para cada IP configurada en el router, su máscara.
IP_ADDR_TABLE_NETMASK_OID = "1.3.6.1.2.1.4.20.1.3"


@dataclass(frozen=True)
class Subnet:
    cidr: str  # p.ej. "192.168.1.0/24", ya normalizado (bits de host a 0)
    discovery_method: str  # "direct" | "route" | "router"
    interface: str | None = None
    gateway: str | None = None

    @property
    def network(self) -> ipaddress.IPv4Network:
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
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    except ValueError:
        return None
    if network.is_loopback or network.is_link_local:
        return None
    return Subnet(cidr=str(network), discovery_method=method, **kwargs)


def discover_local_networks() -> list[Subnet]:
    """Redes directamente conectadas, derivadas de cada interfaz local."""
    if not _NETIFACES_AVAILABLE:
        logger.warning("netifaces no disponible; no se pueden enumerar interfaces locales")
        return []

    subnets: dict[str, Subnet] = {}
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for addr in addrs:
            ip, netmask = addr.get("addr"), addr.get("netmask")
            if not ip or not netmask:
                continue
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
            for route in ipr.get_routes(family=2):  # AF_INET
                dst = route.get_attr("RTA_DST")
                dst_len = route.get("dst_len")
                gateway = route.get_attr("RTA_GATEWAY")

                if not dst or dst_len is None or dst_len == 0:
                    continue  # sin RTA_DST es la ruta por defecto (0.0.0.0/0)

                try:
                    network = ipaddress.ip_network(f"{dst}/{dst_len}", strict=False)
                except ValueError:
                    continue

                if any(network.subnet_of(local) or network == local for local in local_cidrs):
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
