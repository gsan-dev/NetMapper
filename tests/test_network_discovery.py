"""Pruebas del descubrimiento de redes (Fase 0)."""
from unittest.mock import MagicMock, patch

import network_discovery as nd


class FakeRoute(dict):
    """Imita un netlink route record de pyroute2: dict + .get_attr()."""

    def __init__(self, dst_len, attrs):
        super().__init__(dst_len=dst_len)
        self._attrs = attrs

    def get_attr(self, name):
        return self._attrs.get(name)


def test_discover_local_networks_derives_cidr_from_interfaces():
    fake_interfaces = ["lo", "eth0", "wlan0"]

    def fake_ifaddresses(iface):
        if iface == "lo":
            return {nd.netifaces.AF_INET: [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}]}
        if iface == "eth0":
            return {nd.netifaces.AF_INET: [{"addr": "192.168.1.50", "netmask": "255.255.255.0"}]}
        return {}

    with patch.object(nd, "_NETIFACES_AVAILABLE", True), patch.object(
        nd.netifaces, "interfaces", return_value=fake_interfaces
    ), patch.object(nd.netifaces, "ifaddresses", side_effect=fake_ifaddresses):
        subnets = nd.discover_local_networks()

    assert len(subnets) == 1
    assert subnets[0].cidr == "192.168.1.0/24"
    assert subnets[0].discovery_method == "direct"
    assert subnets[0].interface == "eth0"


def test_discover_local_networks_returns_empty_without_netifaces():
    with patch.object(nd, "_NETIFACES_AVAILABLE", False):
        assert nd.discover_local_networks() == []


def test_discover_routed_networks_skips_default_route_and_local_overlap():
    local = [nd.Subnet(cidr="192.168.1.0/24", discovery_method="direct")]

    routes = [
        FakeRoute(dst_len=0, attrs={}),  # ruta por defecto, se ignora
        FakeRoute(
            dst_len=24, attrs={"RTA_DST": "192.168.1.0", "RTA_GATEWAY": "192.168.1.1"}
        ),  # coincide con una red local, se ignora
        FakeRoute(
            dst_len=24, attrs={"RTA_DST": "10.0.0.0", "RTA_GATEWAY": "192.168.1.1"}
        ),  # red remota nueva
    ]

    mock_ipr = MagicMock()
    mock_ipr.get_routes.return_value = routes
    mock_ipr.__enter__.return_value = mock_ipr
    mock_ipr.__exit__.return_value = False

    with patch.object(nd, "_PYROUTE2_AVAILABLE", True), patch.object(
        nd, "IPRoute", return_value=mock_ipr
    ):
        subnets = nd.discover_routed_networks(local)

    assert len(subnets) == 1
    assert subnets[0].cidr == "10.0.0.0/24"
    assert subnets[0].discovery_method == "route"
    assert subnets[0].gateway == "192.168.1.1"


def test_discover_routed_networks_returns_empty_without_pyroute2():
    with patch.object(nd, "_PYROUTE2_AVAILABLE", False):
        assert nd.discover_routed_networks([]) == []


def test_parse_snmp_netmask_walk_builds_subnets():
    var_binds = [
        (f"{nd.IP_ADDR_TABLE_NETMASK_OID}.172.26.0.1", "255.255.0.0"),
        (f"{nd.IP_ADDR_TABLE_NETMASK_OID}.10.0.0.1", "255.255.255.0"),
        ("1.3.6.1.2.1.1.1.0", "some unrelated OID"),  # se ignora
    ]

    subnets = nd._parse_snmp_netmask_walk(var_binds)
    cidrs = {s.cidr for s in subnets}

    assert cidrs == {"172.26.0.0/16", "10.0.0.0/24"}
    assert all(s.discovery_method == "router" for s in subnets)


def test_discover_networks_merges_with_router_priority():
    local = [nd.Subnet(cidr="192.168.1.0/24", discovery_method="direct")]
    routed = [nd.Subnet(cidr="10.0.0.0/24", discovery_method="route")]
    router = [nd.Subnet(cidr="192.168.1.0/24", discovery_method="router")]

    with patch.object(nd, "discover_local_networks", return_value=local), patch.object(
        nd, "discover_routed_networks", return_value=routed
    ), patch.object(nd, "discover_router_networks", return_value=router):
        subnets = nd.discover_networks(
            router_ip="192.168.1.1", snmp_enabled=True, snmp_community="public"
        )

    by_cidr = {s.cidr: s for s in subnets}
    assert len(subnets) == 2
    assert by_cidr["192.168.1.0/24"].discovery_method == "router"  # gana SNMP
    assert by_cidr["10.0.0.0/24"].discovery_method == "route"


def test_discover_networks_skips_snmp_when_disabled():
    with patch.object(nd, "discover_local_networks", return_value=[]), patch.object(
        nd, "discover_routed_networks", return_value=[]
    ), patch.object(nd, "discover_router_networks") as mock_router:
        nd.discover_networks(router_ip="192.168.1.1", snmp_enabled=False)

    mock_router.assert_not_called()
