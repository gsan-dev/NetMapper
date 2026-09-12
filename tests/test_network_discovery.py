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


def test_make_subnet_converts_full_ipv6_netmask_notation():
    # ipaddress.ip_network no acepta "direccion/ffff:ffff:ffff:ffff::" para
    # IPv6 (solo para IPv4) — pero así es como netifaces da la máscara.
    subnet = nd._make_subnet("2001:db8::10", "ffff:ffff:ffff:ffff::", "direct")
    assert subnet is not None
    assert subnet.cidr == "2001:db8::/64"


def test_make_subnet_accepts_plain_ipv6_prefix_length_too():
    subnet = nd._make_subnet("2001:db8::10", "64", "direct")
    assert subnet is not None
    assert subnet.cidr == "2001:db8::/64"


def test_discover_local_networks_returns_empty_without_netifaces():
    with patch.object(nd, "_NETIFACES_AVAILABLE", False):
        assert nd.discover_local_networks() == []


def test_discover_local_networks_includes_ipv6_and_strips_scope_id():
    fake_interfaces = ["eth0"]

    def fake_ifaddresses(iface):
        return {
            nd.netifaces.AF_INET: [{"addr": "192.168.1.50", "netmask": "255.255.255.0"}],
            nd.netifaces.AF_INET6: [
                {"addr": "2001:db8::10", "netmask": "ffff:ffff:ffff:ffff::"},
                # link-local con scope id, como lo devuelve netifaces de verdad;
                # debe descartarse por ser link-local, no solo por el "%eth0".
                {"addr": "fe80::1%eth0", "netmask": "ffff:ffff:ffff:ffff::"},
            ],
        }

    with patch.object(nd, "_NETIFACES_AVAILABLE", True), patch.object(
        nd.netifaces, "interfaces", return_value=fake_interfaces
    ), patch.object(nd.netifaces, "ifaddresses", side_effect=fake_ifaddresses):
        subnets = nd.discover_local_networks()

    cidrs = {s.cidr for s in subnets}
    assert "192.168.1.0/24" in cidrs
    assert "2001:db8::/64" in cidrs
    assert not any(c.startswith("fe80") for c in cidrs)


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


def test_discover_routed_networks_includes_ipv6_family_routes():
    def fake_get_routes(family):
        if family == 10:  # AF_INET6
            return [
                FakeRoute(
                    dst_len=32, attrs={"RTA_DST": "2001:db8:1::", "RTA_GATEWAY": "fe80::1"}
                )
            ]
        return []

    mock_ipr = MagicMock()
    mock_ipr.get_routes.side_effect = fake_get_routes
    mock_ipr.__enter__.return_value = mock_ipr
    mock_ipr.__exit__.return_value = False

    with patch.object(nd, "_PYROUTE2_AVAILABLE", True), patch.object(
        nd, "IPRoute", return_value=mock_ipr
    ):
        subnets = nd.discover_routed_networks([])

    assert len(subnets) == 1
    # /32 enmascara todo salvo los primeros 32 bits: 2001:db8:1:: -> 2001:db8::/32
    assert subnets[0].cidr == "2001:db8::/32"
    assert subnets[0].gateway == "fe80::1"


def test_discover_routed_networks_does_not_crash_comparing_ipv6_route_to_ipv4_local():
    local = [nd.Subnet(cidr="192.168.1.0/24", discovery_method="direct")]

    def fake_get_routes(family):
        if family == 10:
            return [FakeRoute(dst_len=32, attrs={"RTA_DST": "2001:db8::", "RTA_GATEWAY": None})]
        return []

    mock_ipr = MagicMock()
    mock_ipr.get_routes.side_effect = fake_get_routes
    mock_ipr.__enter__.return_value = mock_ipr
    mock_ipr.__exit__.return_value = False

    with patch.object(nd, "_PYROUTE2_AVAILABLE", True), patch.object(
        nd, "IPRoute", return_value=mock_ipr
    ):
        subnets = nd.discover_routed_networks(local)

    assert len(subnets) == 1
    assert subnets[0].cidr == "2001:db8::/32"


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
