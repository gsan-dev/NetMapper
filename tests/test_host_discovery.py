"""Pruebas del descubrimiento de hosts (Fase 1)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from scapy.all import Ether as ScapyEther
from scapy.all import ICMPv6EchoReply
from scapy.all import IPv6 as ScapyIPv6

import host_discovery as hd
from network_discovery import Subnet


def _subnet(cidr="192.168.1.0/24", method="direct", interface="eth0"):
    return Subnet(cidr=cidr, discovery_method=method, interface=interface)


def test_arp_scan_returns_hosts_from_answered_pairs():
    received1 = MagicMock(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")
    received2 = MagicMock(psrc="192.168.1.11", hwsrc="aa:bb:cc:dd:ee:02")
    answered = [(MagicMock(), received1), (MagicMock(), received2)]

    with patch.object(hd, "_SCAPY_AVAILABLE", True), patch.object(
        hd, "srp", return_value=(answered, [])
    ):
        hosts = hd.arp_scan(_subnet(), timeout=1)

    assert len(hosts) == 2
    assert {h.ip for h in hosts} == {"192.168.1.10", "192.168.1.11"}
    assert all(h.discovery_method == "arp" for h in hosts)


def test_arp_scan_returns_empty_without_scapy():
    with patch.object(hd, "_SCAPY_AVAILABLE", False):
        assert hd.arp_scan(_subnet()) == []


def test_arp_scan_handles_exceptions_gracefully():
    with patch.object(hd, "_SCAPY_AVAILABLE", True), patch.object(
        hd, "srp", side_effect=OSError("no such device")
    ):
        assert hd.arp_scan(_subnet()) == []


def test_ndp_scan_returns_hosts_from_answered_pairs():
    received1 = (
        ScapyEther(src="aa:bb:cc:dd:ee:01")
        / ScapyIPv6(src="2001:db8::10", dst="2001:db8::1")
        / ICMPv6EchoReply()
    )
    received2 = (
        ScapyEther(src="aa:bb:cc:dd:ee:02")
        / ScapyIPv6(src="2001:db8::11", dst="2001:db8::1")
        / ICMPv6EchoReply()
    )
    answered = [(MagicMock(), received1), (MagicMock(), received2)]

    with patch.object(hd, "_SCAPY_AVAILABLE", True), patch.object(
        hd, "sr", return_value=(answered, [])
    ):
        hosts = hd.ndp_scan(_subnet(cidr="2001:db8::/64"), timeout=1)

    assert len(hosts) == 2
    assert {h.ip for h in hosts} == {"2001:db8::10", "2001:db8::11"}
    assert {h.mac for h in hosts} == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}
    assert all(h.discovery_method == "ndp" for h in hosts)


def test_ndp_scan_returns_empty_without_scapy():
    with patch.object(hd, "_SCAPY_AVAILABLE", False):
        assert hd.ndp_scan(_subnet(cidr="2001:db8::/64")) == []


def test_ndp_scan_handles_exceptions_gracefully():
    with patch.object(hd, "_SCAPY_AVAILABLE", True), patch.object(
        hd, "sr", side_effect=OSError("no such device")
    ):
        assert hd.ndp_scan(_subnet(cidr="2001:db8::/64")) == []


def test_discover_hosts_uses_ndp_for_direct_ipv6_networks():
    with patch.object(hd, "ndp_scan", return_value=["fake"]) as mock_ndp, patch.object(
        hd, "arp_scan"
    ) as mock_arp:
        result = hd.discover_hosts(_subnet(cidr="2001:db8::/64", method="direct"))

    assert result == ["fake"]
    mock_ndp.assert_called_once()
    mock_arp.assert_not_called()


@pytest.mark.asyncio
async def test_probe_host_true_on_successful_connection():
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch.object(
        hd.asyncio, "open_connection", AsyncMock(return_value=(MagicMock(), mock_writer))
    ):
        alive = await hd._probe_host("10.0.0.5", (80,), timeout=1)

    assert alive is True
    mock_writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_probe_host_true_on_connection_refused():
    with patch.object(
        hd.asyncio, "open_connection", AsyncMock(side_effect=ConnectionRefusedError())
    ):
        alive = await hd._probe_host("10.0.0.5", (80,), timeout=1)

    assert alive is True


@pytest.mark.asyncio
async def test_probe_host_false_when_all_ports_timeout():
    with patch.object(
        hd.asyncio, "open_connection", AsyncMock(side_effect=TimeoutError())
    ):
        alive = await hd._probe_host("10.0.0.5", (80, 443), timeout=1)

    assert alive is False


@pytest.mark.asyncio
async def test_tcp_probe_sweep_skips_huge_subnets():
    huge_subnet = _subnet(cidr="10.0.0.0/16", method="route")

    with patch.object(hd, "_probe_host", AsyncMock(return_value=True)) as mock_probe:
        hosts = await hd.tcp_probe_sweep_async(huge_subnet)

    assert hosts == []
    mock_probe.assert_not_called()


@pytest.mark.asyncio
async def test_tcp_probe_sweep_returns_only_alive_hosts():
    subnet = _subnet(cidr="10.0.0.0/29", method="route")  # 6 hosts útiles

    async def fake_probe(ip, ports, timeout):
        return ip.endswith(".2") or ip.endswith(".5")

    with patch.object(hd, "_probe_host", fake_probe):
        hosts = await hd.tcp_probe_sweep_async(subnet, timeout=0.1, concurrency=10)

    ips = {h.ip for h in hosts}
    assert ips == {"10.0.0.2", "10.0.0.5"}
    assert all(h.discovery_method == "tcp_probe" and h.mac is None for h in hosts)


def test_discover_hosts_uses_arp_for_direct_networks():
    with patch.object(hd, "arp_scan", return_value=["fake"]) as mock_arp, patch.object(
        hd, "tcp_probe_sweep"
    ) as mock_tcp:
        result = hd.discover_hosts(_subnet(method="direct"))

    assert result == ["fake"]
    mock_arp.assert_called_once()
    mock_tcp.assert_not_called()


def test_discover_hosts_uses_tcp_probe_for_remote_networks():
    with patch.object(hd, "arp_scan") as mock_arp, patch.object(
        hd, "tcp_probe_sweep", return_value=["fake"]
    ) as mock_tcp:
        result = hd.discover_hosts(_subnet(method="route"))

    assert result == ["fake"]
    mock_tcp.assert_called_once()
    mock_arp.assert_not_called()
