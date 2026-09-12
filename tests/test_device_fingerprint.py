"""Pruebas de la caracterización de dispositivos (Fase 2)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import device_fingerprint as df
from host_discovery import Host


def test_lookup_vendor_uses_mac_parser():
    fake_parser = MagicMock()
    fake_parser.get_manuf_long.return_value = "Synology Incorporated"

    with patch.object(df, "_MANUF_AVAILABLE", True), patch.object(
        df, "_mac_parser", fake_parser
    ):
        vendor = df.lookup_vendor("00:11:32:aa:bb:cc")

    assert vendor == "Synology Incorporated"


def test_lookup_vendor_falls_back_to_short_name():
    fake_parser = MagicMock()
    fake_parser.get_manuf_long.return_value = None
    fake_parser.get_manuf.return_value = "Synology"

    with patch.object(df, "_MANUF_AVAILABLE", True), patch.object(
        df, "_mac_parser", fake_parser
    ):
        vendor = df.lookup_vendor("00:11:32:aa:bb:cc")

    assert vendor == "Synology"


def test_lookup_vendor_returns_none_without_manuf():
    with patch.object(df, "_MANUF_AVAILABLE", False):
        assert df.lookup_vendor("00:11:32:aa:bb:cc") is None


def test_lookup_vendor_returns_none_without_mac():
    assert df.lookup_vendor(None) is None


@pytest.mark.asyncio
async def test_scan_port_true_on_open_port():
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch.object(
        df.asyncio, "open_connection", AsyncMock(return_value=(MagicMock(), mock_writer))
    ):
        assert await df._scan_port("10.0.0.5", 80, timeout=1) is True


@pytest.mark.asyncio
async def test_scan_port_false_on_refused_or_timeout():
    with patch.object(
        df.asyncio, "open_connection", AsyncMock(side_effect=ConnectionRefusedError())
    ):
        assert await df._scan_port("10.0.0.5", 80, timeout=1) is False

    with patch.object(df.asyncio, "open_connection", AsyncMock(side_effect=TimeoutError())):
        assert await df._scan_port("10.0.0.5", 80, timeout=1) is False


@pytest.mark.asyncio
async def test_scan_ports_async_returns_only_open_ports():
    async def fake_scan(ip, port, timeout):
        return port in (80, 443)

    with patch.object(df, "_scan_port", fake_scan):
        open_ports = await df.scan_ports_async("10.0.0.5", ports=(22, 80, 443, 9100))

    assert open_ports == {80, 443}


def test_mdns_collector_parses_ipv4_addresses():
    collector = df._MdnsCollector()
    fake_info = MagicMock(addresses=[bytes([192, 168, 1, 42])])
    fake_zc = MagicMock()
    fake_zc.get_service_info.return_value = fake_info

    collector.add_service(fake_zc, "_http._tcp.local.", "printer._http._tcp.local.")

    assert collector.services_by_ip == {"192.168.1.42": ["printer._http._tcp.local."]}


def test_mdns_collector_ignores_service_without_info():
    collector = df._MdnsCollector()
    fake_zc = MagicMock()
    fake_zc.get_service_info.return_value = None

    collector.add_service(fake_zc, "_http._tcp.local.", "phantom")

    assert collector.services_by_ip == {}


def test_listen_mdns_returns_empty_without_zeroconf():
    with patch.object(df, "_ZEROCONF_AVAILABLE", False):
        assert df.listen_mdns(duration_seconds=0) == {}


def test_fingerprint_host_combines_all_signals():
    host = Host(ip="192.168.1.42", mac="00:11:32:aa:bb:cc", subnet_cidr="192.168.1.0/24", discovery_method="arp")

    with patch.object(df, "lookup_vendor", return_value="Synology Incorporated"), patch.object(
        df, "scan_ports", return_value={445, 5000}
    ):
        profile = df.fingerprint_host(host, mdns_services_by_ip={"192.168.1.42": ["nas._smb._tcp.local."]})

    assert profile.mac == "00:11:32:aa:bb:cc"
    assert profile.vendor == "Synology Incorporated"
    assert profile.open_ports == {445, 5000}
    assert profile.device_type == "nas"
    assert profile.mdns_services == ["nas._smb._tcp.local."]


def test_fingerprint_host_uses_placeholder_mac_when_missing():
    host = Host(ip="10.0.0.9", mac=None, subnet_cidr="10.0.0.0/24", discovery_method="tcp_probe")

    with patch.object(df, "lookup_vendor", return_value=None), patch.object(
        df, "scan_ports", return_value=set()
    ):
        profile = df.fingerprint_host(host)

    assert profile.mac == "unknown-10.0.0.9"
    assert profile.device_type == "unknown"
