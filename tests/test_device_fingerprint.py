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
    ), patch.object(df, "grab_banners", return_value={445: "Samba 4.15"}) as mock_banners:
        profile = df.fingerprint_host(host, mdns_services_by_ip={"192.168.1.42": ["nas._smb._tcp.local."]})

    assert profile.mac == "00:11:32:aa:bb:cc"
    assert profile.vendor == "Synology Incorporated"
    assert profile.open_ports == {445, 5000}
    assert profile.device_type == "nas"
    assert profile.mdns_services == ["nas._smb._tcp.local."]
    assert profile.service_banners == {445: "Samba 4.15"}
    mock_banners.assert_called_once()


def test_fingerprint_host_skips_banner_grab_when_disabled():
    host = Host(ip="192.168.1.42", mac="00:11:32:aa:bb:cc", subnet_cidr="192.168.1.0/24", discovery_method="arp")

    with patch.object(df, "lookup_vendor", return_value=None), patch.object(
        df, "scan_ports", return_value={22}
    ), patch.object(df, "grab_banners") as mock_banners:
        profile = df.fingerprint_host(host, banner_grab_enabled=False)

    mock_banners.assert_not_called()
    assert profile.service_banners == {}


def test_parse_certificate_returns_expected_fields():
    fake_cert = MagicMock()
    fake_cert.subject.rfc4514_string.return_value = "CN=nas.local"
    fake_cert.issuer.rfc4514_string.return_value = "CN=nas.local"
    fake_cert.not_valid_after_utc = df.datetime(2099, 1, 1, tzinfo=df.timezone.utc)

    with patch.object(df, "_CRYPTOGRAPHY_AVAILABLE", True), patch.object(
        df, "x509", MagicMock(load_der_x509_certificate=MagicMock(return_value=fake_cert))
    ):
        result = df._parse_certificate(b"fake-der-bytes")

    assert result["subject"] == "CN=nas.local"
    assert result["issuer"] == "CN=nas.local"
    assert result["expired"] is False
    assert result["self_signed"] is True


def test_parse_certificate_returns_none_without_cryptography():
    with patch.object(df, "_CRYPTOGRAPHY_AVAILABLE", False):
        assert df._parse_certificate(b"fake-der-bytes") is None


@pytest.mark.asyncio
async def test_inspect_tls_returns_none_on_connection_failure():
    with patch.object(
        df.asyncio, "open_connection", AsyncMock(side_effect=OSError())
    ):
        assert await df._inspect_tls("10.0.0.5", 443, timeout=1) is None


@pytest.mark.asyncio
async def test_inspect_tls_parses_peer_certificate():
    mock_writer = MagicMock()
    mock_ssl_object = MagicMock()
    mock_ssl_object.getpeercert.return_value = b"fake-der-bytes"
    mock_writer.get_extra_info.return_value = mock_ssl_object

    with patch.object(
        df.asyncio, "open_connection", AsyncMock(return_value=(MagicMock(), mock_writer))
    ), patch.object(df, "_parse_certificate", return_value={"subject": "CN=nas.local"}):
        result = await df._inspect_tls("10.0.0.5", 443, timeout=1)

    assert result == {"subject": "CN=nas.local"}


@pytest.mark.asyncio
async def test_inspect_tls_certificates_async_returns_only_parsed():
    async def fake_inspect(ip, port, timeout):
        return {"subject": "CN=x"} if port == 443 else None

    with patch.object(df, "_inspect_tls", fake_inspect):
        result = await df.inspect_tls_certificates_async("10.0.0.5", {443, 8443})

    assert result == {443: {"subject": "CN=x"}}


def test_fingerprint_host_inspects_tls_when_port_open():
    host = Host(ip="192.168.1.7", mac="00:11:32:aa:bb:cc", subnet_cidr="192.168.1.0/24", discovery_method="arp")

    with patch.object(df, "lookup_vendor", return_value=None), patch.object(
        df, "scan_ports", return_value={443}
    ), patch.object(df, "grab_banners", return_value={}), patch.object(
        df, "inspect_tls_certificates", return_value={443: {"subject": "CN=nas.local"}}
    ) as mock_tls:
        profile = df.fingerprint_host(host)

    assert profile.tls_certificates == {443: {"subject": "CN=nas.local"}}
    mock_tls.assert_called_once_with("192.168.1.7", {443}, timeout=2.0)


def test_fingerprint_host_skips_tls_inspection_when_disabled():
    host = Host(ip="192.168.1.7", mac="00:11:32:aa:bb:cc", subnet_cidr="192.168.1.0/24", discovery_method="arp")

    with patch.object(df, "lookup_vendor", return_value=None), patch.object(
        df, "scan_ports", return_value={443}
    ), patch.object(df, "grab_banners", return_value={}), patch.object(
        df, "inspect_tls_certificates"
    ) as mock_tls:
        profile = df.fingerprint_host(host, tls_inspect_enabled=False)

    mock_tls.assert_not_called()
    assert profile.tls_certificates == {}


def test_fingerprint_host_uses_placeholder_mac_when_missing():
    host = Host(ip="10.0.0.9", mac=None, subnet_cidr="10.0.0.0/24", discovery_method="tcp_probe")

    with patch.object(df, "lookup_vendor", return_value=None), patch.object(
        df, "scan_ports", return_value=set()
    ):
        profile = df.fingerprint_host(host)

    assert profile.mac == "unknown-10.0.0.9"
    assert profile.device_type == "unknown"
