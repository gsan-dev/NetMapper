"""Pruebas de common/config.py: parseo de listas de redes/MACs y la
comprobación de la lista blanca de redes autorizadas."""
import ipaddress

from common.config import Settings, _mac_set, _networks


def test_networks_parses_mixed_ipv4_and_ipv6(monkeypatch):
    monkeypatch.setenv("TEST_NETWORKS", "192.168.1.0/24, fe80::/10 , 10.0.0.0/24")
    networks = _networks("TEST_NETWORKS")

    cidrs = {str(n) for n in networks}
    assert cidrs == {"192.168.1.0/24", "fe80::/10", "10.0.0.0/24"}


def test_networks_skips_invalid_entries(monkeypatch):
    monkeypatch.setenv("TEST_NETWORKS", "192.168.1.0/24,not-a-network")
    networks = _networks("TEST_NETWORKS")

    assert [str(n) for n in networks] == ["192.168.1.0/24"]


def test_mac_set_normalizes_case(monkeypatch):
    monkeypatch.setenv("TEST_MACS", "AA:BB:CC:DD:EE:01, aa:bb:cc:dd:ee:02")
    macs = _mac_set("TEST_MACS")

    assert macs == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}


def test_mac_set_empty_when_unset():
    assert _mac_set("TEST_MACS_NOT_SET") == set()


def _settings_with_networks(*cidrs):
    s = Settings()
    s.allowed_networks = [ipaddress.ip_network(c) for c in cidrs]
    return s


def test_is_network_allowed_matches_exact_and_subnet():
    settings = _settings_with_networks("192.168.1.0/24")

    assert settings.is_network_allowed(ipaddress.ip_network("192.168.1.0/24")) is True
    assert settings.is_network_allowed(ipaddress.ip_network("192.168.1.128/25")) is True
    assert settings.is_network_allowed(ipaddress.ip_network("192.168.2.0/24")) is False


def test_is_network_allowed_does_not_crash_on_version_mismatch():
    # Antes del fix, comparar una red IPv6 contra una whitelist solo-IPv4
    # lanzaba TypeError en subnet_of(); ahora simplemente no coincide.
    settings = _settings_with_networks("192.168.1.0/24")

    assert settings.is_network_allowed(ipaddress.ip_network("fe80::/64")) is False


def test_is_network_allowed_matches_ipv6_entries():
    settings = _settings_with_networks("2001:db8::/32")

    assert settings.is_network_allowed(ipaddress.ip_network("2001:db8:1::/48")) is True
    assert settings.is_network_allowed(ipaddress.ip_network("2001:dead::/32")) is False
