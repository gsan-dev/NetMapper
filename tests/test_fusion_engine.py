"""Pruebas del motor de fusión de datos multi-fuente (Fase 4)."""
from device_fingerprint import DeviceProfile
from fusion_engine import FusionEngine
from host_discovery import Host
from passive_capture import Edge


def _host(ip, mac, method="arp"):
    return Host(ip=ip, mac=mac, subnet_cidr="192.168.1.0/24", discovery_method=method)


def test_ingest_host_creates_device_with_ip_and_subnet():
    engine = FusionEngine()
    device = engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    assert device.mac == "aa:bb:cc:dd:ee:01"
    assert device.ips == {"192.168.1.10"}
    assert device.subnet_cidrs == {"192.168.1.0/24"}
    assert engine.ip_to_mac["192.168.1.10"] == "aa:bb:cc:dd:ee:01"


def test_ingest_host_without_mac_uses_ip_placeholder():
    engine = FusionEngine()
    device = engine.ingest_host(_host("10.0.0.9", None, method="tcp_probe"), "10.0.0.0/24")

    assert device.mac == "unknown-10.0.0.9"
    assert "10.0.0.9" in device.ips


def test_ip_reassigned_between_devices_on_dhcp_change():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:aa:aa:aa:aa:aa"), "192.168.1.0/24")
    engine.ingest_host(_host("192.168.1.10", "bb:bb:bb:bb:bb:bb"), "192.168.1.0/24")

    old_device = engine.devices["aa:aa:aa:aa:aa:aa"]
    new_device = engine.devices["bb:bb:bb:bb:bb:bb"]

    assert "192.168.1.10" not in old_device.ips
    assert "192.168.1.10" in new_device.ips
    assert engine.ip_to_mac["192.168.1.10"] == "bb:bb:bb:bb:bb:bb"


def test_ingest_fingerprint_enriches_existing_device():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    profile = DeviceProfile(
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.10",
        vendor="Synology Incorporated",
        open_ports={445, 5000},
        device_type="nas",
        mdns_services=["nas._smb._tcp.local."],
    )
    device = engine.ingest_fingerprint(profile)

    assert device.vendor == "Synology Incorporated"
    assert device.open_ports == {445, 5000}
    assert device.device_type == "nas"
    assert device.mdns_services == ["nas._smb._tcp.local."]


def test_ingest_fingerprint_creates_device_when_not_seen_before():
    engine = FusionEngine()
    profile = DeviceProfile(mac="cc:cc:cc:cc:cc:cc", ip="192.168.1.20")

    device = engine.ingest_fingerprint(profile)

    assert "cc:cc:cc:cc:cc:cc" in engine.devices
    assert device.ips == {"192.168.1.20"}


def test_ingest_edge_resolves_known_macs_and_keeps_unknown_ip_as_node():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    relation = engine.ingest_edge(
        Edge(src_ip="192.168.1.10", dst_ip="8.8.8.8", bytes_total=500, connections=3)
    )

    assert relation.src_mac == "aa:bb:cc:dd:ee:01"
    assert relation.dst_mac == "8.8.8.8"  # IP externa desconocida, se usa tal cual
    assert relation.bytes_total == 500
    assert relation.connections == 3


def test_ingest_edge_accumulates_across_multiple_calls():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")
    engine.ingest_host(_host("192.168.1.20", "bb:bb:bb:bb:bb:bb"), "192.168.1.0/24")

    edge = Edge(src_ip="192.168.1.10", dst_ip="192.168.1.20", bytes_total=100, connections=1)
    engine.ingest_edge(edge)
    engine.ingest_edge(edge)

    relation = engine.relations[("aa:bb:cc:dd:ee:01", "bb:bb:bb:bb:bb:bb")]
    assert relation.bytes_total == 200
    assert relation.connections == 2


def test_ingest_dns_queries_adds_to_known_device_only():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.ingest_dns_queries(
        {"192.168.1.10": {"example.com": 3}, "10.9.9.9": {"unknown.example": 1}}
    )

    device = engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.dns_queries == {"example.com": 3}
    # La IP desconocida no crea ningún dispositivo nuevo
    assert len(engine.devices) == 1


def test_prune_stale_devices_removes_old_devices_and_ip_mappings():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24", )
    engine.devices["aa:bb:cc:dd:ee:01"].last_seen = 1000.0

    removed = engine.prune_stale_devices(max_age_seconds=60, now=2000.0)

    assert removed == ["aa:bb:cc:dd:ee:01"]
    assert "aa:bb:cc:dd:ee:01" not in engine.devices
    assert "192.168.1.10" not in engine.ip_to_mac


def test_prune_stale_devices_keeps_recent_devices():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")
    engine.devices["aa:bb:cc:dd:ee:01"].last_seen = 1990.0

    removed = engine.prune_stale_devices(max_age_seconds=60, now=2000.0)

    assert removed == []
    assert "aa:bb:cc:dd:ee:01" in engine.devices


def test_snapshot_returns_devices_and_relations():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")
    engine.ingest_edge(Edge(src_ip="192.168.1.10", dst_ip="8.8.8.8", bytes_total=10, connections=1))

    devices, relations = engine.snapshot()

    assert len(devices) == 1
    assert len(relations) == 1
