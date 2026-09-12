"""Pruebas del motor de fusión de datos multi-fuente (Fase 4)."""
from dataclasses import dataclass

from device_fingerprint import DeviceProfile
from fusion_engine import FusionEngine
from host_discovery import Host
from passive_capture import Edge


def _host(ip, mac, method="arp"):
    return Host(ip=ip, mac=mac, subnet_cidr="192.168.1.0/24", discovery_method=method)


@dataclass(frozen=True)
class _FakeAlert:
    alert_id: int
    source_ip: str
    severity: str
    reason: str
    created_at: float = 0.0


def test_ingest_host_creates_device_with_ip_and_subnet():
    engine = FusionEngine()
    device = engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    assert device.mac == "aa:bb:cc:dd:ee:01"
    assert device.ips == {"192.168.1.10"}
    assert device.subnet_cidrs == {"192.168.1.0/24"}
    assert engine.ip_to_mac["192.168.1.10"] == "aa:bb:cc:dd:ee:01"
    assert device.is_authorized is True  # sin whitelist configurada, todo se asume autorizado
    assert device.to_dict()["is_authorized"] is True


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


def test_ingest_fingerprint_merges_banners_and_tls_certificates():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    profile = DeviceProfile(
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.10",
        service_banners={22: "SSH-2.0-OpenSSH_8.9p1"},
        tls_certificates={443: {"subject": "CN=nas.local", "expired": False}},
    )
    device = engine.ingest_fingerprint(profile)

    assert device.service_banners == {22: "SSH-2.0-OpenSSH_8.9p1"}
    assert device.tls_certificates == {443: {"subject": "CN=nas.local", "expired": False}}
    assert device.to_dict()["service_banners"] == {22: "SSH-2.0-OpenSSH_8.9p1"}


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


def test_device_defaults_to_no_security_alerts():
    engine = FusionEngine()
    device = engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    assert device.security_alert_count == 0
    assert device.security_max_severity == "none"
    assert device.to_dict()["security_max_severity"] == "none"


def test_apply_security_alerts_resolves_to_known_device():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.apply_security_alerts(
        [_FakeAlert(alert_id=1, source_ip="192.168.1.10", severity="high", reason="port scan")]
    )

    device = engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.security_alert_count == 1
    assert device.security_max_severity == "high"
    assert device.security_last_reason == "port scan"


def test_apply_security_alerts_ignores_unknown_ips():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.apply_security_alerts(
        [_FakeAlert(alert_id=1, source_ip="10.9.9.9", severity="high", reason="unknown host")]
    )

    assert len(engine.devices) == 1  # no se crea un dispositivo fantasma
    assert engine.devices["aa:bb:cc:dd:ee:01"].security_alert_count == 0


def test_apply_arp_spoof_alert_flags_both_devices():
    from passive_capture import ArpSpoofAlert

    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")
    engine.ingest_host(_host("192.168.1.20", "ff:ff:ff:ff:ff:ff"), "192.168.1.0/24")

    engine.apply_arp_spoof_alert(
        ArpSpoofAlert(
            ip="192.168.1.10", known_mac="aa:bb:cc:dd:ee:01", new_mac="ff:ff:ff:ff:ff:ff", detected_at=1.0
        )
    )

    known = engine.devices["aa:bb:cc:dd:ee:01"]
    new = engine.devices["ff:ff:ff:ff:ff:ff"]
    assert known.security_alert_count == 1
    assert known.security_max_severity == "high"
    assert known.security_alert_source == "local-arp"
    assert new.security_alert_count == 1
    assert new.security_max_severity == "high"
    assert new.security_alert_source == "local-arp"
    assert "192.168.1.10" in known.security_last_reason


def test_apply_arp_spoof_alert_ignores_unknown_macs():
    from passive_capture import ArpSpoofAlert

    engine = FusionEngine()
    engine.apply_arp_spoof_alert(
        ArpSpoofAlert(ip="10.0.0.5", known_mac="aa:aa:aa:aa:aa:aa", new_mac="bb:bb:bb:bb:bb:bb")
    )

    assert len(engine.devices) == 0


def test_apply_lldp_neighbors_enriches_known_device():
    from passive_capture import LldpNeighbor

    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.1", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.apply_lldp_neighbors(
        [LldpNeighbor(mac="aa:bb:cc:dd:ee:01", chassis_id="aa:bb:cc:dd:ee:01", port_id="Gi0/1", system_name="switch01")]
    )

    device = engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.physical_neighbor == {
        "chassis_id": "aa:bb:cc:dd:ee:01",
        "port_id": "Gi0/1",
        "system_name": "switch01",
    }
    assert device.to_dict()["physical_neighbor"]["system_name"] == "switch01"


def test_apply_lldp_neighbors_ignores_unknown_macs():
    from passive_capture import LldpNeighbor

    engine = FusionEngine()
    engine.apply_lldp_neighbors(
        [LldpNeighbor(mac="zz:zz:zz:zz:zz:zz", chassis_id=None, port_id=None, system_name=None)]
    )

    assert len(engine.devices) == 0


def test_apply_security_alerts_sets_netguardian_source():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.apply_security_alerts(
        [_FakeAlert(alert_id=1, source_ip="192.168.1.10", severity="high", reason="port scan")]
    )

    assert engine.devices["aa:bb:cc:dd:ee:01"].security_alert_source == "netguardian"


def test_set_cve_findings_replaces_previous_findings():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.set_cve_findings(
        "aa:bb:cc:dd:ee:01", {22: [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}]}
    )
    device = engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.cve_findings == {22: [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}]}

    engine.set_cve_findings("aa:bb:cc:dd:ee:01", {})
    assert engine.devices["aa:bb:cc:dd:ee:01"].cve_findings == {}


def test_set_cve_findings_ignores_unknown_mac():
    engine = FusionEngine()
    engine.set_cve_findings("unknown-mac", {22: [{"cve_id": "CVE-2023-1"}]})
    assert "unknown-mac" not in engine.devices


def test_apply_security_alerts_keeps_max_severity_across_multiple_alerts():
    engine = FusionEngine()
    engine.ingest_host(_host("192.168.1.10", "aa:bb:cc:dd:ee:01"), "192.168.1.0/24")

    engine.apply_security_alerts(
        [
            _FakeAlert(alert_id=1, source_ip="192.168.1.10", severity="medium", reason="a"),
            _FakeAlert(alert_id=2, source_ip="192.168.1.10", severity="low", reason="b"),
        ]
    )

    device = engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.security_alert_count == 2
    assert device.security_max_severity == "medium"  # no baja aunque llegue una de menor severidad
    assert device.security_last_reason == "b"  # pero el motivo sí se actualiza al más reciente
