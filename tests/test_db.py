"""Pruebas de la capa de persistencia SQLite."""
import time

import pytest

from common.db import Neo4jRepository, SQLiteRepository


@pytest.fixture
def repo(tmp_path):
    r = SQLiteRepository(tmp_path / "test.db")
    r.init_schema()
    return r


def _network(cidr="192.168.1.0/24", **overrides):
    data = {"cidr": cidr, "discovery_method": "direct", "interface": "eth0", "gateway": None}
    data.update(overrides)
    return data


def _device(mac="aa:bb:cc:dd:ee:01", **overrides):
    data = {
        "mac": mac,
        "ips": ["192.168.1.10"],
        "vendor": "Synology Incorporated",
        "device_type": "nas",
        "open_ports": [445, 5000],
        "mdns_services": ["nas._smb._tcp.local."],
        "dns_queries": {"example.com": 3},
        "subnet_cidrs": ["192.168.1.0/24"],
        "last_sensor_id": "default",
    }
    data.update(overrides)
    return data


def test_upsert_network_inserts_and_updates(repo):
    id1 = repo.upsert_network(_network())
    id2 = repo.upsert_network(_network(gateway="192.168.1.1"))

    assert id1 == id2
    networks = repo.list_networks()
    assert len(networks) == 1
    assert networks[0]["gateway"] == "192.168.1.1"


def test_upsert_device_round_trips_json_fields(repo):
    repo.upsert_device(_device())

    devices = repo.list_devices()
    assert len(devices) == 1
    device = devices[0]
    assert device["ips"] == ["192.168.1.10"]
    assert device["open_ports"] == [445, 5000]
    assert device["dns_queries"] == {"example.com": 3}
    assert device["vendor"] == "Synology Incorporated"
    assert device["active"] == 1
    assert device["is_authorized"] is True  # por defecto, sin whitelist configurada


def test_upsert_device_persists_unauthorized_flag(repo):
    repo.upsert_device(_device(is_authorized=False))

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["is_authorized"] is False

    # Una pasada posterior puede reautorizarlo si ya no está flaggeado
    repo.upsert_device(_device(is_authorized=True))
    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["is_authorized"] is True


def test_upsert_device_persists_security_alert_fields(repo):
    repo.upsert_device(
        _device(
            security_alert_count=3,
            security_max_severity="high",
            security_last_reason="port scan",
        )
    )

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["security_alert_count"] == 3
    assert device["security_max_severity"] == "high"
    assert device["security_last_reason"] == "port scan"


def test_upsert_device_defaults_security_fields_to_none_severity(repo):
    repo.upsert_device(_device())

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["security_alert_count"] == 0
    assert device["security_max_severity"] == "none"
    assert device["security_last_reason"] is None


def test_upsert_device_keeps_vendor_when_new_value_is_none(repo):
    repo.upsert_device(_device(vendor="Synology Incorporated"))
    repo.upsert_device(_device(vendor=None, ips=["192.168.1.11"]))

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["vendor"] == "Synology Incorporated"
    assert device["ips"] == ["192.168.1.11"]


def test_mark_stale_devices_inactive(repo):
    repo.upsert_device(_device(mac="aa:aa:aa:aa:aa:aa"))
    repo.upsert_device(_device(mac="bb:bb:bb:bb:bb:bb"))

    repo.mark_stale_devices_inactive({"aa:aa:aa:aa:aa:aa"}, sensor_id="default")

    active = {d["mac"] for d in repo.list_devices(active_only=True)}
    all_devices = {d["mac"] for d in repo.list_devices(active_only=False)}
    assert active == {"aa:aa:aa:aa:aa:aa"}
    assert all_devices == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}


def test_mark_stale_devices_inactive_only_affects_matching_sensor(repo):
    """Dos sensores distintos comparten la misma BD (segmentos/VLANs
    aislados) — el sensor A no debe poder marcar inactivo un dispositivo
    que solo ve el sensor B."""
    repo.upsert_device(_device(mac="aa:aa:aa:aa:aa:aa", last_sensor_id="sensor-a"))
    repo.upsert_device(_device(mac="bb:bb:bb:bb:bb:bb", last_sensor_id="sensor-b"))

    # sensor-a ya no ve a "aa..." en su pasada, pero eso no debe tocar a "bb..."
    repo.mark_stale_devices_inactive(set(), sensor_id="sensor-a")

    active = {d["mac"] for d in repo.list_devices(active_only=True)}
    assert active == {"bb:bb:bb:bb:bb:bb"}


def test_upsert_device_round_trips_service_banners_tls_and_cve_findings(repo):
    repo.upsert_device(
        _device(
            service_banners={22: "SSH-2.0-OpenSSH_8.9p1"},
            tls_certificates={443: {"subject": "CN=nas.local", "expired": False}},
            cve_findings={22: [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}]},
        )
    )

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["service_banners"] == {22: "SSH-2.0-OpenSSH_8.9p1"}
    assert device["tls_certificates"] == {443: {"subject": "CN=nas.local", "expired": False}}
    assert device["cve_findings"] == {22: [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}]}


def test_upsert_device_defaults_new_json_fields_to_empty(repo):
    repo.upsert_device(_device())

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["service_banners"] == {}
    assert device["tls_certificates"] == {}
    assert device["cve_findings"] == {}


def test_upsert_device_persists_last_sensor_id(repo):
    repo.upsert_device(_device(last_sensor_id="sensor-a"))
    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["last_sensor_id"] == "sensor-a"


def test_get_device_by_mac_returns_none_when_missing(repo):
    assert repo.get_device_by_mac("zz:zz:zz:zz:zz:zz") is None


def test_get_device_history_reconstructs_from_snapshots(repo):
    mac = "aa:bb:cc:dd:ee:01"
    other_mac = "aa:bb:cc:dd:ee:02"

    repo.insert_graph_snapshot(
        {
            "created_at": 1000.0,
            "node_count": 1,
            "edge_count": 0,
            "communities": {},
            "centrality": {},
            "layers": {},
            "devices": [{"mac": mac, "device_type": "unknown", "vendor": None}],
            "relations": [],
        }
    )
    repo.insert_graph_snapshot(
        {
            "created_at": 2000.0,
            "node_count": 2,
            "edge_count": 0,
            "communities": {},
            "centrality": {},
            "layers": {},
            # el dispositivo cambia de tipo (fingerprint más preciso con el tiempo)
            # y aparece uno nuevo que no debe colarse en el histórico del primero
            "devices": [
                {"mac": mac, "device_type": "nas", "vendor": "Synology Incorporated"},
                {"mac": other_mac, "device_type": "printer", "vendor": "Canon"},
            ],
            "relations": [],
        }
    )

    history = repo.get_device_history(mac)

    assert len(history) == 2
    assert history[0]["created_at"] == 1000.0
    assert history[0]["device_type"] == "unknown"
    assert history[1]["created_at"] == 2000.0
    assert history[1]["device_type"] == "nas"
    assert history[1]["vendor"] == "Synology Incorporated"
    assert all(h["mac"] == mac for h in history)


def test_get_device_history_empty_when_never_seen(repo):
    assert repo.get_device_history("zz:zz:zz:zz:zz:zz") == []


def test_upsert_relation_replaces_totals_not_adds(repo):
    id1 = repo.upsert_relation(
        {"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02", "bytes_total": 100, "connections": 1}
    )
    id2 = repo.upsert_relation(
        {"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02", "bytes_total": 500, "connections": 4}
    )

    assert id1 == id2
    relations = repo.list_relations()
    assert len(relations) == 1
    assert relations[0]["bytes_total"] == 500
    assert relations[0]["connections"] == 4


def test_insert_and_list_graph_snapshots(repo):
    repo.insert_graph_snapshot(
        {
            "created_at": time.time() - 10,
            "node_count": 2,
            "edge_count": 1,
            "communities": {"mac-1": 0, "mac-2": 0},
            "centrality": {"mac-1": 0.0, "mac-2": 0.0},
            "layers": {"mac-1": 0, "mac-2": 1},
            "devices": [{"mac": "mac-1"}, {"mac": "mac-2"}],
            "relations": [{"src_mac": "mac-1", "dst_mac": "mac-2", "bytes_total": 10, "connections": 1}],
        }
    )
    repo.insert_graph_snapshot(
        {
            "created_at": time.time(),
            "node_count": 3,
            "edge_count": 2,
            "communities": {},
            "centrality": {},
            "layers": {},
        }
    )

    snapshots = repo.list_graph_snapshots(limit=10)
    assert len(snapshots) == 2
    assert snapshots[0]["node_count"] == 2  # el más antiguo primero
    assert snapshots[1]["node_count"] == 3
    assert snapshots[0]["devices"] == [{"mac": "mac-1"}, {"mac": "mac-2"}]
    assert snapshots[0]["relations"][0]["bytes_total"] == 10

    latest = repo.get_latest_graph_snapshot()
    assert latest["node_count"] == 3
    assert latest["devices"] == []


def test_get_latest_graph_snapshot_returns_none_when_empty(repo):
    assert repo.get_latest_graph_snapshot() is None


def _snapshot(created_at, node_count=1):
    return {
        "created_at": created_at,
        "node_count": node_count,
        "edge_count": 0,
        "communities": {},
        "centrality": {},
        "layers": {},
        "devices": [],
        "relations": [],
    }


def test_prune_old_graph_snapshots_removes_only_old_ones(repo):
    now = time.time()
    repo.insert_graph_snapshot(_snapshot(now - 1000, node_count=1))
    repo.insert_graph_snapshot(_snapshot(now - 10, node_count=2))

    deleted = repo.prune_old_graph_snapshots(cutoff=now - 500)

    assert deleted == 1
    remaining = repo.list_graph_snapshots(limit=10)
    assert len(remaining) == 1
    assert remaining[0]["node_count"] == 2


def test_prune_old_graph_snapshots_always_keeps_the_latest(repo):
    now = time.time()
    # un único snapshot muy antiguo: no debe quedar la BD vacía de golpe
    repo.insert_graph_snapshot(_snapshot(now - 999999, node_count=1))

    deleted = repo.prune_old_graph_snapshots(cutoff=now)

    assert deleted == 0
    assert len(repo.list_graph_snapshots(limit=10)) == 1


def test_pipeline_status_starts_as_none(repo):
    assert repo.get_pipeline_status() is None


def test_record_discovery_and_analysis_pass(repo):
    repo.record_discovery_pass(1000.0)
    status = repo.get_pipeline_status()
    assert status["last_discovery_pass_at"] == 1000.0
    assert status["last_analysis_pass_at"] is None

    repo.record_analysis_pass(1005.0)
    status = repo.get_pipeline_status()
    assert status["last_discovery_pass_at"] == 1000.0
    assert status["last_analysis_pass_at"] == 1005.0

    # una segunda pasada actualiza en el sitio, no inserta una fila nueva
    repo.record_discovery_pass(2000.0)
    status = repo.get_pipeline_status()
    assert status["last_discovery_pass_at"] == 2000.0
    assert status["last_analysis_pass_at"] == 1005.0


def test_cve_cache_round_trip(repo):
    assert repo.get_cve_cache("openssh:8.9p1") is None

    repo.upsert_cve_cache(
        "openssh:8.9p1",
        [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}],
        checked_at=1000.0,
    )
    cached = repo.get_cve_cache("openssh:8.9p1")
    assert cached["cves"] == [{"cve_id": "CVE-2023-1", "severity": "high", "summary": "x"}]
    assert cached["checked_at"] == 1000.0

    # una segunda escritura actualiza en el sitio, no crea una fila nueva
    repo.upsert_cve_cache("openssh:8.9p1", [], checked_at=2000.0)
    cached = repo.get_cve_cache("openssh:8.9p1")
    assert cached["cves"] == []
    assert cached["checked_at"] == 2000.0


def test_neo4j_repository_raises_not_implemented():
    repo = Neo4jRepository(uri="bolt://localhost:7687", user="neo4j", password="x")
    with pytest.raises(NotImplementedError):
        repo.init_schema()
