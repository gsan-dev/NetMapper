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


def test_upsert_device_keeps_vendor_when_new_value_is_none(repo):
    repo.upsert_device(_device(vendor="Synology Incorporated"))
    repo.upsert_device(_device(vendor=None, ips=["192.168.1.11"]))

    device = repo.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert device["vendor"] == "Synology Incorporated"
    assert device["ips"] == ["192.168.1.11"]


def test_mark_stale_devices_inactive(repo):
    repo.upsert_device(_device(mac="aa:aa:aa:aa:aa:aa"))
    repo.upsert_device(_device(mac="bb:bb:bb:bb:bb:bb"))

    repo.mark_stale_devices_inactive({"aa:aa:aa:aa:aa:aa"})

    active = {d["mac"] for d in repo.list_devices(active_only=True)}
    all_devices = {d["mac"] for d in repo.list_devices(active_only=False)}
    assert active == {"aa:aa:aa:aa:aa:aa"}
    assert all_devices == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}


def test_get_device_by_mac_returns_none_when_missing(repo):
    assert repo.get_device_by_mac("zz:zz:zz:zz:zz:zz") is None


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


def test_neo4j_repository_raises_not_implemented():
    repo = Neo4jRepository(uri="bolt://localhost:7687", user="neo4j", password="x")
    with pytest.raises(NotImplementedError):
        repo.init_schema()
