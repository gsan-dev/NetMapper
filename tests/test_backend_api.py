"""Pruebas de integración del backend FastAPI (REST + WebSocket)."""
import importlib.util
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(path: Path, name: str):
    """Carga backend/main.py bajo un nombre único para no chocar con
    discovery/main.py cuando ambos coexisten en sys.modules durante los tests.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def backend_app(tmp_path):
    import common.db as db_module
    from common.config import settings

    settings.db_path = str(tmp_path / "test_backend.db")
    db_module._repository_singleton = None

    module = _load_module(REPO_ROOT / "backend" / "main.py", "netmapper_backend_main_test")
    module.POLL_INTERVAL_SECONDS = 0.05  # el bucle de difusión no necesita tardar 5s en los tests
    yield module

    db_module._repository_singleton = None


@pytest.fixture
def client(backend_app):
    with TestClient(backend_app.app) as c:
        yield c


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["sensor_healthy"] is False  # sin ninguna pasada registrada todavía
    assert body["last_discovery_pass_at"] is None


def test_health_reports_sensor_healthy_after_recent_pass(client):
    from common.db import get_repository

    repo = get_repository()
    repo.record_discovery_pass(time.time())

    response = client.get("/api/health")
    assert response.json()["sensor_healthy"] is True


def test_health_reports_sensor_unhealthy_when_pass_is_stale(client):
    from common.config import settings
    from common.db import get_repository

    repo = get_repository()
    repo.record_discovery_pass(time.time() - settings.scan_interval_seconds * 10)

    response = client.get("/api/health")
    assert response.json()["sensor_healthy"] is False


def test_networks_endpoint_empty_by_default(client):
    response = client.get("/api/networks")
    assert response.status_code == 200
    assert response.json() == []


def test_networks_endpoint_returns_seeded_data(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_network({"cidr": "192.168.1.0/24", "discovery_method": "direct"})

    response = client.get("/api/networks")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["cidr"] == "192.168.1.0/24"


def test_devices_endpoint_returns_seeded_data(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device(
        {
            "mac": "aa:bb:cc:dd:ee:01",
            "ips": ["192.168.1.10"],
            "vendor": "Synology Incorporated",
            "device_type": "nas",
        }
    )

    response = client.get("/api/devices")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["mac"] == "aa:bb:cc:dd:ee:01"
    assert body[0]["device_type"] == "nas"


def test_get_device_by_mac_returns_404_when_missing(client):
    response = client.get("/api/devices/zz:zz:zz:zz:zz:zz")
    assert response.status_code == 404


def test_get_device_by_mac_returns_device(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.1.10"]})

    response = client.get("/api/devices/aa:bb:cc:dd:ee:01")
    assert response.status_code == 200
    assert response.json()["mac"] == "aa:bb:cc:dd:ee:01"


def test_get_device_history_returns_snapshot_states(client):
    from common.db import get_repository

    repo = get_repository()
    repo.insert_graph_snapshot(
        {
            "created_at": time.time(),
            "node_count": 1,
            "edge_count": 0,
            "communities": {},
            "centrality": {},
            "layers": {},
            "devices": [{"mac": "aa:bb:cc:dd:ee:01", "device_type": "nas", "vendor": "Synology"}],
            "relations": [],
        }
    )

    response = client.get("/api/devices/aa:bb:cc:dd:ee:01/history")
    assert response.status_code == 200
    history = response.json()
    assert len(history) == 1
    assert history[0]["device_type"] == "nas"


def test_get_device_history_empty_for_unknown_mac(client):
    response = client.get("/api/devices/zz:zz:zz:zz:zz:zz/history")
    assert response.status_code == 200
    assert response.json() == []


def test_graph_endpoint_combines_devices_relations_and_snapshot(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.1.10"]})
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:02", "ips": ["192.168.1.11"]})
    repo.upsert_relation(
        {"src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "aa:bb:cc:dd:ee:02", "bytes_total": 100, "connections": 1}
    )
    repo.insert_graph_snapshot(
        {
            "created_at": time.time(),
            "node_count": 2,
            "edge_count": 1,
            "communities": {},
            "centrality": {},
            "layers": {},
        }
    )

    response = client.get("/api/graph")
    assert response.status_code == 200
    body = response.json()
    assert len(body["devices"]) == 2
    assert len(body["relations"]) == 1
    assert body["snapshot"]["node_count"] == 2


def test_graph_snapshots_endpoint(client):
    from common.db import get_repository

    repo = get_repository()
    repo.insert_graph_snapshot(
        {"created_at": time.time(), "node_count": 1, "edge_count": 0, "communities": {}, "centrality": {}, "layers": {}}
    )

    response = client.get("/api/graph/snapshots")
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_request_traceroute_returns_404_for_unknown_device(client):
    response = client.post("/api/devices/zz:zz:zz:zz:zz:zz/traceroute")
    assert response.status_code == 404


def test_request_traceroute_returns_400_without_known_ip(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": []})

    response = client.post("/api/devices/aa:bb:cc:dd:ee:01/traceroute")
    assert response.status_code == 400


def test_request_traceroute_enqueues_pending_request(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.1.10"]})

    response = client.post("/api/devices/aa:bb:cc:dd:ee:01/traceroute")
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "pending"
    assert body["target_ip"] == "192.168.1.10"

    pending = repo.list_pending_traceroute_requests()
    assert len(pending) == 1
    assert pending[0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_get_traceroute_returns_404_without_prior_request(client):
    response = client.get("/api/devices/aa:bb:cc:dd:ee:01/traceroute")
    assert response.status_code == 404


def test_get_traceroute_returns_latest_result(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.1.10"]})
    request_id = repo.create_traceroute_request("aa:bb:cc:dd:ee:01", "192.168.1.10")
    repo.complete_traceroute_request(
        request_id, [{"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 1.2}]
    )

    response = client.get("/api/devices/aa:bb:cc:dd:ee:01/traceroute")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "done"
    assert body["hops"] == [{"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 1.2}]


def test_weekly_report_returns_pdf(client):
    from common.db import get_repository

    repo = get_repository()
    repo.upsert_device({"mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.1.10"], "vendor": "Synology"})

    response = client.get("/api/reports/weekly")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")


def test_websocket_receives_graph_update(client):
    with client.websocket_connect("/ws") as ws:
        message = ws.receive_json()
        assert message["type"] == "graph_update"
        assert "devices" in message["data"]
        assert "relations" in message["data"]
