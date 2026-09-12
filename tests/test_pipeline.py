"""Pruebas de orquestación de discovery/main.py (el pipeline completo)."""
import importlib.util
import ipaddress
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from device_fingerprint import DeviceProfile
from host_discovery import Host
from network_discovery import Subnet

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(path: Path, name: str):
    """Carga discovery/main.py bajo un nombre único para no chocar con
    backend/main.py cuando ambos coexisten en sys.modules durante los tests.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pipeline_module():
    return _load_module(REPO_ROOT / "discovery" / "main.py", "netmapper_pipeline_test")


@pytest.fixture
def pipeline(tmp_path, pipeline_module):
    import common.db as db_module
    from common.config import settings

    settings.db_path = str(tmp_path / "pipeline_test.db")
    settings.allowed_networks = [ipaddress.ip_network("192.168.1.0/24")]
    settings.allowed_devices = set()
    settings.mdns_enabled = False
    settings.passive_capture_enabled = False
    db_module._repository_singleton = None

    instance = pipeline_module.Pipeline()
    yield instance

    db_module._repository_singleton = None


def _host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01"):
    return Host(ip=ip, mac=mac, subnet_cidr="192.168.1.0/24", discovery_method="arp")


def _profile(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", device_type="nas"):
    return DeviceProfile(mac=mac, ip=ip, vendor="Synology Incorporated", device_type=device_type)


def test_discovery_pass_respects_allowed_networks_whitelist(pipeline, pipeline_module):
    allowed_subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")
    forbidden_subnet = Subnet(cidr="10.0.0.0/24", discovery_method="route")

    with patch.object(
        pipeline_module, "discover_networks", return_value=[allowed_subnet, forbidden_subnet]
    ), patch.object(
        pipeline_module, "discover_hosts", return_value=[_host()]
    ) as mock_discover_hosts, patch.object(
        pipeline_module, "fingerprint_host", return_value=_profile()
    ):
        pipeline.run_discovery_pass()

    networks = {n["cidr"]: n for n in pipeline.repo.list_networks()}
    assert networks["192.168.1.0/24"]["reachable"] == 1
    assert networks["10.0.0.0/24"]["reachable"] == 0

    # discover_hosts solo se llama para la red permitida
    mock_discover_hosts.assert_called_once()
    assert mock_discover_hosts.call_args.args[0].cidr == "192.168.1.0/24"


def test_discovery_pass_flags_unauthorized_devices_when_whitelist_configured(
    pipeline, pipeline_module
):
    from common.config import settings

    settings.allowed_devices = {"aa:bb:cc:dd:ee:01"}  # el otro dispositivo no está en la lista
    subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")
    hosts = [_host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01"), _host(ip="192.168.1.20", mac="bb:bb:bb:bb:bb:bb")]

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=hosts
    ), patch.object(
        pipeline_module,
        "fingerprint_host",
        side_effect=lambda host, **kwargs: _profile(mac=host.mac, ip=host.ip),
    ):
        pipeline.run_discovery_pass()

    assert pipeline.engine.devices["aa:bb:cc:dd:ee:01"].is_authorized is True
    assert pipeline.engine.devices["bb:bb:bb:bb:bb:bb"].is_authorized is False


def test_discovery_pass_does_not_flag_anything_without_whitelist(pipeline, pipeline_module):
    subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=[_host()]
    ), patch.object(pipeline_module, "fingerprint_host", return_value=_profile()):
        pipeline.run_discovery_pass()

    assert pipeline.engine.devices["aa:bb:cc:dd:ee:01"].is_authorized is True


def test_discovery_pass_ingests_hosts_into_fusion_engine(pipeline, pipeline_module):
    subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=[_host()]
    ), patch.object(pipeline_module, "fingerprint_host", return_value=_profile()):
        pipeline.run_discovery_pass()

    assert "aa:bb:cc:dd:ee:01" in pipeline.engine.devices
    device = pipeline.engine.devices["aa:bb:cc:dd:ee:01"]
    assert device.device_type == "nas"
    assert device.vendor == "Synology Incorporated"


def test_discovery_pass_marks_devices_no_longer_seen_as_inactive(pipeline, pipeline_module):
    subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=[_host()]
    ), patch.object(pipeline_module, "fingerprint_host", return_value=_profile()):
        pipeline.run_discovery_pass()
        pipeline.persist_current_state()

    # Simulamos que ha pasado mucho tiempo desde la última vez que se vio
    # el dispositivo (sin necesidad de manipular el reloj del sistema).
    pipeline.engine.devices["aa:bb:cc:dd:ee:01"].last_seen -= 1000

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=[]
    ):
        pipeline.run_discovery_pass(device_stale_after_seconds=1)

    assert "aa:bb:cc:dd:ee:01" not in pipeline.engine.devices
    active = {d["mac"] for d in pipeline.repo.list_devices(active_only=True)}
    assert "aa:bb:cc:dd:ee:01" not in active


def test_persist_current_state_writes_devices_and_relations(pipeline):
    pipeline.engine.ingest_host(_host(), "192.168.1.0/24")
    pipeline.engine.ingest_fingerprint(_profile())

    pipeline.persist_current_state()

    devices = pipeline.repo.list_devices()
    assert len(devices) == 1
    assert devices[0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_run_analysis_pass_persists_snapshot(pipeline):
    pipeline.engine.ingest_host(_host(), "192.168.1.0/24")
    pipeline.engine.ingest_fingerprint(_profile())

    pipeline.run_analysis_pass()

    snapshot = pipeline.repo.get_latest_graph_snapshot()
    assert snapshot is not None
    assert snapshot["node_count"] == 1
    assert snapshot["devices"][0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_run_once_executes_full_pipeline(pipeline, pipeline_module):
    subnet = Subnet(cidr="192.168.1.0/24", discovery_method="direct")

    with patch.object(pipeline_module, "discover_networks", return_value=[subnet]), patch.object(
        pipeline_module, "discover_hosts", return_value=[_host()]
    ), patch.object(pipeline_module, "fingerprint_host", return_value=_profile()):
        pipeline.run_once()

    assert len(pipeline.repo.list_networks()) == 1
    assert len(pipeline.repo.list_devices()) == 1
    assert pipeline.repo.get_latest_graph_snapshot() is not None


def test_start_passive_capture_skipped_when_disabled(pipeline, pipeline_module):
    from common.config import settings

    settings.passive_capture_enabled = False

    with patch.object(pipeline_module, "PassiveCapture") as mock_capture_cls:
        pipeline._start_passive_capture()

    mock_capture_cls.assert_not_called()
    assert pipeline._passive_capture is None


def test_start_passive_capture_starts_when_enabled(pipeline, pipeline_module):
    from common.config import settings

    settings.passive_capture_enabled = True

    with patch.object(pipeline_module, "PassiveCapture") as mock_capture_cls:
        pipeline._start_passive_capture()

    mock_capture_cls.assert_called_once()
    mock_capture_cls.return_value.start.assert_called_once()
