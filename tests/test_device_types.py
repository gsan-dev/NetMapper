"""Pruebas del motor de reglas de inferencia de tipo de dispositivo."""
from common.device_types import IP_CAMERA, NAS, PRINTER, ROUTER, SERVER, UNKNOWN, infer_device_type


def test_infer_device_type_by_vendor_keyword():
    assert infer_device_type("Synology Inc.", set()) == NAS
    assert infer_device_type("Hikvision Digital Technology", set()) == IP_CAMERA


def test_infer_device_type_by_ports_only():
    assert infer_device_type(None, {9100, 631}) == PRINTER


def test_infer_device_type_unknown_without_signals():
    assert infer_device_type(None, set()) == UNKNOWN
    assert infer_device_type("Some Random Vendor Inc.", {12345}) == UNKNOWN


def test_infer_device_type_combines_vendor_and_ports_scores():
    # Vendor de router (3 puntos) debería ganar a un único puerto de NAS (1 punto)
    assert infer_device_type("MikroTik", {445}) == ROUTER


def test_infer_device_type_case_insensitive_vendor_match():
    assert infer_device_type("SYNOLOGY INC.", set()) == NAS


def test_infer_device_type_picks_highest_scoring_type_on_port_overlap():
    # 22, 3306 -> SERVER (2 puntos); 22 también está en SWITCH (1 punto)
    assert infer_device_type(None, {22, 3306}) == SERVER
