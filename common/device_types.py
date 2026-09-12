"""Tipos de dispositivo y motor de reglas de inferencia (Fase 2).

Combina fabricante (vendor) + puertos abiertos en un sistema de
puntuación simple: cada coincidencia (keyword de vendor o puerto
característico) suma puntos al tipo de dispositivo correspondiente, y
gana el que más puntos acumula. No es machine learning — es un motor
de reglas deliberadamente simple y explicable.
"""
from __future__ import annotations

ROUTER = "router"
SWITCH = "switch"
NAS = "nas"
IP_CAMERA = "ip_camera"
PRINTER = "printer"
SERVER = "server"
MOBILE = "mobile"
IOT = "iot"
UNKNOWN = "unknown"

ALL_DEVICE_TYPES = (ROUTER, SWITCH, NAS, IP_CAMERA, PRINTER, SERVER, MOBILE, IOT, UNKNOWN)

# Puertos característicos por tipo. No son exclusivos: son pistas que suman.
PORTS_BY_TYPE: dict[str, set[int]] = {
    ROUTER: {80, 443, 23, 53, 67},
    SWITCH: {22, 23, 161},
    NAS: {445, 139, 5000, 5001, 2049, 548},
    IP_CAMERA: {554, 8000, 8080},
    PRINTER: {9100, 515, 631},
    SERVER: {22, 3306, 5432},
}

# Palabras clave en el nombre de fabricante (comparación en minúsculas).
VENDOR_KEYWORDS_BY_TYPE: dict[str, list[str]] = {
    NAS: ["synology", "qnap", "western digital"],
    IP_CAMERA: ["hikvision", "dahua", "axis communications", "reolink", "amcrest"],
    PRINTER: ["hewlett", "hp inc", "canon", "epson", "brother industries"],
    ROUTER: ["mikrotik", "ubiquiti", "tp-link", "netgear", "asustek", "cisco", "juniper"],
    MOBILE: ["apple", "samsung electro", "huawei", "xiaomi", "oneplus"],
    IOT: ["espressif", "sonoff", "shelly", "tuya", "raspberry pi"],
}

# Puntos que suma cada tipo de coincidencia al sistema de puntuación.
VENDOR_MATCH_SCORE = 3
PORT_MATCH_SCORE = 1


def infer_device_type(vendor: str | None, open_ports: set[int]) -> str:
    """Motor de reglas: puntúa cada tipo por keyword de vendor + puertos típicos."""
    scores: dict[str, int] = {}
    vendor_lower = (vendor or "").lower()

    for device_type, keywords in VENDOR_KEYWORDS_BY_TYPE.items():
        if any(keyword in vendor_lower for keyword in keywords):
            scores[device_type] = scores.get(device_type, 0) + VENDOR_MATCH_SCORE

    for device_type, ports in PORTS_BY_TYPE.items():
        overlap = len(open_ports & ports)
        if overlap:
            scores[device_type] = scores.get(device_type, 0) + overlap * PORT_MATCH_SCORE

    if not scores:
        return UNKNOWN

    return max(scores, key=scores.get)
