"""Correlación de banners de servicio con vulnerabilidades conocidas (NVD).

Mejora futura ya implementada, desactivada por defecto
(`CVE_LOOKUP_ENABLED`): la API pública de NVD tiene límites de tasa
estrictos (5 peticiones/30s sin API key, 50/30s con ella), así que esta
correlación:

- Corre en una pasada aparte del pipeline (`Pipeline.run_cve_lookup_pass`
  en discovery/main.py), no dentro del fingerprinting por host.
- Cachea cada consulta de "producto:versión" en la BD durante
  `CVE_LOOKUP_INTERVAL_SECONDS` antes de repetirla.
- Solo actúa sobre banners ya reconocidos por un puñado de patrones
  habituales — un banner no reconocido se ignora en vez de arriesgarse
  a una consulta con datos basura.
"""
from __future__ import annotations

import logging
import re

import requests

logger = logging.getLogger("netmapper.cve_lookup")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (patrón, nombre de producto normalizado). Conservador a propósito:
# solo servicios habituales en un homelab.
_BANNER_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"OpenSSH[_ ]v?([\d.]+(?:p\d+)?)", re.IGNORECASE), "openssh"),
    (re.compile(r"Apache/([\d.]+)", re.IGNORECASE), "apache_http_server"),
    (re.compile(r"nginx/([\d.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"ProFTPD[ /]([\d.]+)", re.IGNORECASE), "proftpd"),
    (re.compile(r"vsftpd[ /]([\d.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE), "iis"),
    (re.compile(r"Samba[ /]([\d.]+)", re.IGNORECASE), "samba"),
    (re.compile(r"MySQL[- ]?([\d.]+)", re.IGNORECASE), "mysql"),
    (re.compile(r"lighttpd/([\d.]+)", re.IGNORECASE), "lighttpd"),
)


def parse_product_version(banner: str) -> tuple[str, str] | None:
    """Extrae (producto normalizado, versión) de un banner conocido, o None."""
    for pattern, product in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            return product, match.group(1)
    return None


def _extract_severity(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0].get("cvssData", {}).get("baseSeverity", "unknown").lower()
    return "unknown"


def query_nvd(
    product: str,
    version: str,
    api_key: str = "",
    timeout: float = 10.0,
    max_results: int = 5,
) -> list[dict]:
    """Busca CVEs conocidos para `product` `version` por palabra clave en NVD.

    Devuelve una lista (posiblemente vacía) de
    {cve_id, severity, summary}. Cualquier fallo de red o de la API se
    registra y se trata como "sin resultados" — esta correlación es un
    plus informativo, no debe tumbar el resto del pipeline.
    """
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": max_results}
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException:
        logger.warning("Error consultando NVD para %s %s", product, version, exc_info=True)
        return []

    findings = []
    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        findings.append(
            {
                "cve_id": cve_id,
                "severity": _extract_severity(cve.get("metrics", {})),
                "summary": summary[:300],
            }
        )
    return findings
