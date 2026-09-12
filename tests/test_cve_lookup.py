"""Pruebas de la correlación de banners con CVEs conocidos (NVD)."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from common import cve_lookup as cl


@pytest.mark.parametrize(
    "banner,expected",
    [
        ("SSH-2.0-OpenSSH_8.9p1", ("openssh", "8.9p1")),
        ("Apache/2.4.41 (Ubuntu)", ("apache_http_server", "2.4.41")),
        ("nginx/1.18.0", ("nginx", "1.18.0")),
        ("ProFTPD 1.3.7a", ("proftpd", "1.3.7")),
        ("Samba 4.15.13-Debian", ("samba", "4.15.13")),
    ],
)
def test_parse_product_version_recognizes_common_banners(banner, expected):
    assert cl.parse_product_version(banner) == expected


def test_parse_product_version_returns_none_for_unknown_banner():
    assert cl.parse_product_version("totally-custom-service/1.0") is None


def test_query_nvd_parses_vulnerabilities_from_response():
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-12345",
                    "descriptions": [{"lang": "en", "value": "A vulnerability in OpenSSH."}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]
                    },
                }
            }
        ]
    }

    with patch.object(cl.requests, "get", return_value=fake_response) as mock_get:
        findings = cl.query_nvd("openssh", "8.9p1", api_key="secret")

    assert findings == [
        {"cve_id": "CVE-2023-12345", "severity": "high", "summary": "A vulnerability in OpenSSH."}
    ]
    assert mock_get.call_args.kwargs["headers"] == {"apiKey": "secret"}


def test_query_nvd_returns_empty_list_without_api_key_header():
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {"vulnerabilities": []}

    with patch.object(cl.requests, "get", return_value=fake_response) as mock_get:
        findings = cl.query_nvd("nginx", "1.18.0")

    assert findings == []
    assert mock_get.call_args.kwargs["headers"] == {}


def test_query_nvd_returns_empty_list_on_request_error():
    with patch.object(cl.requests, "get", side_effect=requests.RequestException("boom")):
        findings = cl.query_nvd("nginx", "1.18.0")

    assert findings == []


def test_query_nvd_skips_vulnerabilities_without_cve_id():
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {"vulnerabilities": [{"cve": {}}]}

    with patch.object(cl.requests, "get", return_value=fake_response):
        findings = cl.query_nvd("nginx", "1.18.0")

    assert findings == []
