"""Pruebas del cliente de integración con NetGuardian."""
from unittest.mock import MagicMock, patch

import requests

from common.netguardian_client import NetGuardianClient


def _client():
    return NetGuardianClient(base_url="http://localhost:8000", username="admin", password="secret")


def _mock_response(json_data, status_ok=True):
    response = MagicMock()
    response.json.return_value = json_data
    if status_ok:
        response.raise_for_status = MagicMock()
    else:
        response.raise_for_status.side_effect = requests.HTTPError("401")
    return response


def test_login_success_caches_token():
    client = _client()
    login_response = _mock_response({"access_token": "tok123", "expires_in": 600})

    with patch("common.netguardian_client.requests.post", return_value=login_response) as mock_post:
        token = client._get_token()
        token_again = client._get_token()  # no debería volver a llamar a login

    assert token == "tok123"
    assert token_again == "tok123"
    mock_post.assert_called_once()


def test_login_failure_returns_none_without_raising():
    client = _client()
    with patch(
        "common.netguardian_client.requests.post",
        side_effect=requests.RequestException("connection refused"),
    ):
        assert client._get_token() is None


def test_fetch_recent_alerts_parses_response():
    client = _client()
    login_response = _mock_response({"access_token": "tok123", "expires_in": 600})
    alerts_response = _mock_response(
        [
            {
                "id": 5,
                "source_ip": "10.0.0.5",
                "severity": "high",
                "reason": "port scan",
                "created_at": 1000.0,
            },
            {"id": 6, "source_ip": None, "severity": "low", "reason": "sin ip"},
        ]
    )

    with patch("common.netguardian_client.requests.post", return_value=login_response), patch(
        "common.netguardian_client.requests.get", return_value=alerts_response
    ) as mock_get:
        alerts = client.fetch_recent_alerts(limit=50)

    assert len(alerts) == 1  # la alerta sin source_ip se descarta
    assert alerts[0].alert_id == 5
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].severity == "high"
    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["headers"] == {"Authorization": "Bearer tok123"}


def test_fetch_recent_alerts_filters_by_since_id():
    client = _client()
    login_response = _mock_response({"access_token": "tok123", "expires_in": 600})
    alerts_response = _mock_response(
        [
            {"id": 3, "source_ip": "10.0.0.5", "severity": "low", "reason": "a", "created_at": 1.0},
            {"id": 7, "source_ip": "10.0.0.6", "severity": "high", "reason": "b", "created_at": 2.0},
        ]
    )

    with patch("common.netguardian_client.requests.post", return_value=login_response), patch(
        "common.netguardian_client.requests.get", return_value=alerts_response
    ):
        alerts = client.fetch_recent_alerts(since_id=3)

    assert len(alerts) == 1
    assert alerts[0].alert_id == 7


def test_fetch_recent_alerts_returns_empty_on_request_error():
    client = _client()
    login_response = _mock_response({"access_token": "tok123", "expires_in": 600})

    with patch("common.netguardian_client.requests.post", return_value=login_response), patch(
        "common.netguardian_client.requests.get",
        side_effect=requests.RequestException("timeout"),
    ):
        assert client.fetch_recent_alerts() == []


def test_fetch_recent_alerts_works_without_token_when_auth_disabled():
    """Si NetGuardian tiene AUTH_ENABLED=false, el login puede fallar (o no
    hacer falta) y el resto de endpoints igualmente no piden token."""
    client = _client()
    alerts_response = _mock_response(
        [{"id": 1, "source_ip": "10.0.0.5", "severity": "medium", "reason": "x", "created_at": 1.0}]
    )

    with patch(
        "common.netguardian_client.requests.post",
        side_effect=requests.RequestException("no auth endpoint configured"),
    ), patch("common.netguardian_client.requests.get", return_value=alerts_response) as mock_get:
        alerts = client.fetch_recent_alerts()

    assert len(alerts) == 1
    assert mock_get.call_args.kwargs["headers"] == {}
