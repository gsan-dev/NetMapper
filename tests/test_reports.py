"""Pruebas de la generación del informe semanal en PDF."""
import time

from common.reports import generate_weekly_report


def _summary(**overrides):
    data = {
        "total_devices": 5,
        "new_devices_count": 1,
        "new_devices": [{"mac": "aa:bb:cc:dd:ee:01", "vendor": "Synology", "device_type": "nas"}],
        "unauthorized_devices": [],
        "security_alerts": [],
        "cve_findings_count": 0,
        "cve_devices": [],
        "node_count": 5,
        "edge_count": 4,
        "community_count": 2,
    }
    data.update(overrides)
    return data


def test_generate_weekly_report_creates_valid_pdf(tmp_path):
    output_path = tmp_path / "report.pdf"
    until = time.time()
    since = until - 7 * 24 * 3600

    result = generate_weekly_report(_summary(), since, until, output_path)

    assert result == output_path
    assert output_path.exists()
    assert output_path.read_bytes().startswith(b"%PDF")


def test_generate_weekly_report_handles_empty_lists(tmp_path):
    output_path = tmp_path / "report.pdf"
    until = time.time()
    since = until - 7 * 24 * 3600

    generate_weekly_report(
        _summary(
            unauthorized_devices=[],
            security_alerts=[],
            cve_devices=[],
            new_devices=[],
        ),
        since,
        until,
        output_path,
    )

    assert output_path.exists()


def test_generate_weekly_report_includes_unauthorized_and_alerts(tmp_path):
    output_path = tmp_path / "report.pdf"
    until = time.time()
    since = until - 7 * 24 * 3600

    generate_weekly_report(
        _summary(
            unauthorized_devices=[{"mac": "zz:zz:zz:zz:zz:zz", "vendor": None, "ips": ["10.0.0.9"]}],
            security_alerts=[
                {
                    "mac": "aa:bb:cc:dd:ee:01",
                    "vendor": "Synology",
                    "count": 3,
                    "severity": "high",
                    "reason": "port scan",
                    "source": "netguardian",
                }
            ],
            cve_devices=[{"mac": "aa:bb:cc:dd:ee:01", "vendor": "Synology", "cve_count": 2}],
            cve_findings_count=2,
        ),
        since,
        until,
        output_path,
    )

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_generate_weekly_report_creates_parent_directories(tmp_path):
    output_path = tmp_path / "nested" / "dir" / "report.pdf"
    until = time.time()
    since = until - 7 * 24 * 3600

    generate_weekly_report(_summary(), since, until, output_path)

    assert output_path.exists()
