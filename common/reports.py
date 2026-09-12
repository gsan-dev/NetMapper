"""Generación del informe semanal de red en PDF (mejora futura ya implementada).

Tanto el backend (endpoint bajo demanda) como cualquier tarea programada
futura pueden usar esta misma función para no duplicar el formato del
informe — mismo patrón que common/reports.py en NetGuardian.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fpdf import FPDF


def generate_weekly_report(
    summary: dict[str, Any], since: float, until: float, output_path: Path
) -> Path:
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "NetMapper - Informe semanal", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    since_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(since))
    until_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(until))
    pdf.cell(0, 8, f"Periodo: {since_str}  -  {until_str}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Resumen de la red", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Dispositivos activos: {summary.get('total_devices', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0, 8, f"Dispositivos nuevos esta semana: {summary.get('new_devices_count', 0)}",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.cell(
        0, 8,
        f"Grafo actual: {summary.get('node_count', 0)} nodos, {summary.get('edge_count', 0)} "
        f"relaciones, {summary.get('community_count', 0)} comunidades",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Dispositivos no autorizados", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    unauthorized = summary.get("unauthorized_devices") or []
    if not unauthorized:
        pdf.cell(0, 8, "Ninguno.", new_x="LMARGIN", new_y="NEXT")
    else:
        for device in unauthorized:
            ips = ", ".join(device.get("ips") or []) or "sin IP"
            pdf.cell(
                0, 8,
                f"{device['mac']} ({device.get('vendor') or 'fabricante desconocido'}) - {ips}",
                new_x="LMARGIN", new_y="NEXT",
            )
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Alertas de seguridad", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    alerts = summary.get("security_alerts") or []
    if not alerts:
        pdf.cell(0, 8, "Sin alertas registradas.", new_x="LMARGIN", new_y="NEXT")
    else:
        for alert in alerts:
            pdf.cell(
                0, 8,
                f"{alert['mac']}: {alert['count']} alerta(s), severidad {alert['severity']} "
                f"({alert.get('source') or 'desconocido'})",
                new_x="LMARGIN", new_y="NEXT",
            )
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "CVEs conocidos correlacionados", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    cve_devices = summary.get("cve_devices") or []
    pdf.cell(
        0, 8, f"Total de CVEs encontrados: {summary.get('cve_findings_count', 0)}",
        new_x="LMARGIN", new_y="NEXT",
    )
    if cve_devices:
        for entry in cve_devices:
            pdf.cell(
                0, 8,
                f"{entry['mac']} ({entry.get('vendor') or 'fabricante desconocido'}): "
                f"{entry['cve_count']} CVE(s)",
                new_x="LMARGIN", new_y="NEXT",
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return output_path
