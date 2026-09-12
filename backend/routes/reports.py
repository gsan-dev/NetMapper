"""Endpoint para descargar el informe semanal de red en PDF (mejora futura
ya implementada, mismo patrón que NetGuardian)."""
from __future__ import annotations

import time
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import FileResponse

from common.config import settings
from common.db import get_repository
from common.reports import generate_weekly_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/weekly")
async def weekly_report():
    repo = get_repository()
    until = time.time()
    since = until - 7 * 24 * 3600
    summary = repo.get_weekly_summary(since)

    filename = f"netmapper_weekly_{datetime.fromtimestamp(until):%Y%m%d_%H%M}.pdf"
    output_path = settings.reports_dir_absolute / filename
    generate_weekly_report(summary, since, until, output_path)

    return FileResponse(output_path, media_type="application/pdf", filename=filename)
