"""Orden de severidad de alertas de seguridad (compatible con las de
NetGuardian: none < low < medium < high)."""
from __future__ import annotations

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def is_higher_severity(candidate: str, current: str) -> bool:
    """True si `candidate` es una severidad estrictamente mayor que `current`."""
    return SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(current, 0)
