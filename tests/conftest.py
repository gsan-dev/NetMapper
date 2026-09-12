"""Configuración común de pytest: añade discovery/, analysis/, backend/ y la
raíz del repo a sys.path."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

for sub in ("discovery", "analysis", "backend", ""):
    path = str(REPO_ROOT / sub) if sub else str(REPO_ROOT)
    if path not in sys.path:
        sys.path.insert(0, path)
