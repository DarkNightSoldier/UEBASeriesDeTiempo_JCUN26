"""Carga de la configuración YAML con rutas resueltas desde la raíz del repositorio."""
from __future__ import annotations

import os

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def load(path: str) -> dict:
    with open(path) as fh:
        cfg = yaml.safe_load(fh)
    for k in ("raw_dir", "answers_dir", "processed_dir", "results_dir"):
        if not os.path.isabs(cfg[k]):
            cfg[k] = os.path.normpath(os.path.join(ROOT, cfg[k]))
    return cfg
