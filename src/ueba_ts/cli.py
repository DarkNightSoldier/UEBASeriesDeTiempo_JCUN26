"""Línea de comandos.

    python -m ueba_ts build     --config configs/cert_r42.yaml   ingesta y rejilla usuario-día
    python -m ueba_ts identify  --config configs/cert_r42.yaml   Box-Jenkins: ADF, KPSS, periodograma, AIC
    python -m ueba_ts detect    --config configs/cert_r42.yaml   seis detectores x dos protocolos
    python -m ueba_ts evaluate  --config configs/cert_r42.yaml   métricas, bootstrap y tablas
    python -m ueba_ts figures   --config configs/cert_r42.yaml   figuras para el artículo y el póster
    python -m ueba_ts export    --config configs/cert_r42.yaml   datos para la app y el sitio estático
    python -m ueba_ts all       --config configs/cert_r42.yaml   todo lo anterior en orden
"""
from __future__ import annotations

import argparse
import json
import os
import time

from . import config

STEPS = ["build", "identify", "detect", "evaluate", "figures", "export"]


def run_step(step: str, cfg: dict, jobs: int):
    t0 = time.time()
    if step == "build":
        from .ingest import build
        out = build(cfg)
    elif step == "identify":
        from .identify import run
        out = run(cfg, jobs)
    elif step == "detect":
        from .detectors import run
        out = run(cfg, jobs)
    elif step == "evaluate":
        from .evaluate import run
        out = run(cfg)
    elif step == "figures":
        from .figures import run
        out = run(cfg)
    elif step == "export":
        from .export import run
        out = run(cfg)
    print(f"[{step}] {time.time() - t0:.0f} s")
    if out:
        print(json.dumps(out, indent=2, default=str, ensure_ascii=False)[:4000])


def main(argv=None):
    # Un hilo de BLAS por proceso: el paralelismo se hace con procesos (evita sobresuscripción).
    for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ.setdefault(v, "1")
    p = argparse.ArgumentParser(prog="ueba_ts")
    p.add_argument("step", choices=STEPS + ["all"])
    p.add_argument("--config", default="configs/cert_r42.yaml")
    p.add_argument("--jobs", type=int, default=max((os.cpu_count() or 2) - 1, 1))
    a = p.parse_args(argv)
    cfg = config.load(a.config)
    for step in (STEPS if a.step == "all" else [a.step]):
        run_step(step, cfg, a.jobs)
