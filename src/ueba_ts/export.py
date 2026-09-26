"""Exporta los resultados para la app dinámica (app/data) y el sitio estático (docs/data).

App dinámica: conteos exactos (uint16) y pronósticos en float32, idénticos a los del proceso (escala 1/5000
en log(1 + y); error de redondeo < 1e-4, es decir, < 0,001 en z con el piso de sigma).
Sitio estático: tablas en JSON y series por usuario para los usuarios con días maliciosos
más una muestra aleatoria de benignos (semilla fija), cargadas bajo demanda.
"""
from __future__ import annotations

import glob
import json
import os
import shutil

import numpy as np
import pandas as pd

SCALE = 5000.0


def _q(x: np.ndarray) -> np.ndarray:
    return np.clip(np.round(np.nan_to_num(x, nan=0.0) * SCALE), 0, 65535).astype(np.uint16)


def _q32(x: np.ndarray) -> np.ndarray:
    """Pronósticos en punto fijo con signo (int32): conserva los valores negativos y las desviaciones grandes,
    así el laboratorio reproduce exactamente las métricas oficiales (con uint16 se recortaban)."""
    return np.round(np.nan_to_num(x, nan=0.0).astype(np.float64) * SCALE).astype(np.int32)


def run(cfg: dict) -> dict:
    from .config import ROOT
    res = cfg["results_dir"]
    arr = os.path.join(res, "arrays")
    with open(os.path.join(arr, "meta.json")) as fh:
        meta = json.load(fh)
    Z = np.load(os.path.join(arr, "Z.npy"))
    counts = np.round(np.expm1(Z)).astype(np.uint16)
    active = np.load(os.path.join(arr, "active.npy"))
    peer = np.load(os.path.join(arr, "peer.npy"))
    yhat = np.load(os.path.join(arr, "yhat.npy"), mmap_mode="r")
    sig = np.load(os.path.join(arr, "sigma.npy"), mmap_mode="r")

    app = os.path.join(ROOT, "app", "data")
    if os.path.exists(app):
        shutil.rmtree(app)
    os.makedirs(os.path.join(app, "pred"))
    os.makedirs(os.path.join(app, "tables"))
    meta_app = dict(meta, alpha=cfg["alpha"], budget_k=cfg["budget_k"], scale=SCALE, pred_scale=1.0,
                    sigma_floor=cfg["sigma_floor"], work_hours=[cfg["work_start"], cfg["work_end"]])
    with open(os.path.join(app, "meta.json"), "w") as fh:
        json.dump(meta_app, fh)
    np.savez_compressed(os.path.join(app, "base.npz"), counts=counts, active=active, peer=_q(peer))
    for pi, p in enumerate(meta["protocols"]):
        for di, d in enumerate(meta["detectors"]):
            np.savez_compressed(os.path.join(app, "pred", f"{p}_{d}.npz"),
                                yhat=np.asarray(yhat[pi, di], np.float32), sigma=np.asarray(sig[pi, di], np.float32))
    for f in ("users", "calendar", "incidents"):
        shutil.copy(os.path.join(cfg["processed_dir"], f"{f}.parquet"), app)
    lab = pd.read_parquet(os.path.join(cfg["processed_dir"], "labels.parquet"))
    lab[(lab["is_malicious"] == 1) & lab["user"].isin(meta["users"])].to_parquet(
        os.path.join(app, "malicious_days.parquet"), index=False)
    fits = pd.read_parquet(os.path.join(res, "fits.parquet"))
    fits.to_parquet(os.path.join(app, "fits.parquet"), index=False)
    for f in glob.glob(os.path.join(res, "tables", "*.csv")):
        if os.path.basename(f) not in ("identificacion_series.csv", "seleccion_ordenes_detalle.csv"):
            shutil.copy(f, os.path.join(app, "tables"))
    shutil.copy(os.path.join(res, "orders.json"), app)
    shutil.copy(os.path.join(cfg["processed_dir"], "ingest_log.json"), app)

    # ---------------- Sitio estático (docs/data) ----------------
    site = os.path.join(ROOT, "docs", "data")
    if os.path.exists(site):
        shutil.rmtree(site)
    os.makedirs(os.path.join(site, "users"))
    tabs = os.path.join(res, "tables")
    out = {}
    for name in ("deteccion_resumen", "deteccion_por_escenario", "bootstrap_diferencias", "lo_que_no_ven",
                 "identificacion_resumen", "calidad_linea_base", "ljungbox_resumen", "estado_ajustes",
                 "incidentes_detalle", "seleccion_ordenes", "presupuesto_alertas", "presupuesto_diferencias"):
        p = os.path.join(tabs, f"{name}.csv")
        if os.path.exists(p):
            out[name] = json.loads(pd.read_csv(p).to_json(orient="records", double_precision=5))
    daily = pd.read_csv(os.path.join(tabs, "alertas_diarias.csv"))
    daily = daily[daily["day"] >= meta["days"][meta["test_start_idx"]]]
    out["alertas_diarias"] = {"days": sorted(daily["day"].unique().tolist()), "series": {
        f"{p}|{d}|{r}": g.sort_values("day")["alertas"].astype(int).tolist()
        for (p, d, r), g in daily.groupby(["protocolo", "detector", "regla"])}}
    with open(os.path.join(cfg["processed_dir"], "ingest_log.json")) as fh:
        out["ingesta"] = json.load(fh)
    inc = pd.read_parquet(os.path.join(cfg["processed_dir"], "incidents.parquet"))
    out["incidentes"] = json.loads(inc.to_json(orient="records", date_format="iso"))
    with open(os.path.join(res, "orders.json")) as fh:
        out["ordenes"] = json.load(fh)
    out["meta"] = {k: meta[k] for k in ("signals", "detectors", "protocols", "test_start_idx")}
    out["meta"].update({"alpha": cfg["alpha"], "budget_k": cfg["budget_k"], "first_day": meta["days"][0],
                        "last_day": meta["days"][-1]})

    # Curvas PR submuestreadas (200 puntos por curva) para el sitio
    from sklearn.metrics import precision_recall_curve

    from .evaluate import load
    d = load(cfg)
    A = np.load(os.path.join(arr, "A.npy"))
    m, y = d["mask"], d["y"][d["mask"]]
    curves = []
    for pi, p in enumerate(meta["protocols"]):
        for di, det in enumerate(meta["detectors"]):
            pr, rc, _ = precision_recall_curve(y, A[pi, di][m])
            idx = np.unique(np.linspace(0, len(pr) - 1, 200).astype(int))
            curves.append({"protocolo": p, "detector": det, "precision": np.round(pr[idx].astype(np.float64), 4).tolist(),
                           "recall": np.round(rc[idx].astype(np.float64), 4).tolist()})
    out["curvas_pr"] = curves
    with open(os.path.join(site, "summary.json"), "w") as fh:
        json.dump(out, fh, ensure_ascii=False, separators=(",", ":"))

    # Usuarios del sitio: todas las cuentas con días maliciosos + 60 benignos al azar (semilla 0)
    mal_users = sorted(set(lab.loc[lab["is_malicious"] == 1, "user"]) & set(meta["users"]))
    rng = np.random.default_rng(0)
    pool = sorted(set(meta["users"]) - set(mal_users))
    benign = sorted(rng.choice(pool, min(60, len(pool)), replace=False))
    t_from = max(meta["test_start_idx"] - 56, 0)
    idx_users = []
    users = pd.read_parquet(os.path.join(cfg["processed_dir"], "users.parquet")).set_index("user")
    for u in mal_users + benign:
        ui = meta["users"].index(u)
        rec = {"user": u, "role": users.loc[u, "role"], "grupo": users.loc[u, "peer_group"],
               "t_from": t_from, "counts": counts[ui, t_from:].T.tolist(),
               "malicious": d["y"][ui, t_from:].tolist(), "active": active[ui, t_from:].astype(int).tolist(),
               "pred": {}}
        # Series completas solo con reestimación mensual y dos detectores (tamaño del sitio);
        # el puntaje A va para todos los detectores y protocolos. La app dinámica tiene todo.
        for pi, p in enumerate(meta["protocols"]):
            for di, det in enumerate(meta["detectors"]):
                e = {"A": np.round(np.nan_to_num(A[pi, di, ui, t_from:]).astype(np.float64), 1).tolist()}
                if p == "rolling" and det in ("user", "sarima", "sarimax"):
                    e["yhat"] = np.round(np.nan_to_num(yhat[pi, di, ui, t_from:].T).astype(np.float64), 2).tolist()
                    e["sigma"] = np.round(np.nan_to_num(sig[pi, di, ui, t_from:].T).astype(np.float64), 2).tolist()
                rec["pred"][f"{p}|{det}"] = e
        with open(os.path.join(site, "users", f"{u}.json"), "w") as fh:
            json.dump(rec, fh, separators=(",", ":"))
        idx_users.append({"user": u, "malicioso": u in mal_users, "role": rec["role"], "grupo": rec["grupo"]})
    with open(os.path.join(site, "users_index.json"), "w") as fh:
        json.dump({"days": meta["days"][t_from:], "users": idx_users}, fh, separators=(",", ":"))
    size = sum(os.path.getsize(f) for f in glob.glob(os.path.join(site, "**", "*"), recursive=True) if os.path.isfile(f))
    size_app = sum(os.path.getsize(f) for f in glob.glob(os.path.join(app, "**", "*"), recursive=True) if os.path.isfile(f))
    return {"app_data_MB": round(size_app / 1e6, 1), "sitio_MB": round(size / 1e6, 1),
            "usuarios_sitio": len(idx_users)}
