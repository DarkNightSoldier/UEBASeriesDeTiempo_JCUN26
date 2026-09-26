"""Capa de datos de la app: carga el paquete exportado por `python -m ueba_ts export`.

Los pronósticos (yhat, sigma) vienen en punto fijo de 16 bits. Al arrancar se descomprimen
una sola vez a archivos .npy en un directorio de caché y se leen con memory map, así la app
usa poca RAM (sirve en un dyno de Heroku) y cada consulta por usuario es inmediata.
Las métricas se recalculan con numpy siguiendo exactamente las definiciones del artículo
(src/ueba_ts/evaluate.py).
"""
from __future__ import annotations

import json
import os
import tempfile
from functools import lru_cache

import numpy as np
import pandas as pd
from scipy.stats import norm, rankdata

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("UEBA_DATA", os.path.join(HERE, "data"))
CACHE = os.environ.get("UEBA_CACHE", os.path.join(tempfile.gettempdir(), "ueba_ts_cache"))

DETECTORS = ["global", "user", "seasonal_naive", "arima", "sarima", "sarimax"]
NAMES = {"global": "Regla global", "user": "Línea base estática", "seasonal_naive": "Regla ingenua (semana anterior)",
         "arima": "ARIMA", "sarima": "SARIMA", "sarimax": "SARIMAX + pares"}
# Paleta JCUN validada para daltonismo en este orden (skill dataviz, modo claro).
COLORS = {"global": "#ec6a52", "user": "#a3241f", "seasonal_naive": "#d4a017", "arima": "#6a5bb5",
          "sarima": "#8fbf45", "sarimax": "#2e6b25"}
PROTOCOLS = {"rolling": "Reentrenamiento mensual", "fixed": "Sin reentrenar (origen fijo)"}
# Cada contador se nombra por lo que puede indicar, sin afirmar que todo uso sea malicioso.
SIGNALS = {"logons": "Inicios de sesión", "after_hours_logons": "Inicios de sesión fuera de horario",
           "unique_pcs": "Equipos distintos usados", "usb_events": "Posible fuga por USB (memorias conectadas)",
           "after_hours_usb": "Posible fuga por USB fuera de horario",
           "file_events": "Posible robo de información (archivos copiados a USB)", "emails_sent": "Correos enviados",
           "external_emails": "Posible fuga por correo (destinatarios externos)", "http_requests": "Páginas web visitadas"}
SCENARIOS = {1: "Fuga de información a WikiLeaks, fuera de horario",
             2: "Robo de datos antes de renunciar",
             3: "Sabotaje con la cuenta del supervisor"}


class Store:
    def __init__(self, data: str = DATA):
        self.data = data
        with open(os.path.join(data, "meta.json")) as fh:
            self.meta = json.load(fh)
        m = self.meta
        self.scale = m["scale"]
        self.pscale = m.get("pred_scale", self.scale)   # pronósticos en float32 exactos (1) o en punto fijo
        self.signals = m["signals"]
        self.days = pd.to_datetime(m["days"])
        self.t0 = m["test_start_idx"]
        self.users = m["users"]
        self.uidx = {u: i for i, u in enumerate(self.users)}
        base = np.load(os.path.join(data, "base.npz"))
        self.counts = base["counts"]
        self.Z = np.log1p(self.counts.astype(np.float32))
        self.active = base["active"]
        self.peer = base["peer"].astype(np.float32) / self.scale
        self.mask = self.active.copy()
        self.mask[:, :self.t0] = False
        self.user_info = pd.read_parquet(os.path.join(data, "users.parquet")).set_index("user").loc[self.users]
        self.calendar = pd.read_parquet(os.path.join(data, "calendar.parquet"))
        self.incidents = pd.read_parquet(os.path.join(data, "incidents.parquet"))
        mal = pd.read_parquet(os.path.join(data, "malicious_days.parquet"))
        U, T = self.Z.shape[:2]
        self.y = np.zeros((U, T), bool)
        self.inc = np.full((U, T), "", object)
        self.scen = np.zeros((U, T), np.int8)
        self.types = np.full((U, T), "", object)
        didx = {d: i for i, d in enumerate(self.days)}
        for r in mal.itertuples():
            i, t = self.uidx[r.user], didx[pd.Timestamp(r.day)]
            self.y[i, t], self.inc[i, t], self.scen[i, t], self.types[i, t] = True, r.incident, r.scenario, r.event_types
        self.mal_users = sorted(mal["user"].unique())
        self.tables = {}
        tdir = os.path.join(data, "tables")
        for f in os.listdir(tdir):
            self.tables[f[:-4]] = pd.read_csv(os.path.join(tdir, f))
        with open(os.path.join(data, "orders.json")) as fh:
            self.orders = json.load(fh)
        with open(os.path.join(data, "ingest_log.json")) as fh:
            self.ingest = json.load(fh)
        self._fits = None
        self._pred = {}
        # La caché se identifica con una huella del paquete de datos: si se vuelve a exportar,
        # no se reutilizan pronósticos viejos.
        import hashlib
        h = hashlib.sha1()
        for f in sorted(os.listdir(os.path.join(data, "pred"))):
            st = os.stat(os.path.join(data, "pred", f))
            h.update(f"{f}:{st.st_size}:{int(st.st_mtime)}".encode())
        self.cache = os.path.join(CACHE, h.hexdigest()[:12])
        os.makedirs(self.cache, exist_ok=True)

    # ------------------------------------------------------------------ pronósticos
    def pred(self, p: str, d: str):
        key = (p, d)
        if key not in self._pred:
            out = []
            for arr in ("yhat", "sigma"):
                path = os.path.join(self.cache, f"{p}_{d}_{arr}.npy")
                if not os.path.exists(path):
                    with np.load(os.path.join(self.data, "pred", f"{p}_{d}.npz")) as z:
                        np.save(path, z[arr])
                out.append(np.load(path, mmap_mode="r"))
            self._pred[key] = tuple(out)
        return self._pred[key]

    def user_forecast(self, p: str, d: str, ui: int):
        yq, sq = self.pred(p, d)
        return yq[ui].astype(np.float32) / self.pscale, sq[ui].astype(np.float32) / self.pscale

    @property
    def fits(self) -> pd.DataFrame:
        if self._fits is None:
            self._fits = pd.read_parquet(os.path.join(self.data, "fits.parquet"))
        return self._fits

    # ------------------------------------------------------------------ puntajes
    @lru_cache(maxsize=8)
    def zpos(self, p: str, d: str, sig: tuple) -> np.ndarray:
        """z^+ para las señales elegidas: arreglo (U, T, k) en float32 (igual precisión que la evaluación oficial)."""
        yq, sq = self.pred(p, d)
        idx = [self.signals.index(s) for s in sig]
        out = np.empty(self.Z.shape[:2] + (len(idx),), np.float32)
        for k, si in enumerate(idx):
            z = (self.Z[:, :, si] - yq[:, :, si].astype(np.float32) / self.pscale) / (
                sq[:, :, si].astype(np.float32) / self.pscale)
            out[:, :, k] = np.nan_to_num(np.clip(z, 0, None), nan=0.0)   # igual que evaluate.scores
        return out

    def score(self, p: str, d: str, sig: tuple, alpha: float):
        zp = self.zpos(p, d, sig).astype(np.float32)
        A = zp.max(axis=-1)
        top = np.asarray(sig)[zp.argmax(axis=-1)]
        R = (zp > norm.ppf(1 - alpha)).sum(axis=-1)
        return A, R, top


# ---------------------------------------------------------------------- métricas
def average_precision(s: np.ndarray, y: np.ndarray) -> float:
    order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order].astype(float)
    tp, fp = np.cumsum(y), np.cumsum(1 - y)
    idx = np.r_[np.where(np.diff(s))[0], len(s) - 1]
    tp, fp = tp[idx], fp[idx]
    if tp[-1] == 0:
        return float("nan")
    prec = tp / np.maximum(tp + fp, 1e-12)
    rec = tp / tp[-1]
    return float(np.sum(np.diff(np.r_[0, rec]) * prec))


def pr_curve(s: np.ndarray, y: np.ndarray, n: int = 250):
    order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order].astype(float)
    tp, fp = np.cumsum(y), np.cumsum(1 - y)
    idx = np.r_[np.where(np.diff(s))[0], len(s) - 1]
    prec, rec = tp[idx] / np.maximum(tp[idx] + fp[idx], 1e-12), tp[idx] / max(tp[-1], 1)
    keep = np.unique(np.linspace(0, len(idx) - 1, min(n, len(idx))).astype(int))
    return rec[keep], prec[keep]


def roc_auc(s: np.ndarray, y: np.ndarray) -> float:
    r = rankdata(s)
    npos, nneg = y.sum(), (~y).sum()
    return float((r[y].sum() - npos * (npos + 1) / 2) / (npos * nneg))


def budget_alerts(A: np.ndarray, mask: np.ndarray, k: int) -> np.ndarray:
    Am = np.where(mask, A, -np.inf)
    alert = np.zeros_like(mask)
    for t in np.where(mask.any(axis=0))[0]:
        col = Am[:, t]
        top = np.argpartition(-col, k)[:k]
        top = top[np.isfinite(col[top]) & (col[top] > 0)]
        alert[top, t] = True
    return alert


def evaluate(st: Store, alert: np.ndarray, A: np.ndarray) -> dict:
    m, y = st.mask, st.y
    a = alert & m
    tp, fp = int((a & y).sum()), int((a & ~y).sum())
    fn = int((~a & y & m).sum())
    neg = int((~y & m).sum())
    ndays = int(m.any(axis=0).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    det, delays, by_scen = [], [], {1: [0, 0], 2: [0, 0], 3: [0, 0]}
    for inc in st.incidents["incident"]:
        sel = (st.inc == inc) & y & m
        ii, tt = np.where(sel)
        if len(ii) == 0:
            continue
        sc = int(st.scen[ii[0], tt[0]])
        hit = a[ii, tt]
        by_scen[sc][1] += 1
        if hit.any():
            by_scen[sc][0] += 1
            det.append(inc)
            delays.append(int(tt[hit].min() - tt.min()))
    return {"TP": tp, "FP": fp, "precision": prec, "recall": rec,
            "F1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "FP_1000": 1000 * fp / max(neg, 1), "alertas_dia": (tp + fp) / max(ndays, 1),
            "incidentes": len(det), "demora_mediana": float(np.median(delays)) if delays else float("nan"),
            "por_escenario": by_scen, "detectados": det}
