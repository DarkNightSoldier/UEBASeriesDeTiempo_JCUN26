"""Identificación Box-Jenkins a escala, solo con la ventana de entrenamiento inicial.

Preguntas previas al modelado:
    ¿Las series son estacionarias?          ADF (H0: raíz unitaria) y KPSS (H0: estacionaria)
    ¿Hay ciclo semanal?                      periodograma y FAC en el rezago 7
    ¿Hay dependencia día a día?              FAC en el rezago 1 frente a la banda 2/sqrt(n)
    ¿Qué órdenes (p,q)(P,Q)_7 usar?          AIC sobre una muestra aleatoria de usuarios
    ¿Los residuos son ruido blanco?          Ljung-Box en el rezago 14

La estacionalidad semanal no se supone: se verifica y se reporta qué fracción de series la tiene.
"""
from __future__ import annotations

import itertools
import json
import os
import warnings
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
from scipy.signal import periodogram


def load_training(cfg: dict) -> tuple[pd.DataFrame, list[str]]:
    f = pd.read_parquet(os.path.join(cfg["processed_dir"], "features.parquet"))
    tr = f[(f["day"] >= cfg["train_start"]) & (f["day"] < cfg["test_start"])].sort_values(["user", "day"])
    return tr, cfg["signals"]


def dominant_period(x: np.ndarray) -> float:
    x = x - x.mean()
    if np.allclose(x, 0):
        return np.nan
    fr, p = periodogram(x)
    fr, p = fr[1:], p[1:]
    return float(1 / fr[np.argmax(p)])


def _diagnose(args):
    from statsmodels.tsa.stattools import acf, adfuller, kpss
    user, signal, x, min_active = args
    z = np.log1p(x)
    row = {"user": user, "signal": signal, "dias_activos": float((x > 0).mean()),
           "modelable": bool((x > 0).mean() >= min_active and z.std() > 0)}
    if row["modelable"]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = acf(z, nlags=14, fft=True)
            # ADF pierde potencia ante estacionalidad determinística fuerte: se repite sobre la
            # serie sin medias por día de la semana (desestacionalizada).
            dow = np.arange(len(z)) % 7
            zd = z - pd.Series(z).groupby(dow).transform("mean").to_numpy()
            row.update({"acf1": r[1], "acf7": r[7], "banda": 2 / np.sqrt(len(z)),
                        "periodo_dominante": dominant_period(z),
                        "adf_p": adfuller(z, autolag="AIC")[1],
                        # serie constante tras quitar el patrón semanal: periódica pura, ADF no aplica
                        "adf_p_desest": adfuller(zd, autolag="AIC")[1] if zd.std() > 1e-9 else np.nan,
                        "kpss_p": kpss(z, regression="c", nlags="auto")[1]})
    return row


def _grid_fit(args):
    from statsmodels.stats.diagnostic import acorr_ljungbox
    from statsmodels.tsa.statespace.sarimax import SARIMAX
    user, signal, z, grid, period, maxiter = args
    out = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for (p, q, sp) in grid:
            seas = (sp[0], sp[1], sp[2], period if any(sp) else 0)
            try:
                m = SARIMAX(z, order=(p, 0, q), seasonal_order=seas, trend="c",
                            enforce_stationarity=False, enforce_invertibility=False)
                r = m.fit(disp=False, maxiter=maxiter)
                burn = max(p, q) + period * max(sp[0], sp[2])
                lb = float(acorr_ljungbox(r.resid[burn:], lags=[14], return_df=True)["lb_pvalue"].iloc[0])
                out.append({"user": user, "signal": signal, "p": p, "q": q, "P": sp[0], "D": sp[1], "Q": sp[2],
                            "aic": float(r.aic), "ljungbox_p": lb})
            except Exception:  # noqa: BLE001  (convergencia fallida: se registra como ausente)
                out.append({"user": user, "signal": signal, "p": p, "q": q, "P": sp[0], "D": sp[1], "Q": sp[2],
                            "aic": np.nan, "ljungbox_p": np.nan})
    return out


def _choose(sel: pd.DataFrame, seasonal: bool) -> pd.DataFrame:
    """Orden con la menor mediana de delta-AIC (AIC del modelo menos el mejor AIC de esa serie)."""
    s = sel if seasonal else sel[(sel["P"] == 0) & (sel["Q"] == 0)]
    s = s.dropna(subset=["aic"]).copy()
    s["delta_aic"] = s["aic"] - s.groupby(["user", "signal"])["aic"].transform("min")
    s["es_mejor"] = (s["delta_aic"] == 0).astype(int)
    g = s.groupby(["signal", "p", "q", "P", "D", "Q"]).agg(
        mediana_delta_aic=("delta_aic", "median"), pct_mejor=("es_mejor", "mean"),
        pct_ljungbox_ok=("ljungbox_p", lambda v: float((v > 0.05).mean())), series=("user", "size")).reset_index()
    return g


def run(cfg: dict, jobs: int = 4) -> dict:
    out_t = os.path.join(cfg["results_dir"], "tables")
    os.makedirs(out_t, exist_ok=True)
    tr, signals = load_training(cfg)
    ic = cfg["identification"]
    tasks = [(u, s, g[s].to_numpy(float), cfg["sparse_min_active"])
             for u, g in tr.groupby("user") for s in signals]
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        diag = pd.DataFrame(list(ex.map(_diagnose, tasks, chunksize=64)))
    diag["ciclo_semanal"] = diag["periodo_dominante"].between(6.5, 7.5) | diag["periodo_dominante"].between(3.4, 3.6)
    diag.to_csv(os.path.join(out_t, "identificacion_series.csv"), index=False)
    m = diag[diag["modelable"]]
    resumen = diag.groupby("signal").agg(series=("user", "size"), pct_modelables=("modelable", "mean")).join(
        m.groupby("signal").agg(
            pct_ciclo_semanal=("ciclo_semanal", "mean"),
            pct_acf7_signif=("acf7", lambda v: float((v.abs() > m.loc[v.index, "banda"]).mean())),
            pct_acf1_signif=("acf1", lambda v: float((v.abs() > m.loc[v.index, "banda"]).mean())),
            pct_adf_rechaza=("adf_p", lambda v: float((v < 0.05).mean())),
            pct_adf_desest_rechaza=("adf_p_desest", lambda v: float((v < 0.05).mean())),
            pct_kpss_no_rechaza=("kpss_p", lambda v: float((v > 0.05).mean())),
        )).reindex(signals).reset_index()
    resumen.to_csv(os.path.join(out_t, "identificacion_resumen.csv"), index=False)

    # Selección de órdenes por AIC en una muestra aleatoria de usuarios (sin etiquetas)
    rng = np.random.default_rng(ic["seed"])
    sample = rng.choice(sorted(tr["user"].unique()), ic["sample_users"], replace=False)
    grid = [(p, q, tuple(sp)) for p, q, sp in itertools.product(ic["p"], ic["q"], ic["seasonal"])]
    ok = set(map(tuple, m[["user", "signal"]].to_numpy()))
    tasks = [(u, s, np.log1p(g[s].to_numpy(float)), grid, ic["period"], ic["maxiter"])
             for u, g in tr[tr["user"].isin(sample)].groupby("user") for s in signals if (u, s) in ok]
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        sel = pd.DataFrame([r for part in ex.map(_grid_fit, tasks, chunksize=2) for r in part])
    sel.to_csv(os.path.join(out_t, "seleccion_ordenes_detalle.csv"), index=False)

    orders = {}
    tabs = []
    for name, seasonal in (("sarima", True), ("arima", False)):
        g = _choose(sel, seasonal).assign(modelo=name)
        tabs.append(g)
        for s in signals:
            gs = g[g["signal"] == s].sort_values(["mediana_delta_aic", "pct_mejor"], ascending=[True, False])
            if gs.empty:  # señal sin series modelables en la muestra
                best = {"p": 1, "q": 1, "P": int(seasonal), "D": 0, "Q": int(seasonal)}
            else:
                best = gs.iloc[0][["p", "q", "P", "D", "Q"]].astype(int).to_dict()
            orders.setdefault(name, {})[s] = {"order": [best["p"], 0, best["q"]],
                                              "seasonal_order": [best["P"], best["D"], best["Q"],
                                                                 ic["period"] if best["P"] or best["Q"] else 0]}
    pd.concat(tabs).to_csv(os.path.join(out_t, "seleccion_ordenes.csv"), index=False)
    with open(os.path.join(cfg["results_dir"], "orders.json"), "w") as fh:
        json.dump(orders, fh, indent=2)
    return {"resumen": resumen.round(3).to_dict("records"), "orders": orders}
