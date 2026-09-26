"""Seis detectores, desde la regla estática hasta SARIMAX con contexto de pares.

Todos entregan, para cada usuario, señal y día, un pronóstico a un paso (yhat) y su
desviación estándar (sigma) en la escala Z = log(1 + conteo). El puntaje es
z = (Z - yhat) / sigma.

Detector          Equivale en un SOC a                                   Qué aísla
----------------  -----------------------------------------------------  -----------------------------
global            Regla SIEM "conteo > K" igual para toda la organización  punto de partida
user              Línea base estática por usuario (media y desviación)     valor de personalizar
seasonal_naive    "Hoy como el mismo día de la semana pasada"              ciclo semanal sin modelo
arima             Línea base dinámica ARMA(p,q)                            autocorrelación
sarima            Línea base dinámica y estacional (s = 7)                 estacionalidad
sarimax           SARIMA + mediana de pares del departamento (exógena)     contexto organizacional

Protocolos (Tashman, 2000):
    fixed    parámetros estimados una vez con el entrenamiento inicial; el filtro de Kalman
             actualiza el estado día a día con los parámetros congelados.
    rolling  reestimación al inicio de cada mes con los últimos W días (perfil regenerado
             periódicamente, NIST SP 800-94, sec. 2.3.2). No usa etiquetas: si hubo actividad
             maliciosa en la ventana, entra a la línea base, como pasaría en un SOC real.
"""
from __future__ import annotations

import json
import os
import warnings
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

MODEL_DETECTORS = ("arima", "sarima", "sarimax")


def load_inputs(cfg: dict):
    f = pd.read_parquet(os.path.join(cfg["processed_dir"], "features.parquet"))
    users = pd.read_parquet(os.path.join(cfg["processed_dir"], "users.parquet")).set_index("user")
    signals = cfg["signals"]
    ulist = sorted(f["user"].unique())
    if cfg.get("user_list"):  # solo para pruebas de humo: subconjunto explícito de usuarios
        ulist = sorted(set(cfg["user_list"]) & set(ulist))
    days = pd.DatetimeIndex(sorted(f["day"].unique()))
    f = f.set_index(["user", "day"]).reindex(pd.MultiIndex.from_product([ulist, days]))
    Z = np.log1p(f[signals].to_numpy(np.float64)).reshape(len(ulist), len(days), len(signals))
    last = users.loc[ulist, "last_active"].to_numpy()
    active = days.to_numpy()[None, :] <= last[:, None]
    groups = users.loc[ulist, "peer_group"].to_numpy()
    return Z, active, groups, ulist, days, signals


def loo_median(Z: np.ndarray, active: np.ndarray, groups: np.ndarray) -> np.ndarray:
    """Mediana diaria de los DEMÁS miembros activos del grupo de pares (leave-one-out)."""
    U, T, S = Z.shape
    peer = np.zeros_like(Z)
    for g in np.unique(groups):
        idx = np.where(groups == g)[0]
        for t in range(T):
            members = idx[active[idx, t]]
            if len(members) < 2:
                continue
            vals = Z[members, t, :]
            for k, u in enumerate(members):
                peer[u, t, :] = np.median(np.delete(vals, k, axis=0), axis=0)
    return peer


def segments(days: pd.DatetimeIndex, test_start: str, window: int):
    """Tramos del protocolo rodante: (inicio_ventana, inicio_tramo, fin_tramo) en índices."""
    t0 = days.get_loc(pd.Timestamp(test_start))
    starts = [t0] + [i for i in range(t0 + 1, len(days)) if days[i].day == 1]
    ends = starts[1:] + [len(days)]
    return [(max(0, s - window), s, e) for s, e in zip(starts, ends)]


def _static(z_win: np.ndarray, floor: float):
    return z_win.mean(), max(z_win.std(), floor)


def _fit_filter(z, exog, w0, s, e, order, seas, floor, maxiter, start_params=None, cached=None):
    """Estima en [w0, s) y devuelve pronósticos a un paso en [w0, e) con esos parámetros.

    cached = (params, aic, ljungbox_p, converged) de un ajuste idéntico ya hecho: solo se filtra.
    """
    from statsmodels.stats.diagnostic import acorr_ljungbox
    from statsmodels.tsa.statespace.sarimax import SARIMAX
    kw = dict(order=order, seasonal_order=seas, trend="c", enforce_stationarity=False, enforce_invertibility=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if cached is None:
            ex_fit = exog[w0:s] if exog is not None else None
            r = SARIMAX(z[w0:s], exog=ex_fit, **kw).fit(disp=False, maxiter=maxiter, start_params=start_params)
            burn = order[0] + order[2] + seas[3] * (seas[0] + seas[2]) + 1
            lb = float(acorr_ljungbox(r.resid[burn:], lags=[14], return_df=True)["lb_pvalue"].iloc[0])
            params, aic, conv = r.params, float(r.aic), bool(r.mle_retvals.get("converged", False))
        else:
            params, aic, lb, conv = cached
        ex_all = exog[w0:e] if exog is not None else None
        fr = SARIMAX(z[w0:e], exog=ex_all, **kw).filter(params)
    yhat = np.asarray(fr.filter_results.forecasts[0])
    sig = np.sqrt(np.maximum(np.asarray(fr.filter_results.forecasts_error_cov[0, 0]), 0))
    return yhat, np.maximum(sig, floor), params, aic, lb, conv


def _run_user(args):
    (ui, Zu, Pu, act_u, glob, cfg, orders, segs, t0) = args
    warnings.simplefilter("ignore")
    T, S = Zu.shape
    D = cfg["detectors"]
    P = cfg["protocols"]
    floor, min_act = cfg["sigma_floor"], cfg["sparse_min_active"]
    yhat = np.full((len(P), len(D), T, S), np.nan, np.float32)
    sig = np.full_like(yhat, np.nan)
    fits = []
    last_t = int(np.where(act_u)[0].max()) + 1 if act_u.any() else 0
    warm, cache = {}, {}   # parámetros del mes anterior (rodante) y ajustes ya hechos por ventana

    # Tramos por protocolo. fixed: un tramo [0, T) con ventana [0, t0). rolling: tramos mensuales.
    plan = {"fixed": [(0, t0, 0, T)], "rolling": [(w0, s, s, e) for (w0, s, e) in segs]}
    for pi, proto in enumerate(P):
        for (w0, s_fit, s_out, e) in plan[proto]:
            if s_out >= last_t:        # el usuario ya salió de la organización
                continue
            e_eff = min(e, T)
            for si in range(S):
                z = Zu[:, si]
                win = z[w0:s_fit][act_u[w0:s_fit]]
                mu_u, sd_u = _static(win, floor)
                frac = float((win > 0).mean()) if len(win) else 0.0
                for di, det in enumerate(D):
                    if det == "global":
                        mu, sd = glob[(proto, s_fit)][si]
                        yh, sg = np.full(e_eff - s_out, mu), np.full(e_eff - s_out, max(sd, floor))
                    elif det == "user":
                        yh, sg = np.full(e_eff - s_out, mu_u), np.full(e_eff - s_out, sd_u)
                    elif det == "seasonal_naive":
                        lag = np.concatenate([np.full(7, np.nan), z[:-7]])
                        d7 = (z[w0:s_fit] - lag[w0:s_fit])[act_u[w0:s_fit]]
                        sd = max(np.nanstd(d7), floor) if np.isfinite(d7).any() else floor
                        yh = lag[s_out:e_eff].copy()
                        yh[np.isnan(yh)] = mu_u
                        sg = np.full(e_eff - s_out, sd)
                    else:
                        o = orders["arima" if det == "arima" else "sarima"][cfg["signals"][si]]
                        order, seas = tuple(o["order"]), tuple(o["seasonal_order"])
                        ex = Pu[:, [si]] if det == "sarimax" else None
                        status, params, aic, lb, conv = "ok", None, np.nan, np.nan, None
                        if frac < min_act or win.std() == 0:
                            status = "fallback_sparse"
                        else:
                            prev = warm.get((proto, det, si))
                            try:
                                it = cfg["fit"]["refit_maxiter"] if prev is not None else cfg["fit"]["maxiter"]
                                yh_all, sg_all, params, aic, lb, conv = _fit_filter(
                                    z, ex, w0, s_fit, e_eff, order, seas, floor, it, prev,
                                    cache.get((det, si, w0, s_fit)))
                                warm[(proto, det, si)] = params
                                cache[(det, si, w0, s_fit)] = (params, aic, lb, conv)
                                yh, sg = yh_all[s_out - w0:], sg_all[s_out - w0:]
                            except Exception:  # noqa: BLE001  (sin convergencia: respaldo documentado)
                                status = "fallback_error"
                        if status != "ok":
                            yh, sg = np.full(e_eff - s_out, mu_u), np.full(e_eff - s_out, sd_u)
                        fits.append({"protocol": proto, "detector": det, "user_idx": ui, "signal": cfg["signals"][si],
                                     "fit_start": int(w0), "segment_start": int(s_out), "status": status,
                                     "aic": aic, "ljungbox_p": lb, "converged": conv,
                                     "params": json.dumps(np.round(params, 4).tolist()) if params is not None else ""})
                    yhat[pi, di, s_out:e_eff, si] = yh
                    sig[pi, di, s_out:e_eff, si] = sg
    # Antes del inicio de prueba ambos protocolos usan el mismo ajuste inicial.
    if "rolling" in P and "fixed" in P:
        pr, pf = P.index("rolling"), P.index("fixed")
        yhat[pr, :, :t0] = yhat[pf, :, :t0]
        sig[pr, :, :t0] = sig[pf, :, :t0]
    return ui, yhat, sig, fits



def run(cfg: dict, jobs: int = 4) -> dict:
    for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[v] = "1"
    Z, active, groups, ulist, days, signals = load_inputs(cfg)
    peer = loo_median(Z, active, groups)
    with open(os.path.join(cfg["results_dir"], "orders.json")) as fh:
        orders = json.load(fh)
    t0 = days.get_loc(pd.Timestamp(cfg["test_start"]))
    segs = segments(days, cfg["test_start"], cfg["rolling_window_days"])

    # Regla global: media y desviación de toda la organización (usuario-día activos) en cada ventana.
    glob = {}
    for proto, plan in (("fixed", [(0, t0)]), ("rolling", [(w0, s) for (w0, s, _) in segs])):
        for (w0, s) in plan:
            a = active[:, w0:s]
            glob[(proto, s)] = [(Z[:, w0:s, k][a].mean(), Z[:, w0:s, k][a].std()) for k in range(len(signals))]

    tasks = [(ui, Z[ui], peer[ui], active[ui], glob, cfg, orders, segs, t0) for ui in range(len(ulist))]
    P, D = cfg["protocols"], cfg["detectors"]
    U, T, S = Z.shape
    yhat = np.full((len(P), len(D), U, T, S), np.nan, np.float32)
    sig = np.full_like(yhat, np.nan)
    fits = []
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        for n, (ui, yh, sg, ft) in enumerate(ex.map(_run_user, tasks, chunksize=2)):
            yhat[:, :, ui], sig[:, :, ui] = yh, sg
            fits.extend(ft)
            if n % 100 == 0:
                print(f"  usuarios procesados: {n}/{U}", flush=True)

    out = os.path.join(cfg["results_dir"], "arrays")
    os.makedirs(out, exist_ok=True)
    np.save(os.path.join(out, "Z.npy"), Z.astype(np.float32))
    np.save(os.path.join(out, "peer.npy"), peer.astype(np.float32))
    np.save(os.path.join(out, "active.npy"), active)
    np.save(os.path.join(out, "yhat.npy"), yhat)
    np.save(os.path.join(out, "sigma.npy"), sig)
    meta = {"users": ulist, "days": [d.strftime("%Y-%m-%d") for d in days], "signals": signals,
            "detectors": D, "protocols": P, "test_start_idx": int(t0),
            "segments": [[int(a), int(b), int(c)] for a, b, c in segs]}
    with open(os.path.join(out, "meta.json"), "w") as fh:
        json.dump(meta, fh)
    fits = pd.DataFrame(fits)
    fits["user"] = [ulist[i] for i in fits.pop("user_idx")]
    fits.to_parquet(os.path.join(cfg["results_dir"], "fits.parquet"), index=False)
    st = fits.groupby(["protocol", "detector", "status"]).size().unstack(fill_value=0)
    st.to_csv(os.path.join(cfg["results_dir"], "tables", "estado_ajustes.csv"))
    return {"estado_ajustes": {f"{p}/{d}": row.to_dict() for (p, d), row in st.iterrows()}}
