"""Sensibilidad: ¿cambian los puntajes de SARIMAX si se permiten más iteraciones?

En la corrida principal SARIMAX convergió (según statsmodels) en menos ajustes que SARIMA con el
límite de 60 iteraciones (30 en los reajustes mensuales con arranque en caliente). Aquí se vuelve
a estimar SARIMAX con hasta 300 iteraciones (150 en reajustes) para una muestra aleatoria de
usuarios y se compara z en los usuario-día activos del periodo de prueba.

    python scripts/sensibilidad_convergencia.py --users 40 --jobs 13
"""
import argparse
import json
import os
import warnings

import numpy as np
import pandas as pd

from ueba_ts import config
from ueba_ts.detectors import _fit_filter, load_inputs, loo_median, segments


def run_user(args):
    ui, Zu, Pu, act, cfg, orders, segs, t0, it0, it1 = args
    warnings.simplefilter("ignore")
    T, S = Zu.shape
    out = {"fixed": np.full((T, S), np.nan), "rolling": np.full((T, S), np.nan)}
    sig = {"fixed": np.full((T, S), np.nan), "rolling": np.full((T, S), np.nan)}
    conv = []
    last_t = int(np.where(act)[0].max()) + 1
    for si, s in enumerate(cfg["signals"]):
        o = orders["sarima"][s]
        order, seas = tuple(o["order"]), tuple(o["seasonal_order"])
        z, ex = Zu[:, si], Pu[:, [si]]
        prev = None
        for proto, plan in (("fixed", [(0, t0, 0, T)]), ("rolling", [(w0, a, a, e) for (w0, a, e) in segs])):
            prev = None
            for (w0, s_fit, s_out, e) in plan:
                if s_out >= last_t:
                    continue
                win = z[w0:s_fit][act[w0:s_fit]]
                if (win > 0).mean() < cfg["sparse_min_active"] or win.std() == 0:
                    continue
                try:
                    yh, sg, params, _, _, c = _fit_filter(z, ex, w0, s_fit, e, order, seas, cfg["sigma_floor"],
                                                          it1 if prev is not None else it0, prev)
                except Exception:  # noqa: BLE001
                    continue
                prev = params
                conv.append(c)
                out[proto][s_out:e, si] = yh[s_out - w0:]
                sig[proto][s_out:e, si] = sg[s_out - w0:]
    return ui, out, sig, conv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=40)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--maxiter", type=int, default=300)
    ap.add_argument("--refit-maxiter", type=int, default=150)
    a = ap.parse_args()
    for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[v] = "1"
    cfg = config.load(os.path.join(config.ROOT, "configs", "cert_r42.yaml"))
    Z, active, groups, ulist, days, signals = load_inputs(cfg)
    peer = loo_median(Z, active, groups)
    with open(os.path.join(cfg["results_dir"], "orders.json")) as fh:
        orders = json.load(fh)
    t0 = days.get_loc(pd.Timestamp(cfg["test_start"]))
    segs = segments(days, cfg["test_start"], cfg["rolling_window_days"])
    rng = np.random.default_rng(7)
    sample = rng.choice(len(ulist), a.users, replace=False)
    arr = os.path.join(cfg["results_dir"], "arrays")
    with open(os.path.join(arr, "meta.json")) as fh:
        meta = json.load(fh)
    yhat = np.load(os.path.join(arr, "yhat.npy"), mmap_mode="r")
    sgm = np.load(os.path.join(arr, "sigma.npy"), mmap_mode="r")
    dx = meta["detectors"].index("sarimax")
    from concurrent.futures import ProcessPoolExecutor
    tasks = [(ui, Z[ui], peer[ui], active[ui], cfg, orders, segs, t0, a.maxiter, a.refit_maxiter) for ui in sample]
    rows, conv = [], []
    pooled = {"fixed": {"dz": [], "flip": []}, "rolling": {"dz": [], "flip": []}}
    with ProcessPoolExecutor(max_workers=a.jobs) as ex:
        for ui, out, sig, c in ex.map(run_user, tasks):
            conv += c
            for proto in ("fixed", "rolling"):
                pi = meta["protocols"].index(proto)
                z_new = (Z[ui] - out[proto]) / sig[proto]
                z_old = (Z[ui] - yhat[pi, dx, ui]) / sgm[pi, dx, ui]
                m = np.isfinite(z_new) & active[ui][:, None]
                m[:t0] = False
                pooled[proto]["dz"].append(np.abs(z_new - z_old)[m])
                pooled[proto]["flip"].append(((z_new > 2.3263) != (z_old > 2.3263))[m])
                rows.append({"user": ulist[ui], "protocolo": proto, "n": int(m.sum()),
                             "dz_mediana": float(np.nanmedian(np.abs(z_new - z_old)[m])) if m.any() else np.nan,
                             "dz_p95": float(np.nanpercentile(np.abs(z_new - z_old)[m], 95)) if m.any() else np.nan,
                             "cambia_alerta_IP99": float(np.mean(((z_new > 2.3263) != (z_old > 2.3263))[m])) if m.any() else np.nan,
                             "corr_spearman_z": float(pd.Series(z_new[m]).corr(pd.Series(z_old[m]), method="spearman")) if m.sum() > 10 else np.nan})
    r = pd.DataFrame(rows)
    res = {"usuarios": a.users, "maxiter": a.maxiter, "refit_maxiter": a.refit_maxiter,
           "convergencia_con_mas_iteraciones": float(np.mean(conv)),
           "por_protocolo": r.groupby("protocolo")[["dz_mediana", "dz_p95", "cambia_alerta_IP99", "corr_spearman_z"]]
           .median().round(4).to_dict("index")}
    res["agregado"] = {}
    for proto, v in pooled.items():
        dz, fl = np.concatenate(v["dz"]), np.concatenate(v["flip"])
        res["agregado"][proto] = {"usuario_dia_senal": int(dz.size), "dz_mediana": float(np.median(dz)),
                                  "dz_p95": float(np.percentile(dz, 95)), "dz_p99": float(np.percentile(dz, 99)),
                                  "pct_cambia_alerta_IP99": float(100 * fl.mean())}
    out = os.path.join(cfg["results_dir"], "tables", "sensibilidad_convergencia_sarimax.json")
    with open(out, "w") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
