"""Control de sensibilidad: línea base estática POR DÍA DE LA SEMANA.

    python scripts/linea_base_semanal.py [--config configs/cert_r42.yaml]

Motivo: los SARIMA(0,0,0)(1,0,1)7 estimados tienen Φ ≈ 1 y Θ ≈ -1 (mediana 0,997 y -1,00 en fits.parquet),
así que en la práctica aprenden un perfil por día de la semana. Este script mide si un competidor sin modelo,
la media y la desviación de cada usuario, contador y día de la semana en la misma ventana, logra lo mismo.

Mismo diseño que la línea base estática de detectors.py: ventanas de detectors.segments (reentrenamiento mensual
con 182 días) y origen fijo, solo días activos, piso de desviación cfg["sigma_floor"], y media del usuario en las
series casi vacías (menos de cfg["sparse_min_active"] días con actividad) o cuando un día de la semana tiene menos
de 3 observaciones en la ventana. Se evalúa igual que evaluate.budget_curves: k = 1..30 alertas diarias, días
maliciosos e incidentes detectados, y un IC del 95 % por remuestreo de usuarios (mismos pesos y semilla).
Escribe results/tables/sensibilidad_linea_base_semanal.csv y .json. No modifica ningún resultado oficial.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
import yaml
from scipy.stats import norm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from ueba_ts.detectors import segments  # noqa: E402
from ueba_ts.evaluate import budget_alerts, load, weighted_ap  # noqa: E402


def dow_baseline(Z, active, days, cfg, t0):
    """yhat y sigma (P, U, T, S) de la línea base por día de la semana, para los protocolos fixed y rolling."""
    floor, min_act = cfg["sigma_floor"], cfg["sparse_min_active"]
    U, T, S = Z.shape
    dow = np.asarray(days.dayofweek)
    segs = segments(days, cfg["test_start"], cfg["rolling_window_days"])
    plans = {"fixed": [(0, t0, 0, T)], "rolling": [(w0, s, s, e) for (w0, s, e) in segs]}
    out = {}
    for proto, plan in plans.items():
        yh = np.full((U, T, S), np.nan, np.float32)
        sg = np.full_like(yh, np.nan)
        for (w0, s_fit, s_out, e) in plan:
            a = active[:, w0:s_fit]
            dw = dow[w0:s_fit]
            dw_out = dow[s_out:e]
            for si in range(S):
                z = Z[:, w0:s_fit, si]
                zz = np.where(a, z, np.nan)
                n = a.sum(axis=1)
                mu_u = np.nanmean(zz, axis=1)
                sd_u = np.maximum(np.nanstd(zz, axis=1), floor)
                frac = np.where(n > 0, np.nansum(zz > 0, axis=1) / np.maximum(n, 1), 0.0)
                sparse = (frac < min_act) | ~(np.nanstd(zz, axis=1) > 0)
                mu_d = np.empty((U, 7)); sd_d = np.empty((U, 7))
                for k in range(7):
                    col = zz[:, dw == k]
                    nk = np.isfinite(col).sum(axis=1)
                    with np.errstate(all="ignore"):
                        m_k = np.nanmean(col, axis=1)
                        s_k = np.nanstd(col, axis=1)
                    few = (nk < 3) | sparse
                    mu_d[:, k] = np.where(few, mu_u, m_k)
                    sd_d[:, k] = np.where(few, sd_u, np.maximum(s_k, floor))
                yh[:, s_out:e, si] = mu_d[:, dw_out]
                sg[:, s_out:e, si] = sd_d[:, dw_out]
        out[proto] = (yh, sg)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(ROOT, "configs", "cert_r42.yaml"))
    args = ap.parse_args()
    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)
    for k in ("results_dir", "processed_dir"):
        if not os.path.isabs(cfg[k]):
            cfg[k] = os.path.join(ROOT, cfg[k])
    d = load(cfg)
    meta = d["meta"]
    days = pd.to_datetime(meta["days"])
    t0 = meta["test_start_idx"]
    m, y = d["mask"], d["y"] == 1
    Aoff = np.load(os.path.join(cfg["results_dir"], "arrays", "A.npy"), mmap_mode="r")
    base = dow_baseline(d["Z"], d["active"], days, cfg, t0)

    incs = sorted(set(d["inc"][y]))
    inc_mask = {i: (d["inc"] == i) & y & m for i in incs}
    rng = np.random.default_rng(cfg["bootstrap"]["seed"])
    U = y.shape[0]
    W = rng.multinomial(U, np.full(U, 1 / U), size=cfg["bootstrap"]["n"])
    crit = norm.ppf(1 - cfg["alpha"])
    benign = m & ~y

    rows, diffs, resumen = [], [], {}
    for proto in ("rolling", "fixed"):
        pi = meta["protocols"].index(proto)
        yh, sg = base[proto]
        z = (d["Z"] - yh) / sg
        A_new = np.nan_to_num(np.clip(z, 0, None), nan=0.0).max(axis=-1)
        dets = {"semanal": A_new, "user": np.asarray(Aoff[pi, meta["detectors"].index("user")]),
                "sarima": np.asarray(Aoff[pi, meta["detectors"].index("sarima")])}
        tp = {}
        for name, A in dets.items():
            for k in range(1, 31):
                al = budget_alerts(A, m, k) & m
                tpu = (al & y).sum(axis=1)
                tp[(name, k)] = tpu
                rows.append({"protocolo": proto, "detector": name, "k": k, "alertas": int(al.sum()), "dias_maliciosos_detectados": int(tpu.sum()),
                             "incidentes_detectados": sum(bool((al & inc_mask[i]).any()) for i in incs)})
        for k in (3, 5, 10, 20):
            for ref in ("user", "sarima"):
                dlt = tp[("semanal", k)] - tp[(ref, k)]
                boot = W @ dlt
                diffs.append({"protocolo": proto, "k": k, "frente_a": ref, "diferencia_dias": int(dlt.sum()),
                              "IC95_inf": float(np.percentile(boot, 2.5)), "IC95_sup": float(np.percentile(boot, 97.5))})
        s = m.ravel()
        resumen[proto] = {
            "PR_AUC_semanal": weighted_ap(A_new.ravel()[s], y.ravel()[s]),
            "tasa_dias_normales_sobre_limite_por_contador": {
                meta["signals"][si]: float(np.nanmean(z[..., si][benign] > crit)) for si in range(z.shape[-1])},
        }
    curv = pd.DataFrame(rows)
    out = os.path.join(cfg["results_dir"], "tables")
    curv.to_csv(os.path.join(out, "sensibilidad_linea_base_semanal.csv"), index=False)
    res = {"diferencias": diffs, "resumen": resumen}
    with open(os.path.join(out, "sensibilidad_linea_base_semanal.json"), "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    w = curv.pivot_table(index=["protocolo", "k"], columns="detector", values="dias_maliciosos_detectados")
    wi = curv.pivot_table(index=["protocolo", "k"], columns="detector", values="incidentes_detectados")
    for proto in ("rolling", "fixed"):
        print(f"\n{proto}: días maliciosos detectados (incidentes)")
        for k in (3, 5, 10, 20):
            print(f"  k={k:2d}  semanal {int(w.loc[(proto, k), 'semanal']):4d} ({int(wi.loc[(proto, k), 'semanal'])})"
                  f"  estática {int(w.loc[(proto, k), 'user']):4d} ({int(wi.loc[(proto, k), 'user'])})"
                  f"  SARIMA {int(w.loc[(proto, k), 'sarima']):4d} ({int(wi.loc[(proto, k), 'sarima'])})")
        ws = w.loc[proto]
        print("  semanal > SARIMA en", int((ws["semanal"] > ws["sarima"]).sum()), "de 30 k;",
              "semanal > estática en", int((ws["semanal"] > ws["user"]).sum()), "de 30 k")
        print("  PR-AUC semanal:", round(resumen[proto]["PR_AUC_semanal"], 4))
    print(json.dumps(diffs, indent=0)[:1500])


if __name__ == "__main__":
    main()
