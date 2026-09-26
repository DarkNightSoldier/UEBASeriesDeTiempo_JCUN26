"""Evaluación en dos niveles, solo en el periodo de prueba y solo con usuario-día activos.

Calidad de la línea base (usuario-día benignos):
    MAE y RMSE en la escala log(1 + y), cobertura real del intervalo de predicción del 99 %,
    y Ljung-Box de los residuos de cada ajuste.
Calidad de la detección (prevalencia real, sin remuestreo):
    PR-AUC (métrica principal, Saito y Rehmsmeier, 2015) y ROC-AUC del puntaje A = max_j z_j^+.
    Regla del intervalo de predicción: alerta si alguna señal supera z_{1-alpha} (R >= 1) o dos (R >= 2).
    Presupuesto del SOC: los k usuario-día de mayor A cada día.
    Nivel incidente: detectado si hay al menos una alerta en uno de sus usuario-día maliciosos;
    demora = días desde el primer día malicioso hasta la primera alerta sobre un día malicioso.
Incertidumbre: bootstrap por conglomerados de usuarios (se remuestrean usuarios, no días).
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd
from scipy.stats import norm
from sklearn.metrics import roc_auc_score

LABELS = {"global": "Regla global", "user": "Línea base estática", "seasonal_naive": "Ingenuo estacional",
          "arima": "ARIMA", "sarima": "SARIMA", "sarimax": "SARIMAX + pares"}


def load(cfg: dict) -> dict:
    a = os.path.join(cfg["results_dir"], "arrays")
    with open(os.path.join(a, "meta.json")) as fh:
        meta = json.load(fh)
    Z = np.load(os.path.join(a, "Z.npy"))
    yhat = np.load(os.path.join(a, "yhat.npy"), mmap_mode="r")
    sig = np.load(os.path.join(a, "sigma.npy"), mmap_mode="r")
    active = np.load(os.path.join(a, "active.npy"))
    lab = pd.read_parquet(os.path.join(cfg["processed_dir"], "labels.parquet"))
    U, T = len(meta["users"]), len(meta["days"])
    uidx = {u: i for i, u in enumerate(meta["users"])}
    didx = {d: i for i, d in enumerate(pd.to_datetime(meta["days"]))}
    y = np.zeros((U, T), np.int8)
    inc = np.full((U, T), "", object)
    scen = np.zeros((U, T), np.int8)
    m = lab[(lab["is_malicious"] == 1) & lab["user"].isin(uidx)]
    for r in m.itertuples():
        i, t = uidx[r.user], didx[r.day]
        y[i, t], inc[i, t], scen[i, t] = 1, r.incident, r.scenario
    mask = active.copy()
    mask[:, :meta["test_start_idx"]] = False
    return {"meta": meta, "Z": Z, "yhat": yhat, "sigma": sig, "active": active, "y": y, "inc": inc,
            "scen": scen, "mask": mask}


def scores(d: dict, alpha: float):
    """z por señal, puntaje continuo A, señal dominante y número de señales que rompen el IP."""
    z = (d["Z"][None, None] - d["yhat"]) / d["sigma"]
    zp = np.nan_to_num(np.clip(z, 0, None), nan=0.0)
    A = zp.max(axis=-1)
    top = zp.argmax(axis=-1).astype(np.int8)
    R = (zp > norm.ppf(1 - alpha)).sum(axis=-1).astype(np.int8)
    return z, A, top, R


def weighted_ap(s: np.ndarray, y: np.ndarray, w: np.ndarray | None = None, order=None) -> float:
    """Average precision con el mismo tratamiento de empates que scikit-learn, con pesos opcionales."""
    if order is None:
        order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order].astype(float)
    w = np.ones_like(y) if w is None else w[order]
    tp, fp = np.cumsum(w * y), np.cumsum(w * (1 - y))
    idx = np.r_[np.where(np.diff(s))[0], len(s) - 1]
    tp, fp = tp[idx], fp[idx]
    if tp[-1] == 0:
        return np.nan
    prec = tp / np.maximum(tp + fp, 1e-12)
    rec = tp / tp[-1]
    return float(np.sum(np.diff(np.r_[0, rec]) * prec))


def budget_alerts(A: np.ndarray, mask: np.ndarray, k: int) -> np.ndarray:
    """Los k usuario-día con mayor puntaje cada día (solo con A > 0)."""
    Am = np.where(mask, A, -np.inf)
    alert = np.zeros_like(mask)
    for t in np.where(mask.any(axis=0))[0]:
        col = Am[:, t]
        top = np.argpartition(-col, k)[:k]
        top = top[np.isfinite(col[top]) & (col[top] > 0)]
        alert[top, t] = True
    return alert


def rule_metrics(alert: np.ndarray, d: dict) -> dict:
    m, y = d["mask"], d["y"].astype(bool)
    a = alert & m
    tp, fp = int((a & y).sum()), int((a & ~y).sum())
    fn = int((~a & y & m).sum())
    neg = int((~y & m).sum())
    ndays = int(m.any(axis=0).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "precision": prec, "recall": rec,
            "F1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "FP_por_1000_ud": 1000 * fp / max(neg, 1), "alertas_por_dia": (tp + fp) / max(ndays, 1)}


def incident_table(alert: np.ndarray, A: np.ndarray, top: np.ndarray, d: dict, days) -> pd.DataFrame:
    m = d["mask"]
    rows = []
    for inc in sorted(set(d["inc"][d["y"] == 1])):
        ii, tt = np.where((d["inc"] == inc) & (d["y"] == 1) & m)
        if len(ii) == 0:
            continue
        first = tt.min()
        hit = alert[ii, tt]
        k = np.argmax(A[ii, tt])
        rows.append({"incident": inc, "scenario": int(d["scen"][ii[0], tt[0]]), "dias_maliciosos": len(tt),
                     "detectado": bool(hit.any()),
                     "dias_detectados": int(hit.sum()),
                     "demora_dias": int(tt[hit].min() - first) if hit.any() else np.nan,
                     "A_max": float(A[ii[k], tt[k]]), "senal_top": d["meta"]["signals"][top[ii[k], tt[k]]],
                     "dia_A_max": str(days[tt[k]].date())})
    return pd.DataFrame(rows)


def budget_curves(d: dict, A: np.ndarray, cfg: dict, kmax: int = 30) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Comparación a igual carga de trabajo del SOC: con k alertas por día (k = 1..kmax), cuántos
    usuario-día maliciosos e incidentes detecta cada detector. Incluye un IC 95 % por bootstrap de
    usuarios para la diferencia de días maliciosos detectados de cada modelo temporal frente a la
    línea base estática (alertas fijas, se remuestrean los usuarios que las reciben)."""
    meta, m, y = d["meta"], d["mask"], d["y"] == 1
    incs = sorted(set(d["inc"][d["y"] == 1]))
    inc_mask = {i: (d["inc"] == i) & y & m for i in incs}
    rng = np.random.default_rng(cfg["bootstrap"]["seed"])
    U = y.shape[0]
    W = rng.multinomial(U, np.full(U, 1 / U), size=cfg["bootstrap"]["n"])
    rows, diffs = [], []
    for pi, p in enumerate(meta["protocols"]):
        tp_user = {}
        for di, det in enumerate(meta["detectors"]):
            for k in range(1, kmax + 1):
                al = budget_alerts(A[pi, di], m, k) & m
                tp_u = (al & y).sum(axis=1)                      # días maliciosos detectados por usuario
                rows.append({"protocolo": p, "detector": det, "k": k, "alertas": int(al.sum()),
                             "dias_maliciosos_detectados": int(tp_u.sum()),
                             "precision": float(tp_u.sum() / max(al.sum(), 1)),
                             "incidentes_detectados": sum(bool((al & inc_mask[i]).any()) for i in incs)})
                tp_user[(det, k)] = tp_u
        for det in ("arima", "sarima", "sarimax"):
            for k in (3, 5, 10, 20):
                dlt = tp_user[(det, k)] - tp_user[("user", k)]
                boot = W @ dlt
                diffs.append({"protocolo": p, "detector": det, "k": k, "diferencia_dias": int(dlt.sum()),
                              "IC95_inf": float(np.percentile(boot, 2.5)), "IC95_sup": float(np.percentile(boot, 97.5)),
                              "mejora_relativa": float(dlt.sum() / max(tp_user[("user", k)].sum(), 1))})
    return pd.DataFrame(rows), pd.DataFrame(diffs)


def run(cfg: dict) -> dict:
    out_t = os.path.join(cfg["results_dir"], "tables")
    os.makedirs(out_t, exist_ok=True)
    d = load(cfg)
    meta = d["meta"]
    days = pd.to_datetime(meta["days"])
    P, D, S = meta["protocols"], meta["detectors"], meta["signals"]
    z, A, top, R = scores(d, cfg["alpha"])
    np.save(os.path.join(cfg["results_dir"], "arrays", "A.npy"), A.astype(np.float32))
    np.save(os.path.join(cfg["results_dir"], "arrays", "top.npy"), top)
    np.save(os.path.join(cfg["results_dir"], "arrays", "R.npy"), R)

    m, y = d["mask"], d["y"]
    yv = y[m]
    user_of = np.broadcast_to(np.arange(y.shape[0])[:, None], y.shape)[m]
    rows, per_scen, incs, daily = [], [], [], []
    rng = np.random.default_rng(cfg["bootstrap"]["seed"])
    nb = cfg["bootstrap"]["n"]
    W = rng.multinomial(y.shape[0], np.full(y.shape[0], 1 / y.shape[0]), size=nb)  # pesos por usuario
    boot = {}
    for pi, p in enumerate(P):
        for di, det in enumerate(D):
            s = A[pi, di][m]
            order = np.argsort(-s, kind="mergesort")
            ap = weighted_ap(s, yv, order=order)
            boot[(p, det)] = np.array([weighted_ap(s, yv, W[b][user_of], order) for b in range(nb)])
            r = {"protocolo": p, "detector": det, "nombre": LABELS[det], "PR_AUC": ap,
                 "PR_AUC_IC95_inf": float(np.nanpercentile(boot[(p, det)], 2.5)),
                 "PR_AUC_IC95_sup": float(np.nanpercentile(boot[(p, det)], 97.5)),
                 "ROC_AUC": float(roc_auc_score(yv, s)), "prevalencia": float(yv.mean()),
                 "usuario_dia_prueba": int(m.sum())}
            rules = {"IP99_R1": R[pi, di] >= 1, "IP99_R2": R[pi, di] >= 2,
                     f"top{cfg['budget_k']}_dia": budget_alerts(A[pi, di], m, cfg["budget_k"])}
            for name, al in rules.items():
                rm = rule_metrics(al, d)
                it = incident_table(al, A[pi, di], top[pi, di], d, days)
                r.update({f"{name}_{k}": v for k, v in rm.items()})
                r[f"{name}_incidentes_detectados"] = int(it["detectado"].sum())
                r[f"{name}_demora_mediana"] = float(it.loc[it["detectado"], "demora_dias"].median())
                incs.append(it.assign(protocolo=p, detector=det, regla=name))
                for sc in (1, 2, 3):
                    ys = (d["scen"] == sc) & m
                    per_scen.append({"protocolo": p, "detector": det, "regla": name, "escenario": sc,
                                     "recall_ud": float((al & ys).sum() / max(ys.sum(), 1)),
                                     "incidentes": int((it["scenario"] == sc).sum()),
                                     "incidentes_detectados": int(it.loc[it["scenario"] == sc, "detectado"].sum())})
                daily.append(pd.DataFrame({"day": days, "protocolo": p, "detector": det, "regla": name,
                                           "alertas": (al & m).sum(axis=0), "verdaderas": (al & m & (y == 1)).sum(axis=0)}))
            for sc in (1, 2, 3):
                keep = (d["scen"][m] == sc) | (yv == 0)
                per_scen.append({"protocolo": p, "detector": det, "regla": "PR_AUC", "escenario": sc,
                                 "PR_AUC": weighted_ap(s[keep], (yv[keep] == 1).astype(int))})
            rows.append(r)
            print(f"  {p:8s} {det:15s} PR-AUC={ap:.4f}", flush=True)
    res = pd.DataFrame(rows)
    res.to_csv(os.path.join(out_t, "deteccion_resumen.csv"), index=False)
    pd.DataFrame(per_scen).to_csv(os.path.join(out_t, "deteccion_por_escenario.csv"), index=False)
    incs = pd.concat(incs)
    incs.to_csv(os.path.join(out_t, "incidentes_detalle.csv"), index=False)
    pd.concat(daily).to_csv(os.path.join(out_t, "alertas_diarias.csv"), index=False)

    # Diferencias de PR-AUC con IC bootstrap (mismos remuestreos de usuarios para ambos detectores)
    diffs = []
    for p in P:
        for a_ in D:
            for b_ in D:
                if a_ == b_:
                    continue
                dlt = boot[(p, a_)] - boot[(p, b_)]
                base = res[(res["protocolo"] == p)].set_index("detector")["PR_AUC"]
                diffs.append({"protocolo": p, "detector": a_, "frente_a": b_, "diferencia": base[a_] - base[b_],
                              "IC95_inf": float(np.nanpercentile(dlt, 2.5)), "IC95_sup": float(np.nanpercentile(dlt, 97.5)),
                              "p_bootstrap_unilateral": float(np.mean(dlt <= 0))})
    for det in D:
        dlt = boot[("rolling", det)] - boot[("fixed", det)]
        base = res.set_index(["protocolo", "detector"])["PR_AUC"]
        diffs.append({"protocolo": "rolling-fixed", "detector": det, "frente_a": det,
                      "diferencia": base[("rolling", det)] - base[("fixed", det)],
                      "IC95_inf": float(np.nanpercentile(dlt, 2.5)), "IC95_sup": float(np.nanpercentile(dlt, 97.5)),
                      "p_bootstrap_unilateral": float(np.mean(dlt <= 0))})
    pd.DataFrame(diffs).to_csv(os.path.join(out_t, "bootstrap_diferencias.csv"), index=False)

    # Lo que las reglas y las líneas base estáticas no ven (mismo presupuesto de alertas)
    rule = f"top{cfg['budget_k']}_dia"
    miss = []
    for p in P:
        det_sets = {det: set(incs[(incs["protocolo"] == p) & (incs["detector"] == det) & (incs["regla"] == rule)
                                 & incs["detectado"]]["incident"]) for det in D}
        static = det_sets["global"] | det_sets["user"]
        for det in ("seasonal_naive", "arima", "sarima", "sarimax"):
            only = sorted(det_sets[det] - static)
            miss.append({"protocolo": p, "detector": det, "regla": rule,
                         "detectados": len(det_sets[det]), "detectados_por_estaticos": len(static),
                         "solo_temporal": len(only), "incidentes_solo_temporal": ";".join(only),
                         "perdidos_vs_estaticos": len(static - det_sets[det])})
    pd.DataFrame(miss).to_csv(os.path.join(out_t, "lo_que_no_ven.csv"), index=False)

    # Calidad de la línea base: días benignos de prueba, escala log(1 + y)
    crit2, crit1 = norm.ppf(1 - cfg["alpha"] / 2), norm.ppf(1 - cfg["alpha"])
    benign = m & (y == 0)
    fq = []
    for pi, p in enumerate(P):
        for di, det in enumerate(D):
            for si, s_ in enumerate(S):
                e = (d["Z"][:, :, si] - d["yhat"][pi, di, :, :, si])[benign]
                zz = z[pi, di, :, :, si][benign]
                fq.append({"protocolo": p, "detector": det, "signal": s_, "MAE": float(np.nanmean(np.abs(e))),
                           "RMSE": float(np.sqrt(np.nanmean(e ** 2))),
                           "cobertura_IP99_bilateral": float(np.nanmean(np.abs(zz) <= crit2)),
                           "tasa_z_sobre_umbral": float(np.nanmean(zz > crit1))})
    fq = pd.DataFrame(fq)
    fq.to_csv(os.path.join(out_t, "calidad_linea_base.csv"), index=False)

    curvas, dif = budget_curves(d, A, cfg)
    curvas.to_csv(os.path.join(out_t, "presupuesto_alertas.csv"), index=False)
    dif.to_csv(os.path.join(out_t, "presupuesto_diferencias.csv"), index=False)

    fits = pd.read_parquet(os.path.join(cfg["results_dir"], "fits.parquet"))
    ok = fits[fits["status"] == "ok"]
    lb = ok.groupby(["protocol", "detector", "signal"]).agg(
        ajustes=("status", "size"), pct_ljungbox_no_rechaza=("ljungbox_p", lambda v: float((v > 0.05).mean())),
        mediana_p=("ljungbox_p", "median")).reset_index()
    lb.to_csv(os.path.join(out_t, "ljungbox_resumen.csv"), index=False)

    cols = ["protocolo", "detector", "PR_AUC", "PR_AUC_IC95_inf", "PR_AUC_IC95_sup", "ROC_AUC",
            f"{rule}_precision", f"{rule}_recall", f"{rule}_incidentes_detectados",
            "IP99_R1_FP_por_1000_ud", "IP99_R1_recall", "IP99_R2_FP_por_1000_ud", "IP99_R2_recall"]
    return {"resumen": res[cols].round(4).to_dict("records")}
