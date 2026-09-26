"""Figuras del artículo y del póster (PDF vectorial y PNG a 300 ppp).

Paleta derivada de JCUN 2026 y validada para daltonismo (validador del skill dataviz, modo
claro, orden global, user, seasonal_naive, arima, sarima, sarimax): coral y lima de la
plantilla, rojo y verde oscuros escalonados dentro de la banda de luminosidad, ocre y violeta
para los pasos intermedios. Estáticos en tonos cálidos, temporales en verdes; la identidad
nunca depende solo del color (rótulos, leyenda y tablas).
"""
from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy.signal import periodogram  # noqa: E402
from scipy.stats import norm  # noqa: E402

COLORS = {"global": "#ec6a52", "user": "#a3241f", "seasonal_naive": "#d4a017", "arima": "#6a5bb5",
          "sarima": "#8fbf45", "sarimax": "#2e6b25"}
NAMES = {"global": "Regla global", "user": "Línea base estática", "seasonal_naive": "Ingenuo estacional",
         "arima": "ARIMA", "sarima": "SARIMA", "sarimax": "SARIMAX + pares"}
SIGNAL_NAMES = {"logons": "Inicios de sesión", "after_hours_logons": "Inicios de sesión fuera de horario", "unique_pcs": "Equipos distintos usados",
                "usb_events": "Conexiones USB", "after_hours_usb": "USB fuera de horario",
                "file_events": "Copias a USB", "emails_sent": "Correos enviados",
                "external_emails": "Correos externos", "http_requests": "Solicitudes web"}
# Lectura de cada señal en términos de la amenaza (para títulos de figuras del póster y del artículo)
THREAT = {"logons": "inicios de sesión", "after_hours_logons": "accesos fuera de horario",
          "unique_pcs": "uso de equipos ajenos", "usb_events": "posible fuga de información por USB",
          "after_hours_usb": "posible fuga de información por USB fuera de horario",
          "file_events": "posible robo de información: archivos copiados a USB", "emails_sent": "correos enviados",
          "external_emails": "posible fuga por correo externo", "http_requests": "navegación web"}
SCEN_NAMES = {1: "Escenario 1\nfuga de información a WikiLeaks", 2: "Escenario 2\nrobo de datos antes de renunciar",
              3: "Escenario 3\nsabotaje con cuenta ajena"}
INK, INK2, GRID = "#0e0e0c", "#52514e", "#e4e2dc"
FS = 1.0   # multiplicador de fuentes: 1 para el artículo, mayor para el póster A0
WS = 1.0   # multiplicador del tamaño de la figura


def F(x: float) -> float:
    return x * FS


def W(size: tuple) -> tuple:
    return (size[0] * WS, size[1] * WS)


def _style(fs: float = 1.0, ws: float = 1.0):
    global FS, WS
    FS, WS = fs, ws
    plt.rcParams.update({
        "font.family": "Lato", "font.size": 9 * fs, "axes.edgecolor": INK2, "axes.labelcolor": INK,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.6, "xtick.color": INK2, "ytick.color": INK2, "legend.frameon": False,
        "figure.dpi": 150, "savefig.bbox": "tight", "pdf.fonttype": 42, "svg.fonttype": "path"})


def _comma(v, _pos=None):
    return f"{v:g}".replace(".", ",")


def _save(fig, out_dir, name):
    # Coma decimal en los ejes numéricos (los de fechas y los rotulados a mano no se tocan).
    from matplotlib.ticker import FuncFormatter, ScalarFormatter
    for ax in fig.axes:
        for axis in (ax.xaxis, ax.yaxis):
            if isinstance(axis.get_major_formatter(), ScalarFormatter):
                axis.set_major_formatter(FuncFormatter(_comma))
    exts = ("pdf", "png", "svg") if FS > 1 else ("pdf", "png")   # el póster usa SVG vectorial
    for ext in exts:
        fig.savefig(os.path.join(out_dir, f"{name}.{ext}"), dpi=300)
    plt.close(fig)


def fig_pr_auc(res: pd.DataFrame, out_dir: str):
    """PR-AUC con IC 95 % bootstrap por detector y protocolo (gráfico de puntos)."""
    order = ["global", "user", "seasonal_naive", "arima", "sarima", "sarimax"]
    fig, ax = plt.subplots(figsize=W((4.6, 2.6)))
    for k, (proto, mk, off) in enumerate([("rolling", "o", -0.13), ("fixed", "o", 0.13)]):
        r = res[res["protocolo"] == proto].set_index("detector").loc[order]
        y = np.arange(len(order)) + off
        col = [COLORS[d] for d in order]
        ax.hlines(y, r["PR_AUC_IC95_inf"], r["PR_AUC_IC95_sup"], color=col, lw=2)
        ax.scatter(r["PR_AUC"], y, s=36, marker=mk, facecolor=col if proto == "rolling" else "white",
                   edgecolor=col, lw=1.6, zorder=3, label="Reestimación mensual" if proto == "rolling" else "Origen fijo")
    ax.set_yticks(range(len(order)), [NAMES[d] for d in order])
    ax.invert_yaxis()
    ax.set_xlabel("PR-AUC (IC 95 % bootstrap por usuarios)")
    prev = res["prevalencia"].iloc[0]
    ax.axvline(prev, color=INK2, lw=0.8, ls=":")
    ax.text(prev, len(order) - 0.45, f" azar = {prev:.4f}".replace(".", ","), fontsize=F(7), color=INK2, va="top")
    ax.grid(axis="y", visible=False)
    leg = ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.02), ncol=2, fontsize=F(7))
    for h in leg.legend_handles:
        h.set_edgecolor(INK2)
    _save(fig, out_dir, "fig_pr_auc")


def fig_pr_curves(d: dict, A: np.ndarray, out_dir: str, proto_idx: int, detectors: list[str]):
    from sklearn.metrics import precision_recall_curve
    m, y = d["mask"], d["y"][d["mask"]]
    fig, ax = plt.subplots(figsize=W((3.6, 2.8)))
    for det in ["global", "user", "sarima", "sarimax"]:
        s = A[proto_idx, detectors.index(det)][m]
        p, r, _ = precision_recall_curve(y, s)
        ax.plot(r, p, color=COLORS[det], lw=2 if det == "sarimax" else 1.4, label=NAMES[det])
    ax.axhline(y.mean(), color=INK2, lw=0.8, ls=":")
    ax.set_xlabel("Proporción de días maliciosos detectados")
    ax.set_ylabel("Precisión")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, None)
    ax.legend(fontsize=F(7), loc="upper right")
    _save(fig, out_dir, "fig_curvas_pr")


def fig_forecast(d: dict, yhat, sig, meta: dict, user: str, signal: str, out_dir: str, name: str,
                 proto_idx: int, alpha: float, pad_before: int = 56, pad_after: int = 21,
                 size: tuple = (6.4, 3.8), legend_cols: int = 3, top: float = 0.80, modelo: str = "sarima",
                 cola: dict | None = None) -> dict:
    """Observado frente a esperado con la zona normal (bajo el límite del 99 %): línea base estática frente a `modelo`.

    Devuelve, por panel, cuántos días superan el límite y cuántos de ellos son maliciosos (para el pie de figura).
    """
    ui, si = meta["users"].index(user), meta["signals"].index(signal)
    days = pd.to_datetime(meta["days"])
    mal = np.where(d["y"][ui] == 1)[0]
    t0, t1 = max(mal.min() - pad_before, meta["test_start_idx"]), min(mal.max() + pad_after, len(days) - 1)
    tt = np.arange(t0, t1 + 1)
    obs = np.expm1(d["Z"][ui, tt, si])
    crit = norm.ppf(1 - alpha)
    fig, axes = plt.subplots(2, 1, figsize=W(size), sharex=True)
    act = d["active"][ui, tt]
    dx = meta["detectors"].index(modelo)
    up_x = np.expm1(yhat[proto_idx, dx, ui, tt, si] + crit * sig[proto_idx, dx, ui, tt, si])
    ymax = max(np.nanmax(np.where(act, obs, np.nan)) * 1.35, np.nanpercentile(np.where(act, up_x, np.nan), 90) * 1.1) + 1
    handles, conteo = {}, {}
    titulos = {"user": "Línea base estática: el mismo límite todos los días",
               modelo: f"{NAMES[modelo]}: un límite que cambia con el día de la semana"}
    for ax, det in zip(axes, ["user", modelo]):
        di = meta["detectors"].index(det)
        mu, sd = yhat[proto_idx, di, ui, tt, si], sig[proto_idx, di, ui, tt, si]
        up = np.expm1(mu + crit * sd)
        banda = ax.fill_between(days[tt], 0, np.minimum(up, ymax * 1.5), color=COLORS[det], alpha=0.18, lw=0, step="mid")
        esperado, = ax.plot(days[tt], np.expm1(mu), color=COLORS[det], lw=1.6, drawstyle="steps-mid")
        # la leyenda muestra los colores de ambos paneles (línea base estática y modelo)
        handles.setdefault("Bajo el límite estimado del 99 %", []).append(banda)
        handles.setdefault("Esperado", []).append(esperado)
        handles["Observado"], = ax.plot(days[tt], obs, color=INK, lw=1.0, marker="o", ms=2.2, drawstyle="steps-mid")
        alert = (obs > up) & d["mask"][ui, tt]
        conteo[det] = [int(alert.sum()), int((alert & (d["y"][ui, tt] == 1)).sum())]
        if cola is not None and det in cola:   # días que entraron en la cola diaria de k alertas (criterio distinto)
            q = cola[det][tt] & d["mask"][ui, tt]
            conteo[det + "_cola"] = [int(q.sum()), int((q & (d["y"][ui, tt] == 1)).sum())]
            handles["En la cola de 10 alertas"] = ax.scatter(days[tt][q], np.full(q.sum(), ymax * 0.93), marker="v",
                                                             s=34, color=INK, zorder=5)
        handles["Sobre el límite"] = ax.scatter(days[tt][alert], obs[alert], s=46, facecolor="none",
                                                             edgecolor="#d91b1b", lw=1.5, zorder=4)
        mm = d["y"][ui, tt] == 1
        for x in days[tt][mm]:
            handles["Día malicioso"] = ax.axvspan(x - pd.Timedelta(hours=12), x + pd.Timedelta(hours=12),
                                                               color="#8c8a80", alpha=0.28, lw=0)
        ylab = {"usb_events": "Memorias USB/día", "file_events": "Archivos a USB/día",
                "external_emails": "Correos externos/día"}.get(signal, "Por día")
        ax.set_ylabel("")
        ax.set_title(titulos[det], loc="left", fontsize=F(9), color=INK)
        ax.set_ylim(0, ymax)
    order = ["Observado", "Sobre el límite", "En la cola de 10 alertas", "Día malicioso", "Esperado",
             "Bajo el límite estimado del 99 %"]
    order = [k for k in order if k in handles]
    fig.supylabel(ylab if FS > 1 else "Por día", fontsize=F(8), x=0.01)
    fig.subplots_adjust(top=top, hspace=0.35, left=0.08, right=0.99)
    if legend_cols:   # la leyenda ocupa exactamente el ancho de los ejes: el gráfico usa todo el ancho
        from matplotlib.legend_handler import HandlerTuple
        hs = [tuple(handles[k]) if isinstance(handles[k], list) else handles[k] for k in order]
        fig.legend(hs, order, loc="lower center", bbox_to_anchor=(0.535, top + 0.06),
                   ncol=legend_cols, fontsize=F(6.5), frameon=False, columnspacing=1.2, handlelength=2.4,
                   handler_map={tuple: HandlerTuple(ndivide=None, pad=0.3)})
    import matplotlib.dates as mdates
    axes[1].xaxis.set_major_locator(mdates.MonthLocator())
    axes[1].xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    _save(fig, out_dir, name)
    return conteo


def fig_identification(Z: np.ndarray, meta: dict, user: str, out_dir: str):
    from statsmodels.tsa.stattools import acf, pacf
    ui, si = meta["users"].index(user), meta["signals"].index("logons")
    x = Z[ui, :meta["test_start_idx"], si].astype(float)
    band = 2 / np.sqrt(len(x))
    fig, axes = plt.subplots(1, 3, figsize=W((7.0, 2.1)))
    for ax, vals, title in [(axes[0], acf(x, nlags=28, fft=True)[1:], "FAC"), (axes[1], pacf(x, nlags=28)[1:], "FACP")]:
        lags = np.arange(1, 29)
        ax.vlines(lags, 0, vals, color=[COLORS["sarimax"] if lg % 7 == 0 else INK2 for lg in lags], lw=1.6)
        ax.axhspan(-band, band, color=GRID, alpha=0.8, lw=0)
        ax.set_title(title, loc="left", fontsize=F(9))
        ax.set_xlabel("Rezago (días)")
        ax.set_xticks([7, 14, 21, 28])
    f, p = periodogram(x - x.mean())
    axes[2].plot(1 / f[1:], p[1:], color=COLORS["sarimax"], lw=1.2)
    axes[2].set_xscale("log")
    axes[2].set_xticks([2, 3.5, 7, 14, 30, 60], ["2", "3,5", "7", "14", "30", "60"])
    axes[2].set_title("Periodograma", loc="left", fontsize=F(9))
    axes[2].set_xlabel("Periodo (días)")
    fig.suptitle(f"Identificación: log(1 + inicios de sesión) del usuario {user}, entrenamiento", fontsize=F(8), color=INK2, x=0.01,
                 ha="left", y=1.04)
    _save(fig, out_dir, "fig_identificacion")


def fig_incidents(inc: pd.DataFrame, rule: str, proto: str, out_dir: str):
    """Porcentaje de incidentes detectados por escenario (misma escala en los tres paneles)."""
    order = ["global", "user", "seasonal_naive", "arima", "sarima", "sarimax"]
    t = inc[(inc["regla"] == rule) & (inc["protocolo"] == proto)]
    tab = t.groupby(["detector", "scenario"])["detectado"].sum().unstack().reindex(order)
    tot = t.groupby(["detector", "scenario"]).size().unstack().reindex(order)
    fig, axes = plt.subplots(1, 3, figsize=W((7.0, 2.5)), sharey=True, sharex=True)
    titles = SCEN_NAMES
    for ax, sc in zip(axes, (1, 2, 3)):
        share = 100 * tab[sc] / tot[sc]
        ax.barh(range(len(order)), share, color=[COLORS[d] for d in order], height=0.62)
        for i, v in enumerate(share):
            ax.text(min(v, 100) + 3, i, f"{int(tab[sc].iloc[i])}/{int(tot[sc].iloc[i])}", va="center",
                    fontsize=F(7), color=INK)
        ax.set_xlim(0, 135)
        ax.set_xticks([0, 50, 100], ["0 %", "50 %", "100 %"])
        ax.set_title(titles[sc], loc="left", fontsize=F(7.5), color=INK)
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(range(len(order)), [NAMES[d] for d in order])
    axes[0].invert_yaxis()
    fig.supxlabel("Incidentes detectados (al menos una alerta en uno de sus días maliciosos)", fontsize=F(8),
                  color=INK2, y=-0.06)
    fig.subplots_adjust(wspace=0.12)
    _save(fig, out_dir, "fig_incidentes_escenario")


def fig_budget(curvas: pd.DataFrame, proto: str, out_dir: str, name: str = "fig_presupuesto_alertas",
               size: tuple = (7.0, 2.6)):
    """Detecciones a igual carga de trabajo: con k alertas revisadas por día, cuántos días maliciosos e
    incidentes detecta cada detector. Es la comparación justa entre detectores."""
    c = curvas[curvas["protocolo"] == proto]
    fig, axes = plt.subplots(1, 2, figsize=W(size))
    dets = ["global", "user", "arima", "sarima", "sarimax"]
    for ax, col, ttl, tot in ((axes[0], "dias_maliciosos_detectados", "Días maliciosos detectados", 986),
                              (axes[1], "incidentes_detectados", "Incidentes detectados", 70)):
        for det in dets:
            x = c[c["detector"] == det].sort_values("k")
            ax.plot(x["k"], x[col], color=COLORS[det], lw=2.4 if det == "sarima" else 1.6, label=NAMES[det],
                    ls="-" if det in ("global", "user", "sarima") else (0, (4, 1.5)))
        ax.axvline(10, color=INK2, lw=0.8, ls=":")
        if col == "dias_maliciosos_detectados":   # une la figura con la columna «10/día» de la tabla
            ax.text(10.6, 0.2, "10 al día (Tabla 1)", transform=ax.get_xaxis_transform(), fontsize=F(6.2),
                    color=INK2, va="bottom", ha="left")   # entre la regla global y las demás curvas
        ax.set_title(f"{ttl} (de {tot})", loc="left", fontsize=F(8.5), color=INK)
        ax.set_xlabel("Alertas revisadas por día", fontsize=F(8))
        ax.set_xlim(1, c["k"].max())
        ax.set_ylim(0, None)
    axes[1].legend(fontsize=F(6.8), loc="center right", bbox_to_anchor=(1.0, 0.6), frameon=False)   # zona vacía del panel de incidentes
    _save(fig, out_dir, name)


def fig_daily_alerts(daily: pd.DataFrame, proto: str, rule: str, out_dir: str):
    t = daily[(daily["protocolo"] == proto) & (daily["regla"] == rule)].copy()
    t["day"] = pd.to_datetime(t["day"])
    t = t[t["alertas"] > 0]
    fig, ax = plt.subplots(figsize=W((6.4, 2.2)))
    for det in ["global", "user", "sarimax"]:
        s = t[t["detector"] == det].set_index("day")["alertas"].rolling(7, min_periods=1).mean()
        ax.plot(s.index, s.values, color=COLORS[det], lw=1.6, label=NAMES[det])
    ax.set_ylabel("Alertas por día\n(media móvil 7 días)")
    ax.set_ylim(0, None)
    ax.legend(fontsize=F(7), ncol=3, loc="upper left")
    _save(fig, out_dir, "fig_alertas_diarias")


def run(cfg: dict) -> dict:
    info = {}
    for variant, fs, ws in (("figures", 1.0, 1.0), ("figures_poster", 1.45, 1.2)):
        _style(fs, ws)
        info = _run_variant(cfg, os.path.join(cfg["results_dir"], variant))
    return info


def _run_variant(cfg: dict, out: str) -> dict:
    from .evaluate import load
    os.makedirs(out, exist_ok=True)
    d = load(cfg)
    meta = d["meta"]
    arr = os.path.join(cfg["results_dir"], "arrays")
    A = np.load(os.path.join(arr, "A.npy"))
    yhat = np.load(os.path.join(arr, "yhat.npy"), mmap_mode="r")
    sig = np.load(os.path.join(arr, "sigma.npy"), mmap_mode="r")
    tabs = os.path.join(cfg["results_dir"], "tables")
    res = pd.read_csv(os.path.join(tabs, "deteccion_resumen.csv"))
    inc = pd.read_csv(os.path.join(tabs, "incidentes_detalle.csv"))
    daily = pd.read_csv(os.path.join(tabs, "alertas_diarias.csv"))
    pi = meta["protocols"].index("rolling")
    rule = f"top{cfg['budget_k']}_dia"

    fig_pr_auc(res, out)
    fig_pr_curves(d, A, out, pi, meta["detectors"])
    fig_incidents(inc, rule, "rolling", out)
    fig_daily_alerts(daily, "rolling", "IP99_R1", out)
    curvas = pd.read_csv(os.path.join(tabs, "presupuesto_alertas.csv"))
    fig_budget(curvas, "rolling", out, size=(7.0, 1.95) if FS > 1 else (7.0, 2.6))

    # Ejemplo ilustrativo (regla fija, declarada): el incidente que SARIMA, el modelo principal, detecta
    # con el presupuesto diario y que ni la regla global ni la línea base estática detectan; entre
    # ellos, el de mayor puntaje A. Si no hay ninguno, el de mayor A de SARIMA.
    MOD = "sarima"
    t = inc[(inc["regla"] == rule) & (inc["protocolo"] == "rolling")]
    piv = t.pivot_table(index="incident", columns="detector", values="detectado", aggfunc="first")
    only = piv[(piv[MOD] == True) & (piv["global"] == False) & (piv["user"] == False)].index  # noqa: E712
    cand = t[(t["detector"] == MOD) & t["incident"].isin(only if len(only) else piv.index)]
    ex = cand.sort_values("A_max", ascending=False).iloc[0]
    ui = meta["users"].index(ex["incident"])
    from .evaluate import budget_alerts
    cola = {det: budget_alerts(A[pi, meta["detectors"].index(det)], d["mask"], cfg["budget_k"])[ui]
            for det in ("user", MOD)}
    if FS > 1:   # póster: más apaisada para que quepa en la caja de resultados
        conteo = fig_forecast(d, yhat, sig, meta, ex["incident"], ex["senal_top"], out, "fig_pronostico_insider", pi,
                              cfg["alpha"], size=(6.8, 2.35), legend_cols=3, top=0.78, modelo=MOD, cola=cola)
    else:
        conteo = fig_forecast(d, yhat, sig, meta, ex["incident"], ex["senal_top"], out, "fig_pronostico_insider", pi,
                              cfg["alpha"], modelo=MOD, cola=cola)
    # Versión compacta para el artículo LNCS (misma información, menos alto)
    fig_forecast(d, yhat, sig, meta, ex["incident"], ex["senal_top"], out, "fig_pronostico_insider_compacta", pi,
                 cfg["alpha"], size=(6.8, 1.7), legend_cols=0, top=0.89, modelo=MOD)
    fig_identification(d["Z"], meta, ex["incident"], out)
    info = {"ejemplo": {"incidente": ex["incident"], "escenario": int(ex["scenario"]), "senal": ex["senal_top"],
                        "modelo": MOD, "solo_temporal": bool(ex["incident"] in only), "usuario_idx": ui,
                        "dias_maliciosos": int((d["y"][ui] == 1).sum()),
                        "solo_temporal_todos": sorted(map(str, only)),
                        "alertas_en_figura": conteo}}   # por panel: [días sobre el límite, de ellos maliciosos]
    with open(os.path.join(out, "figuras_info.json"), "w") as fh:
        json.dump(info, fh, indent=2)
    return info
