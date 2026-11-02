"""App dinámica: UEBA basado en series de tiempo sobre CERT r4.2.

Ejecutar en local:   python -m app.app            (http://127.0.0.1:8050)
Producción:          gunicorn app.app:server      (ver Procfile y Dockerfile)

Enlaces directos:    /?tab=explorador&user=AAM0658&signal=usb_events
"""
from __future__ import annotations

import os
from urllib.parse import parse_qs, urlencode

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from dash import Dash, Input, Output, State, dash_table, dcc, html, no_update
from plotly.subplots import make_subplots
from scipy.stats import norm

from .store import (COLORS, DETECTORS, NAMES, PROTOCOLS, SCENARIOS, SIGNALS, Store, average_precision,
                    budget_alerts, evaluate, pr_curve, roc_auc)

ST = Store()
FONT = "Lato, 'Segoe UI', sans-serif"
INK, INK2, GRID, SURFACE = "#0e0e0c", "#52514e", "#e4e2dc", "#ffffff"
TITLE_L1 = "Detectando lo que las reglas y las líneas base no ven:"
TITLE_L2 = "UEBA basado en series de tiempo"
TITLE = TITLE_L1 + " " + TITLE_L2


def fig_base(fig: go.Figure, height: int = 360) -> go.Figure:
    fig.update_layout(template="simple_white", font=dict(family=FONT, size=13, color=INK), height=height,
                      margin=dict(l=10, r=10, t=64, b=10), paper_bgcolor=SURFACE, plot_bgcolor=SURFACE,
                      legend=dict(orientation="h", y=1.02, yanchor="bottom", x=0, xanchor="left"),
                      hoverlabel=dict(font_family=FONT), separators=",.")
    fig.update_xaxes(showgrid=True, gridcolor=GRID, linecolor=INK2, ticks="outside", tickcolor=INK2)
    fig.update_yaxes(showgrid=True, gridcolor=GRID, linecolor=INK2, ticks="outside", tickcolor=INK2)
    return fig


GCFG = {"displaylogo": False, "responsive": True, "modeBarButtonsToRemove": ["lasso2d", "select2d"]}
H = lambda px: {"height": f"{px}px", "width": "100%"}   # con responsive=True la altura va en el contenedor
DATEFMT = dict(tickformat="%d/%m/%Y", hoverformat="%d/%m/%Y")   # fechas numéricas: sin nombres de meses en inglés


def fmt(x, nd=3):
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "n. d."
    return f"{x:,.{nd}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def pct(x, nd=1):
    return fmt(100 * x, nd) + " %"


def table(df: pd.DataFrame, id_=None, page=12, style_data_conditional=None, **kw):
    zebra = [{"if": {"row_index": "odd"}, "backgroundColor": "#fafaf8"}]
    args = dict(columns=[{"name": c, "id": c} for c in df.columns], data=df.to_dict("records"),
                page_size=page, sort_action="native", style_as_list_view=True,
                style_table={"overflowX": "auto"},
                style_cell={"fontFamily": FONT, "fontSize": 13, "padding": "6px 8px", "textAlign": "left",
                            "whiteSpace": "normal", "height": "auto", "color": INK},
                style_header={"fontWeight": 700, "backgroundColor": "#f2f2f2", "borderBottom": f"2px solid {INK}"},
                style_data_conditional=zebra + (style_data_conditional or []), **kw)
    if id_:
        args["id"] = id_
    return dash_table.DataTable(**args)


def card(title, *children, icon=None):
    return html.Section(className="card", children=[html.H3(title, className="card-title"), *children])


def kpi(value, label):
    return html.Div(className="kpi", children=[html.Div(value, className="kpi-value"), html.Div(label, className="kpi-label")])


# ============================================================================ resumen
RES = ST.tables["deteccion_resumen"]
K = ST.meta["budget_k"]
N_INC = int(len(ST.incidents))
SCEN_COUNTS = ST.incidents["scenario"].value_counts().sort_index()
RULE = f"top{K}_dia"


def summary_findings() -> list:
    """Frases generadas a partir de las tablas oficiales (ningún número escrito a mano)."""
    tp, inc, alerts, k_eq, dif = budget_numbers()
    r = RES.set_index(["protocolo", "detector"])
    b = DIFS[(DIFS["protocolo"] == "fixed") & (DIFS["detector"] == "sarima") & (DIFS["k"] == K)].iloc[0]
    bt = ST.tables["bootstrap_diferencias"]
    ab = bt[(bt["protocolo"] == "rolling") & (bt["detector"] == "sarima") & (bt["frente_a"] == "arima")].iloc[0]
    ratio = k_eq / K
    esfuerzo = "casi el doble" if 1.7 <= ratio < 2 else ("el doble o más" if ratio >= 2 else "más trabajo")
    return [
        html.Li([html.B(f"{pct(dif['mejora_relativa'], 0)} más con el mismo trabajo. "),
                 f"Revisando {K} alertas al día, SARIMA encuentra {tp['sarima']} días de actividad maliciosa; la línea "
                 f"base estática, {tp['user']}, y la regla global, {tp['global']}. No depende de unos pocos usuarios: al "
                 f"remuestrearlos 1.000 veces, la ventaja de SARIMA quedó entre {round(dif['IC95_inf'])} y "
                 f"{round(dif['IC95_sup'])} días en el 95 % de los casos."]),
        html.Li([html.B("Casi todos los incidentes. "), f"Con esas mismas {K} alertas diarias, SARIMA detecta "
                 f"{inc['sarima']} de los {N_INC} incidentes; la línea base estática, {inc['user']}, y la regla global, "
                 f"{inc['global']}."]),
        html.Li([html.B("Más aciertos por alerta. "), "Para dar con un día malicioso, el analista revisa "
                 f"{fmt(alerts / tp['sarima'], 0)} alertas con SARIMA, {fmt(alerts / tp['user'], 0)} con la línea base "
                 f"estática y {fmt(alerts / tp['global'], 0)} con la regla global."]),
        html.Li([html.B(f"La línea base estática exige {esfuerzo}. "), f"Necesita {k_eq} alertas diarias para "
                 f"encontrar lo que SARIMA encuentra con {K}."]),
        html.Li([html.B("Lo que no favorece al modelo, también se muestra. "), "Sin reentrenar los modelos (origen "
                 f"fijo), SARIMA sigue encontrando más días maliciosos ({int(b['diferencia_dias'])} más con {K} alertas "
                 "diarias), pero en incidentes, con 6 a 11 alertas diarias, la línea base estática detecta más. Con "
                 "reentrenamiento mensual nunca supera al mejor modelo de series de tiempo; a SARIMA solo lo supera por "
                 "un incidente con 21 alertas diarias."]),
        html.Li([html.B("En una sola nota (PR-AUC, de 0 a 1). "), f"SARIMA obtiene "
                 f"{fmt(r.loc[('rolling', 'sarima'), 'PR_AUC'], 4)}; la línea base estática, "
                 f"{fmt(r.loc[('rolling', 'user'), 'PR_AUC'], 4)}, y la regla global, "
                 f"{fmt(r.loc[('rolling', 'global'), 'PR_AUC'], 4)}. Elegir al azar daría "
                 f"{fmt(r.loc[('rolling', 'global'), 'prevalencia'], 4)}. ARIMA obtiene "
                 f"{fmt(r.loc[('rolling', 'arima'), 'PR_AUC'], 4)}, pero su diferencia con SARIMA no es clara: el "
                 f"intervalo del 95 % va de {fmt(-ab['IC95_sup'], 4)} a {fmt(-ab['IC95_inf'], 4)} e incluye el cero."]),
    ]


def fig_prauc() -> go.Figure:
    fig = go.Figure()
    base = np.arange(len(DETECTORS))
    for p, sym, off in (("rolling", "circle", -0.17), ("fixed", "circle-open", 0.17)):
        r = RES[RES["protocolo"] == p].set_index("detector").loc[DETECTORS]
        fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name=PROTOCOLS[p],
                                 marker=dict(symbol=sym, size=12, color=INK2, line=dict(width=2, color=INK2))))
        fig.add_trace(go.Scatter(
            x=r["PR_AUC"], y=base + off, mode="markers", name=PROTOCOLS[p], showlegend=False,
            marker=dict(symbol=sym, size=12, color=[COLORS[d] for d in DETECTORS],
                        line=dict(width=2, color=[COLORS[d] for d in DETECTORS])),
            error_x=dict(type="data", symmetric=False, array=r["PR_AUC_IC95_sup"] - r["PR_AUC"],
                         arrayminus=r["PR_AUC"] - r["PR_AUC_IC95_inf"], color=INK2, thickness=1.5, width=0),
            customdata=np.stack([[NAMES[d] for d in DETECTORS], r["PR_AUC_IC95_inf"], r["PR_AUC_IC95_sup"]], axis=1),
            hovertemplate="%{customdata[0]}<br>PR-AUC %{x:.4f}<br>IC 95 %: %{customdata[1]:.4f} a %{customdata[2]:.4f}"
                          "<extra>" + PROTOCOLS[p] + "</extra>"))
    prev = RES["prevalencia"].iloc[0]
    fig.add_vline(x=prev, line_dash="dot", line_color=INK2, annotation_text=f"azar = {fmt(prev, 4)}",
                  annotation_position="bottom right")
    fig.update_yaxes(tickvals=base, ticktext=[NAMES[d] for d in DETECTORS], autorange="reversed", showgrid=False)
    fig.update_layout(xaxis_title="PR-AUC (nota de 0 a 1) con intervalo de confianza del 95 %")
    fig.update_xaxes(range=[0, 0.052])
    return fig_base(fig, 400)


def fig_scen_official(proto="rolling", rule=RULE) -> go.Figure:
    t = ST.tables["deteccion_por_escenario"]
    t = t[(t["protocolo"] == proto) & (t["regla"] == rule)]
    fig = go.Figure()
    for d in DETECTORS:
        x = t[t["detector"] == d].sort_values("escenario")
        fig.add_trace(go.Bar(x=[f"Esc. {s}" for s in x["escenario"]], y=x["incidentes_detectados"], name=NAMES[d],
                             marker_color=COLORS[d], marker_line_color=SURFACE, marker_line_width=2,
                             customdata=x["incidentes"],
                             hovertemplate="%{x}: %{y} de %{customdata} incidentes<extra>" + NAMES[d] + "</extra>"))
    fig.update_layout(barmode="group", yaxis_title="Incidentes detectados", bargap=0.25)
    return fig_base(fig, 360)


def ablation_table() -> pd.DataFrame:
    rows = []
    for _, r in RES.iterrows():
        rows.append({"Protocolo": PROTOCOLS[r["protocolo"]], "Detector": NAMES[r["detector"]],
                     "PR-AUC": fmt(r["PR_AUC"], 4),
                     "Intervalo del 95 %": f"{fmt(r['PR_AUC_IC95_inf'], 4)} a {fmt(r['PR_AUC_IC95_sup'], 4)}",
                     f"Aciertos por cada 100 alertas ({K}/día)": fmt(100 * r[f"{RULE}_precision"], 1),
                     f"Días maliciosos detectados ({K}/día)": pct(r[f"{RULE}_recall"]),
                     f"Incidentes detectados ({K} alertas/día)": f"{int(r[f'{RULE}_incidentes_detectados'])}/{N_INC}",
                     "Falsas alarmas por 1.000 usuario-día (límite 99 %)": fmt(r["IP99_R1_FP_por_1000_ud"], 1),
                     "Días maliciosos detectados (límite 99 %)": pct(r["IP99_R1_recall"]),
                     "Falsas alarmas por 1.000 usuario-día (2 contadores)": fmt(r["IP99_R2_FP_por_1000_ud"], 1),
                     "Días maliciosos detectados (2 contadores)": pct(r["IP99_R2_recall"])})
    return pd.DataFrame(rows)


def controles_semanal() -> pd.DataFrame:
    """Perfil por día de la semana (control temporal) frente a la línea base estática y SARIMA, mismas alertas."""
    w = ST.tables.get("sensibilidad_linea_base_semanal")
    if w is None:
        return pd.DataFrame({"Nota": ["Correr python scripts/linea_base_semanal.py"]})
    w = w[w["protocolo"] == "rolling"]
    rows = []
    for det, name in (("user", NAMES["user"]), ("semanal", "Perfil semanal (control)"), ("sarima", NAMES["sarima"])):
        x = w[w["detector"] == det].set_index("k")
        rows.append({"Detector": name, **{f"Días maliciosos ({kk} alertas/día)": int(x.loc[kk, "dias_maliciosos_detectados"])
                                          for kk in (3, 5, 10, 20)},
                     f"Incidentes ({K} alertas/día)": f"{int(x.loc[K, 'incidentes_detectados'])}/{N_INC}"})
    return pd.DataFrame(rows)


def tab_resumen():
    ing = ST.ingest
    r0 = RES.iloc[0]
    boot = ST.tables["bootstrap_diferencias"]
    keep = boot[((boot["detector"].isin(["sarimax", "sarima"])) & (boot["frente_a"].isin(["global", "user"])))
                | ((boot["detector"] == "sarima") & boot["frente_a"].isin(["arima", "sarimax"]))
                | (boot["protocolo"] == "rolling-fixed")].copy()
    keep = keep.sort_values("protocolo", key=lambda c: c.map({"rolling": 0, "fixed": 1}).fillna(2), kind="stable")
    keep["Comparación"] = [f"{NAMES[a]} menos {NAMES[b]}" if p != "rolling-fixed" else f"{NAMES[a]}: mensual menos fijo"
                           for a, b, p in zip(keep["detector"], keep["frente_a"], keep["protocolo"])]
    keep["Protocolo"] = keep["protocolo"].map(lambda p: PROTOCOLS.get(p, "Mensual menos fijo"))
    keep = keep.assign(**{"Diferencia PR-AUC": keep["diferencia"].map(lambda v: fmt(v, 4)),
                          "Intervalo del 95 %": [f"{fmt(a, 4)} a {fmt(b, 4)}" for a, b in zip(keep["IC95_inf"], keep["IC95_sup"])],
                          "¿Diferencia clara?": ["No" if a <= 0 <= b else "Sí" for a, b in zip(keep["IC95_inf"], keep["IC95_sup"])]})
    lq = ST.tables["lo_que_no_ven"].copy()
    lq = lq.assign(Protocolo=lq["protocolo"].map(PROTOCOLS), Detector=lq["detector"].map(NAMES))[
        ["Protocolo", "Detector", "detectados", "detectados_por_estaticos", "solo_temporal", "perdidos_vs_estaticos",
         "incidentes_solo_temporal"]].rename(columns={
            "detectados": "Incidentes que detecta (de 70)",
            "detectados_por_estaticos": "Los detecta la regla global o la línea base estática",
            "solo_temporal": "Solo los detecta este detector",
            "perdidos_vs_estaticos": "Los detectan las reglas, pero no este detector",
            "incidentes_solo_temporal": "Cuáles solo detecta este detector"})
    lq["Cuáles solo detecta este detector"] = lq["Cuáles solo detecta este detector"].fillna("").str.replace(";", ", ")
    fq = ST.tables["calidad_linea_base"]
    fq = fq.groupby(["protocolo", "detector"])[["MAE", "RMSE", "cobertura_IP99_bilateral", "tasa_z_sobre_umbral"]].mean().reset_index()
    fq = fq.assign(_p=fq["protocolo"].map({"rolling": 0, "fixed": 1}), _d=fq["detector"].map(DETECTORS.index)).sort_values(["_p", "_d"])
    fq = fq.assign(Protocolo=fq["protocolo"].map(PROTOCOLS), Detector=fq["detector"].map(NAMES),
                   **{"Error medio (MAE)": fq["MAE"].map(lambda v: fmt(v, 3)),
                      "Error cuadrático (RMSE)": fq["RMSE"].map(lambda v: fmt(v, 3)),
                      "Días normales dentro de la franja del 99 %": fq["cobertura_IP99_bilateral"].map(pct),
                      "Días normales sobre el límite del 99 %": fq["tasa_z_sobre_umbral"].map(lambda v: pct(v, 2))})
    fq = fq[["Protocolo", "Detector", "Error medio (MAE)", "Error cuadrático (RMSE)",
             "Días normales dentro de la franja del 99 %", "Días normales sobre el límite del 99 %"]]
    return html.Div([
        html.Div(className="kpis", children=[
            kpi(f"{ing['usuarios']:,}".replace(",", "."), "usuarios"), kpi(str(ing["dias"]), "días de historia"),
            kpi(f"{int(r0['usuario_dia_prueba']):,}".replace(",", "."), "usuario-día evaluados"),
            kpi(str(N_INC), "incidentes (" + ", ".join(str(int(v)) for v in SCEN_COUNTS.values[:-1]) + " y "
                + str(int(SCEN_COUNTS.values[-1])) + ")"), kpi(pct(r0["prevalencia"], 2), "de los usuario-día evaluados son maliciosos")]),
        card("Hallazgos principales", html.Ul(summary_findings(), className="findings"),
             html.P("Resultados oficiales del artículo, calculados por el proceso reproducible del repositorio (carpeta src/ueba_ts). "
                    "La pestaña Laboratorio permite recalcularlos con otras decisiones.", className="note")),
        html.Div(className="grid2", children=[
            card("PR-AUC por detector y protocolo", dcc.Graph(figure=fig_prauc(), config=GCFG, style=H(400)),
                 guide("el PR-AUC resume en un número qué tan arriba quedan los días maliciosos al ordenar todos los "
                       "días de la prueba juntos, del más al menos sospechoso. Más a la derecha es mejor; el azar obtiene "
                       "0,0032 (la línea punteada) porque solo el 0,32 % de los usuario-día es malicioso. Los círculos "
                       "llenos son con reentrenamiento mensual y los vacíos, sin reentrenar; el color es el detector. Las "
                       "rayas son intervalos de confianza del 95 %; si la diferencia entre dos detectores es clara lo dice "
                       "la tabla «¿Las diferencias son reales?» más abajo.")),
            card(f"Incidentes detectados con {K} alertas por día (reentrenamiento mensual)",
                 dcc.Graph(figure=fig_scen_official(), config=GCFG, style=H(360)))]),
        card("Todos los detectores y reglas de alerta", table(ablation_table(), page=12),
             guide(f"«{K}/día» significa que el SOC revisa los {K} usuarios más anómalos cada día. «Límite 99 %» significa "
                   "que se alerta cada vez que un contador supera su máximo normal esperado; «2 contadores», cuando lo "
                   "superan dos a la vez. Con reglas distintas cambia el número de alertas, por eso la comparación justa "
                   "entre detectores es la de igual número de alertas diarias (pestaña Inicio).")),
        card("Lo que las reglas y las líneas base no ven (mismo número de alertas)", table(lq, page=8),
             guide(f"todos con {K} alertas diarias. Cada fila compara un detector con la regla global y la línea base "
                   "estática juntas: un incidente cuenta si cualquiera de las dos lo detecta. Mire primero la fila de "
                   "SARIMA con reentrenamiento mensual: detecta 67 incidentes; las dos reglas juntas, 65. SARIMA encuentra "
                   "3 que ninguna de las dos ve (IKR0401, NWT0098 y XHW0498, los tres de robo de datos antes de "
                   "renunciar) y pierde 1 que la regla global sí ve (MOS0047, un usuario que ya conectaba memorias USB "
                   "fuera de horario casi todos los días: para su propio modelo eso era normal).")),
        card("¿Las diferencias son reales? Diferencias de PR-AUC con su intervalo del 95 %",
             guide("se repitió el cálculo 1.000 veces eligiendo usuarios al azar con reemplazo (remuestreo bootstrap). "
                   "Si el intervalo de la diferencia no incluye el cero, la ventaja no depende de qué usuarios hay en los "
                   "datos («¿Diferencia clara?: Sí»). Entre ARIMA, SARIMA y SARIMAX + pares la diferencia no es clara."),
             table(keep[["Protocolo", "Comparación", "Diferencia PR-AUC", "Intervalo del 95 %", "¿Diferencia clara?"]], page=14)),
        card("Controles adicionales: ¿de dónde viene la ventaja?", table(controles_semanal(), page=8),
             guide("para saber cuánto aporta el ritmo semanal se agregó un control: un perfil por día de la semana "
                   "(promedio y variación de cada usuario para cada día), sin modelo. También es un enfoque temporal y "
                   "también supera ampliamente a la línea base estática, lo que confirma que lo decisivo es modelar el "
                   f"ritmo semanal. Con {K} alertas diarias SARIMA encuentra más días maliciosos que el perfil; con 20, el "
                   "perfil encuentra más. Detalle en scripts/linea_base_semanal.py.")),
        card("Calidad del pronóstico en días normales (promedio de los 9 contadores)", table(fq, page=12),
             guide("los errores miden cuánto se equivoca el pronóstico en los días sin actividad maliciosa (menor es "
                   "mejor); se calculan en log(1 + conteo), la escala comprimida en la que trabajan los modelos. SARIMA "
                   "se equivoca mucho menos que la línea base estática. La última columna es la calibración del límite: "
                   "por diseño, un día normal lo supera cerca del 1 % de las veces; con SARIMA lo superó menos, así "
                   "que el límite es conservador (alerta de más solo en contados días normales).")),
    ])


# ============================================================================ inicio (recorrido guiado)
def guide(*parts):
    """Recuadro 'Cómo leer', siempre visible y en lenguaje llano."""
    return html.Div(className="guide", children=[html.B("Cómo leer: ")] + list(parts))


CURVAS = ST.tables["presupuesto_alertas"]
DIFS = ST.tables["presupuesto_diferencias"]
N_MAL = int(ST.y[ST.mask].sum())


def budget_numbers():
    c = CURVAS[CURVAS["protocolo"] == "rolling"]
    at = lambda d, k, col: c[(c["detector"] == d) & (c["k"] == k)][col].iloc[0]
    tp = {d: int(at(d, K, "dias_maliciosos_detectados")) for d in DETECTORS}
    inc = {d: int(at(d, K, "incidentes_detectados")) for d in DETECTORS}
    alerts = int(at("sarima", K, "alertas"))
    u = c[c["detector"] == "user"].sort_values("k")
    k_eq = int(u[u["dias_maliciosos_detectados"] >= tp["sarima"]]["k"].min())
    dif = DIFS[(DIFS["protocolo"] == "rolling") & (DIFS["detector"] == "sarima") & (DIFS["k"] == K)].iloc[0]
    return tp, inc, alerts, k_eq, dif


def fig_budget(col: str = "dias_maliciosos_detectados") -> go.Figure:
    """Una figura por métrica (días maliciosos o incidentes): en el teléfono quedan una debajo de la otra."""
    c = CURVAS[CURVAS["protocolo"] == "rolling"]
    fig = go.Figure()
    for d in ["global", "user", "arima", "sarima", "sarimax"]:
        x = c[c["detector"] == d].sort_values("k")
        fig.add_trace(go.Scatter(
            x=x["k"], y=x[col], mode="lines", name=NAMES[d],
            line=dict(color=COLORS[d], width=3.5 if d == "sarima" else 2,
                      dash="solid" if d in ("global", "user", "sarima") else "dash"),
            hovertemplate="%{x} alertas por día: %{y}<extra>" + NAMES[d] + "</extra>"))
    fig.add_shape(type="line", xref="x", yref="paper", x0=K, x1=K, y0=0, y1=1, line=dict(dash="dot", color=INK2, width=2))
    fig.add_annotation(x=K, y=1, xref="x", yref="paper", text=f"{K} alertas por día", showarrow=False,
                       xanchor="left", yanchor="top", font=dict(size=12, color=INK2))
    fig.update_xaxes(title_text="Alertas revisadas por día", range=[1, 30])
    fig.update_yaxes(title_text=(f"Días maliciosos detectados (de {N_MAL})" if col.startswith("dias")
                                 else f"Incidentes detectados (de {N_INC})"), rangemode="tozero")
    fig = fig_base(fig, 400)
    fig.update_layout(legend=dict(orientation="h", y=-0.25, yanchor="top", x=0.5, xanchor="center"),
                      margin=dict(l=10, r=10, t=20, b=10))
    return fig


def fig_rhythm() -> go.Figure:
    """Ocho semanas de inicios de sesión de un usuario: el ritmo semanal a simple vista."""
    ui = ST.uidx[ST.incidents.sort_values("incident")["incident"].iloc[0]]
    si = ST.signals.index("emails_sent")
    tt = np.arange(ST.t0 - 56, ST.t0)
    x, y = ST.days[tt], ST.counts[ui, tt, si]
    fig = go.Figure(go.Bar(x=x, y=y, marker_color=[COLORS["sarimax"] if d.dayofweek < 5 else "#c9c7bf" for d in x],
                           hovertemplate="%{x|%d/%m/%Y}: %{y} correos enviados<extra></extra>"))
    fig.update_layout(yaxis_title="Correos enviados", showlegend=False, bargap=0.25)
    fig.update_xaxes(**DATEFMT)
    return fig_base(fig, 260)


def tab_inicio():
    tp, inc, alerts, k_eq, dif = budget_numbers()
    g = RES.set_index(["protocolo", "detector"]).loc[("rolling", "global")]
    ident = ST.tables["identificacion_resumen"]
    per_hit = {d: alerts / tp[d] for d in ("global", "user", "sarima")}
    gain = dif["mejora_relativa"]
    kpis = html.Div(className="kpis", children=[
        kpi(f"+{pct(gain, 0)}", f"días maliciosos detectados frente a la línea base estática ({tp['sarima']} frente a "
            f"{tp['user']}, con las mismas {K} alertas diarias)"),
        kpi(f"{fmt(tp['sarima'] / tp['global'], 1)} veces", f"los días maliciosos de la regla global ({tp['sarima']} "
            f"frente a {tp['global']}, mismas alertas)"),
        kpi(f"{fmt(100 * tp['sarima'] / alerts, 1)} de 100", f"alertas de SARIMA son aciertos (línea base estática, "
            f"{fmt(100 * tp['user'] / alerts, 1)}; regla global, {fmt(100 * tp['global'] / alerts, 1)})"),
        kpi(f"{inc['sarima']} de {N_INC}", f"incidentes cubiertos por SARIMA (línea base estática, {inc['user']}; "
            f"regla global, {inc['global']})")])
    return html.Div(className="story", children=[
        card("En un minuto",
             html.P([html.B("El problema. "), "Las reglas de umbral fijo de un SOC generan tanto ruido que los ataques "
                     "internos se pierden en él. En estos datos, una regla global con límite del 99 % dispara ",
                     f"{fmt(g['IP99_R1_alertas_por_dia'], 0)} alertas al día, y "
                     f"{fmt(100 * (1 - g['IP99_R1_precision']), 0)} de cada 100 son falsas."]),
             html.P([html.B("Lo que se hizo. "), "Para cada uno de los 1.000 usuarios y cada uno de sus 9 contadores "
                     "diarios (sesiones, memorias USB, archivos, correo y web), un modelo SARIMA aprende su ritmo semanal "
                     f"y pronostica cuánto es normal cada día. Cada mañana, el SOC revisa a los {K} usuarios que más se "
                     "alejaron de su pronóstico."]),
             html.P([html.B("Lo que se encontró. "), f"Con esas mismas {K} alertas diarias, SARIMA encuentra "
                     f"{tp['sarima']} días maliciosos; la línea base estática, {tp['user']}, y la regla global, "
                     f"{tp['global']}. SARIMA detecta {inc['sarima']} de los {N_INC} incidentes."]),
             html.P([html.B("El límite. "), "Los datos (CERT r4.2) son sintéticos: el trabajo muestra que el método es "
                     "viable, no cómo rinde en una organización real."])),
        kpis,
        card("¿De qué trata este trabajo?",
             html.P("En una empresa, el equipo de analistas de seguridad (el SOC, centro de operaciones de seguridad) "
                    "recibe alertas cuando algo se sale de lo normal. Muchas vienen de reglas con un umbral fijo, por "
                    "ejemplo «más de cinco memorias USB en un día». Pero la actividad de una persona cambia con el día de "
                    "la semana: un lunes no se parece a un domingo. Un umbral fijo dispara con actividad normal y deja "
                    "pasar ataques que se quedan por debajo."),
             html.P("Aquí la actividad de cada usuario se trata como una serie de tiempo: una medición que se repite día "
                    "tras día y que tiene un ritmo semanal. Con la metodología Box-Jenkins de la estadística, un modelo "
                    "SARIMA aprende ese ritmo para cada persona y predice cuánto es normal para ella cada día. Si lo "
                    "observado se aleja mucho de lo esperado, el sistema lo pone arriba en la lista de revisión.")),
        html.Div(className="grid2", children=[
            card("El problema: demasiado ruido",
                 html.P(["Un analista de SOC lo resume así: “Sabemos que el 99 % de las alarmas que generamos son falsos positivos, pero aun así tenemos que revisarlas” "
                         "(Alahmadi et al., USENIX Security 2022; traducción propia). Revisar tantas "
                         "alarmas lleva al desgaste, y con más alertas de las que se pueden investigar se pierden "
                         "ataques reales en el ruido (Hassan et al., NDSS 2019)."]),
                 html.P([f"En estos datos, una regla global con umbral del 99 % dispara ",
                         html.B(f"{fmt(g['IP99_R1_alertas_por_dia'], 0)} alertas por día"),
                         f", y {fmt(100 * (1 - g['IP99_R1_precision']), 0)} de cada 100 son falsas."])),
            card("La idea: la actividad es una serie de tiempo",
                 dcc.Graph(figure=fig_rhythm(), config=GCFG, style=H(260)),
                 guide("ocho semanas de correos enviados por un usuario; cada barra es un día: verdes los días hábiles y "
                       "grises los fines de semana y festivos. El patrón se repite cada 7 días. De las series de correos "
                       "enviados de los 1.000 usuarios, ",
                       html.B(pct(float((ST.tables['identificacion_resumen'].set_index('signal').loc['emails_sent', 'pct_ciclo_semanal'])), 1)),
                       " tiene este ciclo semanal."))]),
        card("Los datos: una empresa simulada con 70 incidentes",
             html.P(["Se usa el CERT Insider Threat Test Dataset r4.2 (Carnegie Mellon University), un conjunto de datos "
                     "sintético muy usado para investigar amenazas internas: ", html.B("1.000 usuarios"), " de una empresa "
                     "ficticia durante ", html.B("500 días"), ", con registros de inicios de sesión, memorias USB, "
                     "archivos copiados a USB, correo y navegación web. Su registro de incidentes describe ",
                     html.B(f"{N_INC} casos"), " de tres tipos:"]),
             html.Ul([html.Li([html.B("1. Fuga de información a WikiLeaks, fuera de horario (30 casos): "),
                               "el empleado empieza a entrar fuera de horario, usa memorias USB por primera vez y sube "
                               "datos a wikileaks.org."]),
                      html.Li([html.B("2. Robo de datos antes de renunciar (30 casos): "),
                               "busca empleo en la competencia y copia a memorias USB mucho más de lo que solía."]),
                      html.Li([html.B("3. Sabotaje con la cuenta del supervisor (10 casos): "),
                               "un administrador instala un programa espía en el equipo de su supervisor y envía un "
                               "correo masivo desde esa cuenta."])]),
             html.P([f"Un «día malicioso» es un día de un usuario con alguna acción de un incidente: hay {N_MAL} en "
                     "total. Los modelos se entrenan solo con días anteriores a cualquier incidente y se evalúan en los "
                     "meses siguientes, como pasaría en una empresa real."])),
        card("Cómo funciona (cada noche)",
             html.Div(className="steps", children=[
                 html.Div([html.B("1. Contar"), html.P("Los registros de sesiones, USB, archivos, correo y web se resumen "
                                                      "en nueve contadores por usuario y día.")]),
                 html.Div([html.B("2. Pronosticar"), html.P("Para cada usuario y contador, el modelo SARIMA predice el "
                                                           "valor esperado de hoy según su historia y su ritmo semanal.")]),
                 html.Div([html.B("3. Medir"), html.P("Para cada contador se calcula cuánto se alejó lo observado de lo "
                                                     "esperado, en desviaciones estándar. El puntaje del usuario es su "
                                                     "mayor exceso entre los nueve contadores.")]),
                 html.Div([html.B("4. Priorizar"), html.P(f"Cada mañana, los {K} usuarios con mayor puntaje van a la cola "
                                                         "de revisión del SOC. Como referencia, un exceso de más de 2,33 "
                                                         "desviaciones estándar supera el límite del 99 %: el valor que un "
                                                         "día normal de esa persona no debería superar más de 1 vez de "
                                                         "cada 100.")])])),
        card("Resultado principal: con la misma carga de trabajo, las series de tiempo detectan más",
             html.Div(className="grid2", children=[
                 dcc.Graph(figure=fig_budget("dias_maliciosos_detectados"), config=GCFG, style=H(400)),
                 dcc.Graph(figure=fig_budget("incidentes_detectados"), config=GCFG, style=H(400))]),
             guide("cada línea es un detector. El eje horizontal es cuántas alertas revisa el SOC cada día, de 1 a 30; el "
                   f"vertical, cuánto encuentra: a la izquierda, días maliciosos (de {N_MAL}), y a la derecha, incidentes "
                   f"(de {N_INC}). Más arriba es mejor. Mire primero la línea punteada de {K} alertas diarias: ahí SARIMA "
                   f"encuentra {tp['sarima']} días maliciosos; la línea base estática, {tp['user']}, y la regla global, "
                   f"{tp['global']}. En días maliciosos, los tres modelos de series de tiempo superan a la línea base "
                   "estática con cualquier número de alertas. En incidentes, la ventaja está en las primeras alertas del "
                   "día: desde 17 alertas diarias la línea base estática iguala a SARIMA, y con 21 lo supera por un "
                   "incidente. No depende de unos pocos usuarios: al remuestrearlos 1.000 veces, la ventaja de SARIMA "
                   f"con {K} alertas diarias quedó entre {round(dif['IC95_inf'])} y {round(dif['IC95_sup'])} días "
                   "maliciosos en el 95 % de los casos.")),
        card("¿Qué significa y qué no?",
             html.Ul([html.Li("Con los mismos recursos, un modelo que conoce el ritmo de cada persona encuentra más: el "
                              f"analista revisa {fmt(per_hit['sarima'], 1)} alertas por hallazgo en vez de "
                              f"{fmt(per_hit['user'], 1)}, lo que ayuda a reducir la fatiga de alertas."),
                      html.Li("El ritmo semanal importa, pero hay que aprenderlo: con " + str(K) + " alertas diarias, "
                              f"SARIMA, que lo estima con los datos, encuentra {tp['sarima']} días maliciosos; una regla "
                              f"que solo repite el mismo día de la semana anterior, {tp['seasonal_naive']}."),
                      html.Li("Una alerta es una señal para investigar, no un ataque confirmado."),
                      html.Li("Los datos (CERT r4.2) son sintéticos: los resultados muestran viabilidad, no el desempeño "
                              "en una organización real.")])),
        card("Cómo explorar esta aplicación",
             html.Ul([html.Li([html.B("Resultados: "), "todas las tablas y comparaciones."]),
                      html.Li([html.B("Laboratorio: "), "cambie las decisiones del detector y vea cómo cambian las cifras."]),
                      html.Li([html.B("Explorador de usuarios: "), "lo observado frente a lo esperado de cualquiera de los 1.000 usuarios."]),
                      html.Li([html.B("Cola de revisión diaria: "), "lo que vería el analista cada mañana."]),
                      html.Li([html.B("Incidentes: "), "los 70 casos y qué detector encontró cada uno."]),
                      html.Li([html.B("Identificación Box-Jenkins: "), "por qué se eligió un modelo SARIMA semanal."]),
                      html.Li([html.B("Método, glosario y fuentes: "), "cómo se hizo y qué significa cada término."])])),
    ])


# ============================================================================ laboratorio
def tab_lab():
    return html.Div(className="lab", children=[
        html.Aside(className="controls card", children=[
            html.H3("Decisiones del detector", className="card-title"),
            html.Label("Protocolo"),
            dcc.RadioItems(id="lab-proto", options=[{"label": v, "value": k} for k, v in PROTOCOLS.items()],
                           value="rolling", className="radio"),
            html.Label("Contadores que se vigilan (el puntaje es el mayor exceso entre ellos)"),
            dcc.Checklist(id="lab-signals", options=[{"label": v, "value": k} for k, v in SIGNALS.items()],
                          value=list(SIGNALS), className="check"),
            html.Label("Cómo se alerta"),
            dcc.RadioItems(id="lab-rule", options=[{"label": "Cola de revisión: los k usuarios más anómalos de cada día",
                                                    "value": "budget"},
                                                   {"label": "Límite: cada vez que un contador supera su máximo normal",
                                                    "value": "pi"}],
                           value="budget", className="radio"),
            html.Label("k: usuarios que el analista revisa cada día"),
            dcc.Slider(id="lab-k", min=1, max=30, step=1, value=K, marks={1: "1", 10: "10", 20: "20", 30: "30"},
                       tooltip={"placement": "bottom"}),
            html.Label("Nivel del límite (qué tan raro debe ser un día para alertar)"),
            dcc.Slider(id="lab-alpha", min=0, max=4, step=1, value=2,
                       marks={0: "90 %", 1: "95 %", 2: "99 %", 3: "99,5 %", 4: "99,9 %"}),
            html.Label("Contadores que deben superar su límite el mismo día"),
            dcc.Slider(id="lab-minr", min=1, max=4, step=1, value=1, marks={i: str(i) for i in range(1, 5)}),
            html.P("El nivel del límite y el número de contadores cambian la tabla solo con la opción «Límite»; la "
                   "gráfica de abajo siempre los usa. El PR-AUC no depende de cómo se alerta: solo del protocolo y de "
                   "los contadores.", className="note"),
            guide("cambie una decisión y todas las cifras de la derecha se recalculan sobre los 309.661 usuario-día de "
                  "prueba (unos segundos). Por ejemplo, quite los contadores de memorias USB y vea cuánto baja la "
                  "detección del robo de datos antes de renunciar."),
        ]),
        html.Div(className="lab-out", children=[
            dcc.Loading(type="dot", color=COLORS["sarimax"], children=[
                card("Métricas recalculadas en el periodo de prueba", html.Div(id="lab-table"),
                     guide("cada fila es un detector con las decisiones de la izquierda. «Aciertos por cada 100 alertas»: "
                           "cuántas alertas eran de verdad un día malicioso. «Días maliciosos detectados»: qué parte de "
                           "los 986 encontró. «Falsas alarmas por 1.000 usuario-día normales»: ruido que recibe el analista. "
                           "«Incidentes»: casos con al menos un día en las alertas. «Demora»: días entre el inicio del "
                           "incidente y su primera alerta (mediana). «PR-AUC»: nota de 0 a 1 de qué tan arriba quedan los "
                           "días maliciosos al ordenar todo de más a menos sospechoso; elegir al azar da 0,0032. La cola "
                           "toma hasta k usuarios con puntaje positivo por día, así que «Alertas por día» puede quedar un "
                           "poco por debajo de k. La demora mediana se calcula solo entre los incidentes detectados.")),
                html.Div(className="grid2", children=[
                    card("Días maliciosos detectados según las alertas revisadas por día",
                         dcc.Graph(id="lab-pr", config=GCFG, style=H(380)),
                         guide("con las decisiones de la izquierda: si el analista revisa k usuarios al día (eje "
                               "horizontal), cuántos días maliciosos encuentra cada detector. Más arriba es mejor. Es "
                               "la comparación justa: todos con la misma carga de trabajo.")),
                    card("Incidentes detectados por escenario", dcc.Graph(id="lab-scen", config=GCFG, style=H(380)),
                         guide("escenario 1: fuga de información a WikiLeaks fuera de horario (30 casos); 2: robo de "
                               "datos antes de renunciar (30); 3: sabotaje con la cuenta del supervisor (10)."))]),
                card("Alertas por día si se alertara con el límite, sin tope diario (media de 7 días)",
                     dcc.Graph(id="lab-daily", config=GCFG, style=H(300)),
                     guide("en la cola de revisión todos los detectores dan hasta k alertas al día. Esta gráfica "
                           "muestra cuántas darían si alertaran cada vez que un contador supera su límite (nivel y "
                           "número de contadores de la izquierda): así se ve qué detector inundaría al analista. Los "
                           "saltos de la regla ingenua caen la semana siguiente a un festivo: como espera lo mismo que "
                           "hace 7 días y ese día no hubo actividad, casi todo le parece anómalo. SARIMA, que combina "
                           "varias semanas anteriores, casi no salta.")),
            ])]),
    ])


ALPHAS = [0.10, 0.05, 0.01, 0.005, 0.001]


def budget_curve(A: np.ndarray, mask: np.ndarray, y: np.ndarray, kmax: int = 30):
    """Días maliciosos detectados si cada día se revisan los k usuarios de mayor puntaje, para k = 1..kmax."""
    Am = np.where(mask, A, -np.inf)
    days = np.where(mask.any(axis=0))[0]
    top = np.argsort(-Am[:, days], axis=0, kind="stable")[:kmax]            # kmax x días
    val = np.take_along_axis(Am[:, days], top, axis=0)
    hit = y[:, days][top, np.arange(len(days))[None, :]] & np.isfinite(val) & (val > 0)
    return np.arange(1, kmax + 1), np.cumsum(hit.sum(axis=1))


# ============================================================================ explorador
def user_label(u: str) -> str:
    inc = ST.incidents
    if u in set(inc["incident"]):
        sc = int(inc.loc[inc["incident"] == u, "scenario"].iloc[0])
        return f"{u} · empleado malicioso, escenario {sc}"
    if u in ST.mal_users:
        return f"{u} · cuenta usada en un incidente"
    return u


USER_OPTS = [{"label": user_label(u), "value": u} for u in ST.mal_users] + \
            [{"label": u, "value": u} for u in ST.users if u not in set(ST.mal_users)]


def tab_explorer():
    return html.Div([
        html.Div(className="toolbar card", children=[
            html.Div([html.Label("Usuario"), dcc.Dropdown(id="ex-user", options=USER_OPTS, value="IKR0401" if "IKR0401" in ST.uidx else ST.incidents["incident"].iloc[0],
                                                           clearable=False)], className="tb-item wide"),
            html.Div([html.Label("Contador"), dcc.Dropdown(id="ex-signal", options=[{"label": v, "value": k} for k, v in SIGNALS.items()],
                                                         value="usb_events", clearable=False)], className="tb-item"),
            html.Div([html.Label("Detectores (el primero marcado lleva su zona normal rellena)"),
                      dcc.Checklist(id="ex-dets", options=[{"label": NAMES[d], "value": d} for d in DETECTORS],
                                    value=["user", "sarima"], inline=True, className="check inline")], className="tb-item wide"),
            html.Div([html.Label("Protocolo"), dcc.Dropdown(id="ex-proto", options=[{"label": v, "value": k} for k, v in PROTOCOLS.items()],
                                                             value="rolling", clearable=False)], className="tb-item"),
            html.Div([html.Label("Nivel del límite"), dcc.Dropdown(id="ex-alpha", options=[{"label": l, "value": i} for i, l in
                                                                                     enumerate(["90 %", "95 %", "99 %", "99,5 %", "99,9 %"])],
                                                             value=2, clearable=False)], className="tb-item small"),
            html.Div([html.Label("Ventana"), dcc.RadioItems(id="ex-window", options=[{"label": "Incidente", "value": "inc"},
                                                                                     {"label": "Todo", "value": "all"}],
                                                             value="inc", className="radio inline")], className="tb-item"),
        ]),
        html.Div(className="grid-ex", children=[
            card("Observado frente a esperado", dcc.Loading(dcc.Graph(id="ex-graph", config=GCFG, style=H(440)), type="dot"),
                 guide("la línea con puntos es lo que hizo el usuario cada día. La línea continua de color es lo que "
                       "cada detector esperaba y la discontinua, su límite estimado (por defecto del 99 %; se cambia "
                       "arriba); la zona rellena es la del primer detector marcado. Un círculo marca un día que superó "
                       "el límite; entrar en la cola diaria de 10 alertas es otro criterio (pestaña Cola de revisión). "
                       "Las franjas grises son días maliciosos según el registro de incidentes. Al abrir se muestra "
                       "IKR0401, el robo de datos antes de renunciar de la figura 1 del póster: compare el límite fijo de "
                       "la línea base estática con el de SARIMA, que cambia con el día de la semana.")),
            html.Div([card("Perfil", html.Div(id="ex-profile")), card("Modelo ajustado", html.Div(id="ex-model"))]),
        ]),
        card("Qué tan anómalo fue cada día, según cada detector", dcc.Graph(id="ex-heat", config=GCFG, style=H(260)),
             guide("cada fila es un detector y cada columna un día. Más oscuro significa más lejos de lo normal "
                   "(puntaje: el mayor exceso entre los 9 contadores, en desviaciones estándar). Las líneas rojas marcan "
                   "días maliciosos.")),
        card("Los 9 contadores del usuario (conteos diarios)", dcc.Graph(id="ex-multi", config=GCFG, style=H(520)),
             guide("los puntos rojos son días maliciosos. Sirven para ver qué contador cambió durante el incidente.")),
    ])


# ============================================================================ triage
def tab_triage():
    test_days = ST.days[ST.t0:]
    return html.Div([
        html.Div(className="toolbar card", children=[
            html.Div([html.Label("Día"), dcc.DatePickerSingle(id="tr-day", min_date_allowed=test_days[0].date(),
                                                              max_date_allowed=test_days[-1].date(),
                                                              date=pd.Timestamp("2010-10-29").date(), display_format="YYYY-MM-DD",
                                                              first_day_of_week=1)], className="tb-item"),
            html.Div([html.Label("Detector"), dcc.Dropdown(id="tr-det", options=[{"label": NAMES[d], "value": d} for d in DETECTORS],
                                                            value="sarima", clearable=False)], className="tb-item"),
            html.Div([html.Label("Protocolo"), dcc.Dropdown(id="tr-proto", options=[{"label": v, "value": k} for k, v in PROTOCOLS.items()],
                                                             value="rolling", clearable=False)], className="tb-item"),
            html.Div([html.Label("Usuarios a revisar"), dcc.Slider(id="tr-k", min=5, max=30, step=5, value=K,
                                                                    marks={i: str(i) for i in range(5, 31, 5)})], className="tb-item wide"),
            html.Div([dcc.Checklist(id="tr-truth", options=[{"label": " Mostrar si el día era malicioso (registro de incidentes)", "value": "y"}], value=[])],
                     className="tb-item"),
        ]),
        card("Cola de revisión del día", guide("cada fila es un usuario que el analista debería revisar hoy, ordenado de más a menos "
                                                "anómalo. «Máximo normal esperado (límite 99 %)» es el valor que, según la "
                                                "historia de ese usuario, un día normal no debería superar más de 1 vez de "
                                                "cada 100; "
                                                "«Observado hoy» por encima de ese máximo es inusual. «Puntaje» es "
                                                "cuántas desviaciones estándar se alejó del valor esperado en su contador "
                                                "más alterado: con él se ordena la cola. Marque la casilla de arriba para "
                                                "ver cuáles eran de verdad días maliciosos."),
             html.P("Así vería el analista del SOC la salida del detector cada mañana: los usuarios con mayor "
                    "puntaje, el contador que más se alejó y cuánto se esperaba. «Contadores fuera de lo normal»: "
                    "cuántos de sus 9 contadores superaron hoy su límite del 99 %. El rol viene del conjunto de datos, "
                    "en inglés. Haga clic en una fila para abrir su serie en el Explorador.", className="note"),
             html.P("Día de ejemplo: 29 de octubre de 2010. Ese día, 2 de los 10 usuarios de la cola de SARIMA "
                    "(puestos 1 y 4) tenían un incidente en curso; marque la casilla para verlos. Que 8 de 10 sean "
                    "falsas alarmas es lo esperado: en promedio, 7 de cada 100 alertas de SARIMA son aciertos, frente a "
                    "4,8 con la línea base estática.", className="note"),
             html.Div(id="tr-table")),
    ])


# ============================================================================ incidentes
def tab_incidents():
    return html.Div([
        html.Div(className="toolbar card", children=[
            html.Div([html.Label("Cómo se alerta"), dcc.Dropdown(id="in-rule", options=[
                {"label": f"{K} alertas diarias (cola de revisión)", "value": RULE},
                {"label": "Límite del 99 % (1 contador)", "value": "IP99_R1"},
                {"label": "Límite del 99 % (2 contadores a la vez)", "value": "IP99_R2"}], value=RULE, clearable=False)],
                className="tb-item wide"),
            html.Div([html.Label("Protocolo"), dcc.Dropdown(id="in-proto", options=[{"label": v, "value": k} for k, v in PROTOCOLS.items()],
                                                             value="rolling", clearable=False)], className="tb-item"),
            html.Div([html.Label("Escenario"), dcc.Dropdown(id="in-scen", options=[{"label": "Todos", "value": 0}] +
                                                             [{"label": f"{k}. {v}", "value": k} for k, v in SCENARIOS.items()],
                                                             value=0, clearable=False)], className="tb-item wide"),
        ]),
        card(f"Los {N_INC} incidentes del registro",
             guide("cada fila es un incidente del registro de incidentes: su escenario (1: fuga a WikiLeaks fuera de "
                   "horario; 2: robo de datos antes de renunciar; 3: sabotaje con la cuenta del supervisor), la fecha en "
                   "que empezó, cuántos días maliciosos tuvo y qué cuentas participaron. Para cada detector, ✓ (en "
                   "verde) si al menos uno de sus días entró en las alertas y, entre paréntesis, cuántos días pasaron "
                   "desde el primer día malicioso hasta la primera alerta; ✗ si nunca lo alertó. Haga clic en un "
                   "incidente para ver su serie."), html.Div(id="in-table")),
    ])


# ============================================================================ identificación
def tab_ident():
    if "identificacion_resumen" not in ST.tables:
        return card("Identificación", html.P("Falta la tabla de identificación: correr python -m ueba_ts identify.", className="note"))
    r = ST.tables["identificacion_resumen"].copy()
    r["Contador"] = r["signal"].map(SIGNALS)
    cols = {"pct_modelables": "Con actividad suficiente (al menos 5 % de días)",
            "pct_ciclo_semanal": "Con ciclo semanal (periodograma)",
            "pct_acf7_signif": "Se parece a la semana anterior (FAC a 7 días)",
            "pct_acf1_signif": "Se parece al día anterior (FAC a 1 día)",
            "pct_adf_desest_rechaza": "Estable en el tiempo según ADF (sin el ciclo semanal)",
            "pct_kpss_no_rechaza": "Estable en el tiempo según KPSS"}
    for c in cols:
        if c in r:
            r[cols[c]] = r[c].map(pct)
    r = r[["Contador"] + [cols[c] for c in cols if c in r]]
    o = pd.DataFrame([{"Contador": SIGNALS[s], "ARIMA": f"({','.join(map(str, ST.orders['arima'][s]['order']))})",
                       "SARIMA / SARIMAX": f"({','.join(map(str, ST.orders['sarima'][s]['order']))})"
                                           f"({','.join(map(str, ST.orders['sarima'][s]['seasonal_order'][:3]))})"
                                           f"{ST.orders['sarima'][s]['seasonal_order'][3] or ''}"} for s in ST.signals])
    lb = ST.tables["ljungbox_resumen"]
    lb = lb[lb["detector"].isin(["arima", "sarima", "sarimax"])].groupby(["protocol", "detector"]).apply(
        lambda g: pd.Series({"Ajustes": fmt(int(g["ajustes"].sum()), 0),
                             "Errores sin patrón (Ljung-Box, p > 0,05)": pct((g["pct_ljungbox_no_rechaza"] * g["ajustes"]).sum() / g["ajustes"].sum())}),
        include_groups=False).reset_index()
    lb = lb.assign(Protocolo=lb["protocol"].map(PROTOCOLS), Detector=lb["detector"].map(NAMES))[
        ["Protocolo", "Detector", "Ajustes", "Errores sin patrón (Ljung-Box, p > 0,05)"]]
    return html.Div([
        html.P(className="lead", children=[
            "De las 9.000 series (1.000 usuarios por 9 contadores), 5.700 tienen actividad suficiente; de ellas, el 94 % "
            "tiene ciclo semanal y en el 96 % las pruebas ADF y KPSS son compatibles con un nivel estable. Por eso se "
            "eligió un SARIMA semanal sin diferenciar."]),
        card("Identificación en la ventana de entrenamiento (1.000 usuarios)",
             guide("antes de elegir un modelo, la metodología Box-Jenkins revisa cómo se comportan las series. Cada "
                   "fila es un contador. La primera columna es el porcentaje de los 1.000 usuarios con actividad "
                   "suficiente; desde la segunda, el porcentaje se calcula sobre esas series activas. «Con "
                   "ciclo semanal»: el periodograma encuentra un ritmo de 7 días. «Se parece a la semana anterior»: la "
                   "actividad de hoy está correlacionada con la de hace 7 días. «Estable en el tiempo»: su nivel no "
                   "se desplaza sin control, así que no hace falta diferenciarla (restar el día anterior). Con estas "
                   "tres propiedades, un SARIMA semanal sin diferenciar es el modelo natural."), table(r, page=10),
             html.P("Las series con menos de 5 % de días con actividad usan la media del usuario, que funciona como "
                    "detector de primera vez. Detalle técnico de ADF en la pestaña Método.", className="note")),
        html.Div(className="grid2", children=[
            card("Órdenes elegidos por AIC (muestra aleatoria de 60 usuarios)", table(o, page=10),
                 guide("la notación (p,d,q)(P,D,Q)7 dice qué usa el modelo: p y q, cuántos días anteriores (y sus "
                       "errores de pronóstico); P y Q, cuántas semanas anteriores; d = D = 0, que no hace falta "
                       "diferenciar. SARIMA (0,0,0)(1,0,1)7 usa solo el mismo día de la semana anterior y su error. El "
                       "AIC elige, entre varios órdenes, el que mejor se ajusta sin complicarse de más.")),
            card("¿Quedó patrón en los errores? (prueba de Ljung-Box)", table(lb, page=6),
                 guide("la prueba revisa si en los errores del pronóstico quedó un patrón. Si todos los modelos fueran "
                       "adecuados, cerca del 95 % de los ajustes no mostraría patrón. SARIMA llega al 82 %; ARIMA, que "
                       "ignora el día de la semana, solo al 9 %. SARIMAX + pares queda en 62 %, por debajo de SARIMA; aun "
                       "así detecta casi lo mismo (234 frente a 240 días maliciosos con 10 alertas diarias)."))]),
        html.Div(className="toolbar card", children=[
            html.Div([html.Label("Usuario"), dcc.Dropdown(id="id-user", options=USER_OPTS, value=ST.users[0], clearable=False)],
                     className="tb-item wide"),
            html.Div([html.Label("Contador"), dcc.Dropdown(id="id-signal", options=[{"label": v, "value": k} for k, v in SIGNALS.items()],
                                                         value="logons", clearable=False)], className="tb-item"),
        ]),
        card("FAC, FACP y periodograma del usuario (periodo de entrenamiento)",
             guide("la FAC mide cuánto se parece la actividad de un día a la de k días antes; las barras verdes en 7, 14, "
                   "21 y 28 días revelan el ciclo semanal. La FACP mide lo mismo, pero descontando los días intermedios; "
                   "sus barras en 7 y 14 días apuntan al término semanal del modelo. La franja gris marca correlaciones "
                   "que no se distinguen de cero. El periodograma muestra qué periodos dominan: un pico en 7 días es un "
                   "ritmo semanal. Por eso se eligió un modelo SARIMA con periodo 7. Las series se analizan en escala "
                   "comprimida, log(1 + conteo)."),
             dcc.Loading(dcc.Graph(id="id-graph", config=GCFG, style=H(340)), type="dot")),
    ])


# ============================================================================ método
METHOD_MD = open(os.path.join(os.path.dirname(__file__), "metodo.md"), encoding="utf-8").read()


def tab_method():
    return card("Método, decisiones y fuentes", dcc.Markdown(METHOD_MD, link_target="_blank", className="md"))


# ============================================================================ póster
def tab_poster():
    """Visor del póster: el PDF incrustado en pantallas anchas; en el teléfono, donde los navegadores no muestran
    un PDF dentro de la página, una imagen que abre el PDF al tocarla."""
    pdf = app.get_asset_url("PosterAlejandroHigueraJCUN.pdf")
    return card("Póster presentado en la JCUN 2026",
                html.P("Este es el póster que presenté en la 7.ª Jornada de Ciberseguridad de la Universidad Nacional "
                       "de Colombia, del 20 al 24 de octubre de 2026. El PDF es vectorial, así que se puede ampliar "
                       "sin perder nitidez.", className="lead"),
                html.Div(className="poster-actions", children=[
                    html.A("Abrir el PDF en pantalla completa ↗", href=pdf, target="_blank", rel="noopener",
                           className="btn"),
                    html.A("Descargar el PDF", href=pdf, download="PosterAlejandroHigueraJCUN.pdf",
                           className="btn btn--sec")]),
                html.Iframe(src=pdf + "#view=FitH", title="Póster en PDF", className="poster-pdf"),
                html.A(html.Img(src=app.get_asset_url("poster_vista.jpg"), alt="Póster: " + TITLE),
                       href=pdf, target="_blank", rel="noopener", className="poster-img"),
                html.P("En el teléfono, toque el póster para abrir el PDF y ampliarlo.", className="note poster-img"))


# ============================================================================ layout
app = Dash(__name__, title="UEBA temporal · JCUN 2026", suppress_callback_exceptions=True,
           update_title=None, meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}])
server = app.server

TABS = [("inicio", "Inicio"), ("poster", "Póster"), ("resumen", "Resultados"), ("laboratorio", "Laboratorio"),
        ("explorador", "Explorador de usuarios"), ("triage", "Cola de revisión diaria"), ("incidentes", "Incidentes"),
        ("identificacion", "Identificación Box-Jenkins"), ("metodo", "Método, glosario y fuentes")]

REPO_URL = "https://github.com/DarkNightSoldier/UEBASeriesDeTiempo_JCUN26"  # código, resultados y cómo reproducirlos

app.layout = html.Div(className="page", children=[
    dcc.Location(id="url", refresh=False),
    html.Header(className="hero", children=[
        html.Div(className="hero-top", children=[html.Span("JCUN 2026", className="badge"),
                                                 html.Span("7.ª Jornada de Ciberseguridad · Universidad Nacional de Colombia",
                                                           className="event"),
                                                 html.A("Repositorio en GitHub ↗", href=REPO_URL, target="_blank",
                                                        rel="noopener", className="repo")]),
        html.H1([TITLE_L1, html.Br(), html.Span(TITLE_L2, className="t2")]),
        html.P("Alejandro Higuera Castro · Departamento de Estadística, Facultad de Ciencias, Universidad Nacional de "
               "Colombia, Sede Bogotá", className="sub"),
        html.P("La credencial es válida. El acceso es válido. El comportamiento, no necesariamente.", className="hook"),
        html.P("CERT Insider Threat Test Dataset r4.2 · 1.000 usuarios · 500 días · Box-Jenkins, SARIMA y SARIMAX",
               className="sub"),
    ]),
    dcc.Tabs(id="tabs", value="inicio", className="tabs", mobile_breakpoint=0, children=[dcc.Tab(label=l, value=v, className="tab",
                                                                             selected_className="tab--sel") for v, l in TABS]),
    html.Main(id="content", className="content"),
    html.Footer(className="foot", children=[
        html.Span("Datos: Lindauer (2020), Insider Threat Test Dataset, Carnegie Mellon University, CC BY 4.0, "
                  "doi:10.1184/R1/12841247.v1. Los datos son sintéticos: los resultados indican viabilidad, no "
                  "desempeño en una organización real."),
        html.Span(["Código, resultados y pasos para reproducirlos: ",
                   html.A(REPO_URL.replace("https://", ""), href=REPO_URL, target="_blank", rel="noopener")],
                  className="foot-repo")]),
])


@app.callback(Output("tabs", "value"), Input("url", "search"))
def from_url(search):
    """La pestaña sale de la URL (?tab=...&user=...): sirve para enlaces directos y para los clics en tablas."""
    q = parse_qs((search or "").lstrip("?"))
    tab = q.get("tab", ["inicio"])[0]
    return tab if tab in dict(TABS) else "inicio"


@app.callback(Output("content", "children"), Input("tabs", "value"), State("url", "search"))
def render(tab, search):
    q = parse_qs((search or "").lstrip("?"))
    if tab == "laboratorio":
        return tab_lab()
    if tab == "explorador":
        layout = tab_explorer()
        u, s = q.get("user", [None])[0], q.get("signal", [None])[0]
        if u in ST.uidx or s in SIGNALS:
            _set_default(layout, "ex-user", u if u in ST.uidx else None)
            _set_default(layout, "ex-signal", s if s in SIGNALS else None)
        return layout
    if tab == "triage":
        return tab_triage()
    if tab == "incidentes":
        return tab_incidents()
    if tab == "identificacion":
        return tab_ident()
    if tab == "metodo":
        return tab_method()
    if tab == "poster":
        return tab_poster()
    if tab == "resumen":
        return tab_resumen()
    return tab_inicio()


def _set_default(node, id_, value):
    if value is None:
        return
    if getattr(node, "id", None) == id_:
        node.value = value
        return
    kids = getattr(node, "children", None)
    if isinstance(kids, (list, tuple)):
        for k in kids:
            _set_default(k, id_, value)
    elif kids is not None and hasattr(kids, "children"):
        _set_default(kids, id_, value)


# ---------------------------------------------------------------------------- laboratorio
@app.callback(Output("lab-table", "children"), Output("lab-pr", "figure"), Output("lab-scen", "figure"),
              Output("lab-daily", "figure"),
              Input("lab-proto", "value"), Input("lab-signals", "value"), Input("lab-rule", "value"),
              Input("lab-k", "value"), Input("lab-alpha", "value"), Input("lab-minr", "value"))
def lab(proto, signals, rule, k, alpha_i, minr):
    signals = tuple(s for s in ST.signals if s in (signals or []))
    if not signals:
        empty = fig_base(go.Figure(), 300)
        return html.P("Elija al menos un contador."), empty, empty, empty
    alpha = ALPHAS[alpha_i]
    m, y = ST.mask, ST.y
    rows, pr, sc, daily = [], go.Figure(), go.Figure(), go.Figure()
    for d in DETECTORS:
        A, R, _ = ST.score(proto, d, signals, alpha)
        s = A[m]
        ap = average_precision(s, y[m])
        alert = budget_alerts(A, m, k) if rule == "budget" else (R >= minr)
        ev = evaluate(ST, alert, A)
        rows.append({"Detector": NAMES[d], "Aciertos por cada 100 alertas": fmt(100 * ev["precision"], 1),
                     "Días maliciosos detectados": f"{int(round(ev['recall'] * N_MAL))} ({pct(ev['recall'])})",
                     "Falsas alarmas por 1.000 usuario-día normales": fmt(ev["FP_1000"], 1),
                     "Alertas por día": fmt(ev["alertas_dia"], 1), "Incidentes": f"{ev['incidentes']}/{N_INC}",
                     "Demora mediana (días)": fmt(ev["demora_mediana"], 0), "PR-AUC": fmt(ap, 4)})
        ks, hits = budget_curve(A, m, y, 30)
        pr.add_trace(go.Scatter(x=ks, y=hits, mode="lines", name=NAMES[d],
                                line=dict(color=COLORS[d], width=3.2 if d == "sarima" else 1.8,
                                          dash="solid" if d in ("global", "user", "sarima") else "dash"),
                                hovertemplate="%{x} alertas por día: %{y} días maliciosos<extra>" + NAMES[d] + "</extra>"))
        bs = ev["por_escenario"]
        sc.add_trace(go.Bar(x=[f"Esc. {i}" for i in (1, 2, 3)], y=[bs[i][0] for i in (1, 2, 3)], name=NAMES[d],
                            marker_color=COLORS[d], marker_line_color=SURFACE, marker_line_width=2,
                            customdata=[bs[i][1] for i in (1, 2, 3)],
                            hovertemplate="%{x}: %{y} de %{customdata}<extra>" + NAMES[d] + "</extra>"))
        per_day = ((R >= minr) & m).sum(axis=0)[ST.t0:]
        daily.add_trace(go.Scatter(x=ST.days[ST.t0:], y=pd.Series(per_day).rolling(7, min_periods=1).mean(), mode="lines",
                                   name=NAMES[d], line=dict(color=COLORS[d], width=2)))
    pr.add_shape(type="line", xref="x", yref="paper", x0=k, x1=k, y0=0, y1=1, line=dict(dash="dot", color=INK2, width=2))
    pr.update_layout(xaxis_title="Alertas revisadas por día", yaxis_title=f"Días maliciosos detectados (de {N_MAL})")
    sc.update_layout(barmode="group", yaxis_title="Incidentes detectados")
    daily.update_layout(yaxis_title="Alertas por día", hovermode="x unified")
    daily.update_xaxes(**DATEFMT)
    regla = (f"cola de revisión de {k} usuarios por día" if rule == "budget" else
             f"límite del {fmt(100 * (1 - alpha), 1)} % superado en al menos {minr} contador(es)")
    note = html.P(f"Cómo se alerta: {regla}. Contadores vigilados: {len(signals)} de 9. Recalculado sobre "
                  f"{fmt(int(m.sum()), 0)} usuario-día de prueba. Con la configuración oficial (reentrenamiento mensual, 9 "
                  f"contadores, cola de {K}) reproduce exactamente la tabla de la pestaña Resultados.", className="note")
    return [table(pd.DataFrame(rows), page=6), note], fig_base(pr, 380), fig_base(sc, 380), fig_base(daily, 300)


# ---------------------------------------------------------------------------- explorador
def incident_window(ui):
    mal = np.where(ST.y[ui])[0]
    if len(mal):
        return max(mal.min() - 70, 0), min(mal.max() + 30, len(ST.days) - 1)
    return ST.t0 - 56, len(ST.days) - 1


@app.callback(Output("ex-graph", "figure"), Output("ex-heat", "figure"), Output("ex-multi", "figure"),
              Output("ex-profile", "children"), Output("ex-model", "children"),
              Input("ex-user", "value"), Input("ex-signal", "value"), Input("ex-dets", "value"),
              Input("ex-proto", "value"), Input("ex-alpha", "value"), Input("ex-window", "value"))
def explorer(user, signal, dets, proto, alpha_i, window):
    ui, si = ST.uidx[user], ST.signals.index(signal)
    last = int(np.where(ST.active[ui])[0].max())
    t0, t1 = incident_window(ui) if window == "inc" else (0, len(ST.days) - 1)
    t1 = min(t1, last + 10)
    tt = np.arange(t0, t1 + 1)
    x = ST.days[tt]
    act = ST.active[ui, tt]
    obs = ST.counts[ui, tt, si].astype(float)
    obs[~act] = np.nan
    crit = norm.ppf(1 - ALPHAS[alpha_i])
    lvl = fmt(100 * (1 - ALPHAS[alpha_i]), 1).replace(",0", "") + " %"
    fig = go.Figure()
    for t in tt[ST.y[ui, tt]]:   # días maliciosos en gris (el rojo claro se confunde con la banda estática)
        fig.add_vrect(x0=ST.days[t] - pd.Timedelta(hours=12), x1=ST.days[t] + pd.Timedelta(hours=12),
                      fillcolor="#8c8a80", opacity=0.25, line_width=0, layer="below")
    if t0 <= ST.t0 <= t1:
        fig.add_vline(x=ST.days[ST.t0], line_dash="dash", line_color=INK2)
        fig.add_annotation(x=ST.days[ST.t0], y=1.02, yref="paper", text="inicio de prueba", showarrow=False,
                           font=dict(size=11, color=INK2), xanchor="left")
    for j, d in enumerate([d for d in DETECTORS if d in (dets or [])]):
        yh, sg = ST.user_forecast(proto, d, ui)
        mu, up = np.expm1(yh[tt, si]), np.expm1(yh[tt, si] + crit * sg[tt, si])
        mu[~act], up[~act] = np.nan, np.nan
        if j == 0:   # solo el primer detector lleva la zona rellena; los demás, su límite como línea discontinua
            fig.add_trace(go.Scatter(x=x, y=up, mode="lines", line=dict(width=0, shape="hv"), showlegend=False, hoverinfo="skip"))
            fig.add_trace(go.Scatter(x=x, y=np.where(act, 0.0, np.nan), mode="lines", line=dict(width=0, shape="hv"), fill="tonexty",
                                     fillcolor=hex_rgba(COLORS[d], 0.12), name=f"Bajo el límite del {lvl}: {NAMES[d]}", hoverinfo="skip"))
        fig.add_trace(go.Scatter(x=x, y=up, mode="lines", line=dict(color=COLORS[d], width=1.5, dash="dash", shape="hv"),
                                 name=f"Límite estimado del {lvl}: {NAMES[d]}", hoverinfo="skip"))
        fig.add_trace(go.Scatter(x=x, y=mu, mode="lines", line=dict(color=COLORS[d], width=2, shape="hv"),
                                 name=f"Esperado: {NAMES[d]}", customdata=up,
                                 hovertemplate="%{x|%Y-%m-%d}<br>esperado %{y:.1f}<br>límite %{customdata:.1f}<extra>" + NAMES[d] + "</extra>"))
        al = (obs > up) & act
        fig.add_trace(go.Scatter(x=x[al], y=obs[al], mode="markers", name=f"Sobre el límite: {NAMES[d]}",
                                 marker=dict(size=14, symbol="circle-open", color=COLORS[d], line=dict(width=2.5))))
    fig.add_trace(go.Scatter(x=x, y=obs, mode="lines+markers", name="Observado", line=dict(color=INK, width=1.3, shape="hv"),
                             marker=dict(size=5, color=INK), hovertemplate="%{x|%Y-%m-%d} (%{x|%a})<br>observado %{y:.0f}<extra></extra>"))
    fig.update_layout(yaxis_title=SIGNALS[signal], hovermode="closest",
                      xaxis_range=[ST.days[t0] - pd.Timedelta(days=1), ST.days[t1] + pd.Timedelta(days=1)])
    fig.update_xaxes(**DATEFMT)
    fig.add_annotation(x=1, y=1.02, xref="paper", yref="paper", xanchor="right", showarrow=False,
                       text="Gris: días maliciosos del registro de incidentes", font=dict(size=11, color=INK2))
    fig = fig_base(fig, 440)

    # franja de puntajes A por detector
    zr = []
    for d in DETECTORS:
        A, _, _ = ST.score(proto, d, tuple(ST.signals), ALPHAS[alpha_i])
        a = A[ui, tt].astype(float)
        a[~act] = np.nan
        zr.append(a)
    heat = go.Figure(go.Heatmap(z=np.array(zr), x=x, y=[NAMES[d] for d in DETECTORS], colorscale=[[0, "#f7f7f4"], [0.35, "#c6da92"],
                                                                                                    [0.7, "#5f8f2a"], [1, "#25401d"]],
                                zmin=0, zmax=8, colorbar=dict(title="Puntaje"), hovertemplate="%{x|%d/%m/%Y}<br>%{y}: puntaje %{z:.2f}<extra></extra>"))
    for t in tt[ST.y[ui, tt]]:
        heat.add_vline(x=ST.days[t], line_color="#d91b1b", line_width=1, opacity=0.6)
    heat.update_yaxes(autorange="reversed")
    heat.update_xaxes(**DATEFMT)
    heat = fig_base(heat, 260)

    multi = make_subplots(rows=3, cols=3, shared_xaxes=True, subplot_titles=[SIGNALS[s] for s in ST.signals],
                          vertical_spacing=0.09, horizontal_spacing=0.05)
    for k, s in enumerate(ST.signals):
        v = ST.counts[ui, tt, k].astype(float)
        v[~act] = np.nan
        multi.add_trace(go.Scatter(x=x, y=v, mode="lines", line=dict(color=INK2, width=1, shape="hv"), showlegend=False,
                                   hovertemplate="%{x|%Y-%m-%d}: %{y:.0f}<extra>" + SIGNALS[s] + "</extra>"), row=k // 3 + 1, col=k % 3 + 1)
        mm = ST.y[ui, tt]
        multi.add_trace(go.Scatter(x=x[mm], y=v[mm], mode="markers", marker=dict(color="#d91b1b", size=6), showlegend=False,
                                   hoverinfo="skip"), row=k // 3 + 1, col=k % 3 + 1)
    multi.update_annotations(font_size=12)
    multi.update_xaxes(**DATEFMT)
    multi = fig_base(multi, 520)

    info = ST.user_info.loc[user]
    inc_rows = []
    for inc in sorted(set(ST.inc[ui][ST.y[ui]])):
        r = ST.incidents[ST.incidents["incident"] == inc].iloc[0]
        inc_rows.append(html.Li(f"Incidente {inc} (escenario {r['scenario']}: {SCENARIOS[r['scenario']]}), "
                                f"{int(ST.y[ui].sum())} días maliciosos en esta cuenta; cuentas implicadas: {r['accounts'].replace(';', ', ')}."))
    profile = html.Div([
        html.P([html.B("Rol: "), str(info["role"])]), html.P([html.B("Grupo de pares: "), str(info["peer_group"])]),
        html.P([html.B("Último día activo: "), str(pd.Timestamp(info["last_active"]).date())]),
        html.Ul(inc_rows) if inc_rows else html.P("Sin actividad maliciosa en el registro de incidentes.", className="note"),
        html.P(html.A("Enlace directo a esta vista", href="?" + urlencode({"tab": "explorador", "user": user, "signal": signal})),
               className="note")])
    f = ST.fits
    f = f[(f["user"] == user) & (f["signal"] == signal) & (f["protocol"] == proto) & f["detector"].isin(["arima", "sarima", "sarimax"])]
    if len(f):
        f = f.assign(Mes=ST.days[f["segment_start"].to_numpy()].strftime("%Y-%m"),
                     Modelo=f["detector"].map({"arima": "ARIMA", "sarima": "SARIMA", "sarimax": "SARIMAX"}),
                     Estado=f["status"].map({"ok": "ajustado", "fallback_sparse": "respaldo: serie casi vacía",
                                             "fallback_error": "respaldo: falló el ajuste"}),
                     **{"¿Convergió?": f["converged"].map(lambda v: "" if pd.isna(v) else ("Sí" if v else "No")),
                        "Ljung-Box (rezago 14)": f["ljungbox_p"].map(
                            lambda v: "" if pd.isna(v) else ((f"no detecta autocorrelación (p = {fmt(v, 2)})" if v > 0.05
                                                             else "detecta autocorrelación (p "
                                                             + ("< 0,001" if v < 0.001 else f"= {fmt(v, 3)}") + ")")))})
        model = [table(f[["Modelo", "Mes", "Estado", "¿Convergió?", "Ljung-Box (rezago 14)"]], page=9,
                       style_cell_conditional=[{"if": {"column_id": "Mes"}, "minWidth": "72px"}]),
                 html.P("Cada mes el modelo se vuelve a estimar con hasta 182 días previos de este usuario y contador. "
                        "«¿Convergió?»: si el optimizador llegó a su criterio de parada; si no, se usan igual los "
                        "parámetros obtenidos. «Respaldo»: con menos de 5 % de días con actividad o si el ajuste falla, se "
                        "usa la media del usuario. Ljung-Box: «no detecta autocorrelación» no prueba que el modelo sea "
                        "perfecto; «detecta» indica que le faltó capturar parte del ritmo.", className="note"),
                 html.P("Órdenes: SARIMA" + str(tuple(ST.orders["sarima"][signal]["order"])) +
                        str(tuple(ST.orders["sarima"][signal]["seasonal_order"])) + "; ARIMA" +
                        str(tuple(ST.orders["arima"][signal]["order"])) + ". Un tramo por mes con reentrenamiento mensual.",
                        className="note")]
    else:
        model = html.P("Sin ajustes registrados.", className="note")
    return fig, heat, multi, profile, model


def hex_rgba(h, a):
    h = h.lstrip("#")
    return f"rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{a})"


# ---------------------------------------------------------------------------- triage
@app.callback(Output("tr-table", "children"), Input("tr-day", "date"), Input("tr-det", "value"), Input("tr-proto", "value"),
              Input("tr-k", "value"), Input("tr-truth", "value"))
def triage(day, det, proto, k, truth):
    t = ST.days.get_loc(pd.Timestamp(day))
    zp = ST.zpos(proto, det, tuple(ST.signals)).astype(np.float32)[:, t, :]
    A = zp.max(axis=1)
    col = np.where(ST.mask[:, t] if t >= ST.t0 else ST.active[:, t], A, -np.inf)
    top = np.argpartition(-col, k)[:k]            # mismo criterio que la evaluación (budget_alerts)
    top = top[np.isfinite(col[top]) & (col[top] > 0)]
    top = top[np.argsort(-col[top], kind="stable")]
    yq, sq = ST.pred(proto, det)
    rows = []
    for rank, ui in enumerate(top, 1):
        si = int(zp[ui].argmax())
        exp = float(np.expm1(yq[ui, t, si] / ST.pscale))
        up = float(np.expm1(yq[ui, t, si] / ST.pscale + norm.ppf(0.99) * sq[ui, t, si] / ST.pscale))
        r = {"#": rank, "Usuario": ST.users[ui], "Rol": ST.user_info.iloc[ui]["role"], "Puntaje": fmt(float(A[ui]), 2),
             "Contadores fuera de lo normal": int((zp[ui] > norm.ppf(0.99)).sum()),
             "Contador más alejado": SIGNALS[ST.signals[si]], "Observado hoy": int(ST.counts[ui, t, si]),
             "Esperado hoy": fmt(exp, 1), "Máximo normal esperado (límite 99 %)": fmt(up, 1)}
        if truth:
            r["Registro de incidentes"] = f"malicioso (esc. {ST.scen[ui, t]})" if ST.y[ui, t] else "normal"
        rows.append(r)
    df = pd.DataFrame(rows)
    style = [{"if": {"filter_query": '{Registro de incidentes} contains "malicioso"'}, "backgroundColor": "#fbe3df", "fontWeight": 700}] if truth else []
    return table(df, id_="tr-dt", page=30, style_data_conditional=style)


@app.callback(Output("url", "search", allow_duplicate=True), Input("tr-dt", "active_cell"), State("tr-dt", "derived_viewport_data"),
              prevent_initial_call=True)
def triage_click(cell, data):
    if not cell:
        return no_update
    row = data[cell["row"]]
    sig = next((k for k, v in SIGNALS.items() if v == row.get("Contador más alejado")), None)
    return "?" + urlencode({"tab": "explorador", "user": row["Usuario"], **({"signal": sig} if sig else {})})


# ---------------------------------------------------------------------------- incidentes
@app.callback(Output("in-table", "children"), Input("in-rule", "value"), Input("in-proto", "value"), Input("in-scen", "value"))
def incidents(rule, proto, scen):
    t = ST.tables["incidentes_detalle"]
    t = t[(t["regla"] == rule) & (t["protocolo"] == proto)]
    base = ST.incidents.copy()
    if scen:
        base = base[base["scenario"] == scen]
    rows = []
    for _, r in base.iterrows():
        row = {"Incidente": r["incident"], "Esc.": int(r["scenario"]), "Inicio": str(pd.Timestamp(r["start"]).date()),
               "Días maliciosos": int(r["malicious_days"]), "Cuentas": r["accounts"].replace(";", ", ")}
        for d in DETECTORS:
            x = t[(t["incident"] == r["incident"]) & (t["detector"] == d)]
            if len(x) and bool(x.iloc[0]["detectado"]):
                row[NAMES[d]] = f"✓ ({int(x.iloc[0]['demora_dias'])})"
            else:
                row[NAMES[d]] = "✗"
        rows.append(row)
    df = pd.DataFrame(rows)
    # primero los incidentes en que los detectores no coinciden: ahí están los casos interesantes
    ok = df[[NAMES[d] for d in DETECTORS]].apply(lambda c: c.str.startswith("✓"))
    df = df.assign(_n=ok.sum(axis=1), _all=ok.all(axis=1)).sort_values(["_all", "_n", "Incidente"]).drop(columns=["_n", "_all"])
    style = [{"if": {"filter_query": f'{{{NAMES[d]}}} contains "✓"', "column_id": NAMES[d]},
              "backgroundColor": "#e6f0d6", "color": "#25401d", "fontWeight": 700} for d in DETECTORS]
    tot = {NAMES[d]: int(df[NAMES[d]].str.startswith("✓").sum()) for d in DETECTORS}
    summary = html.Div([html.Div(className="kpis", children=[kpi(f"{v}/{len(df)}", k) for k, v in tot.items()]),
                        html.P("Incidentes detectados por cada detector. La tabla muestra primero los incidentes en que "
                               "los detectores no coinciden.", className="note")])
    return [summary, table(df, id_="in-dt", page=25, style_data_conditional=style)]


@app.callback(Output("url", "search", allow_duplicate=True), Input("in-dt", "active_cell"), State("in-dt", "derived_viewport_data"),
              prevent_initial_call=True)
def incident_click(cell, data):
    if not cell:
        return no_update
    return "?" + urlencode({"tab": "explorador", "user": data[cell["row"]]["Incidente"]})


# ---------------------------------------------------------------------------- identificación
@app.callback(Output("id-graph", "figure"), Input("id-user", "value"), Input("id-signal", "value"))
def ident(user, signal):
    from scipy.signal import periodogram
    from statsmodels.tsa.stattools import acf, pacf
    ui, si = ST.uidx[user], ST.signals.index(signal)
    x = ST.Z[ui, :ST.t0, si].astype(float)
    fig = make_subplots(rows=1, cols=3, subplot_titles=["FAC", "FACP", "Periodograma"], horizontal_spacing=0.07)
    if x.std() == 0:
        fig.add_annotation(text="Serie constante en entrenamiento: no hay estructura que identificar", showarrow=False,
                           xref="paper", yref="paper", x=0.5, y=0.5)
        return fig_base(fig, 320)
    lags = np.arange(1, 29)
    band = 2 / np.sqrt(len(x))
    for col, vals in ((1, acf(x, nlags=28, fft=True)[1:]), (2, pacf(x, nlags=28)[1:])):
        fig.add_trace(go.Bar(x=lags, y=vals, marker_color=[COLORS["sarimax"] if lg % 7 == 0 else INK2 for lg in lags],
                             showlegend=False, hovertemplate="rezago %{x}: %{y:.3f}<extra></extra>"), row=1, col=col)
        fig.add_hrect(y0=-band, y1=band, fillcolor=GRID, opacity=0.6, line_width=0, layer="below", row=1, col=col)
    f, p = periodogram(x - x.mean())
    fig.add_trace(go.Scatter(x=1 / f[1:], y=p[1:], mode="lines", line=dict(color=COLORS["sarimax"], width=2), showlegend=False,
                             hovertemplate="periodo %{x:.1f} días<br>%{y:.3f}<extra></extra>"), row=1, col=3)
    fig.update_xaxes(type="log", tickvals=[2, 3.5, 7, 14, 30, 60], row=1, col=3, title_text="periodo (días)")
    fig.update_xaxes(tickvals=[7, 14, 21, 28], row=1, col=1, title_text="rezago (días)")
    fig.update_xaxes(tickvals=[7, 14, 21, 28], row=1, col=2, title_text="rezago (días)")
    return fig_base(fig, 340)


# Registra las rutas de los recursos JS de Dash al importar el módulo. Con gunicorn --preload todos
# los procesos las heredan; sin esto, una petición de JS que cae en un proceso que aún no sirvió la
# página se rechaza ("is registered but the path requested is not valid").
with server.test_request_context("/"):
    app.index()


if __name__ == "__main__":
    app.run(debug=os.environ.get("DASH_DEBUG") == "1", host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", 8050)))
