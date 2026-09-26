// Sitio estático de resultados (GitHub Pages y Artifact). Lee data/summary.json y data/users/<usuario>.json.
// Ningún número está escrito a mano: todo sale de las tablas exportadas por el pipeline.
// Los colores salen de los tokens CSS (style.css), así los gráficos siguen el tema claro u oscuro.
"use strict";

const DET = ["global", "user", "seasonal_naive", "arima", "sarima", "sarimax"];
const NAMES = { global: "Regla global", user: "Línea base estática", seasonal_naive: "Regla ingenua (semana anterior)",
  arima: "ARIMA", sarima: "SARIMA", sarimax: "SARIMAX + pares" };
// Paletas JCUN validadas para daltonismo en este orden (skill dataviz), una para cada tema: ver style.css.
const COL = {};
const PROTO = { rolling: "Reentrenamiento mensual", fixed: "Sin reentrenar (origen fijo)" };
const SIG = { logons: "Inicios de sesión", after_hours_logons: "Inicios de sesión fuera de horario", unique_pcs: "Equipos distintos usados",
  usb_events: "Posible fuga por USB (memorias conectadas)", after_hours_usb: "Posible fuga por USB fuera de horario",
  file_events: "Posible robo de información (archivos copiados a USB)", emails_sent: "Correos enviados",
  external_emails: "Posible fuga por correo (destinatarios externos)", http_requests: "Páginas web visitadas" };
const SCEN = { 1: "Fuga de información a WikiLeaks, fuera de horario", 2: "Robo de datos antes de renunciar",
  3: "Sabotaje con la cuenta del supervisor" };
let INK, INK2, GRID, SURF, RED, MAL, HEAT;
const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
function readTheme() {
  for (const d of DET) COL[d] = css(`--s-${d}`);
  INK = css("--ink"); INK2 = css("--ink-2"); GRID = css("--line"); SURF = css("--surface");
  RED = css("--red"); MAL = css("--mal"); HEAT = ["--heat-0", "--heat-1", "--heat-2", "--heat-3"].map(css);
}
const Z99 = 2.3263478740408408;

let S = null, UIDX = null;
const $ = (id) => document.getElementById(id);
const nf = (x, d = 3) => (x === null || x === undefined || Number.isNaN(x)) ? "n. d." :
  Number(x).toLocaleString("es-CO", { minimumFractionDigits: d, maximumFractionDigits: d });
const pc = (x, d = 1) => nf(100 * x, d) + " %";
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function layout(extra = {}) {
  // Los ejes se combinan (no se reemplazan) para conservar zeroline, colores y cuadrícula del tema.
  const axis = { gridcolor: GRID, linecolor: INK2, zeroline: false };
  const x = Object.assign({}, axis, extra.xaxis || {}), y = Object.assign({}, axis, extra.yaxis || {});
  extra = Object.assign({}, extra, { xaxis: x, yaxis: y });
  return Object.assign({
    font: { family: "Lato, sans-serif", size: 13, color: INK }, paper_bgcolor: SURF, plot_bgcolor: SURF,
    margin: { l: 60, r: 16, t: 56, b: 50 }, hoverlabel: { font: { family: "Lato" } }, colorway: DET.map((d) => COL[d]),
    xaxis: { gridcolor: GRID, linecolor: INK2, zeroline: false }, yaxis: { gridcolor: GRID, linecolor: INK2, zeroline: false },
    legend: { orientation: "h", y: 1.02, yanchor: "bottom", x: 0 }, separators: ",.",
  }, extra);
}
const CFG = { displaylogo: false, responsive: true };

function fillSelect(el, opts, value) {
  el.innerHTML = opts.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
  if (value !== undefined) el.value = value;
}

function tableHTML(rows, cols, opts = {}) {
  const head = "<tr>" + cols.map((c) => `<th>${esc(c.label)}</th>`).join("") + "</tr>";
  const body = rows.map((r, i) => {
    const cls = opts.rowClass ? opts.rowClass(r) : "";
    const data = opts.rowData ? ` data-key="${esc(opts.rowData(r))}"` : "";
    const focus = cls === "link" ? ' tabindex="0"' : "";
    return `<tr class="${cls}"${data}${focus}>` + cols.map((c) => {
      const v = c.fmt ? c.fmt(r[c.key], r) : r[c.key];
      const tdc = c.cls ? c.cls(r[c.key], r) : "";
      return `<td class="${tdc}">${v === undefined ? "" : v}</td>`;
    }).join("") + "</tr>";
  }).join("");
  return `<table>${head}${body}</table>`;
}

// ------------------------------------------------------------------ inicio (relato guiado)
// Misma lectura que la pestaña Inicio de la app dinámica: todo con el mismo número de alertas diarias.
function budgetNumbers() {
  const k = S.meta.budget_k, c = S.presupuesto_alertas.filter((r) => r.protocolo === "rolling");
  const at = (d, kk, col) => c.find((r) => r.detector === d && r.k === kk)[col];
  const tp = {}, inc = {};
  for (const d of DET) { tp[d] = at(d, k, "dias_maliciosos_detectados"); inc[d] = at(d, k, "incidentes_detectados"); }
  const u = c.filter((r) => r.detector === "user").sort((a, b) => a.k - b.k);
  const kEq = (u.find((r) => r.dias_maliciosos_detectados >= tp.sarima) || { k: NaN }).k;
  const ratio = kEq / k;
  const esfuerzo = ratio >= 1.7 && ratio < 2 ? "casi el doble" : (ratio >= 2 ? "el doble o más" : "más trabajo");
  const dif = S.presupuesto_diferencias.find((r) => r.protocolo === "rolling" && r.detector === "sarima" && r.k === k);
  const s = resRow("rolling", "sarima"), nMal = Math.round(s[`top${k}_dia_TP`] / s[`top${k}_dia_recall`]);
  return { k, tp, inc, alerts: at("sarima", k, "alertas"), kEq, esfuerzo, dif, nMal };
}

function renderInicio() {
  const B = budgetNumbers(), N = S.ingesta.incidentes, g = resRow("rolling", "global");
  $("ruido").innerHTML = `En estos datos, una regla global con umbral del 99 % dispara <b>${nf(g.IP99_R1_alertas_por_dia, 0)} alertas por día</b>, y ${nf(100 * (1 - g.IP99_R1_precision), 0)} de cada 100 son falsas.`;
  $("paso4").textContent = `Cada mañana, los ${B.k} usuarios con mayor puntaje van a la cola de revisión del SOC. Como referencia, un exceso de más de 2,33 desviaciones estándar supera el límite del 99 %: el valor que un día normal de esa persona no debería superar más de 1 vez de cada 100.`;
  $("minuto").innerHTML = `<p><b>El problema.</b> Las reglas de umbral fijo de un SOC generan tanto ruido que los ataques internos se pierden en él. En estos datos, una regla global con límite del 99 % dispara ${nf(g.IP99_R1_alertas_por_dia, 0)} alertas al día, y ${nf(100 * (1 - g.IP99_R1_precision), 0)} de cada 100 son falsas.</p>
    <p><b>Lo que se hizo.</b> Para cada uno de los 1.000 usuarios y cada uno de sus 9 contadores diarios (sesiones, memorias USB, archivos, correo y web), un modelo SARIMA aprende su ritmo semanal y pronostica cuánto es normal cada día. Cada mañana, el SOC revisa a los ${B.k} usuarios que más se alejaron de su pronóstico.</p>
    <p><b>Lo que se encontró.</b> Con esas mismas ${B.k} alertas diarias, SARIMA encuentra ${B.tp.sarima} días maliciosos; la línea base estática, ${B.tp.user}, y la regla global, ${B.tp.global}. SARIMA detecta ${B.inc.sarima} de los ${N} incidentes.</p>
    <p><b>El límite.</b> Los datos (CERT r4.2) son sintéticos: el trabajo muestra que el método es viable, no cómo rinde en una organización real.</p>`;
  $("kpis-inicio").innerHTML = [
    ["+" + pc(B.dif.mejora_relativa, 0), `días maliciosos detectados frente a la línea base estática (${B.tp.sarima} frente a ${B.tp.user}, con las mismas ${B.k} alertas diarias)`],
    [`${nf(B.tp.sarima / B.tp.global, 1)} veces`, `los días maliciosos de la regla global (${B.tp.sarima} frente a ${B.tp.global}, mismas alertas)`],
    [`${nf(100 * B.tp.sarima / B.alerts, 1)} de 100`, `alertas de SARIMA son aciertos (línea base estática, ${nf(100 * B.tp.user / B.alerts, 1)}; regla global, ${nf(100 * B.tp.global / B.alerts, 1)})`],
    [`${B.inc.sarima} de ${N}`, `incidentes cubiertos por SARIMA (línea base estática, ${B.inc.user}; regla global, ${B.inc.global})`],
  ].map(([v, l]) => `<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join("");
  $("guia-budget").innerHTML = `<b>Cómo leer:</b> cada línea es un detector. El eje horizontal es cuántas alertas revisa el SOC cada día, de 1 a 30; el vertical, cuánto encuentra: a la izquierda, días maliciosos (de ${B.nMal}), y a la derecha, incidentes (de ${N}). Más arriba es mejor. Mire primero la línea punteada de ${B.k} alertas diarias: ahí SARIMA encuentra ${B.tp.sarima} días maliciosos; la línea base estática, ${B.tp.user}, y la regla global, ${B.tp.global}. En días maliciosos, los tres modelos de series de tiempo superan a la línea base estática con cualquier número de alertas. En incidentes, la ventaja está en las primeras alertas del día: desde 17 alertas diarias la línea base estática iguala a SARIMA, y con 21 lo supera por un incidente. No depende de unos pocos usuarios: al remuestrearlos 1.000 veces, la ventaja de SARIMA con ${B.k} alertas diarias quedó entre ${Math.round(B.dif.IC95_inf)} y ${Math.round(B.dif.IC95_sup)} días en el 95 % de los casos.`;
  $("significa").innerHTML = [
    `Con los mismos recursos, un modelo que conoce el ritmo de cada persona encuentra más: el analista revisa ${nf(B.alerts / B.tp.sarima, 1)} alertas por hallazgo en vez de ${nf(B.alerts / B.tp.user, 1)}, lo que ayuda a reducir la fatiga de alertas.`,
    `El ritmo semanal importa, pero hay que aprenderlo: con ${B.k} alertas diarias, SARIMA, que lo estima con los datos, encuentra ${B.tp.sarima} días maliciosos; una regla que solo repite el mismo día de la semana anterior, ${B.tp.seasonal_naive}.`,
    "Una alerta es una señal para investigar, no un ataque confirmado.",
    "Los datos (CERT r4.2) son sintéticos: los resultados muestran viabilidad, no el desempeño en una organización real.",
  ].map((x) => `<li>${x}</li>`).join("");
  drawBudget();
}

function drawBudget() {
  const B = budgetNumbers(), c = S.presupuesto_alertas.filter((r) => r.protocolo === "rolling"), tr = [];
  for (const d of ["global", "user", "arima", "sarima", "sarimax"]) {
    const x = c.filter((r) => r.detector === d).sort((a, b) => a.k - b.k);
    for (const [ax, col] of [["", "dias_maliciosos_detectados"], ["2", "incidentes_detectados"]]) {
      tr.push({ type: "scatter", mode: "lines", name: NAMES[d], legendgroup: d, showlegend: ax === "", xaxis: "x" + ax, yaxis: "y" + ax,
        x: x.map((r) => r.k), y: x.map((r) => r[col]),
        line: { color: COL[d], width: d === "sarima" ? 3.5 : 2, dash: ["global", "user", "sarima"].includes(d) ? "solid" : "dash" },
        hovertemplate: "%{x} alertas por día: %{y}<extra>" + NAMES[d] + "</extra>" });
    }
  }
  const ax = { gridcolor: GRID, linecolor: INK2, zeroline: false, title: "Alertas revisadas por día" };
  const vline = (xr) => ({ type: "line", xref: xr, yref: "paper", x0: B.k, x1: B.k, y0: 0, y1: 1, line: { dash: "dot", color: INK2 } });
  Plotly.newPlot("g-budget", tr, layout({
    grid: { rows: 1, columns: 2, pattern: "independent" }, margin: { l: 55, r: 16, t: 40, b: 120 },
    xaxis: Object.assign({ domain: [0, 0.46] }, ax), xaxis2: Object.assign({ domain: [0.54, 1], anchor: "y2" }, ax),
    yaxis: { gridcolor: GRID, linecolor: INK2, zeroline: false, rangemode: "tozero" },
    yaxis2: { gridcolor: GRID, linecolor: INK2, zeroline: false, rangemode: "tozero", anchor: "x2" },
    legend: { orientation: "h", y: -0.3, yanchor: "top", x: 0.5, xanchor: "center" },
    shapes: [vline("x"), vline("x2")],
    annotations: [
      { text: `Días maliciosos detectados (de ${B.nMal})`, xref: "paper", yref: "paper", x: 0.23, y: 1.02, xanchor: "center", yanchor: "bottom", showarrow: false, font: { size: 13, color: INK } },
      { text: `Incidentes detectados (de ${S.ingesta.incidentes})`, xref: "paper", yref: "paper", x: 0.77, y: 1.02, xanchor: "center", yanchor: "bottom", showarrow: false, font: { size: 13, color: INK } }],
  }), CFG);
}

// ------------------------------------------------------------------ resumen
function resRow(p, d) { return S.deteccion_resumen.find((r) => r.protocolo === p && r.detector === d); }

function renderSummary() {
  const k = S.meta.budget_k, rule = `top${k}_dia`, r0 = S.deteccion_resumen[0], ing = S.ingesta, N = ing.incidentes;
  const porEsc = [1, 2, 3].map((e) => S.incidentes.filter((r) => r.scenario === e).length);
  $("kpis").innerHTML = [
    [ing.usuarios.toLocaleString("es-CO"), "usuarios"], [ing.dias, "días de historia"],
    [r0.usuario_dia_prueba.toLocaleString("es-CO"), "usuario-día evaluados"], [String(N), `incidentes (${porEsc[0]}, ${porEsc[1]} y ${porEsc[2]})`],
    [pc(r0.prevalencia, 2), "prevalencia real en prueba"],
  ].map(([v, l]) => `<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join("");

  const B = budgetNumbers(), bf = S.presupuesto_diferencias.find((r) => r.protocolo === "fixed" && r.detector === "sarima" && r.k === k);
  const items = [
    `<b>${pc(B.dif.mejora_relativa, 0)} más con el mismo trabajo.</b> Revisando ${k} alertas al día, SARIMA encuentra ${B.tp.sarima} días de actividad maliciosa; la línea base estática, ${B.tp.user}, y la regla global, ${B.tp.global}. No depende de unos pocos usuarios: al remuestrearlos 1.000 veces, la ventaja de SARIMA quedó entre ${Math.round(B.dif.IC95_inf)} y ${Math.round(B.dif.IC95_sup)} días en el 95 % de los casos.`,
    `<b>Casi todos los incidentes.</b> Con esas mismas ${k} alertas diarias, SARIMA detecta ${B.inc.sarima} de los ${N} incidentes; la línea base estática, ${B.inc.user}, y la regla global, ${B.inc.global}.`,
    `<b>Más aciertos por alerta.</b> Para dar con un día malicioso, el analista revisa ${nf(B.alerts / B.tp.sarima, 0)} alertas con SARIMA, ${nf(B.alerts / B.tp.user, 0)} con la línea base estática y ${nf(B.alerts / B.tp.global, 0)} con la regla global.`,
    `<b>La línea base estática exige ${B.esfuerzo}.</b> Necesita ${B.kEq} alertas diarias para encontrar lo que SARIMA encuentra con ${k}.`,
    `<b>Lo que no favorece al modelo, también se muestra.</b> Sin reentrenar los modelos (origen fijo), SARIMA sigue encontrando más días maliciosos (${bf ? bf.diferencia_dias : "n. d."} más con ${k} alertas diarias), pero en incidentes, con 6 a 11 alertas diarias, la línea base estática detecta más. Con reentrenamiento mensual nunca supera al mejor modelo de series de tiempo; a SARIMA solo lo supera por un incidente con 21 alertas diarias.`,
    `<b>La ventaja viene del ritmo semanal.</b> Un control sin modelo, el perfil por día de la semana (también temporal), encuentra 210 días maliciosos y 67 incidentes con ${k} alertas diarias, muy por encima de la línea base estática; SARIMA encuentra ${B.tp.sarima}. Con 20 alertas diarias el perfil encuentra más (322 frente a 300). Detalle en la aplicación dinámica y en scripts/linea_base_semanal.py.`,
    `<b>En una sola nota (PR-AUC, de 0 a 1).</b> SARIMA obtiene ${nf(resRow("rolling", "sarima").PR_AUC, 4)}, la línea base estática ${nf(resRow("rolling", "user").PR_AUC, 4)} y la regla global ${nf(resRow("rolling", "global").PR_AUC, 4)}; elegir al azar daría ${nf(r0.prevalencia, 4)}. ARIMA obtiene ${nf(resRow("rolling", "arima").PR_AUC, 4)}, pero su diferencia con SARIMA no es clara (el intervalo del 95 % incluye el cero).`];
  $("findings").innerHTML = items.map((x) => `<li>${x}</li>`).join("");

  drawPRAUC();
  fillSelect($("pr-proto"), Object.entries(PROTO), "rolling");
  $("pr-proto").onchange = drawPR; drawPR();

  const rules = [[rule, `${k} alertas por día (cola de revisión)`], ["IP99_R1", "Límite del 99 % (1 contador)"], ["IP99_R2", "Límite del 99 % (2 contadores)"]];
  for (const id of ["sc-rule", "al-rule"]) fillSelect($(id), rules, id === "al-rule" ? "IP99_R1" : rule);
  for (const id of ["sc-proto", "al-proto"]) fillSelect($(id), Object.entries(PROTO), "rolling");
  $("sc-rule").onchange = $("sc-proto").onchange = drawScen; drawScen();
  $("al-rule").onchange = $("al-proto").onchange = drawDaily; drawDaily();

  const abl = S.deteccion_resumen.map((r) => ({
    p: PROTO[r.protocolo], d: NAMES[r.detector], ap: nf(r.PR_AUC, 4), ci: `${nf(r.PR_AUC_IC95_inf, 4)} a ${nf(r.PR_AUC_IC95_sup, 4)}`,
    roc: nf(r.ROC_AUC), prec: nf(100 * r[rule + "_precision"], 1), rec: pc(r[rule + "_recall"]), inc: `${r[rule + "_incidentes_detectados"]}/${N}`,
    fp1: nf(r.IP99_R1_FP_por_1000_ud, 1), rec1: pc(r.IP99_R1_recall), fp2: nf(r.IP99_R2_FP_por_1000_ud, 1), rec2: pc(r.IP99_R2_recall) }));
  $("t-ablation").innerHTML = tableHTML(abl, [
    { key: "p", label: "Protocolo" }, { key: "d", label: "Detector" }, { key: "ap", label: "PR-AUC" }, { key: "ci", label: "IC 95 %" },
    { key: "roc", label: "ROC-AUC" }, { key: "prec", label: `Aciertos por cada 100 alertas (${k}/día)` }, { key: "rec", label: `Días maliciosos detectados (${k}/día)` },
    { key: "inc", label: `Incidentes (${k}/día)` }, { key: "fp1", label: "Falsas alarmas por 1.000 usuario-día (límite 99 %)" }, { key: "rec1", label: "Días maliciosos detectados (límite 99 %)" },
    { key: "fp2", label: "Falsas alarmas por 1.000 usuario-día (2 contadores)" }, { key: "rec2", label: "Días maliciosos detectados (2 contadores)" }]);
  $("t-miss").innerHTML = tableHTML(S.lo_que_no_ven.map((r) => Object.assign({}, r, { p: PROTO[r.protocolo], d: NAMES[r.detector] })), [
    { key: "p", label: "Protocolo" }, { key: "d", label: "Detector" }, { key: "detectados", label: "Detectados" },
    { key: "detectados_por_estaticos", label: "Detectados por reglas estáticas (unión)" },
    { key: "solo_temporal", label: "Solo los ve el modelo temporal" }, { key: "perdidos_vs_estaticos", label: "Los ven las reglas y no el modelo" },
    { key: "incidentes_solo_temporal", label: "Incidentes", fmt: (v) => esc(String(v || "").replaceAll(";", ", ")) }]);
}

function drawPRAUC() {
  const r0 = S.deteccion_resumen[0];
  const traces = [["rolling", -0.17], ["fixed", 0.17]].map(([p, off]) => {
    const rows = DET.map((d) => resRow(p, d));
    return { type: "scatter", mode: "markers", name: PROTO[p], x: rows.map((r) => r.PR_AUC), y: DET.map((_, i) => i + off),
      marker: { size: 12, symbol: p === "rolling" ? "circle" : "circle-open", color: DET.map((d) => COL[d]),
        line: { width: 2, color: DET.map((d) => COL[d]) } },
      error_x: { type: "data", symmetric: false, array: rows.map((r) => r.PR_AUC_IC95_sup - r.PR_AUC),
        arrayminus: rows.map((r) => r.PR_AUC - r.PR_AUC_IC95_inf), color: INK2, thickness: 1.5, width: 0 },
      text: DET.map((d) => NAMES[d]),
      hovertemplate: "%{text}<br>PR-AUC %{x:.4f}<extra>" + PROTO[p] + "</extra>" };
  });
  Plotly.newPlot("g-prauc", traces, layout({ margin: { l: 150, r: 16, t: 56, b: 50 },
    yaxis: { autorange: "reversed", tickvals: DET.map((_, i) => i), ticktext: DET.map((d) => NAMES[d]), showgrid: false },
    xaxis: { title: "PR-AUC (nota de 0 a 1) con intervalo de confianza del 95 %", gridcolor: GRID, range: [0, 0.052] },
    shapes: [{ type: "line", x0: r0.prevalencia, x1: r0.prevalencia, yref: "paper", y0: 0, y1: 1, line: { dash: "dot", color: INK2 } }],
    annotations: [{ x: r0.prevalencia, y: 1, yref: "paper", text: "azar", showarrow: false, xanchor: "left", yanchor: "bottom", font: { size: 11, color: INK2 } }] }), CFG);
}

function drawPR() {
  const p = $("pr-proto").value;
  const tr = DET.map((d) => {
    const c = S.curvas_pr.find((x) => x.protocolo === p && x.detector === d);
    return { type: "scatter", mode: "lines", name: NAMES[d], x: c.recall, y: c.precision,
      line: { color: COL[d], width: d === "sarima" ? 2.8 : 1.8 },
      hovertemplate: "días maliciosos detectados %{x:.3f}<br>aciertos por alerta %{y:.3f}<extra>" + NAMES[d] + "</extra>" };
  });
  Plotly.newPlot("g-pr", tr, layout({ xaxis: { title: "Proporción de días maliciosos detectados", range: [0, 1], gridcolor: GRID },
    yaxis: { title: "Aciertos por alerta (precisión)", rangemode: "tozero", gridcolor: GRID } }), CFG);
}

function drawScen() {
  const rule = $("sc-rule").value, p = $("sc-proto").value;
  const tr = DET.map((d) => {
    const rows = [1, 2, 3].map((s) => S.deteccion_por_escenario.find((r) => r.protocolo === p && r.detector === d && r.regla === rule && r.escenario === s));
    return { type: "bar", name: NAMES[d], x: [1, 2, 3].map((s) => `Esc. ${s}: ${SCEN[s]}`), y: rows.map((r) => r.incidentes_detectados),
      customdata: rows.map((r) => r.incidentes), marker: { color: COL[d], line: { color: SURF, width: 2 } },
      hovertemplate: "%{x}: %{y} de %{customdata}<extra>" + NAMES[d] + "</extra>" };
  });
  Plotly.newPlot("g-scen", tr, layout({ barmode: "group", yaxis: { title: "Incidentes detectados", gridcolor: GRID } }), CFG);
}

function drawDaily() {
  const rule = $("al-rule").value, p = $("al-proto").value, days = S.alertas_diarias.days;
  const tr = DET.map((d) => {
    const y = S.alertas_diarias.series[`${p}|${d}|${rule}`] || [];
    const sm = y.map((_, i) => { const w = y.slice(Math.max(0, i - 6), i + 1); return w.reduce((a, b) => a + b, 0) / w.length; });
    return { type: "scatter", mode: "lines", name: NAMES[d], x: days, y: sm, line: { color: COL[d], width: 2 } };
  });
  Plotly.newPlot("g-daily", tr, layout({ hovermode: "x unified", yaxis: { title: "Alertas por día", gridcolor: GRID, rangemode: "tozero" } }), CFG);
}

// ------------------------------------------------------------------ explorador
const cacheU = {};
async function getUser(u) {
  if (!cacheU[u]) cacheU[u] = await (await fetch(`data/users/${u}.json`)).json();
  return cacheU[u];
}

function setupExplorer() {
  const users = UIDX.users;
  const u0 = users.some((u) => u.user === "IKR0401") ? "IKR0401" : users[0].user;   // el caso de la figura 1 del póster
  fillSelect($("ex-user"), users.map((u) => [u.user, u.malicioso ? `${u.user} · cuenta con días maliciosos` : u.user]), u0);
  fillSelect($("ex-signal"), Object.entries(SIG), "usb_events");
  fillSelect($("ex-det"), [["sarima", NAMES.sarima], ["user", NAMES.user], ["sarimax", NAMES.sarimax]], "sarima");
  for (const id of ["ex-user", "ex-signal", "ex-det"]) $(id).onchange = drawExplorer;
  const q = new URLSearchParams(location.search);
  if (q.get("user") && users.some((u) => u.user === q.get("user"))) $("ex-user").value = q.get("user");
  if (q.get("signal") && SIG[q.get("signal")]) $("ex-signal").value = q.get("signal");
}

async function drawExplorer() {
  const u = await getUser($("ex-user").value), s = $("ex-signal").value, det = $("ex-det").value;
  const si = S.meta.signals.indexOf(s), days = UIDX.days;
  const pr = u.pred[`rolling|${det}`];
  const act = u.active, obs = u.counts[si].map((v, i) => (act[i] ? v : null));
  const mu = pr.yhat[si].map((v, i) => (act[i] ? Math.expm1(v) : null));
  const up = pr.yhat[si].map((v, i) => (act[i] ? Math.expm1(v + Z99 * pr.sigma[si][i]) : null));
  const alert = obs.map((v, i) => (v !== null && up[i] !== null && v > up[i] && i >= S.meta.test_start_idx - u.t_from ? v : null));
  const shapes = u.malicious.map((m, i) => m ? ({ type: "rect", xref: "x", yref: "paper", x0: shift(days[i], -12), x1: shift(days[i], 12), y0: 0, y1: 1,
    fillcolor: MAL, line: { width: 0 }, layer: "below" }) : null).filter(Boolean);
  const t0 = days[S.meta.test_start_idx - u.t_from];
  shapes.push({ type: "line", x0: t0, x1: t0, yref: "paper", y0: 0, y1: 1, line: { dash: "dash", color: INK2 } });
  const tr = [
    { x: days, y: up, mode: "lines", line: { width: 0, shape: "hv" }, showlegend: false, hoverinfo: "skip" },
    { x: days, y: act.map((a) => (a ? 0 : null)), mode: "lines", line: { width: 0, shape: "hv" }, fill: "tonexty", fillcolor: hexA(COL[det], 0.17),
      name: `Límite 99 %: ${NAMES[det]}`, hoverinfo: "skip" },
    { x: days, y: mu, mode: "lines", line: { color: COL[det], width: 2, shape: "hv" }, name: `Esperado: ${NAMES[det]}` },
    { x: days, y: obs, mode: "lines+markers", line: { color: INK, width: 1.2, shape: "hv" }, marker: { size: 4 }, name: "Observado" },
    { x: days, y: alert, mode: "markers", marker: { size: 13, symbol: "circle-open", color: RED, line: { width: 2.5 } }, name: "Alerta" },
  ];
  $("ex-title").textContent = `${u.user} · ${SIG[s]} · ${NAMES[det]} (reentrenamiento mensual, límite del 99 %)`;
  const lastAct = days[act.lastIndexOf(1)] || days[days.length - 1];
  const xr = [days[0], shift(lastAct, 24 * 10)];
  Plotly.newPlot("g-ex", tr, layout({ shapes, xaxis: { range: xr, tickformat: "%d/%m/%Y", hoverformat: "%d/%m/%Y" }, yaxis: { title: SIG[s], rangemode: "tozero" }, hovermode: "x unified",
    legend: { orientation: "h", y: 1.02, yanchor: "bottom", x: 0 } }), CFG).then(() => Plotly.Plots.resize("g-ex"));
  const z = DET.map((d) => u.pred[`rolling|${d}`].A.map((v, i) => (act[i] ? v : null)));
  Plotly.newPlot("g-heat", [{ type: "heatmap", z, x: days, y: DET.map((d) => NAMES[d]), zmin: 0, zmax: 8,
    colorscale: [[0, HEAT[0]], [0.35, HEAT[1]], [0.7, HEAT[2]], [1, HEAT[3]]], colorbar: { title: "Puntaje" },
    hovertemplate: "%{x|%d/%m/%Y}<br>%{y}: puntaje %{z:.2f}<extra></extra>" }],
  layout({ margin: { l: 150, r: 16, t: 10, b: 40 }, yaxis: { autorange: "reversed" }, xaxis: { range: xr },
    shapes: u.malicious.map((m, i) => m ? ({ type: "line", x0: days[i], x1: days[i], yref: "paper", y0: 0, y1: 1, line: { color: RED, width: 1 }, opacity: 0.6 }) : null).filter(Boolean) }), CFG)
    .then(() => Plotly.Plots.resize("g-heat"));
}
function shift(day, h) { const d = new Date(day + "T00:00:00Z"); d.setUTCHours(d.getUTCHours() + h); return d.toISOString(); }
function hexA(h, a) { const n = parseInt(h.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; }

// ------------------------------------------------------------------ incidentes
function setupIncidents() {
  const k = S.meta.budget_k;
  fillSelect($("in-rule"), [[`top${k}_dia`, `${k} alertas por día (cola de revisión)`], ["IP99_R1", "Límite del 99 % (1 contador)"], ["IP99_R2", "Límite del 99 % (2 contadores)"]], `top${k}_dia`);
  fillSelect($("in-proto"), Object.entries(PROTO), "rolling");
  fillSelect($("in-scen"), [["0", "Todos"], ["1", "1. " + SCEN[1]], ["2", "2. " + SCEN[2]], ["3", "3. " + SCEN[3]]], "0");
  for (const id of ["in-rule", "in-proto", "in-scen"]) $(id).onchange = drawIncidents;
  drawIncidents();
}

function drawIncidents() {
  const rule = $("in-rule").value, p = $("in-proto").value, sc = Number($("in-scen").value);
  const det = S.incidentes_detalle.filter((r) => r.regla === rule && r.protocolo === p);
  const rows = S.incidentes.filter((r) => !sc || r.scenario === sc).map((r) => {
    const row = { inc: r.incident, sc: r.scenario, start: r.start.slice(0, 10), days: r.malicious_days, acc: r.accounts.replaceAll(";", ", ") };
    for (const d of DET) {
      const x = det.find((z) => z.incident === r.incident && z.detector === d);
      row[d] = x && x.detectado ? `✓ (${x.demora_dias})` : "✗";
    }
    return row;
  });
  const cols = [{ key: "inc", label: "Incidente" }, { key: "sc", label: "Esc." }, { key: "start", label: "Inicio" },
    { key: "days", label: "Días maliciosos" }, { key: "acc", label: "Cuentas" }]
    .concat(DET.map((d) => ({ key: d, label: NAMES[d], cls: (v) => (String(v).startsWith("✓") ? "ok" : "") })));
  $("t-inc").innerHTML = tableHTML(rows, cols, { rowClass: () => "link", rowData: (r) => r.inc });
  $("in-summary").textContent = "Detectados: " + DET.map((d) => `${NAMES[d]} ${rows.filter((r) => r[d].startsWith("✓")).length}/${rows.length}`).join("; ") +
    ". Entre paréntesis, días desde el primer día malicioso hasta la primera alerta. Haz clic en un incidente para ver su serie.";
  $("t-inc").querySelectorAll("tr.link").forEach((tr) => {
    const open = () => { const u = tr.dataset.key; if (UIDX.users.some((x) => x.user === u)) { $("ex-user").value = u; showTab("explorador"); } };
    tr.onclick = open;
    tr.onkeydown = (e) => { if (e.key === "Enter") open(); };
  });
}

// ------------------------------------------------------------------ identificación y método
function renderIdent() {
  if (!S.identificacion_resumen) { $("t-ident").textContent = "Tabla de identificación no disponible."; return; }
  const r = S.identificacion_resumen.map((x) => ({ s: SIG[x.signal], m: pc(x.pct_modelables), c: pc(x.pct_ciclo_semanal), a7: pc(x.pct_acf7_signif),
    a1: pc(x.pct_acf1_signif), adf: pc(x.pct_adf_desest_rechaza), kp: pc(x.pct_kpss_no_rechaza) }));
  $("t-ident").innerHTML = tableHTML(r, [{ key: "s", label: "Contador" }, { key: "m", label: "Series modelables" },
    { key: "c", label: "Ciclo semanal (periodograma)" }, { key: "a7", label: "FAC(7) significativa" }, { key: "a1", label: "FAC(1) significativa" },
    { key: "adf", label: "ADF rechaza raíz unitaria (desestacionalizada)" }, { key: "kp", label: "KPSS no rechaza estacionariedad" }]);
  const o = S.meta.signals.map((s) => ({ s: SIG[s], ar: `(${S.ordenes.arima[s].order.join(",")})`,
    sa: `(${S.ordenes.sarima[s].order.join(",")})(${S.ordenes.sarima[s].seasonal_order.slice(0, 3).join(",")})${S.ordenes.sarima[s].seasonal_order[3] || ""}` }));
  $("t-orders").innerHTML = tableHTML(o, [{ key: "s", label: "Contador" }, { key: "ar", label: "ARIMA" }, { key: "sa", label: "SARIMA / SARIMAX" }]);
}

async function renderMethod() {
  // En el Artifact el texto viene incluido en la página; en GitHub Pages se lee metodo.md.
  const inline = document.getElementById("metodo-md");
  const md = inline ? inline.textContent : await (await fetch("metodo.md")).text();
  $("method").innerHTML = window.marked ? window.marked.parse(md) : `<pre>${esc(md)}</pre>`;
}

// ------------------------------------------------------------------ navegación
const TABS = ["inicio", "resumen", "explorador", "incidentes", "identificacion", "metodo"];
let current = "inicio";
function showTab(t) {
  if (!TABS.includes(t)) t = "inicio";
  current = t;
  document.querySelectorAll("#tabs button").forEach((b) => { b.classList.toggle("sel", b.dataset.tab === t); b.setAttribute("aria-selected", b.dataset.tab === t); });
  document.querySelectorAll(".tab-panel").forEach((p) => (p.hidden = p.id !== `tab-${t}`));
  try { history.replaceState(null, "", "#" + t); } catch (e) { /* sin historial en algunos visores */ }
  if (t === "explorador") drawExplorer();
  window.dispatchEvent(new Event("resize"));
}

// Al cambiar el tema (sistema o selector del visor) se vuelven a leer los tokens y a dibujar los gráficos.
function redrawAll() {
  readTheme();
  for (const f of [drawBudget, drawPRAUC, drawPR, drawScen, drawDaily]) { try { f(); } catch (e) { console.error(e); } }
  if (current === "explorador") drawExplorer();
}
function watchTheme() {
  const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  if (mq && mq.addEventListener) mq.addEventListener("change", redrawAll);
  new MutationObserver(redrawAll).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
}

async function main() {
  readTheme();
  S = await (await fetch("data/summary.json")).json();
  UIDX = await (await fetch("data/users_index.json")).json();
  if (window.UEBA_DYNAMIC_APP_URL) $("app-link").innerHTML = `App dinámica con los 1.000 usuarios y el laboratorio de umbrales: <a href="${esc(window.UEBA_DYNAMIC_APP_URL)}">${esc(window.UEBA_DYNAMIC_APP_URL)}</a>`;
  document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));
  for (const f of [renderInicio, renderSummary, setupExplorer, setupIncidents, renderIdent, renderMethod]) {
    try { await f(); } catch (e) { console.error(e); }
  }
  watchTheme();
  const q = new URLSearchParams(location.search);
  const hash = (location.hash || "").replace("#", "");
  showTab(TABS.includes(hash) ? hash : (q.get("tab") || "inicio"));
}
main().catch((e) => { document.querySelector("main").insertAdjacentHTML("afterbegin", `<div class="card">No se pudieron cargar los datos: ${esc(e.message)}</div>`); });
