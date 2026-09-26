<p align="center">
  <img src="docs/img/escudo_unal.svg" alt="Escudo de la Universidad Nacional de Colombia" width="120">
</p>

<h1 align="center">Detectando lo que las reglas y las líneas base no ven:<br>UEBA basado en series de tiempo</h1>

<p align="center">
  <b>Alejandro Higuera Castro</b><br>
  Departamento de Estadística · Facultad de Ciencias · Universidad Nacional de Colombia, Sede Bogotá<br>
  Póster y artículo para la <b>7.ª Jornada de Ciberseguridad de la Universidad Nacional de Colombia (JCUN 2026)</b>
</p>

> La credencial es válida. El acceso es válido. El comportamiento, no necesariamente.

## De qué trata

Los centros de operaciones de seguridad (SOC) buscan amenazas internas con reglas de umbral y líneas base estáticas que generan tantas falsas alarmas que los analistas terminan por ignorarlas. Este trabajo trata la actividad de cada usuario como una **serie de tiempo con ciclo semanal**: cada noche, un modelo SARIMA por usuario (metodología Box-Jenkins) pronostica nueve contadores diarios (inicios de sesión, memorias USB, archivos copiados a USB, correo y navegación web), mide cuánto se aleja lo observado de lo normal para ese usuario y entrega al analista los casos más anómalos del día.

Seis detectores se comparan **con el mismo número de alertas diarias**, es decir, con la misma carga de trabajo para el analista, sobre el conjunto de datos sintético CERT r4.2 (1.000 usuarios, 500 días, 32,8 millones de eventos y 70 incidentes de tres tipos: fuga de información a WikiLeaks, robo de datos antes de renunciar y sabotaje con la cuenta del supervisor).

## Resultados principales

Periodo de prueba: 309.661 usuario-día activos, con 986 días maliciosos (0,32 %). Reentrenamiento mensual. Todas las cifras salen de `results/tables/` (`presupuesto_alertas.csv`, `presupuesto_diferencias.csv`, `deteccion_resumen.csv`, `bootstrap_diferencias.csv`).

**Días maliciosos detectados (de 986) con el mismo número de alertas diarias.** En negrita, el mejor valor de cada columna.

| Detector | 3 alertas/día | 5/día | 10/día | 20/día | Incidentes (10/día) | Aciertos por 100 alertas (10/día) | PR-AUC (azar: 0,0032) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Regla global | 16 | 19 | 36 | 42 | 17/70 | 1,1 | 0,0125 |
| Línea base estática | 52 | 82 | 163 | 258 | 64/70 | 4,8 | 0,0270 |
| Regla ingenua (semana anterior) | 32 | 53 | 93 | 157 | 46/70 | 2,7 | 0,0118 |
| ARIMA | **85** | 126 | 220 | 293 | **67/70** | 6,5 | **0,0346** |
| SARIMA | 81 | **146** | **240** | 300 | **67/70** | **7,0** | 0,0331 |
| SARIMAX + pares | 83 | 131 | 234 | **305** | 65/70 | 6,9 | 0,0330 |

* **47 % más con el mismo trabajo.** Con 10 alertas al día, SARIMA encuentra 240 días maliciosos; la línea base estática, 163 (intervalo de confianza del 95 % de la diferencia, por remuestreo de usuarios: 43 a 117 días), y la regla global, 36.
* **Siempre por encima.** Los tres modelos de series de tiempo detectan más días maliciosos que la línea base estática con cualquier número de alertas diarias entre 1 y 30.
* **Más aciertos por alerta.** Por cada día malicioso encontrado, el analista revisa 14,2 alertas con SARIMA, 20,9 con la línea base estática y 94,7 con la regla global. La línea base estática necesita 18 alertas diarias para igualar lo que SARIMA encuentra con 10.
* **Un umbral fijo satura.** Si cada detector usa su propio límite del 99 %, sin tope diario, la regla global dispara 108 alertas al día (98 de cada 100 falsas); SARIMA, 18,5 (95 de cada 100 falsas).
* **El ritmo semanal importa, pero hay que estimarlo.** Repetir el mismo día de la semana anterior (regla ingenua) encuentra 93 días maliciosos con 10 alertas diarias; SARIMA, 240. La prueba de Ljung-Box no encuentra patrón en los errores del 82 % de los ajustes SARIMA y solo del 9 % de los ARIMA, que no modelan el ciclo semanal.
* **La ventaja viene del ritmo semanal.** Un control sin modelo, el perfil por día de la semana (también temporal; `scripts/linea_base_semanal.py`), encuentra 210 días maliciosos y 67 incidentes con 10 alertas diarias, muy por encima de la línea base estática. SARIMA encuentra más con 10 alertas diarias (240) y el perfil, con 20 (322 frente a 300).
* **También lo que no favorece al modelo.** En PR-AUC, ARIMA, SARIMA y SARIMAX no se distinguen entre sí (los intervalos de sus diferencias incluyen el cero). Sin reentrenar (origen fijo), SARIMA sigue encontrando más días maliciosos que la línea base estática (233 frente a 171 con 10 alertas diarias), pero en incidentes la línea base estática detecta más con 6 a 11 alertas diarias. Con reentrenamiento mensual, la línea base estática nunca supera al mejor modelo de series de tiempo en incidentes; a SARIMA solo lo supera por uno con 21 alertas diarias.

## Entregables

| Entregable | Archivo | Descripción |
| --- | --- | --- |
| PDF para la convocatoria | [`paper/entrega_4_paginas.pdf`](paper/entrega_4_paginas.pdf) | 4 páginas: artículo en formato LNCS (páginas 1 a 3) y póster (página 4) |
| Artículo | [`paper/main.pdf`](paper/main.pdf) | 3 páginas, Springer LNCS, A4 |
| Póster A0 | [`poster/poster_A0.pdf`](poster/poster_A0.pdf) | 841 x 1189 mm, sobre la plantilla oficial JCUN 2026, completamente vectorial |
| Contenido del póster | [`poster/contenido_poster.md`](poster/contenido_poster.md) | Texto de cada sección, glosario, tabla y referencias |
| Aplicación dinámica | `app/` | Dash: todos los resultados, laboratorio y explorador de los 1.000 usuarios |
| Sitio estático | `docs/` | Versión liviana para GitHub Pages |

## Estructura del repositorio

| Carpeta | Qué hay |
| --- | --- |
| `src/ueba_ts/` | Proceso reproducible: ingesta, identificación Box-Jenkins, detectores, evaluación, figuras y exportación |
| `configs/` | `cert_r42.yaml` (todas las decisiones del experimento) y `smoke.yaml` (prueba rápida con pocos usuarios) |
| `results/tables/` | Tablas de resultados en CSV que citan el artículo, el póster y la aplicación |
| `results/figures/`, `results/figures_poster/` | Figuras del artículo y del póster (PDF, PNG y SVG) |
| `app/` | Aplicación dinámica en Dash y sus datos (`app/data/`, generados por `python -m ueba_ts export`) |
| `docs/` | Sitio estático (HTML, JavaScript y datos en JSON) y `artefacto.html`, la misma página en un solo archivo |
| `paper/` | `main.tex`, `entrega_4_paginas.tex`, `referencias.bib` y los PDF |
| `poster/` | Generador del póster (`build_poster.py`, `contenido.py`, `poster.css`), control de calidad (`qa_poster.py`), vectorización de la plantilla (`vectorizar_plantilla.py`), fuentes del evento (`assets/fuentes/`, licencia OFL) y figuras |
| `detections/` | La analítica documentada como detección para un SOC (formato inspirado en Sigma, no ejecutable, y una versión equivalente en KQL) |
| `scripts/` | Controles de sensibilidad (convergencia de SARIMAX y perfil por día de la semana) y armado de `docs/artefacto.html` |
| `tests/` | Pruebas de las métricas |

## Reproducir los resultados

1. Descargar el [Insider Threat Test Dataset](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247/1) (Lindauer, 2020, CC BY 4.0, doi:10.1184/R1/12841247.v1) y descomprimir r4.2 y `answers` (el registro de incidentes) de forma que queden `r4.2/logon.csv`, `r4.2/device.csv`, `r4.2/file.csv`, `r4.2/email.csv`, `r4.2/http.csv`, `r4.2/LDAP/` y `answers/insiders.csv`. Ajustar `raw_dir` y `answers_dir` en `configs/cert_r42.yaml`.
2. Instalar y correr:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-analysis.txt && pip install -e .
python -m ueba_ts all --config configs/cert_r42.yaml --jobs 8
pytest
```

| Paso | Qué hace | Tiempo aproximado (13 procesos) |
| --- | --- | --- |
| `build` | 32,8 millones de eventos a una rejilla de 500.000 usuario-día con ceros explícitos; etiquetas aparte | 20 s |
| `identify` | ADF, KPSS, FAC y periodograma en 9.000 series; órdenes por AIC en 60 usuarios | 6 min |
| `detect` | 6 detectores x 2 protocolos x 1.000 usuarios x 9 contadores (202.824 modelos estimados) | 61 min |
| `evaluate` | Métricas con igual número de alertas diarias, reglas de alerta, incidentes y bootstrap por usuarios (1.000 remuestreos) | 1,5 min |
| `figures`, `export` | Figuras y datos para la aplicación y el sitio | 1 min |

## Aplicación dinámica (Dash)

```bash
pip install -r requirements.txt
python -m app.app            # http://127.0.0.1:8050
```

Pestañas:
* **Inicio:** relato guiado para todo público: el problema, los datos, la idea, cómo funciona y el resultado principal.
* **Resultados:** tablas y comparaciones oficiales.
* **Laboratorio:** recalcula todas las métricas al cambiar el protocolo, los contadores vigilados, la forma de alertar y el número de alertas diarias.
* **Explorador de usuarios:** lo observado frente a lo esperado y el límite del 99 % de los 1.000 usuarios y los 6 detectores.
* **Cola de revisión diaria:** lo que vería el analista cada mañana.
* **Incidentes:** los 70 incidentes y qué detector encontró cada uno.
* **Identificación Box-Jenkins:** FAC, FACP y periodograma de cualquier usuario y contador.
* **Método, glosario y fuentes.**

Cada gráfica trae un recuadro «Cómo leer» en lenguaje llano. Enlace directo de ejemplo: `/?tab=explorador&user=IKR0401&signal=usb_events`.

La aplicación lee `app/data/`, que genera `python -m ueba_ts export` (conteos exactos y pronósticos en float32, idénticos a los del proceso: el Laboratorio reproduce exactamente las tablas oficiales). Al arrancar descomprime los pronósticos una sola vez en una carpeta de caché (`UEBA_CACHE`, por defecto el directorio temporal) y los lee con memory map, así funciona con poca memoria.

### Despliegue

**Heroku** (usa `Procfile`, `requirements.txt` y `.python-version`):

```bash
heroku create ueba-jcun2026
git push heroku main
```

Un dyno Basic o Standard-1X es suficiente (un proceso con 8 hilos); con Standard-2X el laboratorio responde más rápido.

**AWS App Runner, Azure App Service o Azure Container Apps** (usa el `Dockerfile`):

```bash
docker build -t ueba-jcun2026 .
docker run -p 8050:8050 ueba-jcun2026
```

## Sitio estático (GitHub Pages)

`docs/` es una versión liviana sin servidor: inicio guiado, resultados, incidentes, identificación, glosario y el explorador para las cuentas con días maliciosos más 60 usuarios benignos al azar. Para publicarlo: *Settings, Pages, Deploy from a branch, `main` / `docs`*. Si la aplicación dinámica está desplegada, poner su URL en `docs/config.js` para que el sitio la enlace.

## Artículo y póster

```bash
cd paper && latexmk -pdf main.tex                    # páginas 1 a 3 (LNCS, A4)
python poster/build_poster.py                        # poster_A0.html y contenido_poster.md desde results/tables
python poster/qa_poster.py                           # desbordes, equilibrio de columnas y tamaños de letra
chromium --headless --no-pdf-header-footer --print-to-pdf=poster/poster_A0.pdf poster/poster_A0.html
cd paper && latexmk -pdf entrega_4_paginas.tex       # PDF de entrega: artículo + póster como página 4
UEBA_QR_URL=https://tu-app.herokuapp.com python poster/build_poster.py   # agrega el QR cuando exista la URL
```

El encabezado y el pie del póster salen de la plantilla oficial JCUN 2026, que no se incluye en el repositorio. En su PDF son una imagen de 150 ppp; `poster/vectorizar_plantilla.py` los reconstruye en vectores para imprimir en A0 (bandas, píldoras y líneas como formas exactas, textos como texto real con las fuentes del evento, logos trazados). Se corre una sola vez con la ruta del PDF de la plantilla y `VTRACER_PY` apuntando a un Python 3.13 con `vtracer`, porque su versión para Python 3.14 falla. El resultado (`poster/assets/encabezado.svg`, `pie.svg` y `plantilla.json`) sí está en el repositorio.

## Qué no se incluye en el repositorio

`.gitignore` deja fuera lo que se puede reconstruir o que no pertenece al proyecto:

* **Datos crudos de CERT r4.2** (unos 16 GB): se descargan de KiltHub.
* **Datos intermedios** (`data/interim/`, `data/processed/`, salvo `ingest_log.json`): los genera `python -m ueba_ts build`.
* **Pronósticos completos** (`results/arrays/`, unos 480 MB, salvo `meta.json`): los genera `python -m ueba_ts detect`. La aplicación y el sitio usan versiones reducidas que sí están incluidas (`app/data/` y `docs/data/`).
* **Registros de ejecución** (`results/*.log`), archivos auxiliares de LaTeX, entornos virtuales y cachés de Python.
* **La plantilla oficial del póster** (PDF de la JCUN), que pertenece al evento.

## Decisiones metodológicas

* **Partición cronológica.** Ningún incidente del registro de incidentes empieza antes del 10 de junio de 2010: el entrenamiento inicial (2 de enero a 9 de junio de 2010) no contiene ataques y los 70 incidentes quedan en la prueba.
* **Dos protocolos.** Reentrenamiento mensual con los últimos 182 días (principal; origen rodante, Tashman 2000; perfil regenerado periódicamente, NIST SP 800-94) y origen fijo (sensibilidad, como BRITD). La diferencia mide el intercambio entre deriva y contaminación de la línea base que describe NIST.
* **Etiquetas por usuario del evento.** En el escenario 3 el correo masivo sale desde la cuenta del supervisor; ese usuario-día también es malicioso.
* **Solo aumentos.** Solo interesan los aumentos de actividad (prueba de una cola).
* **Series casi vacías** (menos de 5 % de días con actividad): línea base estática con desviación mínima de 0,25, que actúa como detector de primera vez.
* **Proporción real de días maliciosos.** Sin remuestreo: se evalúan todos los usuario-día activos del periodo de prueba.
* **Comparación con la misma carga de trabajo.** La comparación principal usa el mismo número de alertas diarias (de 1 a 30), con intervalos de confianza por remuestreo bootstrap de usuarios. También se reporta el PR-AUC (Saito y Rehmsmeier, 2015).

## Limitaciones

CERT es sintético: los resultados indican viabilidad, no desempeño en una organización real. Una anomalía es una señal para investigar y correlacionar con EDR, NIDS, DLP e IAM, no un ataque confirmado. El conteo diario no ve una acción única sin cambio de volumen.

## Licencias y cita

* **Código:** licencia MIT (`LICENSE`).
* **Datos:** CERT Insider Threat Test Dataset, CC BY 4.0; citar a Lindauer (2020) y a Glasser y Lindauer (2013).
* **Fuentes tipográficas** (`poster/assets/fuentes/`): Lato y MuseoModerno, SIL Open Font License 1.1.
* **Escudo:** símbolo institucional de la Universidad Nacional de Colombia (diseño de César Puertas Céspedes, guía de identidad visual de la UNAL; archivo de Wikimedia Commons). Se usa solo para indicar la afiliación del autor.
* **Encabezado y pie del póster:** identidad visual de la JCUN 2026.

Para citar este trabajo, ver `CITATION.cff`.
