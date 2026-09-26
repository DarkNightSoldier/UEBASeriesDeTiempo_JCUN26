"""Arma docs/artefacto.html: la misma página de docs/index.html con CSS, JS y el texto del método
incluidos, sin <html>/<head>/<body> (el visor de Artifacts agrega su propio esqueleto).
Los datos se publican aparte, en las mismas rutas relativas (data/summary.json, data/users/...).

    python scripts/build_artifact.py
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")


def read(name):
    with open(os.path.join(DOCS, name), encoding="utf-8") as fh:
        return fh.read()


html = read("index.html")
body = re.search(r"<body>(.*)</body>", html, re.S).group(1)
body = re.sub(r'\s*<script src="(config|app)\.js"></script>', "", body)
metodo = read("metodo.md").replace("</script", "<\\/script")

page = f"""<title>UEBA temporal JCUN 2026</title>
<meta name="description" content="Resultados interactivos del póster JCUN 2026: UEBA basado en series de tiempo sobre CERT r4.2.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@300;400;700&family=MuseoModerno:wght@600;700&display=swap" rel="stylesheet">
<style>
{read("style.css")}
</style>
{body.strip()}
<script type="text/markdown" id="metodo-md">
{metodo}
</script>
<script src="https://cdn.jsdelivr.net/npm/plotly.js-dist-min@2.35.2/plotly.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js"></script>
<script>
window.UEBA_DYNAMIC_APP_URL = "";
{read("app.js")}
</script>
"""
out = os.path.join(DOCS, "artefacto.html")
with open(out, "w", encoding="utf-8") as fh:
    fh.write(page)
print(out, round(len(page.encode()) / 1024, 1), "KB")
