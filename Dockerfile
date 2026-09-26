# Imagen de la app para AWS App Runner, Azure App Service / Container Apps o cualquier servicio de contenedores.
FROM python:3.12-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8050 UEBA_CACHE=/tmp/ueba_ts_cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8050
CMD gunicorn app.app:server --workers 1 --threads 8 --timeout 120 --preload --bind 0.0.0.0:${PORT}
