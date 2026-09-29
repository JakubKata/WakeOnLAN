FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --system --uid 10001 --no-create-home wol

COPY requirements.txt pyproject.toml ./
RUN pip install -r requirements.txt
# Editable install: relative paths (TLS_CERT_FILE, .env) are resolved against /app.
COPY wol_server ./wol_server
RUN pip install --no-deps -e .

USER wol

EXPOSE 8443 8444

# The server shuts down cleanly on KeyboardInterrupt, not on SIGTERM.
STOPSIGNAL SIGINT

CMD ["python", "-m", "wol_server"]
