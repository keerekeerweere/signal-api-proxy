# Proxy only. signal-cli is NOT in this image: it keeps running on the host
# (registered and linked there as usual) and this container just fronts it.
FROM python:3.13-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SIGNAL_PROXY_CONFIG=/config/config.json

COPY server.py /app/server.py

# Overridden by compose `user:` so spool files are readable by the host's signal-cli.
USER 1000:1000
ENTRYPOINT ["python3", "/app/server.py"]
