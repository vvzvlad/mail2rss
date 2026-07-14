FROM python:3.12-slim

WORKDIR /app

# curl is required by the compose healthcheck — it runs INSIDE this container.
# No build toolchain here on purpose: lxml, nh3 and cryptography all ship
# manylinux wheels, so pip installs them without gcc.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Logs must reach the json-file driver immediately, without stdio buffering.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependencies as a separate layer: they change less often than code → cached better
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code and static assets. templates/ ships INSIDE the image: on prod data/ is
# shadowed by the volume, so assets placed there would vanish.
COPY src/ src/
COPY templates/ templates/
COPY main.py .

# The only mutable state (disposable SQLite cache). Created before the ownership
# switch below, so the named volume inherits appuser's ownership on first mount.
RUN mkdir -p data

# Non-root: the service needs no privileges beyond writing to data/.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# No EXPOSE: the service is published by Traefik via docker-compose labels.

CMD ["python", "main.py"]
