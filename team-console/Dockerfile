FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY team-console/frontend/package.json team-console/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY team-console/frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NODE_EXECUTABLE=/usr/local/bin/node \
    TZ=Asia/Shanghai \
    TEAM_CONSOLE_HOST=0.0.0.0 \
    TEAM_CONSOLE_PORT=5050 \
    TEAM_CONSOLE_DATA_DIR=/data

# Protocol authorization uses Node, not a browser. No Chromium/Go/Roxy service.
COPY --from=frontend /usr/local/bin/node /usr/local/bin/node
COPY team-console/requirements-docker.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
    && groupadd --gid 10001 console \
    && useradd --uid 10001 --gid console --no-create-home console \
    && mkdir -p /data \
    && chown console:console /data

WORKDIR /app
COPY core/ ./core/
COPY config/ ./config/
COPY sentinel/ ./sentinel/
COPY webui/__init__.py webui/team_admin_routes.py ./webui/
COPY team-console/ ./team-console/
COPY --from=frontend /build/dist/ ./team-console/frontend/dist/
RUN test -s team-console/frontend/dist/index.html \
    && test -s sentinel/sentinel-runner.js \
    && node --version

WORKDIR /app/team-console
USER 10001:10001
EXPOSE 5050
HEALTHCHECK --interval=30s --timeout=8s --start-period=30s --retries=3 \
    CMD ["python", "docker_healthcheck.py"]
CMD ["python", "container_server.py"]
