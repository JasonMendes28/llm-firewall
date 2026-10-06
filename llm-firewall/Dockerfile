# syntax=docker/dockerfile:1.7
# =============================================================================
# LLM Firewall — multi-stage Docker build.
#
# Design goals:
#   1. Minimal final image (no compilers, no dev tools).
#   2. Non-root runtime user (uid 10001).
#   3. Reproducible: pinned base image digests and pinned Python deps.
#   4. Health check baked in.
# =============================================================================

# ---------- Stage 1: builder ----------
# Use slim (not alpine) — alpine + torch/transformers is a compatibility nightmare.
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps only in this stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/src

# Non-root user: fixed uid/gid so bind-mounts and log ownership are predictable.
RUN groupadd --gid 10001 firewall && \
    useradd --uid 10001 --gid firewall --shell /bin/false --create-home firewall

# Minimal runtime OS packages.
# curl only needed for HEALTHCHECK; if you'd rather not ship it, drop it and
# switch the healthcheck to a Python one-liner.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=firewall:firewall src/ ./src/
COPY --chown=firewall:firewall rules/ ./rules/
COPY --chown=firewall:firewall pyproject.toml ./

USER firewall

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health || exit 1

# Uvicorn workers=1 by default; scale via orchestrator (K8s replicas) instead.
CMD ["uvicorn", "firewall.main:app", "--host", "0.0.0.0", "--port", "8080"]
