# ╔══════════════════════════════════════════════════════════════════════╗
# ║  Forge Suite v5 APEX — Dockerfile                                   ║
# ║  Enterprise Offensive Security Platform                              ║
# ║  FOR AUTHORIZED PENETRATION TESTING ENGAGEMENTS ONLY                 ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# Build:
#   docker build -t forge-suite:5.0.0 .
#
# Run (interactive):
#   docker run -it --rm --name forge forge-suite:5.0.0 bash
#
# Run a scan:
#   docker run -it --rm -v ./results:/opt/forge-suite/results forge-suite:5.0.0 \
#     python3 forge.py net --target 10.0.0.0/24 --mode internal
#
# Dashboard:
#   docker run -it --rm -p 1337:1337 forge-suite:5.0.0 \
#     python3 forge.py dashboard --host 0.0.0.0
#
# C2 team server:
#   docker run -it --rm -p 8443:8443 -p 50050:50050 forge-suite:5.0.0 \
#     python3 forge.py c2 server --bind 0.0.0.0 --port 8443
#
# docker-compose (recommended):
#   docker compose up -d

# ── Stage 1: Build dependencies ──────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime image ───────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Forge Suite <ops@forge-suite.local>" \
      version="5.0.0" \
      description="Forge Suite v5 APEX — Enterprise Offensive Security Platform"

# Install runtime system deps (nmap, hydra, network tools, chromium)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    curl \
    wget \
    git \
    smbclient \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /install /usr/local

# Install nuclei (Go binary — latest release)
RUN ARCH=$(dpkg --print-architecture) && \
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v')_linux_${ARCH}.zip" && \
    curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei 2>/dev/null || true && \
    chmod +x /usr/local/bin/nuclei 2>/dev/null || true && \
    rm -f /tmp/nuclei.zip

# Create forge user (non-root for opsec)
RUN groupadd -r forge && useradd -r -g forge -m -s /bin/bash forge

# Set up application directory
WORKDIR /opt/forge-suite
COPY . .

# Create results directories
RUN mkdir -p webforge/results netforge/results adforge/results aiforge/results \
    && chown -R forge:forge /opt/forge-suite

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FORGE_HOME=/opt/forge-suite \
    FORGE_INTEL_DB=/opt/forge-suite/data/intel.db \
    FORGE_DASHBOARD_PASSWORD=forge2026 \
    FORGE_C2_ADMIN_PW=changeme \
    TERM=xterm-256color

# Expose ports:
#   1337  — War Room Dashboard (HTTPS)
#   8443  — C2 HTTP/S Listener
#   50050 — C2 Team Server Operator API
#   53    — C2 DNS Listener
EXPOSE 1337 8443 50050 53/udp

# Health check — dashboard responds on /api/v1/state
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://localhost:1337/api/v1/state || exit 1

# Default: drop into bash so the operator can choose what to run
USER forge
ENTRYPOINT ["python3"]
CMD ["forge.py", "--help"]
