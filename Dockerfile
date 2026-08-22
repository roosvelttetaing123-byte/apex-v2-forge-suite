# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Forge Suite container image. Build with:
#   docker build --build-arg FORGE_VERSION="$(tr -d '\r\n' < VERSION)" \
#     --tag "forge-suite:$(tr -d '\r\n' < VERSION)" .

# Tags are retained for operator readability; immutable multi-platform index
# digests prevent registry tag drift. Update these references deliberately.
ARG PYTHON_IMAGE=python:3.13.9-slim-bookworm@sha256:b685a4fa58bb19d1814d78a1ec0f0208f351452724f78b20212c984d6e124a34
ARG NODE_IMAGE=node:20.19.5-bookworm-slim@sha256:9e70124bd00f47dd023e349cd587132ae61892acc0e47ed641416c3e18f401c3

# Build the checked-in UI lockfile in an isolated stage. VERSION is copied to
# the parent directory because apex-ui/vite.config.js reads ../VERSION.
FROM ${NODE_IMAGE} AS frontend-builder
WORKDIR /build/apex-ui
# The immutable official image bundles the exact qualified npm release. Assert
# both executables before the checked-in dependency graph is consumed.
RUN test "$(node --version)" = "v20.19.5" \
    && test "$(npm --version)" = "10.8.2"
COPY apex-ui/package.json apex-ui/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY VERSION /build/VERSION
COPY apex-ui/index.html apex-ui/tsconfig.json apex-ui/vite.config.js ./
COPY apex-ui/public ./public
COPY apex-ui/src ./src
RUN npm run typecheck \
    && npm run build

# The immutable snapshot date is the one recorded in the reviewed base-image
# source metadata. Disabling Valid-Until is required for historic snapshots;
# signature verification remains enabled through Debian's archive keyring.
FROM ${PYTHON_IMAGE} AS python-base
RUN sed -i \
        -e 's|^URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20251117T000000Z|' \
        -e 's|^URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20251117T000000Z|' \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99forge-snapshot

FROM python-base AS python-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc=4:12.2.0-3 \
        libffi-dev=3.4.4-1 \
        libssl-dev=3.0.17-1~deb12u3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.lock ./
RUN python -m pip install \
    --no-cache-dir \
    --require-hashes \
    --prefix=/install \
    --requirement requirements.lock

FROM python-base AS runtime
ARG FORGE_VERSION
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Forge Suite" \
      org.opencontainers.image.description="Enterprise offensive-security platform for authorized engagements" \
      org.opencontainers.image.version="${FORGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/forge-suite/forge-suite" \
      org.forge.optional.nuclei="operator-provided-not-bundled"

# Nuclei is intentionally omitted. Operators who need it provide and govern a
# separately pinned binary; the Forge image never downloads a moving release.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium=142.0.7444.162-1~deb12u1 \
        curl=7.88.1-10+deb12u14 \
        dnsutils=1:9.18.41-1~deb12u1 \
        hydra=9.4-1 \
        iputils-ping=3:20221126-1+deb12u1 \
        netcat-openbsd=1.219-1 \
        nmap=7.93+dfsg1-1 \
        smbclient=2:4.17.12+dfsg-0+deb12u2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /install /usr/local

RUN groupadd --gid 10001 forge \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --create-home \
        --shell /usr/sbin/nologin \
        forge

WORKDIR /opt/forge-suite
# Copy only the runtime surface.  The root build context is deny-by-default in
# .dockerignore, and these explicit sources provide a second boundary against
# local reports, engagement data, credentials, tests, and build evidence.
COPY --chown=0:0 VERSION forge.py forge_agent.py ./
COPY --chown=0:0 common ./common
COPY --chown=0:0 webforge ./webforge
COPY --chown=0:0 netforge ./netforge
COPY --chown=0:0 adforge ./adforge
COPY --chown=0:0 aiforge ./aiforge
COPY --chown=0:0 forge_c2 ./forge_c2
COPY --chown=0:0 forge_collab ./forge_collab
COPY --chown=0:0 forge_payload ./forge_payload
COPY --chown=0:0 cloud ./cloud
COPY --chown=0:0 leak_intel ./leak_intel
COPY --chown=0:0 --from=frontend-builder /build/apex-ui/dist ./apex-ui/dist

# A missing build argument or a mismatch with the canonical source fails the
# image build before any artifact can be tagged or published.
RUN test -n "${FORGE_VERSION}" \
    && test "$(tr -d '\r\n' < VERSION)" = "${FORGE_VERSION}" \
    && install -d -o forge -g forge -m 0700 \
        webforge/results \
        netforge/results \
        adforge/results \
        aiforge/results \
        results \
        data \
        data/backups \
        state \
        c2_data \
        tmp \
        tmp/dashboard_scans \
        tmp/dashboard_controls \
    && test ! -e netforge/data/cve_cache.db \
    && test ! -L netforge/data/cve_cache.db \
    && ln -s /opt/forge-suite/data/cve_cache.db netforge/data/cve_cache.db

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FORGE_HOME=/opt/forge-suite \
    FORGE_AUTHORIZATION_DB=/opt/forge-suite/state/authorization.db \
    FORGE_DASHBOARD_STATE_DIR=/opt/forge-suite/state \
    FORGE_ENGAGEMENT_DB=/opt/forge-suite/state/engagement.db \
    FORGE_INTEL_BACKUP_DIR=/opt/forge-suite/data/backups \
    FORGE_INTEL_DB=/opt/forge-suite/data/intel.db \
    FORGE_VERSION=${FORGE_VERSION} \
    TERM=xterm-256color

EXPOSE 1337

# Health is service-specific: the dashboard's Compose definition supplies the
# operator certificate as its trust anchor. Keeping the image itself free of a
# dashboard-only probe prevents the C2 and one-shot scan profiles from
# inheriting a permanently failing healthcheck.
HEALTHCHECK NONE

USER forge
ENTRYPOINT ["python3"]
CMD ["forge.py", "--help"]
