# syntax=docker/dockerfile:1.7
#
# Deep View forensics toolkit — multi-stage container build.
#
# Stage 1 (builder):
#   - Python 3.11-slim + apt build deps
#   - Resolves the full `[all]` extras set into a local wheelhouse
#     so the runtime stage can install offline from disk.
#
# Stage 2 (runtime):
#   - Python 3.11-slim + only the libraries that runtime code links against
#   - Installs deepview + a curated subset of extras from the wheelhouse
#   - Runs as the unprivileged `deepview` user by default
#   - ENTRYPOINT is the `deepview` CLI
#
# DMA / eBPF / NFQUEUE capabilities are NOT granted by this image. Those
# paths require either `--privileged` or specific `--cap-add` + device
# mounts. See docs/deployment/docker.md before running in privileged mode.

ARG PYTHON_VERSION=3.11
ARG DEEPVIEW_VERSION=0.2.0

############################
# Stage 1 — builder
############################
FROM python:${PYTHON_VERSION}-slim AS builder

ARG DEEPVIEW_VERSION

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Build-time apt deps for native wheels (capstone, lief, frida, cryptography,
# pyroute2, bcc headers, libtsk, libfvde/libbde bindings, numpy/scipy).
# Kept in the builder only — the runtime stage pulls compiled wheels.
RUN apt-get update && apt-get install --yes --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
        git \
        curl \
        ca-certificates \
        libssl-dev \
        libffi-dev \
        libcapstone-dev \
        libmagic-dev \
        libfuse3-dev \
        libyara-dev \
        libtsk-dev \
        libbde-dev \
        libfvde-dev \
        libdw-dev \
        libelf-dev \
        zlib1g-dev \
        libbz2-dev \
        liblzma-dev \
        liblz4-dev \
        libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy only the metadata first so the dependency resolve layer is cached
# across source-only changes. pyproject.toml pins the extras groups.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Resolve every extra into a wheelhouse. We intentionally use `pip wheel`
# (not `pip install`) so the runtime stage can install offline and we can
# inspect exactly what will ship.
RUN pip install --upgrade pip build \
    && pip wheel --wheel-dir /wheels \
        "." \
        ".[memory]" \
        ".[tracing]" \
        ".[instrumentation]" \
        ".[detection]" \
        ".[sigma]" \
        ".[disassembly]" \
        ".[storage]" \
        ".[compression]" \
        ".[ecc]" \
        ".[containers]" \
        ".[remote_acquisition]"

# Record the resolved set for traceability (useful for supply-chain audits).
RUN ls /wheels > /wheels/MANIFEST.txt

############################
# Stage 2 — runtime
############################
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG DEEPVIEW_VERSION

LABEL org.opencontainers.image.title="Deep View" \
      org.opencontainers.image.description="Cross-platform forensics and runtime-analysis toolkit" \
      org.opencontainers.image.version="${DEEPVIEW_VERSION}" \
      org.opencontainers.image.source="https://github.com/example/deepview" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://example.invalid/deepview/deployment/docker/"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEEPVIEW_CONFIG_DIR=/etc/deepview \
    XDG_CACHE_HOME=/var/cache/deepview \
    PATH=/opt/deepview/bin:$PATH

# Runtime-only native libraries. Must match the shared-object names linked
# by the wheels built in stage 1 — everything else was development headers.
RUN apt-get update && apt-get install --yes --no-install-recommends \
        libssl3 \
        libffi8 \
        libcapstone4 \
        libmagic1 \
        libfuse3-3 \
        libyara9 \
        libtsk19 \
        libbde1 \
        libfvde1 \
        libdw1 \
        libelf1 \
        zlib1g \
        libbz2-1.0 \
        liblzma5 \
        liblz4-1 \
        libzstd1 \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Pull the prebuilt wheelhouse from the builder stage. We do NOT copy the
# source tree itself — deepview is installed as a normal site-packages
# distribution from the wheel produced by stage 1.
COPY --from=builder /wheels /wheels

RUN python -m venv /opt/deepview \
    && /opt/deepview/bin/pip install --no-index --find-links /wheels \
        "deepview[memory,tracing,instrumentation,detection,sigma,disassembly,storage,compression,ecc,containers,remote_acquisition]==${DEEPVIEW_VERSION}" \
    && rm -rf /wheels

# Unprivileged runtime user. Evidence directories should be mounted with
# ownership matching this UID:GID (1000:1000 by default — override with
# `--build-arg` if your host convention differs).
ARG DEEPVIEW_UID=1000
ARG DEEPVIEW_GID=1000
RUN groupadd --gid ${DEEPVIEW_GID} deepview \
    && useradd --uid ${DEEPVIEW_UID} --gid ${DEEPVIEW_GID} \
               --home-dir /home/deepview --create-home \
               --shell /usr/sbin/nologin \
               deepview \
    && mkdir -p /etc/deepview /var/cache/deepview /evidence /reports \
    && chown -R deepview:deepview /etc/deepview /var/cache/deepview /home/deepview

# Minimal default config. Operators mount /etc/deepview over this at run
# time (see docs/deployment/kubernetes.md for a ConfigMap example).
RUN printf '[acquisition]\nevidence_dir = "/evidence"\n[reporting]\noutput_dir = "/reports"\n' \
        > /etc/deepview/config.toml \
    && chown deepview:deepview /etc/deepview/config.toml

USER deepview
WORKDIR /home/deepview

VOLUME ["/evidence", "/reports", "/etc/deepview"]

# Liveness probe — if `deepview --version` can't import the CLI package we
# have a broken image. Keeps failures visible to orchestrators.
HEALTHCHECK --interval=1m --timeout=10s --start-period=10s --retries=3 \
    CMD deepview --version || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "deepview"]
CMD ["--help"]
