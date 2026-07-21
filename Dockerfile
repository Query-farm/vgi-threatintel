# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image that serves the network transports of the `vgi-threatintel` VGI
# worker:
#   docker run ... IMG            -> HTTP server on $PORT      (default; Fly.io / local)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
#   docker run ... IMG unix       -> AF_UNIX launcher transport on a socket path
# See docker-entrypoint.sh.
#
# The worker is STATELESS: the offline classifiers are compiled in and the
# reputation table function calls out to a per-request base_url, so there is no
# /data volume, no model registry, and no `farm.query.vgi.volumes` label. The
# image is just the binary + a tiny entrypoint.
# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# CGO is REQUIRED: the vgi-go SDK links DuckDB (via duckdb/duckdb-go) to pull
# Arrow RecordBatches over the C Data Interface, so CGO_ENABLED=0 fails to
# build. gcc/g++ + libc6-dev provide the C toolchain the cgo link needs.
FROM golang:1.26-bookworm AS build
WORKDIR /src

ENV CGO_ENABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Resolve modules first (this layer is independent of the worker source, so it
# stays cached across normal code changes). No vendoring / no replaces — modules
# come from the proxy into the BuildKit-cached module cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# BuildKit cache mounts persist the Go build + module caches across image
# rebuilds, so incremental code changes only recompile the changed packages and
# the cgo link, not the full DuckDB-linked tree from scratch every time. The
# binary is copied OUT to a non-cache path before the layer ends (cache mounts
# do not persist into the image).
COPY internal/ ./internal/
COPY cmd/ ./cmd/
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -ldflags="-s -w" \
        -o /worker ./cmd/vgi-threatintel-worker

# ---- runtime stage ---------------------------------------------------------
# debian-slim (not distroless) so the HEALTHCHECK below has a real `curl`.
FROM debian:bookworm-slim

# Build metadata, wired from docker/metadata-action outputs in CI.
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-threatintel

# Standard OCI labels + the VGI transport-advertisement label. `transports`
# lists the NETWORK transports this image serves; stdio is a spawn mode and unix
# is a local-socket launcher, so neither is a published network transport.
LABEL org.opencontainers.image.title="vgi-threatintel" \
      org.opencontainers.image.description="Enrich & classify cyber threat indicators (IPs, domains, URLs, file hashes) against threat-intel reputation feeds as a VGI worker for DuckDB/SQL (stdio + HTTP)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http"]'

ENV PORT=8000 \
    VGI_THREATINTEL_GIT_COMMIT=${GIT_COMMIT}

WORKDIR /app

# ca-certificates: the reputation table function fetches over HTTPS from real
# threat-intel feeds. curl backs the HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# `--chmod` sets the mode in the COPY layer itself. A separate `RUN chmod` would
# rewrite the whole binary into a second layer (overlayfs copies the file on a
# metadata change), needlessly doubling its on-disk footprint in the image.
COPY --from=build --chmod=0755 /worker /usr/local/bin/vgi-threatintel-worker
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run unprivileged. No state, no volume — there is nothing to own or persist.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000

# Readiness probe for HTTP mode. Inert for a short-lived stdio container, which
# has no HTTP server (the probe just fails harmlessly there).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["http"]
