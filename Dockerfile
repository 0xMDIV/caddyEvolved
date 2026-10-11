# caddyEvolved als Container: Caddy + WebUI in einem Image.
#
#   docker build -t caddyevolved .
#   docker run -d --name caddyevolved --network host -v caddyevolved:/data caddyevolved
#
# Alles Veränderliche liegt im Volume /data – Konfiguration, Sites,
# Zertifikate, Logs und die Caddy-Binary selbst, damit ein Build mit Plugins
# ein neues Image übersteht. Details: docs/DOCKER.md

# ---- caddyEvolved bauen ----------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X caddyevolved/internal/buildinfo.Version=${VERSION#v} -X caddyevolved/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/caddyevolved ./cmd/caddyevolved

# ---- offizielles Caddy holen (wird beim ersten Start ins Volume kopiert) ---
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS caddy
ARG TARGETARCH
ARG CADDY_VERSION=2.11.7
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/caddy.tgz "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && curl -fsSL -o /tmp/sums "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_checksums.txt" \
 && (cd /tmp && grep " caddy_${CADDY_VERSION}_linux_${TARGETARCH}.tar.gz$" sums | sed 's/caddy_.*/caddy.tgz/' | sha512sum -c -) \
 && mkdir -p /out && tar -xzf /tmp/caddy.tgz -C /out caddy

# ---- Laufzeit ---------------------------------------------------------------
FROM debian:bookworm-slim
# git: manche Plugins lädt xcaddy direkt aus dem Repository.
# tini: reicht Signale weiter und räumt beendete Prozesse ab.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata git tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system caddy \
 && useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy \
 && mkdir -p /data /usr/local/share/caddyevolved \
 && for d in etc/caddy etc/caddyevolved var/lib/caddy var/lib/caddyevolved var/log/caddy; do \
      rm -rf "/$d" && ln -s "/data/$d" "/$d"; \
    done

COPY --from=build /out/caddyevolved /usr/local/bin/caddyevolved
COPY --from=caddy /out/caddy /usr/local/share/caddyevolved/caddy

ENV CADDYEVOLVED_CONTAINER=1 \
    CADDYEVOLVED_CADDY_BIN=/var/lib/caddyevolved/bin/caddy \
    XDG_DATA_HOME=/var/lib/caddy/.local/share \
    XDG_CONFIG_HOME=/var/lib/caddy/.config \
    PATH=/var/lib/caddyevolved/bin:$PATH

VOLUME ["/data"]
EXPOSE 80 443 443/udp 8484
ENTRYPOINT ["/usr/bin/tini", "--", "caddyevolved", "container"]

LABEL org.opencontainers.image.title="caddyEvolved" \
      org.opencontainers.image.description="Caddy mit WebUI: Sites, Zertifikate, Plugins, Schutz" \
      org.opencontainers.image.source="https://github.com/0xMDIV/caddyEvolved" \
      org.opencontainers.image.licenses="MIT"
