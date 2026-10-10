#!/usr/bin/env bash
# Baut die Release-Archive für Linux: ein statisches Binary pro Architektur,
# verpackt als caddyevolved_<version>_linux_<arch>.tar.gz, plus SHA256SUMS.
#
#   scripts/release.sh v0.2.0          # Ausgabe nach dist/release/
#
# Das Frontend ist in internal/webui/dist eingecheckt; wer ui/ geändert hat,
# baut es vorher mit "cd ui && npm ci && npm run build".
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty)}"
COMMIT="$(git rev-parse --short HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARCHES="${ARCHES:-amd64 arm64}"
OUT="dist/release"

rm -rf "$OUT" && mkdir -p "$OUT"

LDFLAGS="-s -w -X caddyevolved/internal/buildinfo.Version=${VERSION#v} -X caddyevolved/internal/buildinfo.Commit=$COMMIT -X caddyevolved/internal/buildinfo.Date=$DATE"

for arch in $ARCHES; do
  name="caddyevolved_${VERSION#v}_linux_${arch}"
  stage="$OUT/$name"
  mkdir -p "$stage"
  echo "==> $name"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$stage/caddyevolved" ./cmd/caddyevolved
  cp LICENSE README.md INSTALLATION.md "$stage/"
  tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  rm -rf "$stage"
done

(cd "$OUT" && sha256sum ./*.tar.gz | sed 's| \./| |' > SHA256SUMS)
cat "$OUT/SHA256SUMS"
