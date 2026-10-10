#!/bin/sh
# caddyforge-Installer für Linux (amd64/arm64, systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
#
# Lädt das neueste Release, prüft die SHA-256-Summe und startet den
# Installations-Assistenten. Ist caddyforge schon eingerichtet, wird nur das
# Binary ersetzt und der Dienst neu gestartet (Update).
#
# Variablen:  CADDYFORGE_VERSION=v0.2.0   bestimmte Version statt der neuesten
#             CADDYFORGE_NO_SETUP=1       nur das Binary installieren
# Argumente nach "-s --" gehen an "caddyforge install", z. B.
#   curl -fsSL …/install.sh | sudo sh -s -- --unattended /root/answers.json
set -eu

REPO="0xMDIV/caddyEvolved"
BIN="/usr/local/bin/caddyforge"

die() { echo "Fehler: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "nur Linux wird unterstützt"
[ "$(id -u)" -eq 0 ] || die "bitte als root ausführen (sudo)"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "Architektur $(uname -m) wird nicht unterstützt (nur amd64, arm64)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  get() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  get() { wget -qO "$2" "$1"; }
else
  die "curl oder wget wird benötigt"
fi
command -v sha256sum >/dev/null 2>&1 || die "sha256sum wird benötigt (coreutils)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VERSION="${CADDYFORGE_VERSION:-}"
if [ -z "$VERSION" ]; then
  get "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json" || die "Release-Info nicht abrufbar"
  VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1)"
  [ -n "$VERSION" ] || die "kein Release gefunden"
fi

NAME="caddyforge_${VERSION#v}_linux_${ARCH}"
BASE="https://github.com/$REPO/releases/download/$VERSION"
echo "==> caddyforge $VERSION für linux/$ARCH"
get "$BASE/$NAME.tar.gz" "$TMP/$NAME.tar.gz" || die "Download fehlgeschlagen: $BASE/$NAME.tar.gz"
get "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "SHA256SUMS fehlt"

(cd "$TMP" && grep " $NAME.tar.gz\$" SHA256SUMS | sha256sum -c -) >/dev/null || die "Prüfsumme stimmt nicht"
echo "==> Prüfsumme ok"

tar -C "$TMP" -xzf "$TMP/$NAME.tar.gz"
install -m 0755 "$TMP/$NAME/caddyforge" "$BIN.new"
mv -f "$BIN.new" "$BIN"
"$BIN" version

if [ -f /etc/caddyforge/state.json ]; then
  echo "==> bestehende Installation gefunden, nur Update"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled caddyforge >/dev/null 2>&1; then
    systemctl restart caddyforge
    echo "==> caddyforge neu gestartet"
  fi
  exit 0
fi

if [ -n "${CADDYFORGE_NO_SETUP:-}" ]; then
  echo "==> installiert. Einrichten mit: sudo caddyforge install"
  exit 0
fi

# Beim "curl | sh" ist stdin das Skript selbst; der Assistent braucht das Terminal.
if [ ! -t 0 ] && [ -r /dev/tty ]; then
  exec "$BIN" install "$@" </dev/tty
fi
exec "$BIN" install "$@"
