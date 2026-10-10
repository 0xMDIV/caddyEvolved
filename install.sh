#!/bin/sh
# caddyevolved-Installer für Linux (amd64/arm64, systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
#
# Lädt das neueste Release, prüft die SHA-256-Summe und startet den
# Installations-Assistenten. Ist caddyevolved schon eingerichtet, wird nur das
# Binary ersetzt und der Dienst neu gestartet (Update).
#
# Variablen:  CADDYEVOLVED_VERSION=v0.2.0   bestimmte Version statt der neuesten
#             CADDYEVOLVED_NO_SETUP=1       nur das Binary installieren
# Argumente nach "-s --" gehen an "caddyevolved install", z. B.
#   curl -fsSL …/install.sh | sudo sh -s -- --unattended /root/answers.json
set -eu

REPO="0xMDIV/caddyEvolved"
BIN="/usr/local/bin/caddyevolved"

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

VERSION="${CADDYEVOLVED_VERSION:-}"
if [ -z "$VERSION" ]; then
  get "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json" || die "Release-Info nicht abrufbar"
  VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1)"
  [ -n "$VERSION" ] || die "kein Release gefunden"
fi

NAME="caddyevolved_${VERSION#v}_linux_${ARCH}"
BASE="https://github.com/$REPO/releases/download/$VERSION"
echo "==> caddyevolved $VERSION für linux/$ARCH"
get "$BASE/$NAME.tar.gz" "$TMP/$NAME.tar.gz" || die "Download fehlgeschlagen: $BASE/$NAME.tar.gz"
get "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "SHA256SUMS fehlt"

(cd "$TMP" && grep " $NAME.tar.gz\$" SHA256SUMS | sha256sum -c -) >/dev/null || die "Prüfsumme stimmt nicht"
echo "==> Prüfsumme ok"

tar -C "$TMP" -xzf "$TMP/$NAME.tar.gz"
install -m 0755 "$TMP/$NAME/caddyevolved" "$BIN.new"
mv -f "$BIN.new" "$BIN"
"$BIN" version

# Umzug einer Installation unter dem alten Namen "caddyforge" (bis v0.2.0).
if [ -d /etc/caddyforge ] && [ ! -e /etc/caddyevolved ]; then
  echo "==> alte caddyforge-Installation gefunden, Umzug nach caddyevolved"
  U=/etc/systemd/system
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now caddyforge >/dev/null 2>&1 || true
  fi
  mv /etc/caddyforge /etc/caddyevolved
  if [ -d /var/lib/caddyforge ]; then mv /var/lib/caddyforge /var/lib/caddyevolved; fi
  for f in /etc/caddyevolved/*.json /etc/caddy/Caddyfile /etc/caddy/sites/*.caddy "$U/caddy.service"; do
    if [ -f "$f" ]; then sed -i 's#/etc/caddyforge#/etc/caddyevolved#g; s#/var/lib/caddyforge#/var/lib/caddyevolved#g' "$f"; fi
  done
  if [ -f /etc/caddy/Caddyfile ]; then sed -i 's/caddyforge/caddyEvolved/g' /etc/caddy/Caddyfile; fi
  if [ -f "$U/caddyforge.service" ]; then
    sed 's/caddyforge/caddyevolved/g; s/^Description=caddyevolved/Description=caddyEvolved/' "$U/caddyforge.service" >"$U/caddyevolved.service"
    rm -f "$U/caddyforge.service"
  fi
  rm -f /usr/local/bin/caddyforge
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable caddyevolved >/dev/null 2>&1 || true
    systemctl reload caddy >/dev/null 2>&1 || true
  fi
  echo "==> Umzug fertig – UI-Passwort bleibt, bitte neu anmelden"
fi

if [ -f /etc/caddyevolved/state.json ]; then
  echo "==> bestehende Installation gefunden, nur Update"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled caddyevolved >/dev/null 2>&1; then
    systemctl restart caddyevolved
    echo "==> caddyevolved neu gestartet"
  fi
  exit 0
fi

if [ -n "${CADDYEVOLVED_NO_SETUP:-}" ]; then
  echo "==> installiert. Einrichten mit: sudo caddyevolved install"
  exit 0
fi

# Beim "curl | sh" ist stdin das Skript selbst; der Assistent braucht das Terminal.
if [ ! -t 0 ] && [ -r /dev/tty ]; then
  exec "$BIN" install "$@" </dev/tty
fi
exec "$BIN" install "$@"
