#!/bin/sh
# caddyEvolved als Docker-Container einrichten.
#
#   curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install_docker.sh | sudo sh
#
# Legt /opt/caddyevolved mit compose.yml und dem Datenordner an, startet den
# Container und zeigt Adresse und Passwort der WebUI. Fehlt Docker, wird es auf
# Nachfrage über das offizielle Skript von get.docker.com installiert.
#
# Variablen:  CADDYEVOLVED_DIR=/opt/caddyevolved   Zielordner
#             CADDYEVOLVED_EMAIL=you@example.com   E-Mail für Let's Encrypt
#             CADDYEVOLVED_NETWORK=bridge          Ports einzeln mappen statt host-Netz
#             CADDYEVOLVED_YES=1                   keine Rückfragen (Docker wird installiert)
set -eu

REPO="0xMDIV/caddyEvolved"
DIR="${CADDYEVOLVED_DIR:-/opt/caddyevolved}"
COMPOSE_URL="https://raw.githubusercontent.com/$REPO/main/docker/compose.yml"

die() { echo "Fehler: $*" >&2; exit 1; }
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

[ "$(uname -s)" = "Linux" ] || die "nur Linux wird unterstützt"
[ "$(id -u)" -eq 0 ] || die "bitte als root ausführen (sudo)"

if command -v curl >/dev/null 2>&1; then
  get() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  get() { wget -qO "$2" "$1"; }
else
  die "curl oder wget wird benötigt"
fi

ask() {
  [ "${CADDYEVOLVED_YES:-}" = "1" ] && return 0
  # Bei "curl | sh" ist stdin die Pipe – die Antwort kommt vom Terminal.
  [ -r /dev/tty ] || return 1
  printf '%s [j/N] ' "$1" >/dev/tty
  read -r a </dev/tty || return 1
  case "$a" in j | J | y | Y | ja | Ja) return 0 ;; esac
  return 1
}

# ---- Docker ---------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  ask "Docker ist nicht installiert. Jetzt über get.docker.com installieren?" || die "Docker wird benötigt: https://docs.docker.com/engine/install/"
  say "Docker installieren"
  get https://get.docker.com /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
fi
docker info >/dev/null 2>&1 || die "Docker läuft nicht (systemctl start docker)"
docker compose version >/dev/null 2>&1 || die "Docker Compose fehlt (Paket docker-compose-plugin)"

# ---- Ports ----------------------------------------------------------------
busy=""
if command -v ss >/dev/null 2>&1; then
  for p in 80 443 8484; do
    if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then busy="$busy $p"; fi
  done
fi
if [ -n "$busy" ] && ! docker ps --format '{{.Names}}' | grep -qx caddyevolved; then
  echo "Achtung: Port(s)$busy sind schon belegt – Caddy oder die WebUI können dann nicht starten."
  echo "         Den anderen Dienst beenden (z. B. einen installierten Caddy/nginx) oder Ports in $DIR/compose.yml ändern."
  ask "Trotzdem fortfahren?" || exit 1
fi

# ---- Compose-Datei ----------------------------------------------------------
mkdir -p "$DIR/data"
if [ -f "$DIR/compose.yml" ]; then
  say "$DIR/compose.yml existiert – wird beibehalten"
else
  say "compose.yml nach $DIR laden"
  get "$COMPOSE_URL" "$DIR/compose.yml"
  if [ -n "${CADDYEVOLVED_EMAIL:-}" ]; then
    sed -i "s|CADDYEVOLVED_EMAIL: \"\"|CADDYEVOLVED_EMAIL: \"$CADDYEVOLVED_EMAIL\"|" "$DIR/compose.yml"
  fi
  if [ "${CADDYEVOLVED_NETWORK:-host}" = "bridge" ]; then
    sed -i -e 's|^    network_mode: host|    # network_mode: host|' \
      -e 's|^    # ports:|    ports:|' -e 's|^    #   - "|      - "|' "$DIR/compose.yml"
  fi
fi

# ---- Starten ----------------------------------------------------------------
cd "$DIR"
say "Image laden und Container starten"
docker compose pull -q
docker compose up -d

say "Warte auf die Einrichtung"
pw=""
i=0
while [ $i -lt 60 ]; do
  logs="$(docker compose logs --no-color caddyevolved 2>/dev/null || true)"
  pw="$(printf '%s\n' "$logs" | sed -n 's/.*Passwort[[:space:]]*\([^[:space:]]\{12,\}\)[[:space:]]*$/\1/p' | tail -n 1)"
  if printf '%s\n' "$logs" | grep -q "caddyevolved serve auf"; then break; fi
  i=$((i + 1))
  sleep 2
done

ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "──────────────────────────────────────────────────────────────"
echo "  caddyEvolved läuft im Container"
echo
echo "  WebUI     https://${ip:-<IP dieses Servers>}:8484"
if [ -n "$pw" ]; then
  echo "  Passwort  $pw"
  echo "            (nur jetzt sichtbar – notieren; ändern unter Einstellungen)"
else
  echo "  Passwort  das in compose.yml gesetzte – oder: docker compose -f $DIR/compose.yml logs | grep Passwort"
fi
echo
echo "  Daten     $DIR/data   (Sites, Zertifikate, Plugins – bleiben bei Updates)"
echo "  Update    cd $DIR && docker compose pull && docker compose up -d"
echo "──────────────────────────────────────────────────────────────"
