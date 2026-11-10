#!/usr/bin/env bash
#
# credshed — one-shot setup for a Proxmox LXC container (Debian 12 / Ubuntu 22.04 / 24.04)
# =========================================================================================
# Installs system deps + MongoDB (native, no Docker), creates a Python venv, configures an
# authenticated MongoDB with a generated password, writes credshed.config, and installs the
# statistics web dashboard as a systemd service.
#
# Run as root INSIDE the container, from the credshed repo:
#     bash deploy/setup_proxmox.sh
#
# Tunables (env vars):
#     MONGO_DATA=/opt/credshed/db     # dbPath — point this at your big disk
#     WEB_PORT=8000                   # dashboard port
#     WEB_BIND=0.0.0.0                # dashboard bind address
#     MONGO_VERSION=8.0               # MongoDB major version
#     SKIP_MONGO=0                    # 1 = don't install/manage MongoDB (use external)
#     MONGO_PASS=<auto>               # set to reuse an existing password
#
set -euo pipefail

# ---------------------------------------------------------------- config / helpers
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONGO_DATA="${MONGO_DATA:-/opt/credshed/db}"
WEB_PORT="${WEB_PORT:-8000}"
WEB_BIND="${WEB_BIND:-0.0.0.0}"
MONGO_VERSION="${MONGO_VERSION:-8.0}"
SKIP_MONGO="${SKIP_MONGO:-0}"
MONGO_USER="root"
VENV="$APP_DIR/.venv"
CONFIG="$APP_DIR/credshed.config"

c_g(){ printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_y(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_r(){ printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }
die(){ c_r "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (inside the LXC container)."

# ---------------------------------------------------------------- OS detection
. /etc/os-release 2>/dev/null || die "Cannot read /etc/os-release"
OS_ID="${ID:-}"; OS_CODENAME="${VERSION_CODENAME:-}"
case "$OS_ID:$OS_CODENAME" in
  ubuntu:jammy|ubuntu:noble|debian:bookworm) : ;;
  ubuntu:*) c_y "Untested Ubuntu ($OS_CODENAME); proceeding, MongoDB repo may need a tweak." ;;
  debian:*) c_y "Untested Debian ($OS_CODENAME); proceeding, MongoDB repo may need a tweak." ;;
  *) die "Unsupported distro '$OS_ID'. Use a Debian 12 or Ubuntu 22.04/24.04 LXC template." ;;
esac
c_g "Detected $PRETTY_NAME   (app dir: $APP_DIR)"

# MongoDB 5.0+ needs AVX. Warn early — this is the #1 LXC/VM gotcha on Proxmox.
if [ "$SKIP_MONGO" != "1" ] && ! grep -qm1 avx /proc/cpuinfo; then
  c_y "CPU does not expose AVX — MongoDB $MONGO_VERSION will not start."
  c_y "In Proxmox set the container/VM CPU type to 'host' (Options → CPU), or use MONGO_VERSION=4.4."
fi

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------- system deps
c_g "Installing system packages…"
apt-get update -qq
apt-get install -y -qq \
  python3 python3-venv python3-pip \
  libmagic1 git curl ca-certificates gnupg lsb-release >/dev/null
c_g "System packages installed."

# ---------------------------------------------------------------- MongoDB
mongo_pass_file="$APP_DIR/.mongo_pass"
if [ "$SKIP_MONGO" = "1" ]; then
  c_y "SKIP_MONGO=1 — not installing MongoDB. Edit $CONFIG to point at your server."
  MONGO_PASS="${MONGO_PASS:-CHANGE_ME}"
else
  # pick / persist a password
  if [ -n "${MONGO_PASS:-}" ]; then :;
  elif [ -f "$mongo_pass_file" ]; then MONGO_PASS="$(cat "$mongo_pass_file")";
  else MONGO_PASS="$(openssl rand -hex 20 2>/dev/null || head -c 40 /dev/urandom | od -An -tx1 | tr -d ' \n')"; fi
  umask 077; printf '%s' "$MONGO_PASS" > "$mongo_pass_file"

  if ! command -v mongod >/dev/null; then
    c_g "Adding MongoDB $MONGO_VERSION apt repository…"
    repo_distro="$OS_ID"; [ "$OS_ID" = "ubuntu" ] && repo_base="ubuntu" || repo_base="debian"
    comp="main"; [ "$OS_ID" = "ubuntu" ] && comp="multiverse"
    curl -fsSL "https://pgp.mongodb.com/server-${MONGO_VERSION}.asc" \
      | gpg --dearmor -o "/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
    echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg ] https://repo.mongodb.org/apt/${repo_base} ${OS_CODENAME}/mongodb-org/${MONGO_VERSION} ${comp}" \
      > "/etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list"
    apt-get update -qq
    apt-get install -y -qq mongodb-org >/dev/null
    c_g "MongoDB installed."
  else
    c_g "MongoDB already installed ($(mongod --version | head -1))."
  fi

  # data dir on the (big) disk
  mkdir -p "$MONGO_DATA"
  chown -R mongodb:mongodb "$MONGO_DATA"

  # write a known-good mongod.conf (dbPath on big disk, localhost-only, auth on)
  c_g "Configuring mongod (dbPath=$MONGO_DATA, bind 127.0.0.1, auth on)…"
  cat > /etc/mongod.conf <<EOF
storage:
  dbPath: $MONGO_DATA
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
EOF
  mkdir -p /var/log/mongodb && chown -R mongodb:mongodb /var/log/mongodb

  systemctl daemon-reload
  systemctl enable mongod >/dev/null 2>&1 || true
  systemctl restart mongod
  # wait for it to accept connections
  for i in $(seq 1 30); do mongosh --quiet --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 && break; sleep 1; done

  # create / update the root user (idempotent) while auth is still off
  c_g "Ensuring root user exists…"
  mongosh --quiet admin --eval "
    const u='$MONGO_USER', p='$MONGO_PASS';
    if (db.getUser(u)) { db.changeUserPassword(u,p); print('updated'); }
    else { db.createUser({user:u, pwd:p, roles:[{role:'root', db:'admin'}]}); print('created'); }
  " || c_y "User step reported an issue (may already be auth-enabled); continuing."

  # turn auth on and restart
  if ! grep -q 'authorization: enabled' /etc/mongod.conf; then
    printf 'security:\n  authorization: enabled\n' >> /etc/mongod.conf
  fi
  systemctl restart mongod
  for i in $(seq 1 30); do \
    mongosh --quiet -u "$MONGO_USER" -p "$MONGO_PASS" --authenticationDatabase admin \
      --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 && break; sleep 1; done
  c_g "MongoDB is up with authentication."
fi

# ---------------------------------------------------------------- python venv
c_g "Creating Python virtualenv + installing requirements…"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip >/dev/null
"$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt" >/dev/null
[ -f "$APP_DIR/requirements-web.txt" ] && "$VENV/bin/pip" install -q -r "$APP_DIR/requirements-web.txt" >/dev/null
c_g "Python environment ready."

# ---------------------------------------------------------------- credshed.config
if [ ! -f "$CONFIG" ] || ! grep -q "pass=$MONGO_PASS" "$CONFIG" 2>/dev/null; then
  c_g "Writing $CONFIG…"
  cat > "$CONFIG" <<EOF
[MONGO]
data_dir=$MONGO_DATA
server=127.0.0.1
port=27017
db=credshed
user=$MONGO_USER
pass=$MONGO_PASS

[EMAIL ALERTS]
from=Credshed <credshed@example.com>
auth_user=credshed@example.com
auth_pass=changeme
mail_server=credshed.example.com
mail_port=25

[FILESTORE]
store_dir=/opt/credshed/raw

[SCRAPER]
paste_dir=/opt/credshed/pastes
EOF
  chmod 600 "$CONFIG"
fi
mkdir -p /opt/credshed/raw /opt/credshed/pastes

# ---------------------------------------------------------------- web dashboard service
c_g "Installing credshed-web systemd service (port $WEB_PORT)…"
cat > /etc/systemd/system/credshed-web.service <<EOF
[Unit]
Description=Credshed statistics dashboard
After=network.target mongod.service
Wants=mongod.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=CREDSHED_WEB_HOST=$WEB_BIND
Environment=CREDSHED_WEB_PORT=$WEB_PORT
ExecStart=$VENV/bin/uvicorn web.app:app --host $WEB_BIND --port $WEB_PORT
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable credshed-web >/dev/null 2>&1 || true
systemctl restart credshed-web

# ---------------------------------------------------------------- summary
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

$(c_g "credshed is set up.")
  Repo / venv .......... $APP_DIR   ($VENV)
  MongoDB data ......... $MONGO_DATA   (point this at your large disk via MONGO_DATA=)
  Config ............... $CONFIG   (chmod 600; Mongo password stored in $mongo_pass_file)
  Dashboard ............ http://${IP:-<container-ip>}:$WEB_PORT/     (systemctl status credshed-web)

Next steps
  1. Ingest data:
       $VENV/bin/python $APP_DIR/credshed-cli.py --unattended --ingest /path/to/leaks
  2. Build search indexes (after a bulk load):
       $VENV/bin/python $APP_DIR/credshed-cli.py --build-indexes
  3. Search / stats:
       $VENV/bin/python $APP_DIR/credshed-cli.py -q tld .ru --limit 20
       $VENV/bin/python $APP_DIR/credshed-cli.py --tld-stats
  4. Open the dashboard in a browser at the URL above.

Security: the dashboard binds $WEB_BIND:$WEB_PORT and serves STATISTICS ONLY (no credential
data). Put it behind the Proxmox firewall / a reverse proxy with auth if the container is reachable
beyond your trusted network.
EOF
