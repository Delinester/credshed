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
#     MONGO_VERSION=<auto>            # MongoDB version; auto = 7.0 on a kernel in the
#                                     #   6.19.0-7.0.13 rseq-broken range (SERVER-121912),
#                                     #   else 8.0.  Set explicitly to force a version.
#     SKIP_MONGO=0                    # 1 = don't install/manage MongoDB (use external)
#     MONGO_PASS=<auto>               # set to reuse an existing password
#     FORCE_WIPE_DB=0                 # 1 = allow wiping a populated dbPath when switching
#                                     #   to an OLDER MongoDB major (data can't downgrade)
#
set -euo pipefail

# ---------------------------------------------------------------- config / helpers
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONGO_DATA="${MONGO_DATA:-/opt/credshed/db}"
WEB_PORT="${WEB_PORT:-8000}"
WEB_BIND="${WEB_BIND:-0.0.0.0}"
MONGO_VERSION="${MONGO_VERSION:-}"   # empty => auto-pick by kernel (see below)
SKIP_MONGO="${SKIP_MONGO:-0}"
MONGO_USER="root"
VENV="$APP_DIR/.venv"
CONFIG="$APP_DIR/credshed.config"

c_g(){ printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_y(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_r(){ printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }
die(){ c_r "$*"; exit 1; }

# MongoDB doesn't publish a repo for every Ubuntu/Debian codename (e.g. 7.0 has no
# 'noble' build).  Probe repo.mongodb.org and step DOWN from the host codename to the
# newest OLDER codename that actually carries the requested version — older packages
# run on a newer OS (deps are satisfied); the reverse isn't safe.  Echoes the chosen
# codename, empty + non-zero on failure.
pick_repo_codename() {
  local ver="$1" base="$2" host="$3" order seen=0 cn
  if [ "$base" = "ubuntu" ]; then order="noble jammy focal bionic"; else order="trixie bookworm bullseye buster"; fi
  for cn in $order; do
    [ "$cn" = "$host" ] && seen=1
    if [ "$seen" = "1" ] || [ -z "$host" ]; then
      curl -fsS -o /dev/null "https://repo.mongodb.org/apt/$base/dists/$cn/mongodb-org/$ver/Release" 2>/dev/null \
        && { echo "$cn"; return 0; }
    fi
  done
  # host codename unknown / newer than all we list: take the newest that exists
  for cn in $order; do
    curl -fsS -o /dev/null "https://repo.mongodb.org/apt/$base/dists/$cn/mongodb-org/$ver/Release" 2>/dev/null \
      && { echo "$cn"; return 0; }
  done
  return 1
}

# Wait (up to 30s) for mongod to accept a ping; on failure print status + log tail and die,
# so we never report success for a mongod that isn't actually up.  $1 = extra mongosh args.
mongod_wait_or_die() {
  local i
  for i in $(seq 1 30); do
    mongosh --quiet $1 --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 && return 0
    sleep 1
  done
  c_r "mongod is not accepting connections on 127.0.0.1:27017 after 30s."
  systemctl --no-pager --full status mongod 2>&1 | sed -n '1,8p' >&2 || true
  tail -n 20 /var/log/mongodb/mongod.log >&2 2>/dev/null || true
  die "MongoDB failed to start (see above).  Common cause: dbPath '$MONGO_DATA' or a parent not traversable by the 'mongodb' user, or a stale/incompatible data dir."
}

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

# ---------------------------------------------------------------- MongoDB version choice
# MongoDB 8.0 uses Google's TCMalloc with per-CPU rseq caches, which the Linux 6.19 kernel
# broke (SERVER-121912): 8.0.21+ HARD-REFUSES to start on kernels 6.19.0-7.0.13.  MongoDB
# 7.0 uses the legacy gperftools TCMalloc (per-thread caches, no rseq) and is immune.  An
# LXC shares the host kernel, so on an affected host we default to 7.0.
KERNEL_RSEQ_BAD=0
if [ "$SKIP_MONGO" != "1" ]; then
  kver="$(uname -r)"; kmaj="${kver%%.*}"; krest="${kver#*.}"; kmin="${krest%%.*}"
  kpatch="$(printf '%s' "$kver" | sed -E 's/^[0-9]+\.[0-9]+\.?([0-9]*).*/\1/')"
  for n in kmaj kmin kpatch; do case "${!n}" in ''|*[!0-9]*) eval "$n=0";; esac; done
  if { [ "$kmaj" -eq 6 ] && [ "$kmin" -ge 19 ]; } || { [ "$kmaj" -eq 7 ] && [ "$kmin" -eq 0 ] && [ "$kpatch" -le 13 ]; }; then
    KERNEL_RSEQ_BAD=1
  fi
fi

if [ -z "$MONGO_VERSION" ]; then
  if [ "$KERNEL_RSEQ_BAD" = "1" ]; then
    MONGO_VERSION="7.0"
    c_y "Kernel $(uname -r) is in the 6.19.0-7.0.13 range that breaks MongoDB 8.0 (SERVER-121912);"
    c_y "defaulting to MongoDB 7.0 (gperftools TCMalloc — immune).  Override with MONGO_VERSION=8.0."
  else
    MONGO_VERSION="8.0"
  fi
fi
MONGO_MAJOR="${MONGO_VERSION%%.*}"

# If an 8.0+ MongoDB was *forced* onto an affected kernel, stop early with the remedy
# instead of letting mongod crash-loop.
if [ "$SKIP_MONGO" != "1" ] && [ "$KERNEL_RSEQ_BAD" = "1" ] && [ "${MONGO_MAJOR:-0}" -ge 8 ]; then
  c_r "MongoDB $MONGO_VERSION will not start on kernel $(uname -r) (6.19.0-7.0.13 rseq bug, SERVER-121912)."
  c_r "Leave MONGO_VERSION unset to use MongoDB 7.0 (immune), or pin the Proxmox HOST kernel <=6.18"
  c_r "or >=7.0.14 and reboot, or re-run with SKIP_MONGO=1 to use an external MongoDB."
  die "Refusing to install a MongoDB that cannot start on this kernel."
fi

# MongoDB 5.0+ needs AVX. Warn early — the #1 LXC/VM gotcha on Proxmox.
if [ "$SKIP_MONGO" != "1" ] && ! grep -qm1 avx /proc/cpuinfo; then
  c_y "CPU does not expose AVX — MongoDB $MONGO_VERSION will not start."
  c_y "In Proxmox set the container/VM CPU type to 'host' (Options → CPU)."
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
  ( umask 077; printf '%s' "$MONGO_PASS" > "$mongo_pass_file" )   # scoped: 077 must not leak into later mkdir

  # ---- install, or REPLACE a different-major MongoDB, to match $MONGO_VERSION ----
  installed_ver="$(dpkg-query -W -f='${Version}' mongodb-org-server 2>/dev/null || true)"
  installed_mmp="$(printf '%s' "$installed_ver" | sed 's/^[0-9]*://; s/[-~].*//')"   # strip epoch + revision
  installed_major="${installed_mmp%%.*}"

  need_install=1
  if [ -n "$installed_ver" ] && [ "${installed_major:-x}" = "$MONGO_MAJOR" ]; then
    c_g "MongoDB $installed_mmp already installed (matches requested $MONGO_VERSION)."
    need_install=0
  elif [ -n "$installed_ver" ]; then
    c_y "Found MongoDB $installed_mmp — replacing with $MONGO_VERSION as requested."
    # Data files can't move DOWN a major version; guard a populated dbPath.
    if [ "${installed_major:-0}" -gt "$MONGO_MAJOR" ] && [ -d "$MONGO_DATA" ] && [ -n "$(ls -A "$MONGO_DATA" 2>/dev/null || true)" ]; then
      if [ "${FORCE_WIPE_DB:-0}" = "1" ]; then
        c_y "FORCE_WIPE_DB=1 — wiping $MONGO_DATA so the older MongoDB can initialize it."
        rm -rf "${MONGO_DATA:?}/"* "${MONGO_DATA:?}/".[!.]* 2>/dev/null || true
      else
        die "dbPath $MONGO_DATA holds MongoDB $installed_mmp data; $MONGO_VERSION cannot read a newer version's files. Back it up and empty it, or re-run with FORCE_WIPE_DB=1."
      fi
    fi
    systemctl stop mongod 2>/dev/null || true
    systemctl disable mongod 2>/dev/null || true
    apt-mark unhold mongodb-org mongodb-org-server mongodb-org-mongos mongodb-org-tools >/dev/null 2>&1 || true
    apt-get purge -y -qq '^mongodb-org.*' >/dev/null 2>&1 || true   # keeps mongodb-mongosh (version-independent)
    rm -f /etc/apt/sources.list.d/mongodb-org-*.list
  fi

  if [ "$need_install" = "1" ]; then
    repo_base="ubuntu"; [ "$OS_ID" = "ubuntu" ] || repo_base="debian"
    comp="main"; [ "$OS_ID" = "ubuntu" ] && comp="multiverse"
    REPO_CODENAME="$(pick_repo_codename "$MONGO_VERSION" "$repo_base" "$OS_CODENAME" || true)"
    [ -n "$REPO_CODENAME" ] \
      || die "MongoDB $MONGO_VERSION has no $repo_base repository for '$OS_CODENAME' or any older supported codename."
    [ "$REPO_CODENAME" = "$OS_CODENAME" ] \
      || c_y "MongoDB $MONGO_VERSION has no '$OS_CODENAME' build; using the '$REPO_CODENAME' packages (their deps are satisfied on $OS_CODENAME)."
    c_g "Adding MongoDB $MONGO_VERSION apt repository ($repo_base/$REPO_CODENAME)…"

    keyring="/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
    key_asc="$(mktemp)"
    # Fetch to a temp file first (not a pipe): lets us verify the download and
    # dearmor with --batch --yes so a pre-existing keyring never prompts to overwrite.
    curl -fsSL "https://pgp.mongodb.com/server-${MONGO_VERSION}.asc" -o "$key_asc" \
      || die "Could not download the MongoDB $MONGO_VERSION signing key from pgp.mongodb.com — check network/DNS/proxy. (The key URL is pgp.mongodb.com, NOT mongodb.org.)"
    grep -q 'BEGIN PGP PUBLIC KEY' "$key_asc" \
      || die "Downloaded key is not a PGP public key (proxy/captive-portal page?). First line: $(head -1 "$key_asc")"
    gpg --batch --yes --dearmor -o "$keyring" "$key_asc"
    chmod 0644 "$keyring"   # apt's sandboxed _apt user must be able to read it, or update reports NO_PUBKEY
    rm -f "$key_asc"

    echo "deb [ signed-by=$keyring ] https://repo.mongodb.org/apt/${repo_base} ${REPO_CODENAME}/mongodb-org/${MONGO_VERSION} ${comp}" \
      > "/etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list"
    # Pin this major so a later 'apt upgrade' can't jump to a version that won't run on
    # this kernel, while still allowing ${MONGO_VERSION}.x patch updates.  Priority >1000
    # also lets it win over (and downgrade from) any other installed major.
    printf 'Package: mongodb-org*\nPin: version %s.*\nPin-Priority: 1001\n' "$MONGO_VERSION" \
      > /etc/apt/preferences.d/mongodb-org
    apt-get update -qq
    apt-get install -y -qq --allow-downgrades mongodb-org >/dev/null
    c_g "MongoDB $(dpkg-query -W -f='${Version}' mongodb-org-server 2>/dev/null | sed 's/^[0-9]*://; s/[-~].*//') installed."
  fi

  # data dir on the (big) disk.  mongod runs as the 'mongodb' user, which must be able
  # to TRAVERSE every parent of dbPath (x bit) and own the dir itself — otherwise it
  # exits 100 (EACCES).  Walk the parents and add o+rx (read/traverse, never write).
  mkdir -p "$MONGO_DATA"
  chown -R mongodb:mongodb "$MONGO_DATA"
  chmod 0755 "$MONGO_DATA"
  d="$(dirname "$MONGO_DATA")"
  while [ -n "$d" ] && [ "$d" != "/" ]; do chmod o+rx "$d" 2>/dev/null || true; d="$(dirname "$d")"; done

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
  # wait for it to accept connections (fails loudly with the log tail if it never comes up)
  mongod_wait_or_die ""

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
  mongod_wait_or_die "-u $MONGO_USER -p $MONGO_PASS --authenticationDatabase admin"
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
