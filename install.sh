#!/bin/bash
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/notify"
LOG_DIR="/var/log/notify"
SERVER_ID="MONITOR-DF-SOURCE"

echo "==================================="
echo " MONITOR-DF-SOURCE - Installer"
echo "==================================="
echo ""

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo)"
    exit 1
fi

# --- Dependencies ---
echo "[1/6] Checking dependencies..."
MISSING=""
for cmd in python3 curl docker mysqladmin fail2ban-client; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    echo "WARNING: Missing binaries:$MISSING"
    echo "Install what you need: apt install python3 curl mariadb-client fail2ban docker.io"
fi
echo "  Done"

# --- Copy scripts ---
echo "[2/6] Installing scripts to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$REPO_DIR"/*.py "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR"/*.py
echo "  Done"

# --- Config ---
echo "[3/6] Configuring..."
if [ ! -f "$INSTALL_DIR/config.ini" ]; then
    if [ -f "$REPO_DIR/config.ini" ]; then
        cp "$REPO_DIR/config.ini" "$INSTALL_DIR/config.ini"
        echo "  Copied config.ini from repo"
    elif [ -f "$REPO_DIR/config.example.ini" ]; then
        cp "$REPO_DIR/config.example.ini" "$INSTALL_DIR/config.ini"
        echo ""
        echo "  IMPORTANTE: Edita /opt/notify/config.ini"
        echo "  - phone: tu numero WhatsApp (ej: 50255551234)"
        echo "  - api_key: tu key de factorybots"
        echo "  - api_url: tu endpoint de factorybots"
        echo ""
    fi
else
    echo "  config.ini already exists, preserving"
fi
chmod 644 "$INSTALL_DIR/config.ini"
echo "  Done"

# --- Log directory ---
echo "[4/6] Creating log directory..."
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"
echo "  Done"

# --- Logrotate ---
echo "[5/6] Setting up logrotate..."
cat > /etc/logrotate.d/notify << 'LOGEOF'
/var/log/notify/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 644 root root
}
LOGEOF
echo "  Done"

# --- Crontab ---
echo "[6/6] Setting up crontab entries..."
CRON_TMP=$(mktemp)
crontab -l 2>/dev/null | grep -v notify > "$CRON_TMP" || true

cat >> "$CRON_TMP" << 'CRONEOF'

# MONITOR-DF-SOURCE - monitoring (do not remove)
*/5 * * * * /usr/bin/python3 /opt/notify/check_vhosts.py >> /var/log/notify/cron.log 2>&1
*/5 * * * * /usr/bin/python3 /opt/notify/check_mysql.py >> /var/log/notify/cron.log 2>&1
*/3 * * * * /usr/bin/python3 /opt/notify/check_docker.py >> /var/log/notify/cron.log 2>&1
*/2 * * * * /usr/bin/python3 /opt/notify/check_miner.py >> /var/log/notify/cron.log 2>&1
* * * * * /usr/bin/python3 /opt/notify/tail_fail2ban.py >> /var/log/notify/cron.log 2>&1
CRONEOF

crontab "$CRON_TMP"
rm "$CRON_TMP"
echo "  Done"

# --- MariaDB config (optional) ---
echo ""
echo "NOTA: Para activar logs MySQL, edita en cada servidor:"
echo "  /etc/mysql/mariadb.conf.d/50-server.cnf"
echo "  - bind-address = 127.0.0.1"
echo "  - general_log = 1"
echo "  - slow_query_log = 1"
echo "  - long_query_time = 2"
echo "  Luego: systemctl restart mariadb"
echo ""

# --- Vhosts (optional) ---
echo "Para configurar vhosts a monitorear, edita:"
echo "  /opt/notify/check_vhosts.py (lista VHOSTS)"
echo ""
echo "==================================="
echo " INSTALLATION COMPLETE"
echo "==================================="
echo "Test: python3 /opt/notify/wa_notify.py 'Prueba de instalacion'"
echo ""
