import subprocess
import logging
import os
import sys
import re
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, build_alert, load_config, logger

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

fh = logging.FileHandler(os.path.join(LOG_DIR, "check_mysql.log"))
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

MYSQL_ERROR_LOG = "/var/log/mysql/error.log"
MYSQL_LOG = "/var/log/mysql/mysql.log"

ALERT_STATE_FILE = os.path.join(LOG_DIR, ".mysql_alerts.json")

SUSPICIOUS_QUERIES = [
    r"\bdrop\s+database", r"\bdrop\s+table", r"\btruncate\s+table",
    r"\bdelete\s+from", r"\bupdate\s+\w+\s+set",
    r"\bgrant\s+all", r"\bflush\s+privileges",
    r"\buninstall\s+plugin", r"\bcreate\s+user",
]

def load_state():
    if os.path.exists(ALERT_STATE_FILE):
        try:
            with open(ALERT_STATE_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {"last_error_pos": 0, "last_log_pos": 0, "failed_logins": [], "alerted_queries": []}

def save_state(state):
    with open(ALERT_STATE_FILE, "w") as f:
        json.dump(state, f, default=str)

def get_connections():
    try:
        result = subprocess.run(
            ["mysqladmin", "status"],
            capture_output=True, text=True, timeout=10
        )
        m = re.search(r'Threads:\s+(\d+)', result.stdout)
        active = int(m.group(1)) if m else 0

        result2 = subprocess.run(
            ["mysql", "-e", "SHOW STATUS LIKE 'Threads_connected';", "-NB"],
            capture_output=True, text=True, timeout=10
        )
        total = 0
        for line in result2.stdout.strip().split("\n"):
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        total = int(parts[1])
                    except:
                        pass
        return active, total
    except Exception as e:
        logger.error("get_connections error: %s", e)
        return 0, 0

def get_processlist():
    try:
        result = subprocess.run(
            ["mysql", "-e", "SHOW FULL PROCESSLIST;", "-NB"],
            capture_output=True, text=True, timeout=10
        )
        processes = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 8:
                processes.append({
                    "id": parts[0],
                    "user": parts[1],
                    "host": parts[2],
                    "db": parts[3],
                    "command": parts[4],
                    "time": parts[5],
                    "state": parts[6],
                    "info": parts[7] if len(parts) > 7 else "",
                })
        return processes
    except Exception as e:
        logger.error("get_processlist error: %s", e)
        return []

def check_error_log(state):
    alerts = []
    if not os.path.exists(MYSQL_ERROR_LOG):
        return alerts, state

    try:
        with open(MYSQL_ERROR_LOG, "r") as f:
            f.seek(state.get("last_error_pos", 0))
            new_lines = f.readlines()
            state["last_error_pos"] = f.tell()

        for line in new_lines:
            line_s = line.strip()
            if not line_s:
                continue

            if "Access denied for user" in line_s or "authentication failed" in line_s.lower():
                m = re.search(r"Access denied for user '([^']+)'@'([^']+)'", line_s)
                if m:
                    user, host = m.group(1), m.group(2)
                    now = time.time()
                    state.setdefault("failed_logins", []).append({"time": now, "user": user, "host": host})
                    alerts.append(
                        build_alert(
                            alert_type="MYSQL",
                            system="MariaDB (127.0.0.1:3306)",
                            detail=f"Acceso denegado: usuario '{user}' desde {host} - intento de conexi\u00f3n fallido",
                            action=f"Verificar si {host} es IP legitima; revisar /var/log/mysql/error.log; bloquear con iptables -A INPUT -s {host} -j DROP si es sospechoso"
                        )
                    )

            elif "Aborted connection" in line_s:
                m = re.search(r"Aborted connection.*from.*?(\d+\.\d+\.\d+\.\d+)", line_s)
                host = m.group(1) if m else "desconocido"
                alerts.append(
                    build_alert(
                        alert_type="MYSQL",
                        system="MariaDB (127.0.0.1:3306)",
                        detail=f"Conexi\u00f3n abortada desde {host}: {line_s[:120]}",
                        action="Posible escaneo de puertos o conexion maliciosa; revisar /var/log/mysql/error.log"
                    )
                )

            elif "Got an error reading communication packets" in line_s:
                alerts.append(
                    build_alert(
                        alert_type="MYSQL",
                        system="MariaDB (127.0.0.1:3306)",
                        detail=f"Error de paquetes: {line_s[:120]}",
                        action="Posible ataque de paquetes malformados; revisar /var/log/mysql/error.log"
                    )
                )

    except Exception as e:
        logger.error("check_error_log error: %s", e)

    return alerts, state

def check_general_log(state):
    alerts = []
    if not os.path.exists(MYSQL_LOG):
        return alerts, state

    try:
        file_size = os.path.getsize(MYSQL_LOG)
        if file_size > 500 * 1024 * 1024:
            logger.warning("MySQL general_log is %d bytes, consider rotating", file_size)

        with open(MYSQL_LOG, "r") as f:
            f.seek(state.get("last_log_pos", 0))
            new_lines = f.readlines()
            state["last_log_pos"] = f.tell()

        for line in new_lines:
            line_s = line.strip().lower()
            if not line_s:
                continue

            for pattern in SUSPICIOUS_QUERIES:
                if re.search(pattern, line_s):
                    query_hash = hash(line_s[:120])
                    if query_hash not in state.get("alerted_queries", []):
                        state.setdefault("alerted_queries", []).append(query_hash)
                        if len(state["alerted_queries"]) > 1000:
                            state["alerted_queries"] = state["alerted_queries"][-500:]
                        db_match = re.search(r"(?:use|`)?(\w+)`?", line_s)
                        db_name = db_match.group(1) if db_match else "?"
                        alerts.append(
                            build_alert(
                                alert_type="MYSQL",
                                system="MariaDB (127.0.0.1:3306)",
                                detail=f"Query destructiva en DB '{db_name}': {line_s[:120]}",
                                action="Verificar si la query es legitima; revisar /var/log/mysql/mysql.log; hacer backup inmediato si es necesario"
                            )
                        )
                    break

    except Exception as e:
        logger.error("check_general_log error: %s", e)

    return alerts, state

def check_failed_login_burst(state):
    alerts = []
    now = time.time()
    window = 300
    threshold = 5

    recent = [f for f in state.get("failed_logins", []) if now - f["time"] < window]
    state["failed_logins"] = recent

    host_counts = {}
    for f in recent:
        host = f["host"]
        host_counts[host] = host_counts.get(host, 0) + 1

    for host, count in host_counts.items():
        if count >= threshold:
            if not state.get(f"alerted_burst_{host}"):
                state[f"alerted_burst_{host}"] = True
                alerts.append(
                    build_alert(
                        alert_type="MYSQL",
                        system="MariaDB (127.0.0.1:3306)",
                        detail=f"FUERZA BRUTA - {count} intentos de conexi\u00f3n fallidos desde {host} en {window//60} minutos",
                        action=f"Bloquear IP: iptables -A INPUT -s {host} -j DROP; verificar si hay usuarios comprometidos"
                    )
                )

    for key in list(state.keys()):
        if key.startswith("alerted_burst_"):
            host = key.replace("alerted_burst_", "")
            if host not in host_counts:
                del state[key]

    return alerts, state

def main():
    state = load_state()
    alerts = []

    active, total = get_connections()
    logger.info("MySQL connections: active=%d, total=%d", active, total)

    config = load_config()
    max_conn = config.getint("thresholds", "mysql_max_connections", fallback=50)
    if total > max_conn:
        alerts.append(
            build_alert(
                alert_type="MYSQL",
                system="MariaDB (127.0.0.1:3306)",
                detail=f"DEMASIADAS CONEXIONES: {total} conexiones activas (l\u00edmite: {max_conn})",
                action="mysqladmin processlist; identificar queries lentas; considerar aumentar max_connections en 50-server.cnf"
            )
        )

    procs = get_processlist()
    long_running = [p for p in procs if p["time"].isdigit() and int(p["time"]) > 60]
    for p in long_running[:5]:
        alerts.append(
            build_alert(
                alert_type="MYSQL",
                system="MariaDB (127.0.0.1:3306)",
                detail=f"QUERY LARGA - Usuario: {p['user']} desde {p['host']} DB: {p['db']} - {p['time']}s ejecut\u00e1ndose - Query: {p['info'][:80]}",
                action=f"Revisar EXPLAIN de la query; matar con: mysqladmin kill {p['id']} si es necesario"
            )
        )

    error_alerts, state = check_error_log(state)
    alerts.extend(error_alerts)

    log_alerts, state = check_general_log(state)
    alerts.extend(log_alerts)

    burst_alerts, state = check_failed_login_burst(state)
    alerts.extend(burst_alerts)

    if alerts:
        send_wa("\n\n".join(alerts), level="WARNING")

    save_state(state)

if __name__ == "__main__":
    main()
