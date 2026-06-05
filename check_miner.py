import subprocess
import logging
import os
import sys
import re
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, build_alert, load_config, logger

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

fh = logging.FileHandler(os.path.join(LOG_DIR, "check_miner.log"))
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

MINER_PROCESS_NAMES = [
    "xmrig", "minerd", "cpuminer", "ccminer", "sgminer", "cgminer",
    "bfgminer", "nicehash", "ethminer", "claymore", "ewbf",
    "nanominer", "trex", "lolminer", "phoenixminer", "gminer",
    "teamredminer", "nbminer", "srbminer", "bminer", "kawpowminer",
    "libnvrtc", "libcuda", "stratum",
]

KNOWN_POOLS = [
    r"pool\.minexmr\.com", r"xmrpool\.eu", r"mine\.monero",
    r"pool\.supportxmr\.com", r"xmr\.nanopool\.org",
    r"eth\.nanopool\.org", r"pool\.ethermine\.org",
    r"ethpool\.org", r"nicehash\.com", r"daggerhashimoto",
    r"stratum\+tcp", r"stratum\.", r"pool\.minecraft",
    r"unmineable\.com", r"2miners\.com", r"pool\.binance",
    r"flexpool\.io", r"pool\.trustpool", r"pool\.viabtc",
    r"hashvault\.pro", r"cryptonote\.pro", r"mine\.cryptonight",
    r"pool\.hashvault", r"pool\.moneroocean",
]

WHITELIST_PATHS = [
    "/usr/bin/python3", "/usr/sbin/", "/usr/lib/", "/usr/share/",
    "/usr/local/", "/opt/", "/bin/", "/sbin/", "/snap/", "/var/lib/",
    "/usr/bin/docker",
]

WHITELIST_ARGS = [
    "/opt/notify/", "docker stats", "docker ps",
]

SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/dev/.crypto", "/var/.cache"]

ALERT_STATE_FILE = os.path.join(LOG_DIR, ".miner_alerts.json")

HOSTNAME = os.uname().nodename

def load_state():
    if os.path.exists(ALERT_STATE_FILE):
        try:
            with open(ALERT_STATE_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {"alerted_items": []}

def save_state(state):
    state["alerted_items"] = state.get("alerted_items", [])[-500:]
    with open(ALERT_STATE_FILE, "w") as f:
        json.dump(state, f)

def is_whitelisted(comm, args):
    for w in WHITELIST_PATHS:
        if args.startswith(w):
            return True
    for a in WHITELIST_ARGS:
        if a in args:
            return True
    if args == f"[{comm}]" or args == comm:
        return True
    return False

def get_high_cpu_processes(threshold=80):
    results = []
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,pcpu,comm,args", "--sort=-pcpu"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split("\n")
        for line in lines[1:]:
            parts = line.split(None, 3)
            if len(parts) >= 3:
                try:
                    pid = parts[0]
                    cpu = float(parts[1])
                    comm = parts[2]
                    args = parts[3] if len(parts) > 3 else ""
                    if cpu >= threshold and not is_whitelisted(comm, args):
                        results.append({"pid": pid, "cpu": cpu, "comm": comm, "args": args})
                except ValueError:
                    continue
        return results
    except Exception as e:
        logger.error("get_high_cpu_processes error: %s", e)
        return []

def check_process_names():
    results = []
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,pcpu,comm,args"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.strip().split("\n"):
            lower = line.lower()
            for miner_name in MINER_PROCESS_NAMES:
                if miner_name in lower:
                    parts = line.split(None, 3)
                    if len(parts) >= 3:
                        results.append({"pid": parts[0], "cpu": parts[1], "comm": parts[2], "args": parts[3] if len(parts) > 3 else "", "match": miner_name})
                    break
        return results
    except Exception as e:
        logger.error("check_process_names error: %s", e)
        return []

def check_network_connections():
    results = []
    try:
        result = subprocess.run(
            ["ss", "-tpn", "state", "established"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.strip().split("\n"):
            lower = line.lower()
            for pool_pattern in KNOWN_POOLS:
                if re.search(pool_pattern, lower):
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
                    ip = m.group(1) if m else "?"
                    results.append({"line": line.strip()[:150], "pool": pool_pattern, "ip": ip})
                    break
        return results
    except Exception as e:
        logger.error("check_network error: %s", e)
        return []

def scan_suspicious_dirs():
    results = []
    for d in SUSPICIOUS_DIRS:
        if not os.path.exists(d):
            continue
        try:
            for entry in os.listdir(d):
                fpath = os.path.join(d, entry)
                if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                    size = os.path.getsize(fpath)
                    if size > 1024:
                        results.append({"path": fpath, "size": size, "dir": d})
                if os.path.isdir(fpath):
                    try:
                        for root, dirs, files in os.walk(fpath):
                            for f in files:
                                ff = os.path.join(root, f)
                                if os.access(ff, os.X_OK) and os.path.getsize(ff) > 1024:
                                    results.append({"path": ff, "size": os.path.getsize(ff), "dir": d})
                    except PermissionError:
                        pass
        except PermissionError:
            pass
    return results

def main():
    state = load_state()
    alerts = []
    config = load_config()
    threshold = config.getint("thresholds", "cpu_miner_threshold", fallback=80)

    high_cpu = get_high_cpu_processes(threshold)
    for p in high_cpu:
        item_key = f"cpu_{p['pid']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            alerts.append(
                build_alert(
                    alert_type="ALERTA MINERIA",
                    system=f"HOST ({HOSTNAME})",
                    detail=f"CPU ANORMAL: PID {p['pid']} consume {p['cpu']:.1f}% CPU - Comando: {p['comm']} - Ruta: {p['args'][:120]}",
                    action=f"ssh al servidor, ejecutar 'top' para confirmar; revisar {p['args'][:60].strip()}; kill -9 {p['pid']}; eliminar binario"
                )
            )

    miner_procs = check_process_names()
    for p in miner_procs:
        item_key = f"miner_{p['pid']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            alerts.append(
                build_alert(
                    alert_type="ALERTA MINERIA",
                    system=f"HOST ({HOSTNAME})",
                    detail=f"MINERO DETECTADO - Proceso: {p['comm']} (PID {p['pid']}, CPU {p['cpu']}%) - Coincide con patr\u00f3n: '{p['match']}' - Args: {p['args'][:100]}",
                    action=f"kill -9 {p['pid']}; localizar binario con 'which {p['comm']}' o 'lsof -p {p['pid']}'; eliminar archivo; revisar crontab"
                )
            )

    pool_conns = check_network_connections()
    for conn in pool_conns:
        item_key = f"pool_{conn['pool']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            alerts.append(
                build_alert(
                    alert_type="ALERTA MINERIA",
                    system=f"HOST ({HOSTNAME})",
                    detail=f"CONEXION A POOL MINERO detectada hacia {conn['ip']} - Pool: {conn['pool']} - Detalle: {conn['line']}",
                    action=f"ss -tpn | grep {conn['ip']} para identificar proceso; matar proceso; bloquear IP con iptables"
                )
            )

    suspicious_files = scan_suspicious_dirs()
    for f in suspicious_files:
        item_key = f"file_{hash(f['path'])}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            alerts.append(
                build_alert(
                    alert_type="ALERTA MINERIA",
                    system=f"HOST ({HOSTNAME})",
                    detail=f"BINARIO SOSPECHOSO en {f['dir']}: {f['path']} ({f['size']} bytes) - ejecutable en directorio temporal",
                    action=f"file {f['path']}; sha256sum {f['path']}; revisar si es minero; rm -f {f['path']}"
                )
            )

    if len(alerts) >= 3:
        send_wa("\n\n".join(alerts[:8]), level="CRITICAL")
    elif alerts:
        send_wa("\n\n".join(alerts), level="WARNING")

    save_state(state)

if __name__ == "__main__":
    main()
