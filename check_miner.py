import subprocess
import logging
import os
import sys
import re
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, load_config, logger

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

SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/dev/.crypto", "/var/.cache"]

ALERT_STATE_FILE = os.path.join(LOG_DIR, ".miner_alerts.json")

HOSTNAME = os.uname().nodename

DEFAULT_WHITELIST_PATHS = [
    "/opt/notify/", "/home/df-source/", "/usr/bin/", "/usr/sbin/",
    "/usr/lib/", "/usr/share/", "/usr/local/", "/bin/", "/sbin/",
    "/snap/", "/var/lib/", "/usr/bin/docker",
]

DEFAULT_WHITELIST_ARGS = [
    "/opt/notify/", "docker stats", "docker ps", "docker top",
    "docker exec", "ps axo pid,pcpu", "main_col_shop.py",
    "main_aki.py", "run_syst.sh", "run_aki.sh",
]

DEFAULT_WHITELIST_COMMANDS = ["python3", "docker", "ps"]

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

def get_whitelist_from_config():
    try:
        config = load_config()
        paths_str = config.get("whitelist", "paths", fallback="")
        args_str = config.get("whitelist", "args", fallback="")
        cmds_str = config.get("whitelist", "commands", fallback="")
        paths = [p.strip() for p in paths_str.split(",") if p.strip()] if paths_str else []
        args = [a.strip() for a in args_str.split(",") if a.strip()] if args_str else []
        cmds = [c.strip() for c in cmds_str.split(",") if c.strip()] if cmds_str else []
        return paths or DEFAULT_WHITELIST_PATHS, args or DEFAULT_WHITELIST_ARGS, cmds or DEFAULT_WHITELIST_COMMANDS
    except Exception as e:
        logger.debug("whitelist config error: %s", e)
        return DEFAULT_WHITELIST_PATHS, DEFAULT_WHITELIST_ARGS, DEFAULT_WHITELIST_COMMANDS

def is_whitelisted(comm, args):
    whitelist_paths, whitelist_args, whitelist_cmds = get_whitelist_from_config()
    if comm in whitelist_cmds:
        return True
    for w in whitelist_paths:
        if args.startswith(w):
            return True
    for a in whitelist_args:
        if a in args:
            return True
    if args == f"[{comm}]" or args == comm:
        return True
    return False

def is_miner_process_name(comm):
    lower = comm.lower()
    for m in MINER_PROCESS_NAMES:
        if m in lower:
            return True
    return False

def is_in_suspicious_dir(path):
    for d in SUSPICIOUS_DIRS:
        if path.startswith(d):
            return True
    return False

def determine_severity(comm, args):
    if is_miner_process_name(comm):
        return "CRITICAL", "Nombre de minero conocido"
    if is_miner_process_name(args):
        return "CRITICAL", "Contiene nombre de minero en la ruta"
    for m in MINER_PROCESS_NAMES:
        if m in args.lower():
            return "CRITICAL", "Coincide con patron de minero"
    cmd = args.split(None, 1)[0] if args else comm
    if is_in_suspicious_dir(cmd):
        return "CRITICAL", "Ejecutable en directorio sospechoso (oculto)"
    return "WARNING", "CPU anormal - puede ser proceso legitimo con mucha carga"

def build_miner_alert(comm, args, pid, cpu, severity, reason):
    lines = []
    if severity == "CRITICAL":
        lines.append("\ud83d\udea8 MINERO CONFIRMADO")
    else:
        lines.append("\u26a0\ufe0f ALERTA MINERIA")
    lines.append(f"Sistema: HOST ({HOSTNAME})")
    lines.append(f"Proceso: {comm} (PID {pid})")
    lines.append(f"Comando: {args}")
    lines.append(f"Consumo: {cpu:.1f}% CPU")
    lines.append(f"Razon: {reason}")
    lines.append("")

    if severity == "CRITICAL":
        lines.append("Esto es un MINERO confirmado porque:")
        if is_in_suspicious_dir(args):
            lines.append("  - Se ejecuta desde directorio oculto (/tmp, /dev/shm)")
        if is_miner_process_name(comm):
            lines.append(f"  - Nombre de proceso conocido de mineria: {comm}")
        lines.append("")
        lines.append("ACCION INMEDIATA:")
        lines.append(f"  1. kill -9 {pid}")
        lines.append("  2. rm -rf /tmp/.crypto /dev/shm/*")
        lines.append("  3. ps aux | grep miner  (buscar mas instancias)")
        lines.append("  4. Revisar crontab, cronologias, y SSH authorized_keys")
    else:
        lines.append("Esto PODRIA SER:")
        lines.append("  - Un cron o sincronizacion con mucha carga")
        lines.append(f"  - O un proceso malicioso disfrazado")
        lines.append("")
        lines.append("Para confirmar:")
        lines.append(f"  1. ssh al servidor")
        lines.append(f"  2. top -p {pid}  (ver consumo en vivo)")
        lines.append(f"  3. ls -la $(which {comm})  (ver ubicacion del binario)")
        lines.append(f"  4. cat /proc/{pid}/cmdline  (argumentos exactos)")
        lines.append("")
        lines.append("Si es sospechoso:")
        lines.append(f"  - kill -9 {pid}")
        lines.append(f"  - Revisar crontab con: crontab -l")
        lines.append(f"  - Verificar conexiones de red: ss -tpn | grep ESTAB")

    return "\n".join(lines)

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
                        pid = parts[0]
                        cpu = parts[1]
                        comm = parts[2]
                        args = parts[3] if len(parts) > 3 else ""
                        if not is_whitelisted(comm, args):
                            results.append({"pid": pid, "cpu": cpu, "comm": comm, "args": args, "match": miner_name})
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
    alerts_warning = []
    alerts_critical = []
    config = load_config()
    threshold = config.getint("thresholds", "cpu_miner_threshold", fallback=80)

    high_cpu = get_high_cpu_processes(threshold)
    for p in high_cpu:
        item_key = f"cpu_{p['pid']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            severity, reason = determine_severity(p["comm"], p["args"])
            msg = build_miner_alert(p["comm"], p["args"], p["pid"], p["cpu"], severity, reason)
            if severity == "CRITICAL":
                alerts_critical.append(msg)
            else:
                alerts_warning.append(msg)

    miner_procs = check_process_names()
    for p in miner_procs:
        item_key = f"miner_{p['pid']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            severity, reason = determine_severity(p["comm"], p["args"])
            msg = build_miner_alert(p["comm"], p["args"], p["pid"], p["cpu"], severity, reason)
            alerts_critical.append(msg)

    pool_conns = check_network_connections()
    for conn in pool_conns:
        item_key = f"pool_{conn['pool']}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            reason = f"Conexion a pool minero detectada: {conn['pool']}"
            alerts_critical.append(
                f"\ud83d\udea8 MINERO CONFIRMADO\n"
                f"Sistema: HOST ({HOSTNAME})\n"
                f"Tipo: Conexion a pool de mineria\n"
                f"Pool: {conn['pool']} (IP: {conn['ip']})\n"
                f"Detalle: {conn['line']}\n\n"
                f"ACCION INMEDIATA:\n"
                f"  1. ss -tpn | grep {conn['ip']}  (identificar proceso)\n"
                f"  2. kill -9 PID  (matar el proceso)\n"
                f"  3. iptables -A OUTPUT -d {conn['ip']} -j DROP  (bloquear pool)"
            )

    suspicious_files = scan_suspicious_dirs()
    for f in suspicious_files:
        item_key = f"file_{hash(f['path'])}"
        if item_key not in state.get("alerted_items", []):
            state.setdefault("alerted_items", []).append(item_key)
            alerts_critical.append(
                f"\ud83d\udea8 MINERO CONFIRMADO\n"
                f"Sistema: HOST ({HOSTNAME})\n"
                f"Tipo: Binario sospechoso en directorio oculto\n"
                f"Archivo: {f['path']} ({f['size']} bytes)\n"
                f"Directorio: {f['dir']}\n\n"
                f"ACCION INMEDIETA:\n"
                f"  1. file {f['path']}  (ver que tipo de binario es)\n"
                f"  2. sha256sum {f['path']}  (calcular hash)\n"
                f"  3. rm -f {f['path']}  (eliminar)\n"
                f"  4. ps aux | grep 'crypto' | grep -v grep"
            )

    if alerts_critical:
        send_wa("\n\n".join(alerts_critical[:5]), level="CRITICAL")

    if alerts_warning and not alerts_critical:
        send_wa("\n\n".join(alerts_warning[:3]), level="WARNING")
    elif alerts_warning:
        for w in alerts_warning[:2]:
            send_wa(w, level="WARNING")

    save_state(state)

if __name__ == "__main__":
    main()
