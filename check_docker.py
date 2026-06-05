import subprocess
import logging
import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, build_alert, logger

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

fh = logging.FileHandler(os.path.join(LOG_DIR, "check_docker.log"))
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

SUSPICIOUS_PROCESSES = [
    "xmrig", "minerd", "cpuminer", "ccminer", "sgminer", "cgminer",
    "bfgminer", "nicehash", "ethminer", "claymore", "ewbf",
    "nanominer", "trex", "lolminer", "phoenixminer", "gminer",
    "teamredminer", "nbminer", "srbminer", "bminer", "kawpowminer",
    ".crypto", ".miner", "stratum",
]

SUSPICIOUS_BIN_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]

CONTAINER_NAMES = ["condomines-web-1", "condomines-db-1", "n8n_n8n_1", "n8n_postgres_1"]

ALERT_STATE_FILE = os.path.join(LOG_DIR, ".docker_alerts.json")

def load_alert_state():
    if os.path.exists(ALERT_STATE_FILE):
        try:
            with open(ALERT_STATE_FILE) as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_alert_state(state):
    with open(ALERT_STATE_FILE, "w") as f:
        json.dump(state, f)

def get_container_stats():
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}|{{.PIDs}}"],
            capture_output=True, text=True, timeout=30
        )
        stats = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 5:
                name = parts[0].strip()
                cpu_str = parts[1].strip().replace("%", "")
                mem_str = parts[2].strip().replace("%", "")
                try:
                    cpu = float(cpu_str) if cpu_str != "N/A" else 0.0
                    mem = float(mem_str) if mem_str != "N/A" else 0.0
                except ValueError:
                    cpu = 0.0
                    mem = 0.0
                stats[name] = {"cpu": cpu, "mem": mem, "pids": parts[4].strip()}
        return stats
    except subprocess.TimeoutExpired:
        logger.error("docker stats timeout")
        return {}
    except FileNotFoundError:
        logger.error("docker command not found")
        return {}
    except Exception as e:
        logger.error("docker stats error: %s", e)
        return {}

def get_container_processes(container_name):
    try:
        result = subprocess.run(
            ["docker", "top", container_name, "-eo", "pid,pcpu,comm,args"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return []
        procs = []
        for line in lines[1:]:
            parts = line.split(None, 3)
            if len(parts) >= 3:
                procs.append({
                    "pid": parts[0],
                    "cpu": parts[1],
                    "comm": parts[2],
                    "args": parts[3] if len(parts) > 3 else "",
                })
        return procs
    except Exception as e:
        logger.debug("docker top %s error: %s", container_name, e)
        return []

def check_container_health():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Image}}"],
            capture_output=True, text=True, timeout=15
        )
        containers = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 2:
                name = parts[0].strip()
                status = parts[1].strip().lower()
                unhealthy = "unhealthy" in status or "exited" in status or "dead" in status
                containers[name] = {"status": status, "unhealthy": unhealthy}
        return containers
    except Exception as e:
        logger.error("docker ps error: %s", e)
        return {}

def scan_container_fs(container_name):
    suspicious = []
    for path in SUSPICIOUS_BIN_PATHS:
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "ls", "-la", path],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                lower = line.lower()
                for proc_name in SUSPICIOUS_PROCESSES:
                    if proc_name in lower:
                        suspicious.append(f"{path}: {line.strip()}")
                        break
        except:
            pass
    return suspicious

def main():
    state = load_alert_state()
    alerts = []

    stats = get_container_stats()
    health = check_container_health()

    all_containers = set(list(stats.keys()) + list(health.keys()))
    for name in CONTAINER_NAMES:
        if name not in all_containers:
            all_containers.add(name)

    for cname in sorted(all_containers):
        issues = []

        if cname in health and health[cname]["unhealthy"]:
            issues.append(
                build_alert(
                    alert_type="ALERTA DOCKER",
                    system=f"Contenedor ({cname})",
                    detail=f"Estado anormal: {health[cname]['status']}",
                    action=f"docker logs {cname}; docker inspect --format '{{{{.State.Health}}}}' {cname}"
                )
            )

        if cname in stats:
            s = stats[cname]

            if s["cpu"] > 90:
                prev = state.get(cname, {}).get("cpu_critical", False)
                if not prev:
                    state.setdefault(cname, {})["cpu_critical"] = True
                    issues.append(
                        build_alert(
                            alert_type="ALERTA DOCKER",
                            system=f"Contenedor ({cname})",
                            detail=f"CPU CRITICO: {s['cpu']:.1f}% - Memoria: {s['mem']:.1f}% - Posible minero",
                            action=f"docker exec -it {cname} top -bn1; verificar procesos con docker top {cname}"
                        )
                    )
            elif s["cpu"] > 70:
                prev = state.get(cname, {}).get("cpu_high", False)
                if not prev:
                    state.setdefault(cname, {})["cpu_high"] = True
                    issues.append(
                        build_alert(
                            alert_type="ALERTA DOCKER",
                            system=f"Contenedor ({cname})",
                            detail=f"CPU elevado: {s['cpu']:.1f}% - Memoria: {s['mem']:.1f}%",
                            action=f"docker exec -it {cname} ps aux --sort=-%cpu | head -10"
                        )
                    )
            else:
                state.get(cname, {}).pop("cpu_critical", None)
                state.get(cname, {}).pop("cpu_high", None)

        procs = get_container_processes(cname)
        for p in procs:
            pname = p["comm"].lower()
            pargs = p["args"].lower()
            for sus in SUSPICIOUS_PROCESSES:
                if sus in pname or sus in pargs:
                    prev_key = f"proc_{p['pid']}"
                    if not state.get(cname, {}).get(prev_key, False):
                        state.setdefault(cname, {})[prev_key] = True
                        issues.append(
                            build_alert(
                                alert_type="ALERTA DOCKER",
                                system=f"Contenedor ({cname})",
                                detail=f"MINERO DETECTADO - Proceso: {p['comm']} (PID {p['pid']}, CPU {p['cpu']}%) - Ruta: {p['args'][:100]}",
                                action=f"docker exec -it {cname} kill -9 {p['pid']}; docker exec -it {cname} rm -rf /tmp/.crypto /dev/shm/*"
                            )
                        )
                    break

        suspicious_files = scan_container_fs(cname)
        for sf in suspicious_files:
            fkey = f"file_{hash(sf)}"
            if not state.get(cname, {}).get(fkey, False):
                state.setdefault(cname, {})[fkey] = True
                issues.append(
                    build_alert(
                        alert_type="ALERTA DOCKER",
                        system=f"Contenedor ({cname})",
                        detail=f"Binario sospechoso encontrado: {sf}",
                        action=f"docker exec -it {cname} file {sf.split(':')[0]}; docker exec -it {cname} rm -f {sf.split(':')[0]}"
                    )
                )

        alerts.extend(issues)

    if alerts:
        send_wa("\n\n".join(alerts), level="WARNING")

    save_alert_state(state)

if __name__ == "__main__":
    main()
