import subprocess
import logging
import os
import sys
import re
import json
import time
import urllib.request
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, build_alert, logger

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

fh = logging.FileHandler(os.path.join(LOG_DIR, "tail_fail2ban.log"))
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

FAIL2BAN_LOG = "/var/log/fail2ban.log"
STATE_FILE = os.path.join(LOG_DIR, ".fail2ban_state.json")

HOSTNAME = os.uname().nodename

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                state = json.load(f)
            if "alerted_keys" not in state:
                state["alerted_keys"] = []
            return state
        except:
            pass
    return {"last_pos": 0, "recent_bans": [], "alerted_keys": []}

def save_state(state):
    state["recent_bans"] = state.get("recent_bans", [])[-200:]
    state["alerted_keys"] = state.get("alerted_keys", [])[-500:]
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def get_geoip(ip):
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=country,isp",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            country = data.get("country", "Desconocido")
            isp = data.get("isp", "")
            return f"{country} ({isp})" if isp else country
    except:
        return "Desconocido"

def parse_fail2ban_line(line):
    m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+.*?\s+(fail2ban\.\w+)\s+.*?\]\s+(Ban|Unban|Found)\s+(.*)", line)
    if m:
        timestamp_str = m.group(1).split(",")[0]
        jail = m.group(2).replace("fail2ban.", "")
        action = m.group(3)
        ip = m.group(4).strip()
        return {"timestamp": timestamp_str, "jail": jail, "action": action, "ip": ip}
    return None

def main():
    if not os.path.exists(FAIL2BAN_LOG):
        logger.error("fail2ban.log not found: %s", FAIL2BAN_LOG)
        return

    state = load_state()
    alerts = []
    now = time.time()
    window = 300

    state["recent_bans"] = [b for b in state.get("recent_bans", []) if now - b["time"] < window]

    try:
        with open(FAIL2BAN_LOG, "r") as f:
            f.seek(state.get("last_pos", 0))
            new_lines = f.readlines()
            if new_lines:
                state["last_pos"] = f.tell()
    except Exception as e:
        logger.error("Error reading fail2ban.log: %s", e)
        return

    for line in new_lines:
        parsed = parse_fail2ban_line(line)
        if not parsed or parsed["action"] != "Ban":
            continue

        ip = parsed["ip"]
        jail = parsed["jail"]
        ts = parsed["timestamp"]

        country = get_geoip(ip)
        state["recent_bans"].append({"time": now, "ip": ip, "jail": jail, "country": country})

        ban_key = f"ban_{jail}_{ip}"
        if ban_key not in state.get("alerted_keys", []):
            state.setdefault("alerted_keys", []).append(ban_key)
            alerts.append(
                build_alert(
                    alert_type="IP BANEADA",
                    system=f"HOST ({HOSTNAME})",
                    detail=f"IP {ip} ({country}) baneada por fail2ban - Jail: {jail} - Puerto: {'22 (SSH)' if jail == 'sshd' else '80/443 (Apache)'}",
                    action=f"fail2ban-client status {jail}; si persiste, considerar cambiar puerto SSH o agregar IP a whitelist si es legitima: fail2ban-client set {jail} unbanip {ip}"
                )
            )

    bans_by_jail = {}
    for b in state["recent_bans"]:
        bans_by_jail.setdefault(b["jail"], []).append(b)

    for jail_name, bans in bans_by_jail.items():
        if len(bans) >= 5:
            bulk_key = f"bulk_{jail_name}_{int(now // window)}"
            if bulk_key not in state.get("alerted_keys", []):
                state.setdefault("alerted_keys", []).append(bulk_key)
                unique_ips = list(set(b["ip"] for b in bans))
                countries = list(set(b.get("country", "?") for b in bans))
                port = "22 (SSH)" if jail_name == "sshd" else "80/443 (Apache)"
                alerts.append(
                    build_alert(
                        alert_type="ATAQUE MASIVO",
                        system=f"HOST ({HOSTNAME})",
                        detail=f"{len(bans)} baneos en {window//60} minutos en jail '{jail_name}' (puerto {port}) - {len(unique_ips)} IPs \u00fanicas de {', '.join(countries[:3])} - Primeras IPs: {', '.join(unique_ips[:5])}",
                        action=f"fail2ban-client status {jail_name}; si el ataque es severo, considerar: cambiar puerto SSH, Cloudflare proxy para HTTP, o VPN de acceso"
                    )
                )

    state["alerted_keys"] = [k for k in state["alerted_keys"]
                             if not k.startswith("bulk_") or
                             int(k.split("_")[-1]) >= int(now // window) - 1]

    for alert in alerts[:5]:
        send_wa(alert, level="WARNING")

    save_state(state)

if __name__ == "__main__":
    main()
