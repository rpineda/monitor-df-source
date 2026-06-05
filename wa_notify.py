import json
import logging
import urllib.request
import urllib.error
import configparser
import os
import sys
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "wa_notify.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("wa_notify")

LEVEL_EMOJI = {
    "INFO": "",
    "WARNING": "\u26a0\ufe0f",
    "CRITICAL": "\ud83d\udea8",
    "ALERT": "\ud83d\udd14",
    "TEST": "\ud83d\udfe2",
}

def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_PATH):
        logger.error("Config file not found: %s", CONFIG_PATH)
        sys.exit(1)
    config.read(CONFIG_PATH)
    return config

def build_alert(alert_type, system, detail, action):
    type_emoji = {
        "VHOST CAIDO": "\ud83d\udea8",
        "DOCKER CAIDO": "\ud83d\udfe0",
        "ALERTA DOCKER": "\ud83d\udfe0",
        "ALERTA MINERIA": "\u26a0\ufe0f",
        "MYSQL": "\ud83d\udfe0",
        "IP BANEADA": "\ud83d\udd10",
        "ATAQUE MASIVO": "\ud83d\udea8",
    }
    emoji = type_emoji.get(alert_type, "\u26a0\ufe0f")
    return f"{emoji} {alert_type}\nSistema: {system}\nTipo: {detail}\nAcci\u00f3n: {action}"

def send_wa(message, level="INFO"):
    config = load_config()
    api_url = config.get("whatsapp", "api_url")
    api_key = config.get("whatsapp", "api_key")
    phone = config.get("whatsapp", "phone")
    server_id = config.get("whatsapp", "server_id", fallback="MONITOR-DF-SOURCE")

    if phone == "REEMPLAZAR_CON_TU_NUMERO":
        logger.error("Phone number not configured in config.ini")
        print("ERROR: Configure phone number in /opt/notify/config.ini", file=sys.stderr)
        return False

    emoji = LEVEL_EMOJI.get(level, "")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    full_message = f"{server_id}\n{emoji} [{level}] {timestamp}\n{message}"

    payload = json.dumps({"phone": phone, "message": full_message}).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-factorybot": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            logger.info("Mensaje enviado (%s): %s", level, message[:80])
            return True
    except urllib.error.HTTPError as e:
        logger.error("HTTP error %s: %s", e.code, e.read().decode("utf-8", errors="replace"))
        return False
    except urllib.error.URLError as e:
        logger.error("Connection error: %s", e.reason)
        return False
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        send_wa(" ".join(sys.argv[1:]), level="TEST")
        print("Mensaje de prueba enviado.")
    else:
        print("Uso: python3 wa_notify.py <mensaje>")
