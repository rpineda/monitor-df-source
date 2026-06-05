import urllib.request
import urllib.error
import urllib.parse
import ssl
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_notify import send_wa, build_alert, logger

LOG_DIR = "/var/log/notify"
os.makedirs(LOG_DIR, exist_ok=True)

fh = logging.FileHandler(os.path.join(LOG_DIR, "check_vhosts.log"))
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

VHOSTS = [
    {"name": "api.laincreibleabm.com.gt", "url": "https://api.laincreibleabm.com.gt", "backend": "PHP-FPM :9000"},
    {"name": "fel.digitalframe.ws", "url": "https://fel.digitalframe.ws", "backend": "PHP 7.2 via socket"},
    {"name": "jardines.digitalframe.ws", "url": "https://jardines.digitalframe.ws", "backend": "Docker :8080"},
    {"name": "n8n.digitalframe.ws", "url": "https://n8n.digitalframe.ws", "backend": "n8n :5678 (Docker)"},
]

DOCKER_ENDPOINTS = [
    {"name": "condomines-web-1", "url": "http://127.0.0.1:8080", "backend": "Apache en Docker"},
    {"name": "n8n_n8n_1", "url": "http://127.0.0.1:5678", "backend": "n8n servicio"},
]

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def check_url(name, url, timeout=10):
    try:
        req = urllib.request.Request(url, method="HEAD")
        scheme = urllib.parse.urlparse(url).scheme
        ctx = ssl_ctx if scheme == "https" else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            if status in (502, 503) or status >= 500:
                return False, f"HTTP {status}"
            return True, f"HTTP {status}"
    except urllib.error.HTTPError as e:
        if e.code in (502, 503) or e.code >= 500:
            return False, f"HTTP {e.code}"
        return True, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, str(e.reason)
    except Exception as e:
        return False, str(e)

def main():
    errors = []

    for v in VHOSTS:
        ok, msg = check_url(v["name"], v["url"])
        if ok:
            logger.info("VHOST OK: %s - %s", v["name"], msg)
        else:
            logger.warning("VHOST FAIL: %s - %s", v["name"], msg)
            alert = build_alert(
                alert_type="VHOST CAIDO",
                system=f"VHOST ({v['name']})",
                detail=f"{msg} - No responde correctamente en {v['url'].split(':')[0]}",
                action=f"Revisar backend ({v['backend']}) y logs de Apache en /var/log/apache2/"
            )
            errors.append(alert)

    for d in DOCKER_ENDPOINTS:
        ok, msg = check_url(d["name"], d["url"])
        if ok:
            logger.info("DOCKER OK: %s - %s", d["name"], msg)
        else:
            logger.warning("DOCKER FAIL: %s - %s", d["name"], msg)
            alert = build_alert(
                alert_type="DOCKER CAIDO",
                system=f"Docker ({d['name']})",
                detail=f"{msg} - No responde en {d['url']}",
                action=f"docker logs {d['name']}; docker restart {d['name']}"
            )
            errors.append(alert)

    if errors:
        send_wa("\n\n".join(errors), level="WARNING")

if __name__ == "__main__":
    main()
