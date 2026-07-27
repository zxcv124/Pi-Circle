#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG="${PI_CIRCLE_CONFIG:-/etc/pi-circle/config.toml}"
AGENT_INTERVAL="${PI_CIRCLE_AGENT_INTERVAL:-5}"
RUN_AGENT="${PI_CIRCLE_RUN_AGENT:-1}"

install -d -o root -g pi-circle -m 0750 "$(dirname "${CONFIG}")"
install -d -o root -g pi-circle -m 2770 /var/lib/pi-circle /var/log/pi-circle
install -d -o root -g root -m 0755 /etc/pihole

if [[ ! -f "${CONFIG}" ]]; then
  cp /opt/pi-circle/source/packaging/defaults/config.toml "${CONFIG}"
fi

python3 - "${CONFIG}" <<'PY'
from pathlib import Path
import os
import re

config = Path(__import__("sys").argv[1])
text = config.read_text(encoding="utf-8")

replacements = {
    r'^interface = ".*"$': f'interface = "{os.environ.get("PI_CIRCLE_INTERFACE", "eth0")}"',
    r'^lan_cidr = ".*"$': f'lan_cidr = "{os.environ.get("PI_CIRCLE_LAN_CIDR", "192.168.1.0/24")}"',
    r'^gateway_ip = ".*"$': f'gateway_ip = "{os.environ.get("PI_CIRCLE_GATEWAY_IP", "192.168.1.1")}"',
    r'^host = ".*"$': f'host = "{os.environ.get("PI_CIRCLE_DASHBOARD_HOST", "0.0.0.0")}"',
    r'^port = .*$': f'port = {int(os.environ.get("PI_CIRCLE_DASHBOARD_PORT", "8088"))}',
}

for pattern, replacement in replacements.items():
    text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"Could not update config line matching {pattern}")

temporary = config.with_suffix(".toml.tmp")
temporary.write_text(text, encoding="utf-8")
temporary.replace(config)
PY

chown root:pi-circle "${CONFIG}"
chmod 0640 "${CONFIG}"
chown -R root:pi-circle /etc/pi-circle
chown -R pi-circle:pi-circle /var/lib/pi-circle /var/log/pi-circle

sudo -E -u pi-circle env PI_CIRCLE_WEB_DIR="${PI_CIRCLE_WEB_DIR}" python3 - "${CONFIG}" <<'PY'
from pathlib import Path
import sys

from pi_circle.config import load_settings
from pi_circle.storage import Store

settings = load_settings(Path(sys.argv[1]))
Store(settings.paths.database).initialize()
PY

children=()

shutdown() {
  for pid in "${children[@]}"; do
    kill -TERM "${pid}" >/dev/null 2>&1 || true
  done
  wait >/dev/null 2>&1 || true
}
trap shutdown TERM INT

if [[ "${RUN_AGENT}" != "0" ]]; then
  PI_CIRCLE_WEB_DIR="${PI_CIRCLE_WEB_DIR}" pi-circle-agent --config "${CONFIG}" --interval "${AGENT_INTERVAL}" &
  children+=("$!")
fi

sudo -E -u pi-circle env PI_CIRCLE_WEB_DIR="${PI_CIRCLE_WEB_DIR}" pi-circle-dashboard --config "${CONFIG}" &
children+=("$!")

set +e
wait -n "${children[@]}"
status="$?"
set -e
shutdown
exit "${status}"
