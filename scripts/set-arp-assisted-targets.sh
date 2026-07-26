#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

CONFIG="/etc/pi-circle/config.toml"
if [[ ! -f "${CONFIG}" ]]; then
  printf 'Config not found: %s\n' "${CONFIG}" >&2
  exit 66
fi

NO_RESTART=0
TARGETS=()
for arg in "$@"; do
  if [[ "${arg}" == "--no-restart" ]]; then
    NO_RESTART=1
  else
    TARGETS+=("${arg}")
  fi
done

python3 - "$CONFIG" "${TARGETS[@]+"${TARGETS[@]}"}" <<'PY'
from ipaddress import ip_address, ip_network
from pathlib import Path
import re
import subprocess
import sys
import tomllib

config = Path(sys.argv[1])
raw_config = tomllib.loads(config.read_text(encoding="utf-8"))
network_config = raw_config.get("network", {})
if not isinstance(network_config, dict):
    raise SystemExit("[network] config table is missing")

interface = str(network_config.get("interface", "wlan0"))
lan_cidr = ip_network(str(network_config.get("lan_cidr", "192.168.1.0/24")), strict=False)
gateway_ip = ip_address(str(network_config.get("gateway_ip", "192.168.1.1")))
unmanaged_ips = {ip_address(str(value)) for value in network_config.get("unmanaged_ips", [])}

local_ips = set()
completed = subprocess.run(
    ["ip", "-4", "-o", "addr", "show", "dev", interface],
    check=False,
    capture_output=True,
    text=True,
)
if completed.returncode == 0:
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            local_ips.add(ip_address(parts[3].split("/", 1)[0]))

targets = []
for raw in sys.argv[2:]:
    parsed = ip_address(raw)
    if parsed.version != 4:
        raise SystemExit(f"{raw} is not IPv4")
    if parsed not in lan_cidr:
        raise SystemExit(f"{raw} is outside configured LAN {lan_cidr}")
    if parsed == gateway_ip:
        raise SystemExit(f"{raw} is the configured gateway and cannot be targeted")
    if parsed in unmanaged_ips:
        raise SystemExit(f"{raw} is listed in unmanaged_ips and cannot be targeted")
    if parsed in local_ips:
        raise SystemExit(f"{raw} is assigned to this Pi and cannot be targeted")
    targets.append(str(parsed))

targets = sorted(set(targets), key=lambda value: tuple(int(part) for part in value.split(".")))
text = config.read_text(encoding="utf-8")
quoted = ", ".join(f'"{target}"' for target in targets)
enabled = bool(targets)
replacements = {
    r'^mode = ".*"$': 'mode = "arp_assisted"' if enabled else 'mode = "dns_only"',
    r'^enable_ipv4_forwarding = .*$': f'enable_ipv4_forwarding = {str(enabled).lower()}',
    r'^dns_redirect_port_53 = .*$': f'dns_redirect_port_53 = {str(enabled).lower()}',
    r'^arp_assisted_enabled = .*$': f'arp_assisted_enabled = {str(enabled).lower()}',
    r'^arp_assisted_targets = \[.*\]$': f'arp_assisted_targets = [{quoted}]',
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

if [[ "${NO_RESTART}" -eq 0 ]]; then
  systemctl restart pi-circle-agent
fi

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  printf 'ARP-assisted mode disabled; DNS-only mode active.\n'
else
  printf 'ARP-assisted mode enabled for %s target(s).\n' "${#TARGETS[@]}"
fi
