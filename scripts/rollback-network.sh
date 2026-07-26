#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

systemctl stop pi-circle-agent 2>/dev/null || true

if [[ -x /opt/pi-circle/venv/bin/pi-circlectl ]]; then
  /opt/pi-circle/venv/bin/pi-circlectl --config /etc/pi-circle/config.toml rollback-network || true
fi

nft delete table inet pi_circle 2>/dev/null || true
systemctl restart pihole-FTL 2>/dev/null || true

printf 'Pi-Circle network controls are stopped. Pi-hole remains available in DNS mode.\n'
