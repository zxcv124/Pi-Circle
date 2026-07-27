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

FORCE_IPV4=""
FORCE_PI_DNS=""
NO_RESTART=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force-ipv4)
      FORCE_IPV4="${2:-}"
      shift 2
      ;;
    --force-pi-dns)
      FORCE_PI_DNS="${2:-}"
      shift 2
      ;;
    --no-restart)
      NO_RESTART=1
      shift
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 64
      ;;
  esac
done

if [[ -z "${FORCE_IPV4}" && -z "${FORCE_PI_DNS}" ]]; then
  printf 'Usage: %s [--force-ipv4 true|false] [--force-pi-dns true|false] [--no-restart]\n' "$0" >&2
  exit 64
fi

normalize_bool() {
  case "${1}" in
    true|false|1|0|yes|no|on|off) ;;
    *)
      printf 'Boolean flag must be true or false: %s\n' "$1" >&2
      exit 64
      ;;
  esac
}

[[ -n "${FORCE_IPV4}" ]] && normalize_bool "${FORCE_IPV4}"
[[ -n "${FORCE_PI_DNS}" ]] && normalize_bool "${FORCE_PI_DNS}"

python3 - "$CONFIG" "${FORCE_IPV4}" "${FORCE_PI_DNS}" <<'PY'
from pathlib import Path
import re
import sys

config = Path(sys.argv[1])
force_ipv4_raw = sys.argv[2].strip().lower()
force_pi_dns_raw = sys.argv[3].strip().lower()
text = config.read_text(encoding="utf-8")


def upsert(text: str, key: str, enabled: bool, anchor_key: str) -> str:
    replacement = f"{key} = {str(enabled).lower()}"
    if re.search(rf"^{re.escape(key)} = .*$", text, flags=re.MULTILINE):
        text, count = re.subn(rf"^{re.escape(key)} = .*$", replacement, text, count=1, flags=re.MULTILINE)
        if count != 1:
            raise SystemExit(f"Could not update {key}")
        return text
    anchor = re.search(rf"^{re.escape(anchor_key)} = .*$", text, flags=re.MULTILINE)
    if not anchor:
        raise SystemExit(f"Could not find anchor {anchor_key} to insert {key}")
    insert_at = anchor.end()
    return text[:insert_at] + "\n" + replacement + text[insert_at:]


if force_ipv4_raw:
    enabled = force_ipv4_raw in {"true", "1", "yes", "on"}
    text = upsert(text, "force_ipv4", enabled, "block_wan_inbound_for_linked")
    print(f"force_ipv4={str(enabled).lower()}")

if force_pi_dns_raw:
    enabled = force_pi_dns_raw in {"true", "1", "yes", "on"}
    text = upsert(text, "force_pi_dns", enabled, "force_ipv4")
    print(f"force_pi_dns={str(enabled).lower()}")

temporary = config.with_suffix(".toml.tmp")
temporary.write_text(text, encoding="utf-8")
temporary.replace(config)
PY

chown root:pi-circle "${CONFIG}"
chmod 0640 "${CONFIG}"

if [[ -n "${FORCE_IPV4}" ]]; then
  if [[ "${FORCE_IPV4}" =~ ^(true|1|yes|on)$ ]]; then
    pihole-FTL --config misc.dnsmasq_lines '["filter-AAAA"]' >/dev/null
    pihole-FTL --config resolver.resolveIPv6 false >/dev/null
  else
    pihole-FTL --config misc.dnsmasq_lines '[]' >/dev/null
    pihole-FTL --config resolver.resolveIPv6 true >/dev/null
  fi
  systemctl reload pihole-FTL 2>/dev/null || systemctl restart pihole-FTL
fi

if [[ -n "${FORCE_PI_DNS}" ]]; then
  DOH_DOMAINS=(
    chrome.cloudflare-dns.com
    mozilla.cloudflare-dns.com
    cloudflare-dns.com
    dns.cloudflare.com
    1dot1dot1dot1.cloudflare-dns.com
    one.one.one.one
    security.cloudflare-dns.com
    family.cloudflare-dns.com
    dns.google
    dns.google.com
    dns.google.pki.goog
    dns.quad9.net
    dns.adguard.com
    dns-family.adguard.com
    doh.opendns.com
    doh.cleanbrowsing.org
    doh.dns.sb
  )
  if [[ "${FORCE_PI_DNS}" =~ ^(true|1|yes|on)$ ]]; then
    pihole deny --comment "Pi-Circle force-pi-dns" "${DOH_DOMAINS[@]}" >/dev/null || true
  else
    pihole deny remove "${DOH_DOMAINS[@]}" >/dev/null || true
  fi
fi

if [[ "${NO_RESTART}" -eq 0 ]]; then
  systemctl restart pi-circle-agent
fi

printf 'Network flags updated.\n'
