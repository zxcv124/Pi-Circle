#!/usr/bin/env bash
# Restricted Pi-hole control helper for the Pi-Circle dashboard.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: pi-circle-pihole-ctl.sh <command> [args]

Commands:
  status
  enable
  disable [duration]
  update-gravity [--force]
  reload-dns
  reload-lists
  flush-log
  allow <domain> [domain...]
  deny <domain> [domain...]
  allow-remove <domain> [domain...]
  deny-remove <domain> [domain...]
EOF
}

# Run as the calling user (dashboard service cannot sudo under capability bounding).
# Pi-hole CLI is usable by the pihole supplementary group for these operations.
if ! command -v pihole >/dev/null 2>&1; then
  echo "pihole CLI not found" >&2
  exit 127
fi

cmd="${1:-}"
shift || true

case "${cmd}" in
  status)
    pihole status
    ;;
  enable)
    pihole enable
    ;;
  disable)
    if [[ -n "${1:-}" ]]; then
      if [[ ! "${1}" =~ ^[0-9]+[smh]?$ ]]; then
        echo "invalid disable duration: ${1}" >&2
        exit 2
      fi
      pihole disable "$1"
    else
      pihole disable
    fi
    ;;
  update-gravity)
    if [[ "${1:-}" == "--force" ]]; then
      pihole -g -f
    else
      pihole -g
    fi
    ;;
  reload-dns)
    pihole reloaddns
    ;;
  reload-lists)
    pihole reloadlists
    ;;
  flush-log)
    pihole -f
    ;;
  allow)
    if [[ "$#" -lt 1 ]]; then
      echo "allow requires at least one domain" >&2
      exit 2
    fi
    for domain in "$@"; do
      if [[ ! "${domain}" =~ ^[A-Za-z0-9._*-]+$ ]]; then
        echo "invalid domain: ${domain}" >&2
        exit 2
      fi
    done
    pihole allow --comment "Pi-Circle" "$@"
    ;;
  deny)
    if [[ "$#" -lt 1 ]]; then
      echo "deny requires at least one domain" >&2
      exit 2
    fi
    for domain in "$@"; do
      if [[ ! "${domain}" =~ ^[A-Za-z0-9._*-]+$ ]]; then
        echo "invalid domain: ${domain}" >&2
        exit 2
      fi
    done
    pihole deny --comment "Pi-Circle" "$@"
    ;;
  allow-remove)
    if [[ "$#" -lt 1 ]]; then
      echo "allow-remove requires at least one domain" >&2
      exit 2
    fi
    for domain in "$@"; do
      if [[ ! "${domain}" =~ ^[A-Za-z0-9._*-]+$ ]]; then
        echo "invalid domain: ${domain}" >&2
        exit 2
      fi
    done
    pihole allow remove "$@"
    ;;
  deny-remove)
    if [[ "$#" -lt 1 ]]; then
      echo "deny-remove requires at least one domain" >&2
      exit 2
    fi
    for domain in "$@"; do
      if [[ ! "${domain}" =~ ^[A-Za-z0-9._*-]+$ ]]; then
        echo "invalid domain: ${domain}" >&2
        exit 2
      fi
    done
    pihole deny remove "$@"
    ;;
  ""|-h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "unsupported command: ${cmd}" >&2
    usage >&2
    exit 2
    ;;
esac
