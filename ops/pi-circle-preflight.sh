#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
base_dir="${PI_CIRCLE_PREFLIGHT_DIR:-$(pwd)/artifacts/preflight-${timestamp}}"
mkdir -p "${base_dir}"

log() {
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" | tee -a "${base_dir}/preflight.log" >/dev/null
}

run_capture() {
  local name="$1"
  shift
  local output="${base_dir}/${name}.txt"
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"${output}" 2>&1 || true
}

copy_if_readable() {
  local source="$1"
  local target="$2"
  if [[ -r "${source}" ]]; then
    mkdir -p "$(dirname "${base_dir}/${target}")"
    cp -a "${source}" "${base_dir}/${target}"
  fi
}

redact_file() {
  local file="$1"
  [[ -f "${file}" ]] || return 0
  sed -E -i.bak \
    -e 's/(password[[:space:]]*=[[:space:]]*)".*"/\1"[REDACTED]"/Ig' \
    -e 's/(api[_-]?key[[:space:]]*=[[:space:]]*)".*"/\1"[REDACTED]"/Ig' \
    -e 's/(token[[:space:]]*=[[:space:]]*)".*"/\1"[REDACTED]"/Ig' \
    -e 's/(webpassword[[:space:]]*=[[:space:]]*)".*"/\1"[REDACTED]"/Ig' \
    "${file}"
  rm -f "${file}.bak"
}

log "Starting Pi-Circle read-only preflight collection"
log "Output directory: ${base_dir}"

run_capture uname uname -a
run_capture date date -u
run_capture os_release sh -c 'cat /etc/os-release'
run_capture cpuinfo sh -c 'cat /proc/cpuinfo'
run_capture memory free -h
run_capture disk df -h
run_capture block_devices lsblk -f
run_capture ip_addr ip addr show
run_capture ip_route ip route show table all
run_capture ip_neigh ip neigh show
run_capture resolv_conf sh -c 'cat /etc/resolv.conf'
run_capture sysctl_forwarding sh -c 'sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding'
run_capture nft_ruleset sh -c 'command -v nft >/dev/null 2>&1 && nft list ruleset || true'
run_capture networkmanager nmcli device status
run_capture networkmanager_connections nmcli connection show
run_capture systemd_pihole systemctl status pihole-FTL --no-pager
run_capture systemd_nftables systemctl status nftables --no-pager
run_capture systemd_networkmanager systemctl status NetworkManager --no-pager
run_capture pihole_version sh -c 'command -v pihole >/dev/null 2>&1 && pihole -v || true'
run_capture pihole_status sh -c 'command -v pihole >/dev/null 2>&1 && pihole status || true'
run_capture pihole_ftl_version sh -c 'command -v pihole-FTL >/dev/null 2>&1 && pihole-FTL -v || true'
run_capture listening_ports ss -lntup
run_capture installed_packages sh -c 'command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W "pihole*" "nftables" "network-manager" "dnsmasq*" "sqlite3" 2>/dev/null || true'

copy_if_readable /etc/pihole/pihole.toml etc/pihole/pihole.toml
copy_if_readable /etc/pihole/setupVars.conf etc/pihole/setupVars.conf
copy_if_readable /etc/nftables.conf etc/nftables.conf
copy_if_readable /etc/dhcpcd.conf etc/dhcpcd.conf

if [[ -d /etc/NetworkManager/system-connections ]]; then
  mkdir -p "${base_dir}/etc/NetworkManager"
  cp -a /etc/NetworkManager/system-connections "${base_dir}/etc/NetworkManager/" 2>/dev/null || true
fi

if [[ -d "${base_dir}/etc" ]]; then
  find "${base_dir}/etc" -maxdepth 6 -type f 2>/dev/null | while read -r file; do
    redact_file "${file}"
  done
fi

if command -v tar >/dev/null 2>&1; then
  archive="${base_dir}.tar.gz"
  tar -C "$(dirname "${base_dir}")" -czf "${archive}" "$(basename "${base_dir}")"
  log "Created archive: ${archive}"
fi

log "Preflight collection complete"
