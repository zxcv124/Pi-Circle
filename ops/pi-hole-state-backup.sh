#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
backup_root="${PI_HOLE_BACKUP_DIR:-$(pwd)/artifacts/pihole-backup-${timestamp}}"
mkdir -p "${backup_root}"

log() {
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" | tee -a "${backup_root}/backup.log" >/dev/null
}

capture() {
  local name="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"${backup_root}/${name}.txt" 2>&1 || true
}

backup_file() {
  local source="$1"
  local target_dir="${backup_root}/files$(dirname "${source}")"
  if [[ -e "${source}" ]]; then
    mkdir -p "${target_dir}"
    cp -a "${source}" "${target_dir}/"
  fi
}

sqlite_dump_if_available() {
  local db="$1"
  local name="$2"
  if [[ -r "${db}" ]] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${db}" '.schema' >"${backup_root}/${name}-schema.sql" 2>"${backup_root}/${name}-schema.err" || true
    sqlite3 "${db}" '.dump' >"${backup_root}/${name}-dump.sql" 2>"${backup_root}/${name}-dump.err" || true
  fi
}

log "Starting Pi-hole read-only state backup"
log "Output directory: ${backup_root}"

capture pihole_version sh -c 'command -v pihole >/dev/null 2>&1 && pihole -v || true'
capture pihole_status sh -c 'command -v pihole >/dev/null 2>&1 && pihole status || true'
capture pihole_groups sh -c 'command -v pihole >/dev/null 2>&1 && pihole-FTL --config --dump 2>/dev/null || true'

backup_file /etc/pihole/pihole.toml
backup_file /etc/pihole/setupVars.conf
backup_file /etc/pihole/gravity.db
backup_file /etc/pihole/pihole-FTL.db
backup_file /etc/pihole/custom.list
backup_file /etc/pihole/local.list
backup_file /etc/pihole/dhcp.leases

sqlite_dump_if_available /etc/pihole/gravity.db gravity
sqlite_dump_if_available /etc/pihole/pihole-FTL.db pihole-ftl

if command -v tar >/dev/null 2>&1; then
  archive="${backup_root}.tar.gz"
  tar -C "$(dirname "${backup_root}")" -czf "${archive}" "$(basename "${backup_root}")"
  log "Created archive: ${archive}"
fi

log "Pi-hole backup complete"
