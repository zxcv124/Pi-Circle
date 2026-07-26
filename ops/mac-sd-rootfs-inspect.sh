#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

BOOTFS_MOUNT="${BOOTFS_MOUNT:-/Volumes/bootfs}"
WORKSPACE_DIR="${WORKSPACE_DIR:-/Users/zer0/Documents/Pi-Circle}"
DEBUGFS="${DEBUGFS:-/usr/local/opt/e2fsprogs/sbin/debugfs}"
DUMPE2FS="${DUMPE2FS:-/usr/local/opt/e2fsprogs/sbin/dumpe2fs}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo BOOTFS_MOUNT="${BOOTFS_MOUNT}" WORKSPACE_DIR="${WORKSPACE_DIR}" DEBUGFS="${DEBUGFS}" DUMPE2FS="${DUMPE2FS}" bash "$0" "$@"
fi

if [[ ! -d "${BOOTFS_MOUNT}" ]]; then
  printf 'Boot partition mount not found: %s\n' "${BOOTFS_MOUNT}" >&2
  exit 1
fi

if [[ ! -x "${DEBUGFS}" || ! -x "${DUMPE2FS}" ]]; then
  printf 'e2fsprogs tools not found. Expected debugfs at %s and dumpe2fs at %s\n' "${DEBUGFS}" "${DUMPE2FS}" >&2
  exit 1
fi

whole_disk="$(diskutil info "${BOOTFS_MOUNT}" | awk -F: '/Part of Whole/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }')"
if [[ -z "${whole_disk}" ]]; then
  printf 'Could not determine whole disk for %s\n' "${BOOTFS_MOUNT}" >&2
  exit 1
fi

root_device="/dev/r${whole_disk}s2"
root_device_block="/dev/${whole_disk}s2"
if [[ ! -e "${root_device}" ]]; then
  printf 'Expected root partition device not found: %s\n' "${root_device}" >&2
  exit 1
fi

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
artifact_dir="${WORKSPACE_DIR}/artifacts/sd-card-rootfs-inspection-${timestamp}"
mkdir -p "${artifact_dir}/rootfs-files"

log() {
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" | tee -a "${artifact_dir}/inspection.log"
}

run_debugfs() {
  local output="$1"
  local command="$2"
  "${DEBUGFS}" -R "${command}" "${root_device}" >"${artifact_dir}/${output}" 2>&1 || true
}

redact_file() {
  local file="$1"
  [[ -f "${file}" ]] || return 0
  sed -E -i.bak \
    -e 's/(password[[:space:]_=-]*).*/\1[REDACTED]/Ig' \
    -e 's/(webpassword[[:space:]_=-]*).*/\1[REDACTED]/Ig' \
    -e 's/(token[[:space:]_=-]*).*/\1[REDACTED]/Ig' \
    -e 's/(api[_-]?key[[:space:]_=-]*).*/\1[REDACTED]/Ig' \
    "${file}"
  rm -f "${file}.bak"
}

log "Starting read-only rootfs inspection"
log "Boot mount: ${BOOTFS_MOUNT}"
log "Whole disk: /dev/${whole_disk}"
log "Root partition: ${root_device_block}"
log "Artifact directory: ${artifact_dir}"

diskutil info "/dev/${whole_disk}" >"${artifact_dir}/diskutil-whole-disk.txt" 2>&1 || true
diskutil info "${root_device_block}" >"${artifact_dir}/diskutil-root-partition.txt" 2>&1 || true
"${DUMPE2FS}" -h "${root_device}" >"${artifact_dir}/dumpe2fs-header.txt" 2>&1 || true

run_debugfs root-ls.txt "ls -p /"
run_debugfs etc-ls.txt "ls -p /etc"
run_debugfs etc-pihole-ls.txt "ls -p /etc/pihole"
run_debugfs systemd-system-ls.txt "ls -p /etc/systemd/system"
run_debugfs networkmanager-ls.txt "ls -p /etc/NetworkManager/system-connections"
run_debugfs os-release.txt "cat /etc/os-release"
run_debugfs debian-version.txt "cat /etc/debian_version"
run_debugfs hostname.txt "cat /etc/hostname"
run_debugfs hosts.txt "cat /etc/hosts"
run_debugfs pihole-toml.txt "cat /etc/pihole/pihole.toml"
run_debugfs setupVars-conf.txt "cat /etc/pihole/setupVars.conf"
run_debugfs pihole-versions.txt "cat /etc/pihole/versions"
run_debugfs gravity-stat.txt "stat /etc/pihole/gravity.db"
run_debugfs ftl-db-stat.txt "stat /etc/pihole/pihole-FTL.db"

"${DEBUGFS}" -R "rdump /etc/pihole ${artifact_dir}/rootfs-files" "${root_device}" >"${artifact_dir}/rdump-etc-pihole.txt" 2>&1 || true

find "${artifact_dir}" -type f \( -name '*.txt' -o -name '*.conf' -o -name '*.toml' \) | while read -r file; do
  redact_file "${file}"
done

chown -R zer0:staff "${artifact_dir}"
log "Inspection complete"
