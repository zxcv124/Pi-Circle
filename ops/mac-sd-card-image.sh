#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

BOOTFS_MOUNT="${BOOTFS_MOUNT:-/Volumes/bootfs}"
WORKSPACE_DIR="${WORKSPACE_DIR:-/Users/zer0/Documents/Pi-Circle}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo BOOTFS_MOUNT="${BOOTFS_MOUNT}" WORKSPACE_DIR="${WORKSPACE_DIR}" bash "$0" "$@"
fi

if [[ ! -d "${BOOTFS_MOUNT}" ]]; then
  printf 'Boot partition mount not found: %s\n' "${BOOTFS_MOUNT}" >&2
  exit 1
fi

whole_disk="$(diskutil info "${BOOTFS_MOUNT}" | awk -F: '/Part of Whole/ { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }')"
if [[ -z "${whole_disk}" ]]; then
  printf 'Could not determine whole disk for %s\n' "${BOOTFS_MOUNT}" >&2
  exit 1
fi

raw_disk="/dev/r${whole_disk}"
block_disk="/dev/${whole_disk}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
image_dir="${WORKSPACE_DIR}/artifacts/sd-card-images"
image_path="${image_dir}/pi-circle-${whole_disk}-${timestamp}.img.gz"
sha_path="${image_path}.sha256"

mkdir -p "${image_dir}"

printf 'Creating compressed SD-card image from %s\n' "${block_disk}"
printf 'Output: %s\n' "${image_path}"
printf 'This is read-only against the SD card. It can take several minutes.\n'

diskutil unmountDisk "${block_disk}" >/dev/null
dd if="${raw_disk}" bs=4m status=progress | gzip -1 >"${image_path}"
shasum -a 256 "${image_path}" >"${sha_path}"
chown -R zer0:staff "${image_dir}"

printf 'Image complete: %s\n' "${image_path}"
printf 'Checksum: %s\n' "${sha_path}"
