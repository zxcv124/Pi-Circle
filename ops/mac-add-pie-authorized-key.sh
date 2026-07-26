#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DEVICE="${ROOT_DEVICE:-/dev/rdisk3s2}"
WORKSPACE_DIR="${WORKSPACE_DIR:-/Users/zer0/Documents/Pi-Circle}"
PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE:-${WORKSPACE_DIR}/artifacts/ssh-access/pi_circle_ed25519.pub}"
DEBUGFS="${DEBUGFS:-/usr/local/opt/e2fsprogs/sbin/debugfs}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo ROOT_DEVICE="${ROOT_DEVICE}" WORKSPACE_DIR="${WORKSPACE_DIR}" PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE}" DEBUGFS="${DEBUGFS}" bash "$0" "$@"
fi

if [[ ! -e "${ROOT_DEVICE}" ]]; then
  printf 'Root partition device not found: %s\n' "${ROOT_DEVICE}" >&2
  exit 1
fi

if [[ ! -x "${DEBUGFS}" ]]; then
  printf 'debugfs not found: %s\n' "${DEBUGFS}" >&2
  exit 1
fi

if [[ ! -r "${PUBLIC_KEY_FILE}" ]]; then
  printf 'Public key not found: %s\n' "${PUBLIC_KEY_FILE}" >&2
  exit 1
fi

public_key="$(tr -d '\r\n' < "${PUBLIC_KEY_FILE}")"
case "${public_key}" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *) ;;
  *)
    printf 'Unsupported or invalid SSH public key format in %s\n' "${PUBLIC_KEY_FILE}" >&2
    exit 1
    ;;
esac

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
artifact_dir="${WORKSPACE_DIR}/artifacts/pie-authorized-keys-${timestamp}"
mkdir -p "${artifact_dir}"
existing="${artifact_dir}/authorized_keys.existing"
merged="${artifact_dir}/authorized_keys"
commands="${artifact_dir}/debugfs.commands"
log_file="${artifact_dir}/debugfs.log"

"${DEBUGFS}" -R "dump /home/pie/.ssh/authorized_keys ${existing}" "${ROOT_DEVICE}" >/dev/null 2>&1 || true
touch "${existing}"

python3 - "${existing}" "${merged}" "${public_key}" <<'PY'
from pathlib import Path
import sys

existing = Path(sys.argv[1])
merged = Path(sys.argv[2])
key = sys.argv[3].strip()
lines = []
for raw in existing.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw.strip()
    if line and line not in lines:
        lines.append(line)
if key not in lines:
    lines.append(key)
merged.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

cat > "${commands}" <<EOF
mkdir /home/pie/.ssh
rm /home/pie/.ssh/authorized_keys
write ${merged} /home/pie/.ssh/authorized_keys
sif /home/pie/.ssh mode 040700
sif /home/pie/.ssh uid 1000
sif /home/pie/.ssh gid 1000
sif /home/pie/.ssh/authorized_keys mode 0100600
sif /home/pie/.ssh/authorized_keys uid 1000
sif /home/pie/.ssh/authorized_keys gid 1000
stat /home/pie/.ssh
stat /home/pie/.ssh/authorized_keys
EOF

"${DEBUGFS}" -w -f "${commands}" "${ROOT_DEVICE}" >"${log_file}" 2>&1

verify_output="$("${DEBUGFS}" -R "cat /home/pie/.ssh/authorized_keys" "${ROOT_DEVICE}" 2>/dev/null || true)"
if ! grep -Fq "${public_key}" <<<"${verify_output}"; then
  printf 'Failed to verify public key in /home/pie/.ssh/authorized_keys\n' >&2
  exit 1
fi

chown -R zer0:staff "${artifact_dir}" 2>/dev/null || true

printf 'Added public key to /home/pie/.ssh/authorized_keys on %s\n' "${ROOT_DEVICE}"
printf 'Artifact directory: %s\n' "${artifact_dir}"
