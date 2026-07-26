#!/usr/bin/env bash
# Sanitized Pi-hole backup suitable for committing (no query history, no password hashes).
set -Eeuo pipefail

umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${ROOT}/backups/pihole}"
mkdir -p "${OUT}/files" "${OUT}/exports"

log() { printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"; }

log "Writing sanitized Pi-hole backup to ${OUT}"

{
  command -v pihole >/dev/null 2>&1 && pihole -v || true
  echo
  command -v pihole >/dev/null 2>&1 && pihole status || true
} >"${OUT}/versions.txt" 2>&1 || true

if [[ -r /etc/pihole/pihole.toml ]]; then
  # Drop likely secrets / API tokens if present.
  sed -E \
    '/(?i)(password|secret|token|webpassword|api_?key)/d' \
    /etc/pihole/pihole.toml >"${OUT}/files/pihole.toml" || true
fi

if [[ -r /etc/pihole/setupVars.conf ]]; then
  grep -v -E '^(WEBPASSWORD|SETUPVARS_WEBPASSWORD)=' /etc/pihole/setupVars.conf \
    >"${OUT}/files/setupVars.conf.redacted" || true
fi

for name in custom.list local.list dhcp.leases; do
  if [[ -r "/etc/pihole/${name}" ]]; then
    cp -a "/etc/pihole/${name}" "${OUT}/files/${name}"
  fi
done

if command -v sqlite3 >/dev/null 2>&1 && [[ -r /etc/pihole/gravity.db ]]; then
  sqlite3 /etc/pihole/gravity.db \
    "SELECT address, enabled, comment FROM adlist ORDER BY id;" \
    >"${OUT}/exports/adlists.tsv" 2>/dev/null || true
  sqlite3 /etc/pihole/gravity.db \
    "SELECT type, domain, enabled, comment FROM domainlist ORDER BY id;" \
    >"${OUT}/exports/domainlist.tsv" 2>/dev/null || true
  sqlite3 /etc/pihole/gravity.db \
    "SELECT 'adlists_enabled', COUNT(*) FROM adlist WHERE enabled=1
     UNION ALL SELECT 'domainlist', COUNT(*) FROM domainlist
     UNION ALL SELECT 'gravity_domains', COUNT(*) FROM gravity;" \
    >"${OUT}/exports/counts.tsv" 2>/dev/null || true
fi

cat >"${OUT}/README.md" <<'EOF'
# Pi-hole backup (sanitized)

This folder holds a **privacy-safe** snapshot of Pi-hole configuration from the
appliance that runs Pi-Circle.

Included:
- versions / status
- redacted `pihole.toml` / `setupVars.conf`
- local DNS lists when present
- adlist + domainlist exports (no full gravity binary, no query history)

Not included (on purpose):
- `pihole-FTL.db` query logs
- web password hashes / API secrets
- full `gravity.db` binary (often 100MB+)

Restore is a guide for operators — prefer Pi-hole’s own Teleporter for full
round-trips, then re-apply Pi-Circle privacy shield via the agent.
EOF

log "Backup complete"
