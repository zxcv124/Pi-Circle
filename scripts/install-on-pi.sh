#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/pi-circle/current"
VENV_DIR="/opt/pi-circle/venv"
CONFIG_DIR="/etc/pi-circle"
STATE_DIR="/var/lib/pi-circle"
LOG_DIR="/var/log/pi-circle"

detect_interface() {
  ip -4 route show default 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }'
}

detect_gateway() {
  ip -4 route show default 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i == "via") { print $(i+1); exit } }'
}

detect_cidr() {
  local interface="$1"
  ip -4 -o addr show dev "${interface}" 2>/dev/null | awk '{ print $4; exit }'
}

interface="$(detect_interface)"
gateway="$(detect_gateway)"
cidr=""
if [[ -n "${interface}" ]]; then
  cidr="$(detect_cidr "${interface}")"
fi

if [[ -z "${interface}" ]]; then
  interface="wlan0"
fi
if [[ -z "${gateway}" ]]; then
  gateway="192.168.1.1"
fi
if [[ -z "${cidr}" ]]; then
  cidr="192.168.1.0/24"
fi

apt-get update
apt-get install -y --no-install-recommends python3 python3-venv python3-pip sqlite3 nftables iproute2 dsniff rsync conntrack nmap curl ca-certificates
# Per-flow byte counters for Sniffnet-style linked-device connections.
if [[ -w /proc/sys/net/netfilter/nf_conntrack_acct ]]; then
  echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct || true
fi
install -d -o root -g root -m 0755 /etc/sysctl.d
cat > /etc/sysctl.d/90-pi-circle-conntrack.conf <<'EOF'
net.netfilter.nf_conntrack_acct = 1
EOF
sysctl --system >/dev/null 2>&1 || true

# Bundle Pi-hole when missing so Pi-Circle is a single appliance install.
# Set PI_CIRCLE_INSTALL_PIHOLE=0 to skip (already have Pi-hole managed separately).
if ! command -v pihole >/dev/null 2>&1; then
  if [[ "${PI_CIRCLE_INSTALL_PIHOLE:-1}" == "1" ]]; then
    printf 'Pi-hole not found — installing upstream Pi-hole (credited engine under Pi-Circle)...\n'
    install -d -o root -g root -m 0755 /etc/pihole
    if [[ ! -f /etc/pihole/setupVars.conf ]]; then
      cat > /etc/pihole/setupVars.conf <<EOF
PIHOLE_INTERFACE=${interface}
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=local
WEBPASSWORD=
BLOCKING_ENABLED=true
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=1.1.1.1
DNSSEC=false
REV_SERVER=false
EOF
      chmod 0644 /etc/pihole/setupVars.conf
    fi
    curl -sSL https://install.pi-hole.net -o /tmp/pihole-install.sh
    PIHOLE_SKIP_OS_CHECK="${PIHOLE_SKIP_OS_CHECK:-true}" bash /tmp/pihole-install.sh --unattended
    rm -f /tmp/pihole-install.sh
  else
    printf 'ERROR: Pi-hole is not installed and PI_CIRCLE_INSTALL_PIHOLE=0.\n' >&2
    exit 1
  fi
fi

if ! getent group pi-circle >/dev/null; then
  groupadd --system pi-circle
fi
if ! id -u pi-circle >/dev/null 2>&1; then
  useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin --gid pi-circle pi-circle
fi
if getent group pihole >/dev/null; then
  usermod -aG pihole pi-circle
fi

install -d -o root -g root -m 0755 /opt/pi-circle
install -d -o root -g pi-circle -m 2770 "${STATE_DIR}" "${LOG_DIR}"
install -d -o root -g pi-circle -m 0750 "${CONFIG_DIR}"
find "${STATE_DIR}" -maxdepth 1 -type f -name 'pi-circle.db*' -exec chown pi-circle:pi-circle {} \; -exec chmod 0660 {} \;
find "${LOG_DIR}" -maxdepth 1 -type f -exec chown pi-circle:pi-circle {} \; -exec chmod 0660 {} \;

rsync -a --delete \
  --exclude '.git' \
  --exclude 'artifacts' \
  --exclude '__pycache__' \
  "${SOURCE_DIR}/" "${INSTALL_DIR}/"

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip wheel
"${VENV_DIR}/bin/python" -m pip install "${INSTALL_DIR}"

if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
  sed \
    -e "s/interface = \"wlan0\"/interface = \"${interface}\"/" \
    -e "s/lan_cidr = \"192.168.1.0\\/24\"/lan_cidr = \"${cidr//\//\\/}\"/" \
    -e "s/gateway_ip = \"192.168.1.1\"/gateway_ip = \"${gateway}\"/" \
    "${INSTALL_DIR}/packaging/defaults/config.toml" > "${CONFIG_DIR}/config.toml"
fi

chown -R root:pi-circle "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}"
chmod 0640 "${CONFIG_DIR}/config.toml"

install -o root -g root -m 0644 "${INSTALL_DIR}/packaging/systemd/pi-circle-agent.service" /etc/systemd/system/pi-circle-agent.service
install -o root -g root -m 0644 "${INSTALL_DIR}/packaging/systemd/pi-circle-dashboard.service" /etc/systemd/system/pi-circle-dashboard.service
install -o root -g root -m 0755 "${INSTALL_DIR}/scripts/set-arp-assisted-targets.sh" /usr/local/sbin/pi-circle-set-arp-assisted-targets
install -o root -g root -m 0755 "${INSTALL_DIR}/scripts/enable-arp-assisted-target.sh" /usr/local/sbin/pi-circle-enable-arp-assisted-target
install -o root -g root -m 0755 "${INSTALL_DIR}/scripts/pi-circle-pihole-ctl.sh" /usr/local/sbin/pi-circle-pihole-ctl
cat > /etc/sudoers.d/pi-circle-dashboard <<'EOF'
pi-circle ALL=(root) NOPASSWD: /usr/local/sbin/pi-circle-set-arp-assisted-targets *
pi-circle ALL=(root) NOPASSWD: /usr/local/sbin/pi-circle-pihole-ctl *
EOF
chmod 0440 /etc/sudoers.d/pi-circle-dashboard
visudo -cf /etc/sudoers.d/pi-circle-dashboard >/dev/null

systemctl daemon-reload
systemctl enable nftables pihole-FTL pi-circle-agent pi-circle-dashboard 2>/dev/null || systemctl enable nftables pi-circle-agent pi-circle-dashboard
systemctl restart nftables
systemctl restart pihole-FTL 2>/dev/null || true
systemctl restart pi-circle-agent
systemctl restart pi-circle-dashboard

printf 'Pi-Circle + Pi-hole appliance installed.\n'
printf 'Dashboard: http://%s:8088/\n' "$(hostname -I | awk '{ print $1 }')"
printf 'Pi-hole engine credited inside Pi-Circle DNS / Settings.\n'
printf 'Config: %s/config.toml\n' "${CONFIG_DIR}"
