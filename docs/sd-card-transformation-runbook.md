# SD Card Transformation Runbook

## Stage 0: Preserve Current State

1. Boot the Pi normally or mount the SD card read-only.
2. Run `ops/pi-circle-preflight.sh` on the live Pi when possible.
3. Run `ops/pi-hole-state-backup.sh` to capture current Pi-hole configuration and databases.
4. Create a full SD card image before installing new services.
5. Verify the image can be mounted and key files are readable.

Artifacts to preserve:

- `/etc/pihole`
- `/etc/nftables.conf`
- `/etc/systemd/system`
- NetworkManager or `dhcpcd` profiles.
- Pi-hole versions and local API docs.

## Stage 1: Identify Deployment Mode

Collect:

- Pi model, RAM, storage size, OS release, architecture.
- Network interfaces and link speeds.
- Router model and DHCP control capability.
- LAN subnet, gateway, DNS, and IPv6 status.
- Whether the Pi has only Ethernet, only Wi-Fi, or both.

Decision:

- Use router-integrated mode when DHCP/DNS can be changed on the router.
- Use inline gateway mode when the Pi can reliably sit between clients and router.
- Use ARP-assisted compatibility mode only when the administrator explicitly selects target devices and accepts the operational tradeoffs.

## Stage 2: Install Pi-Circle Base

Install:

- `pi-circle-agent`
- `pi-circle-dashboard`
- `pi-circle-health.timer`
- `pi-circle-backup.timer`
- `/etc/pi-circle/config.toml`
- `/var/lib/pi-circle`
- `/var/log/pi-circle`

Hardening:

- Dedicated system user.
- Minimal Linux capabilities.
- Localhost-only privileged control socket.
- Systemd sandboxing where compatible with required network capabilities.
- Strict file permissions with `umask 077`.

## Stage 3: Integrate With Pi-hole

Actions:

- Detect Pi-hole v6 API endpoint from the local appliance.
- Validate authentication without storing cleartext secrets.
- Read current groups, clients, blocklists, allowlists, and DNS status.
- Create Pi-Circle-managed groups only after backing up state.
- Keep existing groups and lists unchanged unless explicitly mapped to profiles.

Acceptance checks:

- Pi-hole dashboard still loads.
- Existing blocklists and allowlists remain present.
- DNS queries resolve for a test client.
- Pi-Circle can read policy state through the Pi-hole API.

## Stage 4: Enable Dashboard

Actions:

- Serve dashboard on an admin-only local address.
- Protect access with strong authentication.
- Add CSRF protection, secure cookies, rate limiting, and audit logging.
- Show device map, policy editor, health panel, and rollback controls.

Acceptance checks:

- Keyboard navigation works.
- Dark and light modes work.
- Mobile layout works.
- Network health failures are visible.
- No sensitive tokens appear in browser storage or logs.

## Stage 5: Enable Network Control

Actions:

- Start with DNS-only policy.
- Enable router-integrated or inline gateway mode when available.
- Enable ARP-assisted mode only for selected IPv4 devices after health checks pass.
- Validate throughput, DNS behavior, blocked states, paused states, and rollback.

Acceptance checks:

- Selected devices retain internet access when allowed.
- Paused devices are blocked predictably.
- Unmanaged devices remain unaffected.
- Pi reboot returns to a safe state.
- Agent failure degrades to DNS-only where possible.

## Stage 6: Operations

Runbooks:

- Backup and restore.
- Disable transparent mode.
- Recover from Pi-hole outage.
- Recover from dashboard lockout.
- Rotate admin credentials.
- Upgrade Pi-hole safely.
- Upgrade Pi-Circle safely.

Monitoring:

- Service health.
- Disk space.
- SD card write pressure.
- DNS latency.
- Forwarding latency.
- Device inventory churn.
- Policy application failures.
