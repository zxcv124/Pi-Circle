# Architecture

## Product Goal

Ship a single family network-control appliance: Pi-Circle as the primary GUI and control plane, with Pi-hole installed or reused as the credited DNS engine for blocklists, allowlists, gravity, and query intel — plus per-device policy, transparent network control, and observability.

## Core Principles

- Keep Pi-hole responsible for DNS filtering.
- Add a separate appliance control plane for device identity, routing state, policy, audit logs, and UI-specific data.
- Prefer supported Pi-hole v6 API/CLI paths over direct database writes.
- Use direct database reads only for backups, diagnostics, or migrations where the Pi-hole API cannot represent the needed state.
- Build every network interception path with an explicit kill switch, health gate, allowlist, rollback path, and audit trail.

## Modules

### Appliance Agent

Runs as a hardened system service on the Pi.

Responsibilities:

- Detect interfaces, gateway, subnet, IPv4/IPv6 state, DNS authority, and DHCP authority.
- Maintain device inventory from ARP neighbor state, DHCP leases, Pi-hole client data, and observed DNS clients.
- Apply network policies through `nftables`, Linux routing, and Pi-hole group assignment.
- Emit structured audit and security logs.
- Expose a localhost-only control API to the dashboard backend.

### Policy Engine

Owns family profiles and enforcement decisions.

Objects:

- Device
- Person
- Profile
- Schedule
- Time budget
- Category policy
- Domain allowlist and denylist
- Pause state
- Bedtime state
- Administrative bypass

The policy engine maps product concepts to enforcement targets:

- DNS group assignment in Pi-hole.
- `nftables` allow, block, redirect, and rate-limit rules.
- Transparent gateway inclusion or exclusion.
- Event logs and dashboard status.

### Pi-hole Adapter

Integrates with Pi-hole v6 through local API calls.

Responsibilities:

- Authenticate through local Pi-hole API flow.
- Read clients, groups, lists, blocking status, and query summaries.
- Create and assign groups for profiles when supported by the installed API.
- Fall back to carefully validated CLI/database procedures only when API coverage is insufficient.

### Network Control Layer

Supports three deployment modes:

- `router_integrated`: router DHCP/DNS settings point clients to Pi-hole or gateway policies.
- `inline_gateway`: Pi bridges or routes traffic between LAN and router through dedicated interfaces.
- `arp_assisted`: selected IPv4 clients are directed through the appliance on an owner-administered LAN when router changes are unavailable.

### Dashboard

Runs locally on the Pi and extends or sits beside the Pi-hole dashboard.

Primary views:

- 3D device map showing router, Pi appliance, and known devices.
- Device detail with identity, owner, profile, DNS status, traffic status, and last seen time.
- Family profile editor with schedules, time budgets, and category policies.
- Network control health with gateway, interface, routing, DNS, and enforcement checks.
- Audit log for policy changes, blocked access, bypasses, and network-control state transitions.

## Data Storage

Use a new SQLite database for Pi-Circle state, separate from Pi-hole:

- `/var/lib/pi-circle/pi-circle.db`
- `/var/lib/pi-circle/audit.db` or partitioned audit tables in the same database
- `/etc/pi-circle/config.toml`
- `/var/log/pi-circle/*.log`

Backups include:

- Pi-Circle config and databases.
- Pi-hole `/etc/pihole` state.
- `nftables` ruleset.
- systemd unit files.

## Deployment Shape

System services:

- `pi-circle-agent.service`
- `pi-circle-dashboard.service`
- `pi-circle-health.timer`
- `pi-circle-backup.timer`

Network services retained:

- `pihole-FTL.service`
- `nftables.service`
- `NetworkManager.service` or OS-specific network manager.

## Failure Behavior

Default failure behavior must favor connectivity recovery:

- If the agent fails health checks, stop transparent interception and keep DNS-only Pi-hole mode available.
- If Pi-hole is unhealthy, disable new policy changes and show dashboard degraded state.
- If forwarding/NAT is unhealthy, automatically remove affected clients from transparent control.
- If the dashboard is unreachable, preserve last known safe network rules for a bounded interval, then degrade to DNS-only.

## Edge Cases

- Devices with randomized MAC addresses.
- IPv6 traffic bypassing IPv4 DNS or ARP control.
- Clients using encrypted DNS directly.
- Router client isolation preventing LAN discovery.
- Multiple subnets or guest networks.
- Mesh Wi-Fi systems with proxy ARP or unusual bridge behavior.
- Game consoles and streaming devices sensitive to NAT type changes.
- Devices sleeping and reappearing with new addresses.
- Pi reboot during active interception.
- SD card corruption or sudden power loss.
