# Network Control Design

## Safety Position

Transparent network control is powerful and can disrupt or expose traffic if implemented carelessly. This design supports only authorized local administration and excludes credential capture, HTTPS decryption, covert persistence, and off-network targeting.

ARP-assisted mode is treated as a compatibility mode, not the default. It must be visible in the UI, reversible from the UI and command line, bounded to configured LAN interfaces, and disabled automatically when health checks fail.

## Deployment Modes

### Router-Integrated Mode

Use when router settings are available.

Behavior:

- Router DHCP assigns Pi-hole for DNS.
- Optional static routes or gateway options steer selected traffic through the Pi only if supported and tested.
- Pi-hole groups enforce DNS policy per client.

Benefits:

- Least disruptive.
- Survives reboots more predictably.
- Easier to explain to users.

### Inline Gateway Mode

Use when the Pi can sit in path with two interfaces.

Behavior:

- Clients reach router through the Pi.
- Pi enables IP forwarding.
- `nftables` handles stateful forwarding, masquerade/SNAT as needed, DNS redirection where configured, and per-device policy.

Benefits:

- Transparent and robust.
- No ARP compatibility behavior required.
- Cleanest path for full-device pause and traffic analytics.

### ARP-Assisted Compatibility Mode

Use only when router configuration is unavailable and the LAN owner authorizes selected IPv4 clients.

Behavior requirements:

- Inclusion is per device or per profile, never automatically all devices on first boot.
- Gateway relationship and client reachability are checked before enabling.
- Agent sends bounded neighbor advertisements only for selected clients and only while the health gate is passing.
- Agent forwards traffic using stateful routing and `nftables`.
- Agent continuously confirms that default gateway, Pi IP, interface, subnet, and client IP match expected values.
- Agent stops the mode and restores DNS-only behavior when conditions drift.

Controls:

- Global kill switch in `/etc/pi-circle/config.toml`.
- Hardware-safe command-line disable path through `systemctl stop pi-circle-agent`.
- UI pause control for a single device, profile, or all transparent control.
- Automatic disable on high packet loss, gateway MAC change, IP conflict, repeated conntrack exhaustion, or Pi-hole outage.

## Enforcement Layers

### DNS

- Use Pi-hole groups for blocklist/allowlist differences by person/profile.
- Keep existing blocklists and allowlists intact during migration.
- Add product-managed groups with clear naming.
- Reload lists through supported Pi-hole mechanisms after policy changes.

### Routing

- Enable IP forwarding only for selected deployment modes.
- Use `nftables` stateful rules for forwarding.
- Use explicit allow rules for established/related traffic.
- Use deny rules for paused devices and blocked destinations.
- Use DNS redirect only for port 53 when the administrator enables it.

### Device Identity

Identity confidence levels:

- `high`: stable MAC plus DHCP hostname plus repeated Pi-hole client match.
- `medium`: stable MAC plus IP or hostname.
- `low`: randomized MAC or one-time observation.

Policies should warn before assigning strong restrictions to low-confidence identities.

## IPv6 Strategy

ARP does not apply to IPv6. Before enabling transparent control, determine whether IPv6 is active.

Options:

- Router-integrated IPv6 DNS assignment.
- Inline gateway IPv6 forwarding and firewall rules.
- Router advertisement control only when the appliance is the legitimate RA authority.
- Disable transparent mode warning if IPv6 bypass would make policy misleading.

## Observability

Metrics:

- Device last seen.
- Policy state.
- DNS queries blocked/allowed by profile.
- Routed bytes and packets per device.
- Transparent-control health.
- Gateway reachability.
- Forwarding and NAT rule status.
- Rule application latency.

Audit events:

- Device added, renamed, assigned, or removed.
- Policy created, changed, enabled, disabled, or deleted.
- Transparent mode enabled or disabled.
- Kill switch activated.
- Geographic or administrative access restriction event if remote administration is later added.
- Failed authorization attempt.

## Rollback

Rollback must be testable before enabling transparent control:

1. Stop `pi-circle-agent`.
2. Flush only Pi-Circle-owned `nftables` tables/chains.
3. Disable IP forwarding if Pi-Circle enabled it.
4. Leave Pi-hole running in DNS-only mode.
5. Record rollback reason and operator identity.

## Non-Goals

- Capturing passwords or session tokens.
- Decrypting TLS.
- Hiding the appliance from the administrator.
- Controlling networks the operator does not own or administer.
- Bypassing OS-level protections on client devices.
