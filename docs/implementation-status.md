# Implementation Status

Date: 2026-07-18.

## Completed In Workspace

- Python package scaffold for `pi-circle`.
- Strict TOML config parser with ARP-assisted safety validation.
- SQLite state store for devices, profiles, policy events, and network health.
- Audit JSONL writer.
- Device discovery from `/proc/net/arp` and Pi-hole FTL network inventory.
- Network controller for DNS-only, gateway modes, `nftables`, rollback, and explicitly enabled ARP-assisted process supervision.
- ARP-assisted hardening for target-scoped NAT, same-interface forwarding sysctls, sbin-aware `arpspoof` resolution, unsafe-target rejection, and failed-process audit events.
- MAC-stable device enrollment: connecting a device persists `managed`/`transparent_control`, migrates identity across DHCP IP changes, and lets the agent re-apply ARP-assisted targets when the device reappears.
- `set-arp-assisted-targets.sh --no-restart` so the agent can reconcile targets without restarting itself.
- FastAPI dashboard service.
- Futuristic dashboard UI with live topology, graphical device type icons, editable device names/types, profile assignment, device details drawer, Link/Unlink enrollment controls, health metrics, refresh, and rollback.
- LAN-restricted dashboard mutation API for device refresh, ARP-assisted target changes, and rollback.
- LAN-restricted device identity and profile APIs for saving friendly names, device categories, creating profiles, and assigning devices to profiles such as Default, Parents, Kids, and Guests.
- Pi-side installer script.
- Pi-side rollback script.
- Pi-side ARP-assisted target set/enable scripts and scoped sudoers integration for dashboard-initiated changes.
- systemd units for agent and dashboard.
- Mac-side SD-card rootfs inspection and imaging scripts.

## Current Runtime Defaults

Default mode is `dns_only`.

Transparent control remains off until all of these are true:

- `network.mode = "arp_assisted"`
- `network.arp_assisted_enabled = true`
- `network.enable_ipv4_forwarding = true`
- `network.arp_assisted_targets` contains one or more IPv4 clients inside `network.lan_cidr`
- `arpspoof` from the Debian `dsniff` package is installed
- `pi-circle-agent` is running as root

When enabled through `scripts/enable-arp-assisted-target.sh`, the helper also turns on DNS port 53 redirection and rejects the gateway, this Pi's own address, unmanaged IPs, and clients outside the configured LAN.

## Preserved Pi-hole State

The read-only rootfs artifact contains a copy of `/etc/pihole` from the SD card:

```text
/Users/zer0/Documents/Pi-Circle/artifacts/sd-card-rootfs-inspection-20260718T155302Z
```

Summary:

- Pi-hole Core `v6.1.4`
- Pi-hole Web `v6.2.1`
- Pi-hole FTL `v6.2.3`
- DHCP disabled
- Interface `wlan0`
- 52 enabled adlists
- 3,816,110 gravity domains
- 4,694,794 query rows

## Full SD-Card Backup

Completed compressed image:

```text
/Users/zer0/Documents/Pi-Circle/artifacts/sd-card-images/pi-circle-disk5-20260718T163057Z.img.gz
```

SHA-256:

```text
9c822046f947b17ae16a484cee536a2cb1d0b49cf4ad0e41bbe3ead61a223e73
```

Compressed size: 3.2 GB.

## Install On Booted Pi

After the SD-card image backup is complete, boot the Pi and run:

```bash
cd /path/to/Pi-Circle
sudo bash scripts/install-on-pi.sh
```

The installer starts in DNS-only mode and prints the local dashboard URL.

## Emergency Rollback

On the Pi:

```bash
sudo bash scripts/rollback-network.sh
```

This stops Pi-Circle network controls, removes the Pi-Circle `nftables` table, restarts Pi-hole FTL when available, and leaves Pi-hole in DNS mode.

## Verification

Completed locally:

- `python3 -m compileall -q src tests`
- `bash -n ops/*.sh scripts/*.sh`
- `.venv-test/bin/python -m unittest discover -s tests -v`
- Local dashboard API and static asset smoke test on `127.0.0.1:8099`

`pytest` was not used for verification because the local macOS Python venv segfaulted before running tests. The tests were converted to standard-library `unittest` and passed.
