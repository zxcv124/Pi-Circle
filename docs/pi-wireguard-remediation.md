# Pi WireGuard Remediation

Date: 2026-07-18

The Pi had `wg-quick@wg0.service` enabled at boot. Its `/etc/wireguard/wg0.conf` advertised a full-tunnel peer with `AllowedIPs = 0.0.0.0/0`, but the peer block had no `Endpoint`.

Impact:

- Boot-time WireGuard setup installed policy routing through `wg0`.
- Outbound internet failed with `From 10.140.243.1 Destination Host Unreachable`.
- `apt`, `pip`, and normal WAN checks could not reach external hosts.

Remediation applied on the Pi:

```bash
sudo systemctl stop wg-quick@wg0.service
sudo systemctl disable wg-quick@wg0.service
```

The WireGuard config was preserved in `/etc/wireguard/wg0.conf`; only automatic startup was disabled.

Verified after remediation:

- `systemctl is-active wg-quick@wg0.service` returns `inactive`.
- `systemctl is-enabled wg-quick@wg0.service` returns `disabled`.
- `curl -4 http://deb.debian.org/debian/` succeeds.
- `pi-circle-agent.service` and `pi-circle-dashboard.service` remain active.

If WireGuard is needed later, add a valid peer `Endpoint` and confirm the intended routing policy before re-enabling `wg-quick@wg0.service`.
