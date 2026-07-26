# Pi-Circle

**Family network command for a Raspberry Pi running Pi-hole.**

Pi-Circle is the main GUI. It turns an existing Pi-hole appliance into a Disney Circle–style household controller: devices, activity, DNS protection, alerts, parental schedules, and linked-device traffic insight — with Pi-hole as the DNS engine underneath.

**Made by Yahya** · [@914ix on Instagram](https://instagram.com/914ix)

## What you get

- **Devices** — discover, label, pause, bedtime, daily limits, auto Android link (nmap)
- **Activity** — live DNS feed, history (1h / 24h / 7d), on-path flows for linked devices
- **DNS** — Pi-hole engine status inside Pi-Circle, plus one-click classic admin
- **Alerts** — new devices, spikes, DoH/telemetry privacy hits
- **Controls** — profiles, schedules, rollback

## Requirements

- Raspberry Pi (or similar) already running **Pi-hole**
- Linux with `nftables`, `nmap`, `conntrack`, Python 3.11+
- LAN admin access to the Pi

## Quick install (on the Pi)

```bash
# From a machine with this repo:
rsync -a --exclude .git --exclude .venv-test ./ pie@PI_HOST:/tmp/pi-circle-src/
ssh pie@PI_HOST 'sudo bash /tmp/pi-circle-src/scripts/install-on-pi.sh'
```

Dashboard: `http://PI_HOST:8088/`  
Pi-hole admin (same device): `http://PI_HOST/admin/`

## Configuration

Primary config: `/etc/pi-circle/config.toml`

Important sections:

- `[network]` — mode, ARP-assisted targets, QUIC / WAN inbound safeguards
- `[privacy]` — DoH / telemetry shield
- `[discovery]` — `use_nmap`, `auto_link_android`

## License

See [LICENSE](LICENSE).

- Free for **personal / household / educational / non-enterprise** use
- **Modification and redistribution allowed**
- **You must credit Yahya (@914ix)**
- Enterprise / commercial use needs permission

Pi-hole itself remains under its own licenses; Pi-Circle integrates with it and does not relicense Pi-hole.

## Author

Yahya — [@914ix](https://instagram.com/914ix)

## Safety

Use only on networks you own or administer. ARP-assisted linking is explicit, auditable, and reversible. Pi-Circle does not decrypt HTTPS or capture credentials.
