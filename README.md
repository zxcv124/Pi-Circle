# Pi-Circle

**Family network command for Raspberry Pi — Pi-Circle GUI with Pi-hole as the DNS engine.**

One installer. One appliance. Pi-Circle is the main console; [Pi-hole](https://pi-hole.net/) provides blocking, gravity, and query intel underneath (credited in the UI).

**Made by Yahya** · [@914ix on Instagram](https://instagram.com/914ix)

## What you get

- **Devices** — discover, label, pause, bedtime, daily limits, auto Android link (nmap)
- **Activity** — live DNS feed, history (1h / 24h / 7d), on-path flows for linked devices
- **DNS** — unified status + **Pi-hole Settings** control dash (enable/disable, gravity, allow/deny)
- **Themes** — LCARS Command theme or Stitch NetSight (cyber-modern) theme switch
- **Alerts** — new devices, spikes, DoH/telemetry privacy hits
- **Controls** — profiles, schedules, rollback

## Requirements

- Raspberry Pi (or similar Linux box)
- LAN admin access
- Internet on first install (to fetch Pi-hole if it is not already present)

You do **not** need Pi-hole pre-installed. The installer installs upstream Pi-hole when missing (`PI_CIRCLE_INSTALL_PIHOLE=0` skips that step).

## Quick install (on the Pi)

```bash
# From a machine with this repo:
rsync -a --exclude .git --exclude .venv-test ./ pie@PI_HOST:/tmp/pi-circle-src/
ssh pie@PI_HOST 'sudo bash /tmp/pi-circle-src/scripts/install-on-pi.sh'
```

Dashboard: `http://PI_HOST:8088/`  
Pi-hole Settings: open **DNS → Pi-hole Settings** in the GUI (classic admin remains available as a secondary link).

## Configuration

Primary config: `/etc/pi-circle/config.toml`

Important sections:

- `[network]` — mode, ARP-assisted targets, QUIC / WAN inbound safeguards
- `[privacy]` — DoH / telemetry shield
- `[discovery]` — `use_nmap`, `auto_link_android`

## Themes

Use the header **LCARS / Stitch** switch:

- **LCARS** — original command aesthetic
- **Stitch** — NetSight cyber-modern palette (Inter + JetBrains Mono, glass panels)

Choice is saved in the browser.

## License

See [LICENSE](LICENSE).

- Free for **personal / household / educational / non-enterprise** use
- **Modification and redistribution allowed**
- **You must credit Yahya (@914ix)**
- Enterprise / commercial use needs permission

Pi-hole remains under its own licenses and trademarks. Pi-Circle integrates with and credits Pi-hole; it does not relicense Pi-hole.

## Author

Yahya — [@914ix](https://instagram.com/914ix)

## Safety

Use only on networks you own or administer. ARP-assisted linking is explicit, auditable, and reversible. Pi-Circle does not decrypt HTTPS or capture credentials.
