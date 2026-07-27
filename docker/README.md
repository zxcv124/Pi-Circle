# Pi-Circle Docker Package

This package runs the Pi-Circle dashboard and appliance agent in a Linux container.

## Requirements

- Docker Engine with host networking support.
- A Linux host on the target LAN.
- Existing Pi-hole data mounted at `/etc/pihole`, or a `pihole-etc` Docker volume shared with a Pi-hole container.
- `NET_ADMIN` and `NET_RAW` capabilities when ARP-assisted linked-device control is enabled.

The native Raspberry Pi installer remains the recommended full appliance path because it installs and manages Pi-hole, systemd services, nftables, and recovery helpers directly on the Pi.

## Build

```bash
docker build -f docker/Dockerfile -t pi-circle:0.1.0 .
```

## Run With Compose

Set the LAN values for the host, then start Pi-Circle:

```bash
export PI_CIRCLE_INTERFACE=wlan0
export PI_CIRCLE_LAN_CIDR=192.168.1.0/24
export PI_CIRCLE_GATEWAY_IP=192.168.1.1
docker compose -f docker/docker-compose.yml up -d --build
```

Open `http://HOST_IP:8088/`.

## Persistent Paths

- `/etc/pi-circle` stores Pi-Circle configuration.
- `/var/lib/pi-circle` stores the Pi-Circle SQLite database.
- `/var/log/pi-circle` stores audit and service logs.
- `/etc/pihole` provides Pi-hole gravity and FTL database visibility.

## Operational Notes

Docker runs without systemd inside the Pi-Circle container. Container helper commands update Pi-Circle configuration directly; Pi-hole CLI actions require `pihole` and `pihole-FTL` to be available inside the runtime environment. DNS-only dashboard visibility works with mounted Pi-hole databases. Full transparent linked-device control requires host networking, capabilities, and LAN interface settings that match the Docker host.
