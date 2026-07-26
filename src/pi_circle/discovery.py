from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address
from pathlib import Path
import sqlite3


@dataclass(frozen=True)
class ObservedDevice:
    ip_address: str
    mac_address: str | None
    hostname: str | None
    confidence: str


def read_proc_arp(lan_cidr: IPv4Network, arp_path: Path = Path("/proc/net/arp")) -> list[ObservedDevice]:
    if not arp_path.exists():
        return []
    devices: list[ObservedDevice] = []
    for line in arp_path.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip_text, _hw_type, flags, mac, _mask, _device = parts[:6]
        try:
            parsed_ip = ip_address(ip_text)
        except ValueError:
            continue
        if parsed_ip.version != 4 or parsed_ip not in lan_cidr:
            continue
        if flags == "0x0" or mac == "00:00:00:00:00:00":
            continue
        devices.append(ObservedDevice(ip_text, mac.lower(), None, "medium"))
    return devices


def read_pihole_network(ftl_db: Path, lan_cidr: IPv4Network) -> list[ObservedDevice]:
    if not ftl_db.exists():
        return []
    devices: list[ObservedDevice] = []
    conn = sqlite3.connect(f"file:{ftl_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT na.ip, n.hwaddr, n.name
            FROM network_addresses na
            JOIN network n ON n.id = na.network_id
            WHERE na.ip IS NOT NULL
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    for row in rows:
        ip_text = str(row["ip"])
        try:
            parsed_ip = ip_address(ip_text)
        except ValueError:
            continue
        if parsed_ip.version != 4 or parsed_ip not in lan_cidr:
            continue
        mac = str(row["hwaddr"]).lower() if row["hwaddr"] else None
        hostname = str(row["name"]) if row["name"] else None
        confidence = "high" if mac and hostname else "medium"
        devices.append(ObservedDevice(ip_text, mac, hostname, confidence))
    return devices
