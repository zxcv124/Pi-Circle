from __future__ import annotations

from ipaddress import IPv4Network
from pathlib import Path

from .discovery import ObservedDevice, read_pihole_network, read_proc_arp
from .presence import collect_presence
from .storage import Store


def collect_present_devices(
    lan_cidr: IPv4Network,
    ftl_db: Path,
    arp_path: Path = Path("/proc/net/arp"),
    *,
    known_ips: set[str] | None = None,
    probe: bool = False,
    full_scan: bool = False,
) -> list[ObservedDevice]:
    """Return currently present LAN devices.

    When probe/full_scan are enabled, actively ping candidates so reconnected
    phones reappear even if the ARP cache was FAILED/empty.
    """
    if probe or full_scan:
        return collect_presence(
            lan_cidr,
            ftl_db,
            known_ips=known_ips,
            probe=True,
            full_scan=full_scan,
            arp_path=arp_path,
        )

    present = read_proc_arp(lan_cidr, arp_path=arp_path)
    enrichment = {device.ip_address: device for device in read_pihole_network(ftl_db, lan_cidr)}
    merged: list[ObservedDevice] = []
    seen: set[str] = set()
    for device in present:
        if device.ip_address in seen:
            continue
        seen.add(device.ip_address)
        extra = enrichment.get(device.ip_address)
        mac = device.mac_address or (extra.mac_address if extra else None)
        hostname = extra.hostname if extra and extra.hostname else device.hostname
        confidence = "high" if mac and hostname else device.confidence
        merged.append(ObservedDevice(device.ip_address, mac, hostname, confidence))
    return merged


def sync_device_inventory(
    settings,
    store: Store,
    *,
    probe: bool = True,
    full_scan: bool = False,
) -> set[str]:
    """Upsert present devices, prune absent unenrolled rows, return present IPs."""
    known_ips = {device.ip_address for device in store.list_devices()}
    observed = collect_present_devices(
        settings.network.lan_cidr,
        settings.pihole.ftl_db,
        known_ips=known_ips,
        probe=probe,
        full_scan=full_scan,
    )
    present_ips = {device.ip_address for device in observed}
    gateway_ip = str(settings.network.gateway_ip)
    for device in observed:
        store.upsert_device(
            device.ip_address,
            device.mac_address,
            device.hostname,
            device.confidence,
            gateway_ip=gateway_ip,
        )
    store.prune_absent_devices(present_ips, keep_enrolled=True)
    return present_ips
