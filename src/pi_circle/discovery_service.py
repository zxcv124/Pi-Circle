from __future__ import annotations

import time

from .enrollment import auto_enroll_android_devices
from .nmap_identify import (
    apply_nmap_identities,
    fingerprint_hosts,
    nmap_available,
    select_scan_targets,
)
from .network import _interface_ipv4_addresses
from .storage import Store


def run_nmap_identification(
    store: Store,
    present_ips: set[str],
    *,
    recently_scanned: dict[str, float],
    max_hosts: int = 8,
    min_interval_seconds: int = 900,
    force_ips: set[str] | None = None,
) -> dict[str, object]:
    """Fingerprint present hosts with nmap and apply identity updates."""
    if not nmap_available():
        return {"available": False, "scanned": [], "updated": 0}

    if force_ips:
        targets = sorted(ip for ip in force_ips if ip in present_ips)[:max_hosts]
    else:
        targets = select_scan_targets(
            store,
            present_ips,
            recently_scanned=recently_scanned,
            min_interval_seconds=min_interval_seconds,
            max_hosts=max_hosts,
        )
    if not targets:
        return {"available": True, "scanned": [], "updated": 0}

    identities = fingerprint_hosts(targets, max_hosts=max_hosts)
    now = time.time()
    for ip in targets:
        recently_scanned[ip] = now
    updated = apply_nmap_identities(store, identities)
    return {
        "available": True,
        "scanned": targets,
        "updated": updated,
        "identities": [
            {
                "ip": item.ip_address,
                "deviceType": item.device_type,
                "osGuess": item.os_guess,
                "vendor": item.vendor,
            }
            for item in identities
        ],
    }


def auto_link_androids(settings, store: Store, observed_ips: set[str]) -> list[str]:
    """Enroll present Android devices for ARP-assisted control."""
    if not settings.discovery.auto_link_android:
        return []
    local_ips = {str(ip) for ip in _interface_ipv4_addresses(settings.network.interface)}
    return auto_enroll_android_devices(
        store,
        observed_ips,
        gateway_ip=str(settings.network.gateway_ip),
        unmanaged_ips=settings.network.unmanaged_ips,
        local_ips=local_ips,
    )
