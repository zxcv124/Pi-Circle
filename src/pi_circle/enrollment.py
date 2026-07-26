from __future__ import annotations

from collections.abc import Callable, Iterable
from ipaddress import IPv4Address, ip_address
from pathlib import Path
import subprocess

from .storage import Store


ARP_TARGET_HELPER = Path("/usr/local/sbin/pi-circle-set-arp-assisted-targets")
DEFAULT_ONLINE_AGE_SECONDS = 1800


def auto_enroll_android_devices(
    store: Store,
    observed_ips: set[str],
    *,
    gateway_ip: str,
    unmanaged_ips: Iterable[str | IPv4Address] = (),
    local_ips: Iterable[str | IPv4Address] = (),
) -> list[str]:
    """Enroll every present Android so ARP-assisted control auto-connects it."""
    blocked = {str(gateway_ip)}
    blocked.update(str(ip) for ip in unmanaged_ips)
    blocked.update(str(ip) for ip in local_ips)
    enrolled: list[str] = []
    for device in store.list_devices():
        if device.device_type != "android":
            continue
        if device.ip_address not in observed_ips:
            continue
        if device.ip_address in blocked:
            continue
        if device.transparent_control or device.managed:
            continue
        try:
            ip_address(device.ip_address)
        except ValueError:
            continue
        store.set_device_enrollment(device.ip_address, True)
        enrolled.append(device.ip_address)
    return enrolled


def bootstrap_enrollment_from_targets(store: Store, targets: Iterable[str]) -> None:
    """Mark currently configured ARP targets as persistently enrolled."""
    for target in targets:
        try:
            store.set_device_enrollment(str(target), True)
        except LookupError:
            continue


def resolve_active_enrolled_targets(
    store: Store,
    observed_ips: set[str] | None = None,
    max_age_seconds: int = DEFAULT_ONLINE_AGE_SECONDS,
) -> list[str]:
    """Return live IPv4 targets for enrolled devices that are currently present."""
    return store.list_active_enrolled_ips(observed_ips=observed_ips, max_age_seconds=max_age_seconds)


def targets_differ(current: Iterable[str], desired: Iterable[str]) -> bool:
    return {str(value) for value in current} != {str(value) for value in desired}


def apply_arp_targets(targets: list[str], *, restart_agent: bool = False, helper: Path = ARP_TARGET_HELPER) -> None:
    if not helper.exists():
        raise FileNotFoundError(f"Missing helper: {helper}")
    command = [str(helper)]
    if not restart_agent:
        command.append("--no-restart")
    command.extend(targets)
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Failed to apply ARP-assisted targets"
        raise RuntimeError(detail)


def reconcile_enrolled_targets(
    store: Store,
    current_targets: Iterable[str],
    observed_ips: set[str] | None = None,
    *,
    apply_fn: Callable[[list[str]], None] | None = None,
    max_age_seconds: int = DEFAULT_ONLINE_AGE_SECONDS,
) -> list[str] | None:
    """Sync config targets to enrolled devices that are online.

    Returns the desired target list when a change was applied, otherwise None.
    """
    # Only trust explicit Link enrollment in SQLite. Do not invent enrollment from
    # transient config targets (that fought emergency dns_only rollbacks).
    desired = resolve_active_enrolled_targets(store, observed_ips=observed_ips, max_age_seconds=max_age_seconds)
    current = [str(value) for value in current_targets]
    if not targets_differ(current, desired):
        return None
    # Enrolled devices must auto-reconnect when they reappear, including promoting
    # dns_only -> arp_assisted. Unlink/Rollback clear enrollment and stop this.
    writer = apply_fn or (lambda values: apply_arp_targets(values, restart_agent=False))
    writer(desired)
    return desired
