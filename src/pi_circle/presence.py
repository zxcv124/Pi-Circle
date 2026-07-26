from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network, ip_address
from pathlib import Path
import subprocess
import time

from .discovery import ObservedDevice, read_pihole_network, read_proc_arp


PRESENT_NEIGH_STATES = frozenset({"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"})


def read_ip_neigh(lan_cidr: IPv4Network) -> list[ObservedDevice]:
    """Read live neighbor table — better state than /proc/net/arp alone."""
    try:
        proc = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    devices: list[ObservedDevice] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_text = parts[0]
        try:
            parsed = ip_address(ip_text)
        except ValueError:
            continue
        if parsed.version != 4 or parsed not in lan_cidr:
            continue
        state = parts[-1].upper() if parts else ""
        if state not in PRESENT_NEIGH_STATES:
            continue
        mac = None
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1].lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        devices.append(ObservedDevice(ip_text, mac, None, "high" if state == "REACHABLE" else "medium"))
    return devices


def recent_dns_clients(ftl_db: Path, lan_cidr: IPv4Network, *, window_seconds: int = 1800) -> set[str]:
    if not ftl_db.exists():
        return set()
    import sqlite3

    start = time.time() - max(60, window_seconds)
    conn = sqlite3.connect(f"file:{ftl_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            """
            SELECT DISTINCT client
            FROM queries
            WHERE timestamp >= ?
            """,
            (start,),
        ).fetchall()
    except sqlite3.Error:
        return set()
    finally:
        conn.close()

    clients: set[str] = set()
    for (client,) in rows:
        try:
            parsed = ip_address(str(client))
        except ValueError:
            continue
        if parsed.version == 4 and parsed in lan_cidr and not parsed.is_loopback:
            clients.add(str(parsed))
    return clients


def probe_hosts(ips: set[str] | list[str], *, timeout_ms: int = 400, workers: int = 64) -> int:
    """ICMP ping candidates so the kernel ARP/neighbor table fills in quickly."""
    targets = sorted({str(ip) for ip in ips if _is_ipv4(ip)})
    if not targets:
        return 0
    timeout_ms = max(100, min(int(timeout_ms), 2000))
    workers = max(4, min(int(workers), 128))
    reached = 0

    def _ping(ip: str) -> bool:
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000) or 1), "-n", ip],
                check=False,
                capture_output=True,
                text=True,
                timeout=max(1.5, timeout_ms / 1000 + 0.5),
            )
            return completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    # Linux ping -W is seconds (integer) on many builds; also try millisecond form via deadline.
    def _ping_linux(ip: str) -> bool:
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", "1", "-n", ip],
                check=False,
                capture_output=True,
                text=True,
                timeout=1.8,
            )
            return completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_ping_linux, ip) for ip in targets]
        for future in as_completed(futures):
            if future.result():
                reached += 1
    return reached


def lan_host_ips(lan_cidr: IPv4Network, *, limit: int = 254) -> list[str]:
    hosts = []
    for host in lan_cidr.hosts():
        hosts.append(str(host))
        if len(hosts) >= limit:
            break
    return hosts


def collect_presence(
    lan_cidr: IPv4Network,
    ftl_db: Path,
    *,
    known_ips: set[str] | None = None,
    probe: bool = True,
    full_scan: bool = False,
    arp_path: Path = Path("/proc/net/arp"),
) -> list[ObservedDevice]:
    """Probe + merge neighbor/ARP/Pi-hole enrichment into currently present devices."""
    candidates: set[str] = set(known_ips or set())
    candidates.update(recent_dns_clients(ftl_db, lan_cidr))
    gateway_guess = str(lan_cidr.network_address + 1)
    if ip_address(gateway_guess) in lan_cidr:
        candidates.add(gateway_guess)

    if full_scan and lan_cidr.prefixlen >= 24:
        candidates.update(lan_host_ips(lan_cidr))
    elif probe:
        # Light probe: known + recent DNS clients only (fast).
        pass

    if probe and candidates:
        probe_hosts(candidates)

    by_ip: dict[str, ObservedDevice] = {}
    for source in (read_ip_neigh(lan_cidr), read_proc_arp(lan_cidr, arp_path=arp_path)):
        for device in source:
            previous = by_ip.get(device.ip_address)
            if previous is None or (not previous.mac_address and device.mac_address):
                by_ip[device.ip_address] = device
            elif previous.confidence != "high" and device.confidence == "high":
                by_ip[device.ip_address] = device

    enrichment = {device.ip_address: device for device in read_pihole_network(ftl_db, lan_cidr)}
    merged: list[ObservedDevice] = []
    for ip, device in sorted(by_ip.items(), key=lambda item: tuple(int(part) for part in item[0].split("."))):
        extra = enrichment.get(ip)
        mac = device.mac_address or (extra.mac_address if extra else None)
        hostname = extra.hostname if extra and extra.hostname else device.hostname
        confidence = "high" if mac and hostname else device.confidence
        merged.append(ObservedDevice(ip, mac, hostname, confidence))
    return merged


def _is_ipv4(value: str) -> bool:
    try:
        return ip_address(value).version == 4
    except ValueError:
        return False
