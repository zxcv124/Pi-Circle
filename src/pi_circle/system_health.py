from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import os
import socket
import subprocess
import time

from .config import Settings


SERVICES = {
    "dashboard": "pi-circle-dashboard",
    "agent": "pi-circle-agent",
    "piholeFtl": "pihole-FTL",
    "gravityTimer": "pi-circle-gravity-update.timer",
}


@dataclass(frozen=True)
class ServiceState:
    key: str
    unit: str
    active: bool
    state: str
    enabled: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def system_health(settings: Settings) -> dict[str, object]:
    services = [_service_state(key, unit).to_dict() for key, unit in SERVICES.items()]
    dns = _dns_resolution_test()
    internet = _internet_test()
    disk = _disk_usage(settings.paths.state_dir)
    return {
        "generatedAt": int(time.time()),
        "services": services,
        "checks": {
            "dnsResolution": dns,
            "internetReachability": internet,
            "gatewayIntegration": {
                "mode": settings.network.mode,
                "arpAssisted": settings.network.arp_assisted_enabled,
                "targetCount": len(settings.network.arp_assisted_targets),
            },
        },
        "resources": {
            "cpuLoad": _load_average(),
            "memory": _memory_usage(),
            "disk": disk,
            "temperatureC": _temperature_c(),
            "uptimeSeconds": _uptime_seconds(),
            "databaseBytes": _safe_size(settings.paths.database),
            "logBytes": _directory_size(settings.paths.log_dir, limit=200),
        },
        "versions": _versions(settings.paths.pihole_dir),
        "actions": {
            "restartDashboard": "unavailable: no restricted restart helper is installed",
            "restartAgent": "unavailable: no restricted restart helper is installed",
            "restartPihole": "use Pi-hole controls for DNS reload; full restart helper is not installed",
            "diagnostics": "available through this redacted health payload",
        },
    }


def capability_report(settings: Settings, setup: dict[str, object]) -> dict[str, object]:
    pihole_active = _service_state("piholeFtl", "pihole-FTL").active
    arp_active = settings.network.mode == "arp_assisted" and settings.network.arp_assisted_enabled
    return {
        "generatedAt": int(time.time()),
        "ready": bool(setup.get("ready")),
        "capabilities": [
            _capability("arpDiscovery", "ARP discovery", True, "Active", "Discovers local devices and associates IP/MAC observations."),
            _capability("piholeDnsFiltering", "Pi-hole DNS filtering", pihole_active, "Active" if pihole_active else "Unavailable", "DNS-level filtering through the bundled Pi-hole engine."),
            _capability("perDeviceDnsFiltering", "Per-device DNS filtering", arp_active, "Active" if arp_active else "DNS-only", "Linked devices can be steered through Pi-Circle DNS controls when ARP-assisted mode is active."),
            _capability("gatewayInternetBlocking", "Gateway internet blocking", arp_active, "ARP-assisted only" if arp_active else "Unavailable", "Full internet pause requires gateway/router/firewall control; Pi-Circle labels DNS-only controls separately."),
            _capability("bandwidthMonitoring", "Bandwidth monitoring", arp_active, "Active for linked devices" if arp_active else "Setup required", "Uses real conntrack/nftables counters when devices are linked."),
            _capability("serviceIdentification", "Service identification", True, "Domain-based estimate", "Maps DNS domains to services with confidence labels; no packet inspection."),
            _capability("httpsInspection", "HTTPS content inspection", False, "Not supported", "Pi-Circle cannot read encrypted page content, messages, passwords, or in-service actions."),
            _capability("communityProtection", "Community protection", False, "Disabled by default", "Local privacy architecture exists; no telemetry is sent without explicit opt-in."),
        ],
        "setupChecks": setup.get("checks", []),
        "tips": setup.get("tips", []),
    }


def _capability(key: str, label: str, enabled: bool, status: str, detail: str) -> dict[str, object]:
    return {"key": key, "label": label, "enabled": enabled, "status": status, "detail": detail}


def _service_state(key: str, unit: str) -> ServiceState:
    active = _run(["systemctl", "is-active", unit], timeout=2)
    enabled = _run(["systemctl", "is-enabled", unit], timeout=2)
    state = active.stdout.strip() if active.returncode == 0 else (active.stdout or active.stderr).strip() or "unknown"
    enabled_text = enabled.stdout.strip() if enabled.returncode == 0 else (enabled.stdout or enabled.stderr).strip() or "unknown"
    return ServiceState(key=key, unit=unit, active=state == "active", state=state, enabled=enabled_text)


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 124, "", str(exc))


def _dns_resolution_test() -> dict[str, object]:
    started = time.monotonic()
    try:
        socket.getaddrinfo("pi-hole.net", 443, type=socket.SOCK_STREAM)
        return {"ok": True, "latencyMs": round((time.monotonic() - started) * 1000, 1), "target": "pi-hole.net"}
    except OSError as exc:
        return {"ok": False, "latencyMs": round((time.monotonic() - started) * 1000, 1), "error": str(exc)}


def _internet_test() -> dict[str, object]:
    started = time.monotonic()
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=2.0)
        sock.close()
        return {"ok": True, "latencyMs": round((time.monotonic() - started) * 1000, 1), "target": "1.1.1.1:53"}
    except OSError as exc:
        return {"ok": False, "latencyMs": round((time.monotonic() - started) * 1000, 1), "error": str(exc)}


def _load_average() -> dict[str, object]:
    try:
        one, five, fifteen = os.getloadavg()
        return {"one": round(one, 2), "five": round(five, 2), "fifteen": round(fifteen, 2)}
    except OSError:
        return {"one": 0.0, "five": 0.0, "fifteen": 0.0}


def _memory_usage() -> dict[str, object]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        return {"totalBytes": 0, "availableBytes": 0, "usedPercent": 0.0}
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    used = max(0, total - available)
    return {
        "totalBytes": total,
        "availableBytes": available,
        "usedPercent": round((used / total) * 100, 1) if total else 0.0,
    }


def _disk_usage(path: Path) -> dict[str, object]:
    target = path if path.exists() else Path("/")
    usage = os.statvfs(target)
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    used = max(0, total - free)
    return {"path": str(target), "totalBytes": total, "freeBytes": free, "usedPercent": round((used / total) * 100, 1) if total else 0.0}


def _temperature_c() -> float | None:
    for path in (Path("/sys/class/thermal/thermal_zone0/temp"), Path("/sys/class/hwmon/hwmon0/temp1_input")):
        try:
            value = int(path.read_text(encoding="utf-8").strip())
            return round(value / 1000.0, 1)
        except (OSError, ValueError):
            continue
    return None


def _uptime_seconds() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def _safe_size(path: Path) -> int:
    try:
        return int(path.stat().st_size)
    except OSError:
        return 0


def _directory_size(path: Path, *, limit: int) -> int:
    total = 0
    try:
        for index, item in enumerate(path.iterdir()):
            if index >= limit:
                break
            if item.is_file():
                total += item.stat().st_size
    except OSError:
        return total
    return total


def _versions(pihole_dir: Path) -> dict[str, object]:
    versions_file = pihole_dir / "versions"
    values: dict[str, object] = {"piCircle": "0.1.0"}
    try:
        for line in versions_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    except OSError:
        pass
    return values
