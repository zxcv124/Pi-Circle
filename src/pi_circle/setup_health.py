from __future__ import annotations

from pathlib import Path
import socket
import time

from .config import Settings
from .storage import Store


def evaluate_setup(settings: Settings, store: Store, *, present_count: int = 0) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    ftl_ok = settings.pihole.ftl_db.exists()
    checks.append(
        {
            "id": "pihole_ftl",
            "label": "Pi-hole query database",
            "ok": ftl_ok,
            "detail": str(settings.pihole.ftl_db) if ftl_ok else "pihole-FTL.db not readable",
        }
    )

    gravity_ok = settings.pihole.gravity_db.exists()
    checks.append(
        {
            "id": "pihole_gravity",
            "label": "Pi-hole gravity database",
            "ok": gravity_ok,
            "detail": "Blocking lists available" if gravity_ok else "gravity.db missing",
        }
    )

    gateway_ok = _ping_host(str(settings.network.gateway_ip))
    checks.append(
        {
            "id": "gateway",
            "label": "Gateway reachable",
            "ok": gateway_ok,
            "detail": str(settings.network.gateway_ip),
        }
    )

    health = store.get_network_health()
    mode = str(health.get("mode") or settings.network.mode)
    mode_ok = bool(health.get("healthy", False))
    checks.append(
        {
            "id": "control_plane",
            "label": "Control plane healthy",
            "ok": mode_ok,
            "detail": f"{mode}: {health.get('summary') or 'unknown'}",
        }
    )

    linked = len(settings.network.arp_assisted_targets)
    checks.append(
        {
            "id": "linked_devices",
            "label": "Linked devices",
            "ok": True,
            "detail": f"{linked} linked · {present_count} online",
            "level": "info",
        }
    )

    dns_recent = _recent_query_count(settings.pihole.ftl_db, window_seconds=600)
    checks.append(
        {
            "id": "dns_flow",
            "label": "DNS flowing through Pi-hole",
            "ok": dns_recent > 0,
            "detail": f"{dns_recent} queries in last 10 minutes" if dns_recent else "No recent DNS — check Private DNS / DHCP",
        }
    )

    ready = all(bool(check["ok"]) for check in checks if check["id"] != "linked_devices")
    return {
        "ready": ready,
        "generatedAt": int(time.time()),
        "mode": mode,
        "checks": checks,
        "tips": _tips(checks, linked=linked),
    }


def _tips(checks: list[dict[str, object]], *, linked: int) -> list[str]:
    tips: list[str] = []
    by_id = {str(check["id"]): check for check in checks}
    if not by_id.get("dns_flow", {}).get("ok"):
        tips.append("Point router DHCP DNS to this Pi, or Link devices so Pi-Circle can redirect DNS.")
    if linked == 0:
        tips.append("Link a kid/parent device to enable Pause, bedtime, and bandwidth.")
    if not by_id.get("gateway", {}).get("ok"):
        tips.append("Gateway ping failed — confirm Wi‑Fi uplink on the Pi.")
    if not tips:
        tips.append("Household monitor looks healthy. Open Devices to manage the family.")
    return tips


def _ping_host(host: str) -> bool:
    import subprocess

    try:
        sock = socket.create_connection((host, 53), timeout=1.2)
        sock.close()
        return True
    except OSError:
        pass
    try:
        completed = subprocess.run(
            ["ping", "-c", "1", "-W", "1", "-n", host],
            check=False,
            capture_output=True,
            timeout=2,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _recent_query_count(ftl_db: Path, *, window_seconds: int) -> int:
    if not ftl_db.exists():
        return 0
    import sqlite3

    start = time.time() - window_seconds
    conn = sqlite3.connect(f"file:{ftl_db}?mode=ro", uri=True)
    try:
        row = conn.execute("SELECT COUNT(*) FROM queries WHERE timestamp >= ?", (start,)).fetchone()
        return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        conn.close()
