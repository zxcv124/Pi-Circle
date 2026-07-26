from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
import sqlite3
import time
import urllib.error
import urllib.request

from .pihole import BLOCKED_STATUSES
from .privacy_shield import scan_recent_privacy_hits
from .storage import Store


LATE_NIGHT_START = 23  # 23:00 local
LATE_NIGHT_END = 5  # 05:00 local


@dataclass(frozen=True)
class AlertDraft:
    alert_type: str
    severity: str
    title: str
    detail: str
    subject: str | None = None


def evaluate_alerts(
    store: Store,
    *,
    ftl_db: Path,
    present_ips: set[str],
    known_ips_before: set[str],
    now: datetime | None = None,
) -> list[AlertDraft]:
    current = now or datetime.now().astimezone()
    drafts: list[AlertDraft] = []

    # New devices that just appeared on the LAN.
    for ip in sorted(present_ips - known_ips_before):
        device = store.get_device(ip)
        label = (device.display_name if device else None) or ip
        drafts.append(
            AlertDraft(
                "new_device",
                "warn",
                f"New device online: {label}",
                f"{ip} joined the network.",
                subject=ip,
            )
        )

    drafts.extend(_dns_alerts(ftl_db, store, current))
    drafts.extend(_privacy_alerts(ftl_db, store))
    return drafts


def _privacy_alerts(ftl_db: Path, store: Store) -> list[AlertDraft]:
    drafts: list[AlertDraft] = []
    for hit in scan_recent_privacy_hits(ftl_db, window_seconds=900)[:12]:
        kind = str(hit["kind"])
        ip = str(hit["client"])
        domain = str(hit["domain"])
        device = store.get_device(ip)
        label = (device.display_name if device else None) or ip
        alert_type = "doh_bypass" if kind == "doh_bypass" else "telemetry"
        # One alert per device+class every 2h (subject stays an IP so Open works).
        if _recently_alerted(store, alert_type, ip, minutes=120):
            continue
        title = (
            f"DNS bypass attempt: {label}"
            if kind == "doh_bypass"
            else f"Telemetry contact: {label}"
        )
        drafts.append(
            AlertDraft(
                alert_type,
                "warn" if kind == "doh_bypass" else "info",
                title,
                f"{domain} ({hit['hits']} lookups). Privacy shield denylists this destination.",
                subject=ip,
            )
        )
    return drafts


def _dns_alerts(ftl_db: Path, store: Store, now: datetime) -> list[AlertDraft]:
    if not ftl_db.exists():
        return []
    drafts: list[AlertDraft] = []
    blocked = ", ".join(str(code) for code in sorted(BLOCKED_STATUSES))
    window_start = time.time() - 300
    conn = sqlite3.connect(f"file:{ftl_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            f"""
            SELECT client,
                   COUNT(*) AS queries,
                   SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked
            FROM queries
            WHERE timestamp >= ?
            GROUP BY client
            """,
            (window_start,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    hour = now.hour
    late = hour >= LATE_NIGHT_START or hour < LATE_NIGHT_END
    for client, queries, blocked_count in rows:
        ip = str(client)
        device = store.get_device(ip)
        label = (device.display_name if device else None) or ip
        q = int(queries or 0)
        b = int(blocked_count or 0)
        if late and q >= 20 and not _recently_alerted(store, "late_night", ip, minutes=90):
            drafts.append(
                AlertDraft(
                    "late_night",
                    "warn",
                    f"Late-night activity: {label}",
                    f"{q} DNS lookups in the last 5 minutes.",
                    subject=ip,
                )
            )
        if q >= 120 and not _recently_alerted(store, "spike", ip, minutes=30):
            drafts.append(
                AlertDraft(
                    "spike",
                    "info",
                    f"Traffic spike: {label}",
                    f"{q} DNS lookups in 5 minutes.",
                    subject=ip,
                )
            )
        if b >= 25 and not _recently_alerted(store, "blocked_burst", ip, minutes=30):
            drafts.append(
                AlertDraft(
                    "blocked_burst",
                    "info",
                    f"Blocked burst: {label}",
                    f"{b} blocked queries in 5 minutes.",
                    subject=ip,
                )
            )
    return drafts


def _recently_alerted(store: Store, alert_type: str, subject: str, *, minutes: int) -> bool:
    return store.has_recent_alert(alert_type, subject, within_seconds=minutes * 60)


def deliver_webhook(url: str, alert: dict[str, object]) -> None:
    if not url:
        return
    body = {
        "text": f"[{alert.get('severity')}] {alert.get('title')} — {alert.get('detail')}",
        "alert": alert,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            response.read()
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return
