from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import csv
import io
import sqlite3
import time

from .pihole import BLOCKED_STATUSES, infer_service
from .storage import Store


PERIODS = {
    "daily": 24 * 60 * 60,
    "weekly": 7 * 24 * 60 * 60,
    "monthly": 30 * 24 * 60 * 60,
}
PRIVACY_LEVELS = {"summary", "family", "technical"}


@dataclass(frozen=True)
class ReportRequest:
    period: str = "daily"
    privacy_level: str = "family"

    @property
    def window_seconds(self) -> int:
        return PERIODS.get(self.period, PERIODS["daily"])


class ReportBuilder:
    def __init__(self, ftl_db: Path, store: Store) -> None:
        self.ftl_db = ftl_db
        self.store = store

    def build(self, request: ReportRequest) -> dict[str, object]:
        period = request.period if request.period in PERIODS else "daily"
        privacy_level = request.privacy_level if request.privacy_level in PRIVACY_LEVELS else "family"
        now = int(time.time())
        start = now - PERIODS[period]
        dns = self._dns_summary(start)
        alerts = _alerts_since(self.store, start)
        report: dict[str, object] = {
            "period": period,
            "privacyLevel": privacy_level,
            "generatedAt": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "windowSeconds": PERIODS[period],
            "privacyNotice": _privacy_notice(privacy_level),
            "sections": {
                "dns": dns["totals"],
                "services": dns["services"] if privacy_level in {"family", "technical"} else [],
                "categories": dns["categories"] if privacy_level in {"family", "technical"} else [],
                "devices": dns["devices"] if privacy_level == "technical" else [],
                "domains": dns["domains"] if privacy_level == "technical" else [],
                "alerts": alerts,
                "system": {
                    "source": "Pi-hole DNS query log and Pi-Circle local state",
                    "bandwidth": "Included only where real linked-device counters exist elsewhere in Pi-Circle.",
                },
            },
        }
        return report

    def csv(self, request: ReportRequest) -> str:
        report = self.build(request)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["section", "name", "value", "detail"])
        dns = report["sections"]["dns"]
        if isinstance(dns, dict):
            for key, value in dns.items():
                writer.writerow(["dns", key, value, ""])
        for section in ("services", "categories", "devices", "domains", "alerts"):
            rows = report["sections"].get(section)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = row.get("name") or row.get("domain") or row.get("ip") or row.get("title") or row.get("alert_type")
                value = row.get("count") or row.get("queries") or row.get("severity") or ""
                writer.writerow([section, name, value, _compact_detail(row)])
        return output.getvalue()

    def _dns_summary(self, start: int) -> dict[str, object]:
        if not self.ftl_db.exists():
            return _empty_dns_summary()
        blocked = ", ".join(str(code) for code in sorted(BLOCKED_STATUSES))
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        try:
            totals_row = conn.execute(
                f"""
                SELECT COUNT(*) AS queries,
                       SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked,
                       COUNT(DISTINCT client) AS devices,
                       COUNT(DISTINCT domain) AS domains
                FROM queries
                WHERE timestamp >= ?
                """,
                (start,),
            ).fetchone()
            device_rows = conn.execute(
                """
                SELECT client AS ip, COUNT(*) AS queries
                FROM queries
                WHERE timestamp >= ?
                GROUP BY client
                ORDER BY queries DESC
                LIMIT 12
                """,
                (start,),
            ).fetchall()
            domain_rows = conn.execute(
                """
                SELECT domain, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ? AND domain IS NOT NULL AND TRIM(domain) != ''
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 20
                """,
                (start,),
            ).fetchall()
        except sqlite3.Error:
            return _empty_dns_summary()
        finally:
            conn.close()

        queries = int(totals_row["queries"] or 0) if totals_row else 0
        blocked_count = int(totals_row["blocked"] or 0) if totals_row else 0
        services: dict[str, int] = {}
        categories: dict[str, int] = {}
        domains = []
        for row in domain_rows:
            domain = str(row["domain"] or "").strip().lower().rstrip(".")
            count = int(row["count"] or 0)
            if not domain:
                continue
            service, category = infer_service(domain)
            services[service] = services.get(service, 0) + count
            categories[category] = categories.get(category, 0) + count
            domains.append({"domain": domain, "count": count, "service": service, "category": category})
        return {
            "totals": {
                "queries": queries,
                "blocked": blocked_count,
                "allowed": max(0, queries - blocked_count),
                "blockedPercent": round((blocked_count / queries) * 100, 1) if queries else 0.0,
                "activeDevices": int(totals_row["devices"] or 0) if totals_row else 0,
                "domains": int(totals_row["domains"] or 0) if totals_row else 0,
            },
            "devices": [{"ip": str(row["ip"]), "queries": int(row["queries"] or 0)} for row in device_rows],
            "domains": domains,
            "services": _rank(services, 12),
            "categories": _rank(categories, 12),
        }


def _alerts_since(store: Store, start_epoch: int) -> list[dict[str, object]]:
    rows = store.list_alerts(include_acked=True, limit=200)
    filtered = []
    for row in rows:
        try:
            created = datetime.fromisoformat(str(row["created_at"]))
        except ValueError:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created.timestamp() < start_epoch:
            continue
        filtered.append(
            {
                "title": row["title"],
                "severity": row["severity"],
                "alert_type": row["alert_type"],
                "created_at": row["created_at"],
                "acked": bool(row["acked"]),
            }
        )
    return filtered[:50]


def _rank(counts: dict[str, int], limit: int) -> list[dict[str, object]]:
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def _empty_dns_summary() -> dict[str, object]:
    return {
        "totals": {
            "queries": 0,
            "blocked": 0,
            "allowed": 0,
            "blockedPercent": 0.0,
            "activeDevices": 0,
            "domains": 0,
        },
        "devices": [],
        "domains": [],
        "services": [],
        "categories": [],
    }


def _privacy_notice(level: str) -> str:
    if level == "summary":
        return "Summary export excludes raw devices and domains."
    if level == "family":
        return "Family export includes services and categories, but excludes raw domain lists."
    return "Technical export includes device IPs and raw domains. Review before sharing."


def _compact_detail(row: dict[str, object]) -> str:
    ignored = {"name", "domain", "ip", "title", "alert_type", "count", "queries", "severity"}
    return "; ".join(f"{key}={value}" for key, value in row.items() if key not in ignored and value not in (None, ""))
