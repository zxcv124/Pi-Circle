from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import time

from .pihole import BLOCKED_STATUSES, QUERY_TYPE_NAMES, infer_service


@dataclass(frozen=True)
class TrafficBucket:
    timestamp: int
    queries: int
    blocked: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class QueryAnalytics:
    """Sniffnet-style overview stats from Pi-hole DNS (no packet capture)."""

    def __init__(self, ftl_db: Path) -> None:
        self.ftl_db = ftl_db

    def traffic_series(
        self,
        *,
        window_seconds: int = 600,
        bucket_seconds: int = 10,
        client_ip: str | None = None,
    ) -> list[TrafficBucket]:
        if not self.ftl_db.exists():
            return []
        window_seconds = max(60, min(int(window_seconds), 86400))
        bucket_seconds = max(5, min(int(bucket_seconds), 3600))
        now = int(time.time())
        start = now - window_seconds
        blocked = ", ".join(str(code) for code in sorted(BLOCKED_STATUSES))
        # Pi-hole FTL may expose fractional timestamps; bucket on whole seconds.
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True)
        try:
            if client_ip:
                rows = conn.execute(
                    f"""
                    SELECT (CAST(timestamp AS INTEGER) / ?) * ? AS bucket,
                           COUNT(*) AS queries,
                           SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked
                    FROM queries
                    WHERE timestamp >= ? AND client = ?
                    GROUP BY bucket
                    ORDER BY bucket
                    """,
                    (bucket_seconds, bucket_seconds, start, client_ip),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT (CAST(timestamp AS INTEGER) / ?) * ? AS bucket,
                           COUNT(*) AS queries,
                           SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked
                    FROM queries
                    WHERE timestamp >= ?
                    GROUP BY bucket
                    ORDER BY bucket
                    """,
                    (bucket_seconds, bucket_seconds, start),
                ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()

        by_bucket = {
            int(row[0]): TrafficBucket(int(row[0]), int(row[1] or 0), int(row[2] or 0)) for row in rows if row[0] is not None
        }
        series: list[TrafficBucket] = []
        first = (start // bucket_seconds) * bucket_seconds
        last = (now // bucket_seconds) * bucket_seconds
        cursor = first
        while cursor <= last:
            series.append(by_bucket.get(cursor, TrafficBucket(cursor, 0, 0)))
            cursor += bucket_seconds
        return series

    def overview(
        self,
        *,
        window_seconds: int = 3600,
        client_ip: str | None = None,
        top_limit: int = 8,
    ) -> dict[str, object]:
        if not self.ftl_db.exists():
            return _empty_overview(window_seconds)
        window_seconds = max(60, min(int(window_seconds), 86400))
        top_limit = max(1, min(int(top_limit), 20))
        now = int(time.time())
        start = now - window_seconds
        blocked = ", ".join(str(code) for code in sorted(BLOCKED_STATUSES))
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            totals = self._totals(conn, start, blocked, client_ip)
            top_clients = self._top_clients(conn, start, top_limit) if client_ip is None else []
            top_domains = self._top_domains(conn, start, top_limit, client_ip)
            query_types = self._query_types(conn, start, client_ip)
            sample = self._sample_rows(conn, start, client_ip, limit=4000)
        except sqlite3.Error:
            return _empty_overview(window_seconds)
        finally:
            conn.close()

        services: dict[str, int] = {}
        categories: dict[str, int] = {}
        for domain, count in sample:
            service, category = infer_service(domain)
            services[service] = services.get(service, 0) + count
            categories[category] = categories.get(category, 0) + count

        return {
            "windowSeconds": window_seconds,
            "generatedAt": now,
            "totals": totals,
            "topClients": top_clients,
            "topDomains": top_domains,
            "topServices": _rank(services, top_limit),
            "categories": _rank(categories, top_limit),
            "queryTypes": query_types,
        }

    def _totals(self, conn: sqlite3.Connection, start: int, blocked: str, client_ip: str | None) -> dict[str, object]:
        if client_ip:
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS queries,
                       SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked,
                       COUNT(DISTINCT domain) AS domains
                FROM queries
                WHERE timestamp >= ? AND client = ?
                """,
                (start, client_ip),
            ).fetchone()
            active_devices = 1 if row and int(row["queries"] or 0) else 0
        else:
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS queries,
                       SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked,
                       COUNT(DISTINCT domain) AS domains,
                       COUNT(DISTINCT client) AS devices
                FROM queries
                WHERE timestamp >= ?
                """,
                (start,),
            ).fetchone()
            active_devices = int(row["devices"] or 0) if row else 0
        queries = int(row["queries"] or 0) if row else 0
        blocked_count = int(row["blocked"] or 0) if row else 0
        return {
            "queries": queries,
            "blocked": blocked_count,
            "allowed": max(0, queries - blocked_count),
            "domains": int(row["domains"] or 0) if row else 0,
            "activeDevices": active_devices,
            "blockedPercent": round((blocked_count / queries) * 100, 1) if queries else 0.0,
        }

    def _top_clients(self, conn: sqlite3.Connection, start: int, limit: int) -> list[dict[str, object]]:
        rows = conn.execute(
            """
            SELECT client AS ip, COUNT(*) AS count
            FROM queries
            WHERE timestamp >= ?
            GROUP BY client
            ORDER BY count DESC
            LIMIT ?
            """,
            (start, limit),
        ).fetchall()
        return [{"ip": str(row["ip"]), "count": int(row["count"])} for row in rows]

    def _top_domains(
        self, conn: sqlite3.Connection, start: int, limit: int, client_ip: str | None
    ) -> list[dict[str, object]]:
        if client_ip:
            rows = conn.execute(
                """
                SELECT domain, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ? AND client = ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT ?
                """,
                (start, client_ip, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT domain, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT ?
                """,
                (start, limit),
            ).fetchall()
        return [{"domain": str(row["domain"]), "count": int(row["count"])} for row in rows]

    def _query_types(self, conn: sqlite3.Connection, start: int, client_ip: str | None) -> list[dict[str, object]]:
        if client_ip:
            rows = conn.execute(
                """
                SELECT type, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ? AND client = ?
                GROUP BY type
                ORDER BY count DESC
                LIMIT 8
                """,
                (start, client_ip),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT type, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ?
                GROUP BY type
                ORDER BY count DESC
                LIMIT 8
                """,
                (start,),
            ).fetchall()
        return [
            {
                "type": QUERY_TYPE_NAMES.get(int(row["type"] or 0), f"TYPE{row['type']}"),
                "count": int(row["count"]),
            }
            for row in rows
        ]

    def _sample_rows(
        self, conn: sqlite3.Connection, start: int, client_ip: str | None, *, limit: int
    ) -> list[tuple[str, int]]:
        if client_ip:
            rows = conn.execute(
                """
                SELECT domain, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ? AND client = ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT ?
                """,
                (start, client_ip, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT domain, COUNT(*) AS count
                FROM queries
                WHERE timestamp >= ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT ?
                """,
                (start, limit),
            ).fetchall()
        return [(str(row["domain"] or ""), int(row["count"])) for row in rows]


def _rank(counts: dict[str, int], limit: int) -> list[dict[str, object]]:
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"name": name, "count": count} for name, count in ranked]


def _empty_overview(window_seconds: int) -> dict[str, object]:
    return {
        "windowSeconds": window_seconds,
        "generatedAt": int(time.time()),
        "totals": {
            "queries": 0,
            "blocked": 0,
            "allowed": 0,
            "domains": 0,
            "activeDevices": 0,
            "blockedPercent": 0.0,
        },
        "topClients": [],
        "topDomains": [],
        "topServices": [],
        "categories": [],
        "queryTypes": [],
    }
