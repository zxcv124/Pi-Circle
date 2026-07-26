from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import sqlite3
import time

from .pihole import BLOCKED_STATUSES, infer_service


@dataclass(frozen=True)
class HistoryBucket:
    timestamp: int
    queries: int
    blocked: int
    devices: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class HistoryReader:
    """Rolling 24h / 7d DNS timelines for GlassWire-style history."""

    def __init__(self, ftl_db: Path) -> None:
        self.ftl_db = ftl_db

    def timeline(
        self,
        *,
        window: str = "24h",
        client_ip: str | None = None,
    ) -> dict[str, object]:
        if window == "7d":
            window_seconds = 7 * 86400
            bucket_seconds = 3600
        elif window == "1h":
            window_seconds = 3600
            bucket_seconds = 60
        else:
            window = "24h"
            window_seconds = 86400
            bucket_seconds = 900

        series = self._series(window_seconds=window_seconds, bucket_seconds=bucket_seconds, client_ip=client_ip)
        totals = {
            "queries": sum(item.queries for item in series),
            "blocked": sum(item.blocked for item in series),
            "devices": max((item.devices for item in series), default=0),
        }
        top = self._top_services(window_seconds=window_seconds, client_ip=client_ip, limit=8)
        return {
            "window": window,
            "windowSeconds": window_seconds,
            "bucketSeconds": bucket_seconds,
            "generatedAt": int(time.time()),
            "totals": totals,
            "series": [item.to_dict() for item in series],
            "topServices": top,
        }

    def _series(
        self,
        *,
        window_seconds: int,
        bucket_seconds: int,
        client_ip: str | None,
    ) -> list[HistoryBucket]:
        if not self.ftl_db.exists():
            return []
        now = int(time.time())
        start = now - window_seconds
        blocked = ", ".join(str(code) for code in sorted(BLOCKED_STATUSES))
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True)
        try:
            if client_ip:
                rows = conn.execute(
                    f"""
                    SELECT (CAST(timestamp AS INTEGER) / ?) * ? AS bucket,
                           COUNT(*) AS queries,
                           SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked,
                           1 AS devices
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
                           SUM(CASE WHEN status IN ({blocked}) THEN 1 ELSE 0 END) AS blocked,
                           COUNT(DISTINCT client) AS devices
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
            int(row[0]): HistoryBucket(int(row[0]), int(row[1] or 0), int(row[2] or 0), int(row[3] or 0))
            for row in rows
            if row[0] is not None
        }
        series: list[HistoryBucket] = []
        cursor = (start // bucket_seconds) * bucket_seconds
        last = (now // bucket_seconds) * bucket_seconds
        while cursor <= last:
            series.append(by_bucket.get(cursor, HistoryBucket(cursor, 0, 0, 0)))
            cursor += bucket_seconds
        return series

    def _top_services(self, *, window_seconds: int, client_ip: str | None, limit: int) -> list[dict[str, object]]:
        if not self.ftl_db.exists():
            return []
        start = time.time() - window_seconds
        conn = sqlite3.connect(f"file:{self.ftl_db}?mode=ro", uri=True)
        try:
            if client_ip:
                rows = conn.execute(
                    """
                    SELECT domain, COUNT(*) AS count
                    FROM queries
                    WHERE timestamp >= ? AND client = ?
                    GROUP BY domain
                    ORDER BY count DESC
                    LIMIT 80
                    """,
                    (start, client_ip),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT domain, COUNT(*) AS count
                    FROM queries
                    WHERE timestamp >= ?
                    GROUP BY domain
                    ORDER BY count DESC
                    LIMIT 80
                    """,
                    (start,),
                ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()
        counts: dict[str, int] = {}
        for domain, count in rows:
            service, _category = infer_service(str(domain or ""))
            counts[service] = counts.get(service, 0) + int(count)
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
        return [{"name": name, "count": count} for name, count in ranked]
