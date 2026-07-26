from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import time
import unittest

from pi_circle.analytics import QueryAnalytics


class AnalyticsTests(unittest.TestCase):
    def test_traffic_series_and_overview(self) -> None:
        with TemporaryDirectory() as tmp:
            ftl_db = Path(tmp) / "pihole-FTL.db"
            now = int(time.time())
            conn = sqlite3.connect(ftl_db)
            try:
                conn.execute(
                    """
                    CREATE TABLE queries (
                      id INTEGER PRIMARY KEY,
                      timestamp INTEGER,
                      type INTEGER,
                      status INTEGER,
                      domain TEXT,
                      client TEXT
                    )
                    """
                )
                # Fractional timestamps mirror Pi-hole FTL's queries view.
                rows = [
                    (1, now - 30 + 0.743, 1, 2, "www.youtube.com", "192.168.1.10"),
                    (2, now - 25 + 0.12, 1, 1, "ads.example.com", "192.168.1.10"),
                    (3, now - 20 + 0.5, 1, 2, "www.google.com", "192.168.1.20"),
                    (4, now - 15 + 0.01, 28, 2, "chatgpt.com", "192.168.1.20"),
                ]
                conn.executemany(
                    "INSERT INTO queries(id, timestamp, type, status, domain, client) VALUES (?, ?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
            finally:
                conn.close()

            analytics = QueryAnalytics(ftl_db)
            series = analytics.traffic_series(window_seconds=120, bucket_seconds=10)
            self.assertGreater(sum(bucket.queries for bucket in series), 0)
            self.assertEqual(sum(bucket.queries for bucket in series), 4)
            overview = analytics.overview(window_seconds=120, top_limit=5)
            self.assertEqual(overview["totals"]["queries"], 4)
            self.assertEqual(overview["totals"]["blocked"], 1)
            self.assertGreaterEqual(overview["totals"]["activeDevices"], 2)
            self.assertTrue(any(item["name"] == "YouTube" for item in overview["topServices"]))
