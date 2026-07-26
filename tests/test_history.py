from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import time
import unittest

from pi_circle.history import HistoryReader
from pi_circle.storage import Store


class HistoryAndAlertTests(unittest.TestCase):
    def test_history_timeline_24h(self) -> None:
        with TemporaryDirectory() as tmp:
            ftl_db = Path(tmp) / "pihole-FTL.db"
            now = int(time.time())
            conn = sqlite3.connect(ftl_db)
            try:
                conn.execute(
                    """
                    CREATE TABLE queries (
                      id INTEGER PRIMARY KEY,
                      timestamp REAL,
                      type INTEGER,
                      status INTEGER,
                      domain TEXT,
                      client TEXT
                    )
                    """
                )
                conn.executemany(
                    "INSERT INTO queries(id, timestamp, type, status, domain, client) VALUES (?, ?, 1, ?, ?, ?)",
                    [
                        (1, now - 100, 2, "www.youtube.com", "192.168.1.10"),
                        (2, now - 90, 1, "ads.example.com", "192.168.1.10"),
                        (3, now - 80, 2, "www.google.com", "192.168.1.20"),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            timeline = HistoryReader(ftl_db).timeline(window="24h")
            self.assertEqual(timeline["window"], "24h")
            self.assertEqual(timeline["totals"]["queries"], 3)
            self.assertEqual(timeline["totals"]["blocked"], 1)
            self.assertGreater(sum(item["queries"] for item in timeline["series"]), 0)

    def test_alerts_persist_and_dedupe_window(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            first = store.add_alert(
                alert_type="spike",
                severity="info",
                title="Traffic spike: phone",
                detail="120 lookups",
                subject="192.168.1.10",
            )
            self.assertTrue(store.has_recent_alert("spike", "192.168.1.10", within_seconds=1800))
            self.assertFalse(store.has_recent_alert("late_night", "192.168.1.10", within_seconds=1800))
            self.assertEqual(len(store.list_alerts()), 1)
            self.assertTrue(store.ack_alert(first["id"]))
            self.assertEqual(len(store.list_alerts(include_acked=False)), 0)
