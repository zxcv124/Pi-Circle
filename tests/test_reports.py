from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import time
import unittest

from pi_circle.reports import ReportBuilder, ReportRequest
from pi_circle.storage import Store


class ReportBuilderTests(unittest.TestCase):
    def test_report_privacy_levels_and_csv_export(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ftl_db = root / "pihole-FTL.db"
            now = int(time.time())
            with sqlite3.connect(ftl_db) as conn:
                conn.executescript(
                    """
                    CREATE TABLE queries (
                      id INTEGER PRIMARY KEY,
                      timestamp INTEGER,
                      type INTEGER,
                      status INTEGER,
                      domain TEXT,
                      client TEXT
                    );
                    """
                )
                conn.executemany(
                    "INSERT INTO queries(timestamp, type, status, domain, client) VALUES (?, ?, ?, ?, ?)",
                    [
                        (now - 60, 1, 2, "www.youtube.com", "192.168.4.21"),
                        (now - 50, 1, 1, "ads.example", "192.168.4.21"),
                        (now - 40, 1, 2, "www.google.com", "192.168.4.22"),
                    ],
                )
            store = Store(root / "state.db")
            store.initialize()
            store.add_alert(alert_type="blocked_burst", severity="warning", title="Blocked burst", detail="Many blocks")

            builder = ReportBuilder(ftl_db, store)
            summary = builder.build(ReportRequest(period="daily", privacy_level="summary"))
            technical = builder.build(ReportRequest(period="daily", privacy_level="technical"))
            csv_text = builder.csv(ReportRequest(period="daily", privacy_level="technical"))

            self.assertEqual(summary["sections"]["dns"]["queries"], 3)
            self.assertEqual(summary["sections"]["domains"], [])
            self.assertGreaterEqual(len(technical["sections"]["domains"]), 1)
            self.assertIn("technical", technical["privacyNotice"].lower())
            self.assertIn("section,name,value,detail", csv_text)


if __name__ == "__main__":
    unittest.main()
