from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from pi_circle.privacy_shield import (
    classify_privacy_hit,
    sync_pihole_denylist,
)


class PrivacyShieldTests(unittest.TestCase):
    def test_classify_doh_and_telemetry(self) -> None:
        self.assertEqual(classify_privacy_hit("chrome.cloudflare-dns.com"), "doh_bypass")
        self.assertEqual(classify_privacy_hit("dns.google"), "doh_bypass")
        self.assertEqual(classify_privacy_hit("app-measurement.com"), "telemetry")
        self.assertIsNone(classify_privacy_hit("www.youtube.com"))
        self.assertIsNone(classify_privacy_hit("youtubei.googleapis.com"))

    def test_sync_writes_domainlist_rows(self) -> None:
        with TemporaryDirectory() as tmp:
            gravity = Path(tmp) / "gravity.db"
            conn = sqlite3.connect(gravity)
            try:
                conn.execute(
                    """
                    CREATE TABLE domainlist (
                      id INTEGER PRIMARY KEY,
                      type INTEGER,
                      domain TEXT,
                      enabled INTEGER,
                      date_added INTEGER,
                      date_modified INTEGER,
                      comment TEXT
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

            result = sync_pihole_denylist(gravity, strict=False, reload=False)
            self.assertGreater(result.exact_upserted, 10)
            self.assertGreater(result.regex_upserted, 5)

            conn = sqlite3.connect(gravity)
            try:
                chrome = conn.execute(
                    "SELECT enabled, comment FROM domainlist WHERE domain = ?",
                    ("chrome.cloudflare-dns.com",),
                ).fetchone()
                self.assertIsNotNone(chrome)
                self.assertEqual(chrome[0], 1)
                self.assertIn("pi-circle-privacy-shield", chrome[1])
                count = conn.execute("SELECT COUNT(*) FROM domainlist WHERE enabled = 1").fetchone()[0]
                self.assertGreaterEqual(count, result.exact_upserted)
            finally:
                conn.close()

            # Second sync should be mostly noop.
            again = sync_pihole_denylist(gravity, strict=False, reload=False)
            self.assertEqual(again.exact_upserted, 0)
