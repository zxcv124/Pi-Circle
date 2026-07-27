from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from pi_circle.protection_db import ProtectionDatabaseReader


class ProtectionDatabaseReaderTests(unittest.TestCase):
    def test_summary_blocklists_and_lookup_use_gravity_indexes(self) -> None:
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "gravity.db"
            with sqlite3.connect(db) as conn:
                conn.executescript(
                    """
                    CREATE TABLE adlist (
                      id INTEGER PRIMARY KEY,
                      address TEXT NOT NULL,
                      enabled INTEGER NOT NULL DEFAULT 1,
                      date_added INTEGER NOT NULL DEFAULT 0,
                      date_modified INTEGER NOT NULL DEFAULT 0,
                      comment TEXT,
                      date_updated INTEGER,
                      number INTEGER NOT NULL DEFAULT 0,
                      invalid_domains INTEGER NOT NULL DEFAULT 0,
                      status INTEGER NOT NULL DEFAULT 0,
                      abp_entries INTEGER NOT NULL DEFAULT 0,
                      type INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE gravity(domain TEXT NOT NULL, adlist_id INTEGER NOT NULL);
                    CREATE INDEX idx_gravity_domain ON gravity(domain);
                    CREATE TABLE domainlist (
                      id INTEGER PRIMARY KEY,
                      type INTEGER NOT NULL DEFAULT 0,
                      domain TEXT NOT NULL,
                      enabled INTEGER NOT NULL DEFAULT 1,
                      date_added INTEGER NOT NULL DEFAULT 0,
                      date_modified INTEGER NOT NULL DEFAULT 0,
                      comment TEXT
                    );
                    INSERT INTO adlist(id, address, enabled, date_updated, status, number) VALUES
                      (1, 'https://lists.example/ads.txt', 1, 1800000000, 0, 2),
                      (2, 'https://lists.example/disabled.txt', 0, 1800000000, 0, 1);
                    INSERT INTO gravity(domain, adlist_id) VALUES
                      ('ads.example', 1),
                      ('ads.example', 2),
                      ('tracker.example', 1);
                    INSERT INTO domainlist(type, domain, enabled, comment) VALUES
                      (0, 'allowed.example', 1, 'manual allow'),
                      (1, 'blocked.example', 1, 'manual deny'),
                      (3, '.*tracker.*', 1, 'regex deny');
                    """
                )

            reader = ProtectionDatabaseReader(db)
            summary = reader.summary()
            blocklists = reader.blocklists()
            lookup = reader.lookup("ads.example")

            self.assertTrue(summary.available)
            self.assertEqual(summary.total_active_entries, 3)
            self.assertIsNone(summary.domain_count)
            self.assertIsNone(summary.duplicate_count)
            self.assertFalse(summary.exact_unique_counts)
            self.assertEqual(summary.list_source_count, 2)
            self.assertEqual(summary.enabled_list_source_count, 1)
            self.assertEqual(summary.domain_rule_count, 3)
            self.assertEqual(summary.exact_deny_count, 1)
            self.assertEqual(summary.regex_deny_count, 1)
            self.assertEqual(summary.allow_count, 1)
            self.assertEqual(blocklists[0]["entryCount"], 2)
            self.assertEqual(blocklists[0]["reliability"], "healthy")
            self.assertEqual(len(lookup["gravityMatches"]), 2)

    def test_missing_database_returns_unavailable_summary(self) -> None:
        with TemporaryDirectory() as tmp:
            summary = ProtectionDatabaseReader(Path(tmp) / "missing.db").summary()

            self.assertFalse(summary.available)
            self.assertIn("not present", summary.error or "")


if __name__ == "__main__":
    unittest.main()
