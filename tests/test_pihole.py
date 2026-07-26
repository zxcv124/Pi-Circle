from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from pi_circle.pihole import PiholeQueryReader, PiholeStateReader, describe_activity, extract_search_query, infer_service


class PiholeStateReaderTests(unittest.TestCase):
    def test_summary_reads_versions_and_counts(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            pihole_dir = root / "pihole"
            pihole_dir.mkdir()
            (pihole_dir / "versions").write_text(
                "\n".join(["CORE_VERSION=v6.1.4", "WEB_VERSION=v6.2.1", "FTL_VERSION=v6.2.3"]),
                encoding="utf-8",
            )
            db = pihole_dir / "gravity.db"
            conn = sqlite3.connect(db)
            try:
                conn.executescript(
                    """
                    CREATE TABLE "group"(id INTEGER);
                    CREATE TABLE client(id INTEGER);
                    CREATE TABLE adlist(id INTEGER, enabled INTEGER);
                    CREATE TABLE domainlist(id INTEGER);
                    CREATE TABLE gravity(domain TEXT);
                    INSERT INTO "group" VALUES(0);
                    INSERT INTO client VALUES(1);
                    INSERT INTO adlist VALUES(1, 1);
                    INSERT INTO adlist VALUES(2, 0);
                    INSERT INTO domainlist VALUES(1);
                    INSERT INTO gravity VALUES('example.invalid');
                    INSERT INTO gravity VALUES('ads.invalid');
                    """
                )
            finally:
                conn.close()

            summary = PiholeStateReader(db, pihole_dir).summary()

            self.assertEqual(summary.core_version, "v6.1.4")
            self.assertEqual(summary.enabled_adlists, 1)
            self.assertEqual(summary.gravity_domains, 2)

    def test_infer_service_from_domain(self) -> None:
        self.assertEqual(infer_service("www.youtube.com")[0], "YouTube")
        self.assertEqual(infer_service("graph.facebook.com")[0], "Facebook")
        self.assertEqual(infer_service("news.example.com")[0], "Example")
        self.assertEqual(infer_service("www.google.com"), ("Google", "search"))

    def test_describe_activity_uses_friendly_search_labels(self) -> None:
        headline, detail, query = describe_activity("www.google.com", "Google", "search")
        self.assertEqual(headline, "[searching: Google]")
        self.assertEqual(detail, "google.com")
        self.assertIsNone(query)

        searched = describe_activity("https://www.google.com/search?q=pizza+near+me", "Google", "search")
        self.assertEqual(searched[0], "[searched: pizza near me]")
        self.assertEqual(searched[2], "pizza near me")
        self.assertEqual(extract_search_query("https://duckduckgo.com/?q=weather+today"), "weather today")

    def test_recent_queries_reads_ftl_view(self) -> None:
        with TemporaryDirectory() as tmp:
            ftl_db = Path(tmp) / "pihole-FTL.db"
            conn = sqlite3.connect(ftl_db)
            try:
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
                    INSERT INTO queries VALUES (1, 1700000000, 1, 2, 'www.youtube.com', '192.168.4.21');
                    INSERT INTO queries VALUES (2, 1700000001, 1, 1, 'ads.tracker.test', '192.168.4.21');
                    INSERT INTO queries VALUES (3, 1700000002, 1, 3, 'cdn.example.com', '192.168.4.33');
                    INSERT INTO queries VALUES (4, 1700000003, 1, 2, 'www.google.com', '192.168.4.21');
                    """
                )
            finally:
                conn.close()

            events = PiholeQueryReader(ftl_db).recent_queries(limit=10)
            android = PiholeQueryReader(ftl_db).recent_queries(client_ip="192.168.4.21", limit=10)

            self.assertEqual(len(events), 4)
            self.assertEqual(events[0].domain, "www.youtube.com")
            self.assertEqual(events[0].service, "YouTube")
            self.assertEqual(events[0].headline, "Watching YouTube")
            self.assertFalse(events[0].blocked)
            self.assertTrue(events[1].blocked)
            self.assertEqual(events[3].headline, "[searching: Google]")
            self.assertEqual(len(android), 3)
            self.assertEqual(android[1].status, "blocked")
