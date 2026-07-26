from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import stat
import unittest

from pi_circle.storage import Store, infer_device_type


class StorageTests(unittest.TestCase):
    def test_store_initializes_and_tracks_devices(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()

            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:ff", "phone", "high")
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:ff", "phone", "high")
            devices = store.list_devices()

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].ip_address, "192.168.4.21")
            self.assertEqual(devices[0].hostname, "phone")
            self.assertEqual(devices[0].device_type, "unknown")
            self.assertIsNone(devices[0].profile_id)
            self.assertIs(store.get_network_health()["healthy"], True)

    def test_store_uses_group_writable_database_permissions(self) -> None:
        with TemporaryDirectory() as tmp:
            database = Path(tmp) / "state.db"
            Store(database).initialize()

            permissions = stat.S_IMODE(database.stat().st_mode)

            self.assertEqual(permissions, 0o660)

    def test_store_persists_manual_device_identity(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:ff", "iphone", "high")

            updated = store.update_device_identity("192.168.4.21", "Sam's iPhone", "iphone")

            self.assertEqual(updated.display_name, "Sam's iPhone")
            self.assertEqual(updated.device_type, "iphone")
            self.assertEqual(store.list_devices()[0].display_name, "Sam's iPhone")

    def test_store_migrates_existing_database_without_device_type(self) -> None:
        with TemporaryDirectory() as tmp:
            database = Path(tmp) / "state.db"
            import sqlite3

            with sqlite3.connect(database) as conn:
                conn.execute(
                    """
                    CREATE TABLE devices (
                      id INTEGER PRIMARY KEY,
                      ip_address TEXT NOT NULL UNIQUE,
                      mac_address TEXT,
                      hostname TEXT,
                      display_name TEXT,
                      profile_id INTEGER,
                      identity_confidence TEXT NOT NULL DEFAULT 'low',
                      managed INTEGER NOT NULL DEFAULT 0,
                      paused INTEGER NOT NULL DEFAULT 0,
                      transparent_control INTEGER NOT NULL DEFAULT 0,
                      first_seen TEXT NOT NULL,
                      last_seen TEXT NOT NULL
                    )
                    """
                )

            store = Store(database)
            store.initialize()
            store.upsert_device("192.168.4.22", None, "android-phone", "high")

            self.assertEqual(store.list_devices()[0].device_type, "android")

    def test_infer_device_type_from_hostname(self) -> None:
        self.assertEqual(infer_device_type("Alice-iPhone", "192.168.1.20"), "iphone")
        self.assertEqual(infer_device_type("living-room-roku", "192.168.1.30"), "tv")
        self.assertEqual(infer_device_type(None, "192.168.1.1"), "router")

    def test_store_creates_default_profiles_and_assigns_device(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", None, "kid-ipad", "high")

            profiles = store.list_profiles()
            kids = next(profile for profile in profiles if profile.name == "Kids")
            assigned = store.assign_device_profile("192.168.4.21", kids.id)

            self.assertEqual(assigned.profile_id, kids.id)
            self.assertEqual(assigned.profile_name, "Kids")
            self.assertEqual(next(profile for profile in store.list_profiles() if profile.name == "Kids").device_count, 1)

    def test_store_creates_custom_profile(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()

            profile = store.create_profile("School", "School devices")

            self.assertEqual(profile.name, "School")
            self.assertEqual(profile.description, "School devices")

    def test_store_migrates_enrolled_device_to_new_ip(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:01", "sam-iphone", "high")
            store.update_device_identity("192.168.4.21", "Sam Phone", "iphone")
            store.set_device_enrollment("192.168.4.21", True)

            store.upsert_device("192.168.4.44", "aa:bb:cc:dd:ee:01", "sam-iphone", "high")
            devices = store.list_devices()

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].ip_address, "192.168.4.44")
            self.assertEqual(devices[0].display_name, "Sam Phone")
            self.assertTrue(devices[0].transparent_control)
            self.assertTrue(devices[0].managed)
            self.assertEqual(store.list_active_enrolled_ips({"192.168.4.44"}), ["192.168.4.44"])

    def test_store_enrollment_clears_active_targets(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:02", "tablet", "high")
            store.set_device_enrollment("192.168.4.21", True)
            store.set_device_enrollment("192.168.4.21", False)

            self.assertEqual(store.list_active_enrolled_ips({"192.168.4.21"}), [])

    def test_store_prunes_absent_unenrolled_devices(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:03", "android-phone", "high")
            store.upsert_device("192.168.4.22", "aa:bb:cc:dd:ee:04", "ipad", "high")
            store.set_device_enrollment("192.168.4.22", True)

            removed = store.prune_absent_devices({"192.168.4.99"}, keep_enrolled=True)
            visible = store.list_devices(present_ips={"192.168.4.99"})

            self.assertEqual(removed, 1)
            self.assertEqual(visible, [])
            self.assertEqual(len(store.list_devices()), 1)
            self.assertEqual(store.list_devices()[0].ip_address, "192.168.4.22")
