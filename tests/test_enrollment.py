from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.enrollment import reconcile_enrolled_targets
from pi_circle.storage import Store


class EnrollmentTests(unittest.TestCase):
    def test_reconcile_moves_target_when_enrolled_mac_changes_ip(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:11", "phone", "high")
            store.set_device_enrollment("192.168.4.21", True)
            store.upsert_device("192.168.4.55", "aa:bb:cc:dd:ee:11", "phone", "high")

            applied: list[list[str]] = []
            changed = reconcile_enrolled_targets(
                store,
                ["192.168.4.21"],
                {"192.168.4.55"},
                apply_fn=applied.append,
            )

            self.assertEqual(changed, ["192.168.4.55"])
            self.assertEqual(applied, [["192.168.4.55"]])

    def test_reconcile_is_noop_when_targets_match(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:12", "phone", "high")
            store.set_device_enrollment("192.168.4.21", True)

            applied: list[list[str]] = []
            changed = reconcile_enrolled_targets(
                store,
                ["192.168.4.21"],
                {"192.168.4.21"},
                apply_fn=applied.append,
            )

            self.assertIsNone(changed)
            self.assertEqual(applied, [])

    def test_reconcile_auto_enables_enrolled_device_from_dns_only(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:13", "phone", "high")
            store.set_device_enrollment("192.168.4.21", True)

            applied: list[list[str]] = []
            changed = reconcile_enrolled_targets(
                store,
                [],
                {"192.168.4.21"},
                apply_fn=applied.append,
            )

            self.assertEqual(changed, ["192.168.4.21"])
            self.assertEqual(applied, [["192.168.4.21"]])

    def test_reconcile_ignores_unenrolled_devices(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:14", "phone", "high")

            applied: list[list[str]] = []
            changed = reconcile_enrolled_targets(
                store,
                [],
                {"192.168.4.21"},
                apply_fn=applied.append,
            )

            self.assertIsNone(changed)
            self.assertEqual(applied, [])
