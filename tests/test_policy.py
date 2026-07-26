from __future__ import annotations

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.policy import evaluate_device_policy, is_bedtime_active
from pi_circle.storage import Store


class PolicyTests(unittest.TestCase):
    def test_bedtime_overnight_window(self) -> None:
        evening = datetime(2026, 7, 18, 22, 30)
        morning = datetime(2026, 7, 19, 6, 15)
        midday = datetime(2026, 7, 19, 12, 0)
        self.assertTrue(is_bedtime_active("21:00", "07:00", now=evening))
        self.assertTrue(is_bedtime_active("21:00", "07:00", now=morning))
        self.assertFalse(is_bedtime_active("21:00", "07:00", now=midday))

    def test_pause_requires_link_to_block(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.20", "aa:bb:cc:dd:ee:20", "kid-phone", "high")
            device = store.set_device_paused("192.168.4.20", True)
            kids = next(profile for profile in store.list_profiles() if profile.name == "Kids")
            store.assign_device_profile("192.168.4.20", kids.id)
            device = store.get_device("192.168.4.20")
            assert device is not None

            unlinked = evaluate_device_policy(device, kids, linked=False)
            self.assertTrue(unlinked.paused)
            self.assertTrue(unlinked.requires_link)
            self.assertFalse(unlinked.blocked)

            linked = evaluate_device_policy(device, kids, linked=True)
            self.assertTrue(linked.blocked)
            self.assertEqual(linked.block_reason, "paused")

    def test_daily_limit_blocks_when_over_budget(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.4.21", "aa:bb:cc:dd:ee:21", "tablet", "high")
            kids = next(profile for profile in store.list_profiles() if profile.name == "Kids")
            store.assign_device_profile("192.168.4.21", kids.id)
            device = store.get_device("192.168.4.21")
            assert device is not None
            state = evaluate_device_policy(
                device,
                kids,
                linked=True,
                used_minutes=120,
                now=datetime(2026, 7, 19, 12, 0),
            )
            self.assertTrue(state.over_budget)
            self.assertTrue(state.blocked)
            self.assertEqual(state.block_reason, "daily_limit")

    def test_kids_profile_defaults_seeded(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            kids = next(profile for profile in store.list_profiles() if profile.name == "Kids")
            self.assertEqual(kids.bedtime_start, "21:00")
            self.assertEqual(kids.bedtime_end, "07:00")
            self.assertEqual(kids.daily_minutes, 120)
