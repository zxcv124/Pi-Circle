from __future__ import annotations

from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from pi_circle import pihole_control
from pi_circle.pihole_control import (
    read_gravity_update_status,
    validate_disable_duration,
    validate_domain,
    _map_direct,
)


class PiholeControlValidationTests(unittest.TestCase):
    def test_validate_domain(self) -> None:
        self.assertEqual(validate_domain("Example.COM."), "example.com")
        with self.assertRaises(ValueError):
            validate_domain("bad domain")
        with self.assertRaises(ValueError):
            validate_domain("")

    def test_validate_disable_duration(self) -> None:
        self.assertIsNone(validate_disable_duration(None))
        self.assertEqual(validate_disable_duration("5m"), "5m")
        self.assertEqual(validate_disable_duration("30S"), "30s")
        with self.assertRaises(ValueError):
            validate_disable_duration("forever")

    def test_map_direct_commands(self) -> None:
        self.assertEqual(_map_direct(["update-gravity"]), ["-g"])
        self.assertEqual(_map_direct(["update-gravity", "--force"]), ["-g", "-f"])
        self.assertEqual(_map_direct(["allow-remove", "ads.example"]), ["allow", "remove", "ads.example"])
        self.assertEqual(_map_direct(["enable"]), ["enable"])

    def test_gravity_update_status_reads_systemd_timer(self) -> None:
        def fake_run(command, **_kwargs):
            if command[1] == "list-timers":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        "Tue 2026-07-28 01:00:00 +04 1 day left "
                        "Sun 2026-07-26 01:00:00 +04 1 day ago "
                        "pi-circle-gravity-update.timer pi-circle-gravity-update.service\n"
                    ),
                    stderr="",
                )
            unit = command[2]
            if unit == "pi-circle-gravity-update.timer":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="\n".join(
                        [
                            "LoadState=loaded",
                            "ActiveState=active",
                            "SubState=waiting",
                            "UnitFileState=enabled",
                            "NextElapseUSecRealtime=",
                            "LastTriggerUSec=Sun 2026-07-26 01:00:00 +04",
                            "Result=success",
                        ]
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    [
                        "LoadState=loaded",
                        "ActiveState=inactive",
                        "SubState=dead",
                        "UnitFileState=static",
                        "ExecMainStatus=0",
                        "Result=success",
                        "InactiveExitTimestamp=Sun 2026-07-26 01:03:00 +04",
                    ]
                ),
                stderr="",
            )

        with patch.object(pihole_control.subprocess, "run", side_effect=fake_run):
            status = read_gravity_update_status()

        self.assertTrue(status["installed"])
        self.assertTrue(status["enabled"])
        self.assertTrue(status["active"])
        self.assertEqual(status["intervalHours"], 48)
        self.assertEqual(status["nextRun"], "Tue 2026-07-28 01:00:00 +04")
        self.assertEqual(status["lastExitStatus"], 0)
        self.assertEqual(status["lastResult"], "success")

    def test_gravity_update_systemd_units_are_persistent_48_hour_timer(self) -> None:
        root = Path(__file__).resolve().parents[1]
        timer = (root / "packaging/systemd/pi-circle-gravity-update.timer").read_text(encoding="utf-8")
        service = (root / "packaging/systemd/pi-circle-gravity-update.service").read_text(encoding="utf-8")

        self.assertIn("OnUnitActiveSec=48h", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=", timer)
        self.assertIn("ExecStart=/usr/local/sbin/pi-circle-pihole-ctl update-gravity", service)


if __name__ == "__main__":
    unittest.main()
