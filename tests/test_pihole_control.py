from __future__ import annotations

import unittest

from pi_circle.pihole_control import (
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


if __name__ == "__main__":
    unittest.main()
