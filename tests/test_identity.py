from __future__ import annotations

import unittest

from pi_circle.identity import lookup_vendor, suggest_identity


class IdentityTests(unittest.TestCase):
    def test_lookup_vendor_from_oui(self) -> None:
        self.assertEqual(lookup_vendor("a4:5e:60:11:22:33"), "Apple")
        self.assertEqual(lookup_vendor("f4:f5:d8:aa:bb:cc"), "Google")

    def test_suggest_identity_prefers_hostname(self) -> None:
        suggestion = suggest_identity(
            hostname="Sam-iPhone.local",
            mac_address="a4:5e:60:11:22:33",
            ip_address="192.168.1.20",
            gateway_ip="192.168.1.1",
        )
        self.assertEqual(suggestion.device_type, "iphone")
        self.assertIn("Sam", suggestion.display_name)
        self.assertEqual(suggestion.vendor, "Apple")

    def test_suggest_identity_uses_vendor_when_hostname_missing(self) -> None:
        suggestion = suggest_identity(
            hostname=None,
            mac_address="14:49:e0:11:22:33",
            ip_address="192.168.1.44",
            gateway_ip="192.168.1.1",
        )
        self.assertEqual(suggestion.vendor, "Samsung")
        self.assertEqual(suggestion.device_type, "android")
        self.assertTrue(suggestion.display_name.startswith("Samsung"))

    def test_gateway_labeled_as_router(self) -> None:
        suggestion = suggest_identity(
            hostname=None,
            mac_address=None,
            ip_address="192.168.1.1",
            gateway_ip="192.168.1.1",
        )
        self.assertEqual(suggestion.display_name, "Router")
        self.assertEqual(suggestion.device_type, "router")
