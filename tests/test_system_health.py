from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.config import DashboardConfig, DiscoveryConfig, NetworkConfig, Paths, PiholeConfig, PrivacyConfig, SecurityConfig, Settings
from pi_circle.system_health import capability_report


class SystemHealthTests(unittest.TestCase):
    def test_capability_report_labels_unsupported_https_and_community(self) -> None:
        with TemporaryDirectory() as tmp:
            settings = Settings(
                paths=Paths(
                    state_dir=Path(tmp),
                    log_dir=Path(tmp),
                    pihole_dir=Path(tmp),
                    database=Path(tmp) / "state.db",
                    audit_log=Path(tmp) / "audit.jsonl",
                ),
                network=NetworkConfig(
                    mode="dns_only",
                    lan_cidr=ip_network("192.168.4.0/24"),
                    gateway_ip=ip_address("192.168.4.1"),
                    arp_assisted_enabled=False,
                ),
                dashboard=DashboardConfig(),
                security=SecurityConfig(),
                pihole=PiholeConfig(ftl_db=Path(tmp) / "ftl.db", gravity_db=Path(tmp) / "gravity.db"),
                privacy=PrivacyConfig(),
                discovery=DiscoveryConfig(),
            )

            report = capability_report(settings, {"ready": False, "checks": [], "tips": []})
            by_key = {item["key"]: item for item in report["capabilities"]}

            self.assertEqual(by_key["httpsInspection"]["status"], "Not supported")
            self.assertFalse(by_key["communityProtection"]["enabled"])
            self.assertEqual(by_key["gatewayInternetBlocking"]["status"], "Unavailable")


if __name__ == "__main__":
    unittest.main()
