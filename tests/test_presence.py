from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from pi_circle.discovery import ObservedDevice
from pi_circle.presence import collect_presence, read_ip_neigh


class PresenceTests(unittest.TestCase):
    def test_read_ip_neigh_keeps_stale_and_drops_failed(self) -> None:
        output = "\n".join(
            [
                "192.168.4.10 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE",
                "192.168.4.11 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE",
                "192.168.4.12 dev wlan0 FAILED",
                "10.0.0.5 dev wlan0 lladdr aa:bb:cc:dd:ee:03 REACHABLE",
            ]
        )

        with patch("pi_circle.presence.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = output
            devices = read_ip_neigh(ip_network("192.168.4.0/24"))

        self.assertEqual([device.ip_address for device in devices], ["192.168.4.10", "192.168.4.11"])

    def test_collect_presence_probes_then_merges_neighbors(self) -> None:
        with TemporaryDirectory() as tmp:
            ftl_db = Path(tmp) / "missing.db"
            with patch("pi_circle.presence.probe_hosts", return_value=1) as probe, patch(
                "pi_circle.presence.read_ip_neigh",
                return_value=[ObservedDevice("192.168.4.44", "aa:bb:cc:dd:ee:44", None, "high")],
            ), patch("pi_circle.presence.read_proc_arp", return_value=[]), patch(
                "pi_circle.presence.read_pihole_network",
                return_value=[ObservedDevice("192.168.4.44", "aa:bb:cc:dd:ee:44", "pixel-phone", "high")],
            ), patch("pi_circle.presence.recent_dns_clients", return_value={"192.168.4.44"}):
                devices = collect_presence(
                    ip_network("192.168.4.0/24"),
                    ftl_db,
                    known_ips={"192.168.4.44"},
                    probe=True,
                    full_scan=False,
                )

            probe.assert_called()
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].hostname, "pixel-phone")
