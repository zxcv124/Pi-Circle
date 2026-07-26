from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.discovery import read_proc_arp


class DiscoveryTests(unittest.TestCase):
    def test_read_proc_arp_filters_to_lan(self) -> None:
        with TemporaryDirectory() as tmp:
            arp_file = Path(tmp) / "arp"
            arp_file.write_text(
                "\n".join(
                    [
                        "IP address       HW type     Flags       HW address            Mask     Device",
                        "192.168.4.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0",
                        "10.0.0.5         0x1         0x2         aa:bb:cc:dd:ee:00     *        wlan0",
                        "192.168.4.11     0x1         0x0         00:00:00:00:00:00     *        wlan0",
                    ]
                ),
                encoding="utf-8",
            )

            devices = read_proc_arp(ip_network("192.168.4.0/24"), arp_file)

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].ip_address, "192.168.4.10")
            self.assertEqual(devices[0].mac_address, "aa:bb:cc:dd:ee:ff")
