from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.discovery import ObservedDevice
from pi_circle.inventory import collect_present_devices


class InventoryTests(unittest.TestCase):
    def test_collect_present_devices_uses_arp_not_stale_pihole(self) -> None:
        with TemporaryDirectory() as tmp:
            arp_file = Path(tmp) / "arp"
            arp_file.write_text(
                "\n".join(
                    [
                        "IP address       HW type     Flags       HW address            Mask     Device",
                        "192.168.4.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0",
                    ]
                ),
                encoding="utf-8",
            )
            ftl_db = Path(tmp) / "pihole-FTL.db"
            import sqlite3

            with sqlite3.connect(ftl_db) as conn:
                conn.executescript(
                    """
                    CREATE TABLE network (id INTEGER PRIMARY KEY, hwaddr TEXT, name TEXT);
                    CREATE TABLE network_addresses (network_id INTEGER, ip TEXT);
                    INSERT INTO network(id, hwaddr, name) VALUES (1, 'aa:bb:cc:dd:ee:ff', 'android-phone');
                    INSERT INTO network(id, hwaddr, name) VALUES (2, '11:22:33:44:55:66', 'gone-phone');
                    INSERT INTO network_addresses(network_id, ip) VALUES (1, '192.168.4.10');
                    INSERT INTO network_addresses(network_id, ip) VALUES (2, '192.168.4.77');
                    """
                )

            devices = collect_present_devices(ip_network("192.168.4.0/24"), ftl_db, arp_path=arp_file)

            self.assertEqual([device.ip_address for device in devices], ["192.168.4.10"])
            self.assertEqual(devices[0].hostname, "android-phone")
            self.assertIsInstance(devices[0], ObservedDevice)
