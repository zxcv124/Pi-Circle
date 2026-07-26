from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pi_circle.enrollment import auto_enroll_android_devices
from pi_circle.nmap_identify import classify_os_text, parse_nmap_xml
from pi_circle.storage import Store


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.105" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Samsung Electronics"/>
    <hostnames><hostname name="pixel-6.lan" type="PTR"/></hostnames>
    <os>
      <osmatch name="Android 13 (Linux 5.10)" accuracy="95"/>
    </os>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <os>
      <osmatch name="Apple iPhone iOS 17" accuracy="90"/>
    </os>
  </host>
</nmaprun>
"""


class NmapIdentifyTests(unittest.TestCase):
    def test_classify_android_from_os_text(self) -> None:
        self.assertEqual(classify_os_text("Android 13 (Linux 5.10)"), "android")
        self.assertEqual(classify_os_text("Apple iPhone iOS 17"), "iphone")
        self.assertEqual(classify_os_text("Microsoft Windows 11"), "pc")
        # Regression: 'ios' must not match inside 'bios' / generic Linux.
        self.assertEqual(classify_os_text("Linux 5.0 - 5.3"), "unknown")
        self.assertEqual(classify_os_text("DD-WRT v3.0 (Linux 4.4.2) with BIOS"), "router")

    def test_parse_nmap_xml_android(self) -> None:
        results = parse_nmap_xml(SAMPLE_XML)
        by_ip = {item.ip_address: item for item in results}
        self.assertEqual(by_ip["192.168.1.105"].device_type, "android")
        self.assertEqual(by_ip["192.168.1.105"].vendor, "Samsung Electronics")
        self.assertEqual(by_ip["192.168.1.50"].device_type, "iphone")

    def test_auto_enroll_android_only(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            store.upsert_device("192.168.1.105", "aa:bb:cc:dd:ee:01", "pixel-6", "high")
            store.apply_discovered_identity(
                "192.168.1.105",
                device_type="android",
                identity_confidence="nmap",
                display_name="Pixel 6",
            )
            store.upsert_device("192.168.1.50", "aa:bb:cc:dd:ee:02", "iphone", "high")
            store.apply_discovered_identity(
                "192.168.1.50",
                device_type="iphone",
                identity_confidence="nmap",
            )
            linked = auto_enroll_android_devices(
                store,
                {"192.168.1.105", "192.168.1.50"},
                gateway_ip="192.168.1.1",
            )
            self.assertEqual(linked, ["192.168.1.105"])
            android = store.get_device("192.168.1.105")
            iphone = store.get_device("192.168.1.50")
            assert android is not None and iphone is not None
            self.assertTrue(android.transparent_control)
            self.assertFalse(iphone.transparent_control)
