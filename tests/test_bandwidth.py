from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from pi_circle.bandwidth import (
    DeviceBandwidth,
    _parse_conntrack_line,
    list_active_connections,
    sample_device_bandwidth,
    summarize_flows,
)
from pi_circle.storage import Store


CONNTRACK_SAMPLE = """\
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.105 dst=142.250.72.14 sport=45122 dport=443 packets=12 bytes=1800 src=142.250.72.14 dst=192.168.1.105 sport=443 dport=45122 packets=10 bytes=4200 mark=0 use=1
ipv4     2 udp      17 29 src=192.168.1.105 dst=8.8.8.8 sport=5353 dport=53 packets=2 bytes=140 src=8.8.8.8 dst=192.168.1.105 sport=53 dport=5353 packets=2 bytes=180 mark=0 use=1
ipv4     2 tcp      6 100 SYN_SENT src=192.168.1.20 dst=1.1.1.1 sport=4000 dport=443 packets=1 bytes=60 src=1.1.1.1 dst=192.168.1.20 sport=443 dport=4000 packets=0 bytes=0 mark=0 use=1
"""


class BandwidthTests(unittest.TestCase):
    def test_parse_conntrack_outbound(self) -> None:
        line = CONNTRACK_SAMPLE.splitlines()[0]
        parsed = _parse_conntrack_line(line, "192.168.1.105")
        assert parsed is not None
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["remote"], "142.250.72.14")
        self.assertEqual(parsed["remotePort"], "443")
        self.assertEqual(parsed["direction"], "out")
        self.assertEqual(parsed["serviceHint"], "HTTPS")
        self.assertEqual(parsed["bytes"], 6000)

    def test_list_active_connections_filters_and_sorts(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "nf_conntrack"
            path.write_text(CONNTRACK_SAMPLE, encoding="utf-8")
            with (
                patch("pi_circle.bandwidth.CONNTRACK_PATH", path),
                patch("pi_circle.bandwidth.CONNTRACK_BIN", Path("/nonexistent")),
            ):
                rows = list_active_connections("192.168.1.105", limit=10, resolve_hosts=False)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["protocol"], "tcp")
            self.assertEqual(rows[0]["remote"], "142.250.72.14")
            self.assertEqual(rows[1]["protocol"], "udp")

    def test_parse_conntrack_cli_format(self) -> None:
        line = (
            "tcp      6 431916 ESTABLISHED src=192.168.1.105 dst=57.144.148.36 "
            "sport=48392 dport=5222 src=57.144.148.36 dst=192.168.1.106 "
            "sport=5222 dport=48392 [ASSURED] mark=0 use=1"
        )
        parsed = _parse_conntrack_line(line, "192.168.1.105")
        assert parsed is not None
        self.assertEqual(parsed["protocol"], "tcp")
        self.assertEqual(parsed["remote"], "57.144.148.36")
        self.assertEqual(parsed["remotePort"], "5222")
        self.assertEqual(parsed["serviceHint"], "XMPP")

    def test_summarize_flows_protocol_and_remotes(self) -> None:
        flows = [
            {"protocol": "tcp", "remote": "1.2.3.4", "bytes": 1000, "serviceHint": "HTTPS", "host": "a.example"},
            {"protocol": "tcp", "remote": "1.2.3.4", "bytes": 500, "serviceHint": "HTTPS", "host": "a.example"},
            {"protocol": "udp", "remote": "8.8.8.8", "bytes": 200, "serviceHint": "DNS", "host": ""},
        ]
        summary = summarize_flows(flows, top_limit=5)
        self.assertEqual(summary["flowCount"], 3)
        self.assertEqual(summary["protocols"][0]["protocol"], "tcp")
        self.assertEqual(summary["topRemotes"][0]["remote"], "1.2.3.4")
        self.assertEqual(summary["topRemotes"][0]["bytes"], 1500)
        self.assertEqual(summary["topRemotes"][0]["flows"], 2)

    def test_sample_merges_nft_volume_with_conntrack_connections(self) -> None:
        nft = {
            "192.168.1.105": DeviceBandwidth("192.168.1.105", 9000, 40, 0, "nftables", 100.0),
        }
        ct = {
            "192.168.1.105": DeviceBandwidth("192.168.1.105", 1000, 5, 7, "conntrack", 100.0),
        }
        with (
            patch("pi_circle.bandwidth._sample_nft_counters", return_value=nft),
            patch("pi_circle.bandwidth._sample_conntrack", return_value=ct),
        ):
            merged = sample_device_bandwidth({"192.168.1.105"})
        row = merged["192.168.1.105"]
        self.assertEqual(row.bytes_total, 9000)
        self.assertEqual(row.connections, 7)
        self.assertEqual(row.source, "nftables+conntrack")

    def test_bandwidth_series_from_samples(self) -> None:
        with TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "state.db")
            store.initialize()
            base = time.time() - 60
            for index in range(6):
                store.record_bandwidth_sample(
                    "192.168.1.105",
                    bytes_total=index * 1500,
                    packets_total=index * 10,
                    connections=3,
                    source="nftables+conntrack",
                    sampled_at=base + index * 10,
                )
            series = store.bandwidth_series("192.168.1.105", window_seconds=120, bucket_seconds=10)
            self.assertGreater(len(series), 0)
            self.assertTrue(any(point["bytesPerSec"] > 0 for point in series))
