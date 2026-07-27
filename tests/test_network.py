from __future__ import annotations

from ipaddress import ip_address, ip_network
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pi_circle.config import NetworkConfig
from pi_circle.network import HealthResult, NetworkController
from pi_circle.system import CommandResult


class FakeAudit:
    def __init__(self) -> None:
        self.events = []

    def write(self, event) -> None:
        self.events.append(event)


class FakeRunner:
    def __init__(self, process=None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.process = process or HealthyProcess()

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        self.commands.append(tuple(args))
        return CommandResult(tuple(args), 0, "", "")

    def popen(self, args: list[str]):
        self.commands.append(tuple(args))
        return self.process


class HealthyProcess:
    returncode = None
    stderr = None

    def poll(self):
        return None

    def send_signal(self, _signal) -> None:
        self.returncode = 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class FailedProcess:
    returncode = 1
    stderr = None

    def poll(self):
        return 1


class NetworkControllerTests(unittest.TestCase):
    def test_arp_assisted_nftables_nat_is_scoped_to_targets(self) -> None:
        controller = NetworkController(FakeRunner(), FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            lan_cidr=ip_network("192.168.4.0/24"),
            gateway_ip=ip_address("192.168.4.1"),
            enable_ipv4_forwarding=True,
            arp_assisted_enabled=True,
            arp_assisted_targets=(ip_address("192.168.4.25"), ip_address("192.168.4.26")),
        )
        nft_inputs: list[str] = []

        def fake_subprocess_run(args, **kwargs):
            if args == ["nft", "-f", "-"]:
                nft_inputs.append(kwargs["input"])
                return SimpleNamespace(returncode=0, stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pi_circle.network.os.geteuid", return_value=0), \
            patch("pi_circle.network._binary_path", return_value="/usr/sbin/arpspoof"), \
            patch("pi_circle.network._interface_ipv4_addresses", return_value=set()), \
            patch("pi_circle.network.subprocess.run", side_effect=fake_subprocess_run):
            result = controller.apply(config)

        self.assertTrue(result.healthy)
        self.assertEqual(len(nft_inputs), 1)
        rules = nft_inputs[0]
        self.assertIn("ip saddr { 192.168.4.25, 192.168.4.26 } masquerade", rules)
        self.assertIn("ip saddr 192.168.4.25 counter", rules)
        self.assertNotIn("ip saddr 192.168.4.25 counter accept", rules)
        self.assertIn("tcp dport 853 drop", rules)
        self.assertIn("udp dport 443 drop", rules)
        self.assertNotIn("ip saddr != 192.168.4.0/24 drop", rules)
        self.assertIn("meta nfproto ipv6 drop", rules)
        self.assertIn("1.1.1.1", rules)
        self.assertIn("8.8.8.8", rules)
        self.assertIn("172.64.41.3", rules)
        # DNS hijack is linked-only — never whole LAN (protects unlinked wired PCs).
        self.assertIn("ip saddr { 192.168.4.25, 192.168.4.26 } udp dport 53 redirect to :53", rules)
        self.assertNotIn("ip saddr 192.168.4.0/24 udp dport 53 redirect to :53", rules)
        # Shields must appear before linked accept (Disney Circle-style, no phone settings).
        self.assertLess(rules.index("tcp dport 853 drop"), rules.index("ip saddr { 192.168.4.25, 192.168.4.26 } accept"))
        self.assertLess(rules.index("tcp dport 443 drop"), rules.index("ip saddr { 192.168.4.25, 192.168.4.26 } accept"))
        self.assertLess(rules.index("tcp dport 443 drop"), rules.index("ct state established,related accept"))

    def test_force_ipv4_off_skips_ipv6_drop(self) -> None:
        controller = NetworkController(FakeRunner(), FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            lan_cidr=ip_network("192.168.4.0/24"),
            gateway_ip=ip_address("192.168.4.1"),
            enable_ipv4_forwarding=True,
            arp_assisted_enabled=True,
            arp_assisted_targets=(ip_address("192.168.4.120"),),
            force_ipv4=False,
        )
        nft_inputs: list[str] = []

        def fake_subprocess_run(args, **kwargs):
            if args == ["nft", "-f", "-"]:
                nft_inputs.append(kwargs["input"])
                return SimpleNamespace(returncode=0, stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pi_circle.network.subprocess.run", side_effect=fake_subprocess_run):
            controller.apply_nftables(config)

        self.assertTrue(nft_inputs)
        self.assertNotIn("meta nfproto ipv6 drop", nft_inputs[0])

    def test_force_pi_dns_without_redirect_does_not_hijack_whole_lan(self) -> None:
        controller = NetworkController(FakeRunner(), FakeAudit())
        config = NetworkConfig(
            mode="router_integrated",
            interface="wlan0",
            lan_cidr=ip_network("192.168.4.0/24"),
            gateway_ip=ip_address("192.168.4.1"),
            dns_redirect_port_53=False,
            force_pi_dns=True,
        )
        nft_inputs: list[str] = []

        def fake_subprocess_run(args, **kwargs):
            if args == ["nft", "-f", "-"]:
                nft_inputs.append(kwargs["input"])
                return SimpleNamespace(returncode=0, stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pi_circle.network.subprocess.run", side_effect=fake_subprocess_run):
            controller.apply_nftables(config)

        self.assertTrue(nft_inputs)
        self.assertNotIn("ip saddr 192.168.4.0/24 udp dport 53 redirect to :53", nft_inputs[0])
        self.assertNotIn("ip saddr 192.168.4.0/24 tcp dport 53 redirect to :53", nft_inputs[0])

    def test_arp_assisted_pause_drops_blocked_ips(self) -> None:
        controller = NetworkController(FakeRunner(), FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            lan_cidr=ip_network("192.168.4.0/24"),
            gateway_ip=ip_address("192.168.4.1"),
            enable_ipv4_forwarding=True,
            arp_assisted_enabled=True,
            arp_assisted_targets=(ip_address("192.168.4.25"),),
        )
        nft_inputs: list[str] = []

        def fake_subprocess_run(args, **kwargs):
            if args == ["nft", "-f", "-"]:
                nft_inputs.append(kwargs["input"])
                return SimpleNamespace(returncode=0, stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("pi_circle.network.os.geteuid", return_value=0), \
            patch("pi_circle.network._binary_path", return_value="/usr/sbin/arpspoof"), \
            patch("pi_circle.network._interface_ipv4_addresses", return_value=set()), \
            patch("pi_circle.network.subprocess.run", side_effect=fake_subprocess_run):
            result = controller.apply(config, blocked_ips=["192.168.4.25"])

        self.assertTrue(result.healthy)
        self.assertIn("ip saddr { 192.168.4.25 } drop", nft_inputs[0])
        self.assertIn("ip daddr { 192.168.4.25 } drop", nft_inputs[0])
        # Pause drops must come before established/related accept.
        self.assertLess(nft_inputs[0].index("drop"), nft_inputs[0].index("ct state established,related accept"))

    def test_arp_assisted_configures_same_interface_forwarding_sysctls(self) -> None:
        runner = FakeRunner()
        controller = NetworkController(runner, FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            lan_cidr=ip_network("192.168.4.0/24"),
            gateway_ip=ip_address("192.168.4.1"),
            enable_ipv4_forwarding=True,
            arp_assisted_enabled=True,
            arp_assisted_targets=(ip_address("192.168.4.25"),),
        )

        with patch("pi_circle.network.os.geteuid", return_value=0), \
            patch("pi_circle.network._binary_path", return_value="/usr/sbin/arpspoof"), \
            patch("pi_circle.network._interface_ipv4_addresses", return_value=set()), \
            patch("pi_circle.network.subprocess.run", return_value=SimpleNamespace(returncode=0, stderr="")):
            controller.apply(config)

        commands = [" ".join(command) for command in runner.commands]
        self.assertIn("sysctl -w net.ipv4.ip_forward=1", commands)
        self.assertIn("sysctl -w net.ipv4.conf.wlan0.send_redirects=0", commands)
        self.assertIn("sysctl -w net.ipv4.conf.wlan0.rp_filter=0", commands)

    def test_arp_assisted_without_targets_does_not_apply_nftables(self) -> None:
        runner = FakeRunner()
        controller = NetworkController(runner, FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            gateway_ip=ip_address("192.168.1.1"),
            arp_assisted_enabled=True,
            arp_assisted_targets=(),
        )

        with patch("pi_circle.network.subprocess.run") as subprocess_run:
            result = controller.apply(config)

        self.assertFalse(result.healthy)
        nft_apply_calls = [call for call in subprocess_run.call_args_list if call.args[0] == ["nft", "-f", "-"]]
        self.assertEqual(nft_apply_calls, [])

    def test_arp_assisted_rejects_pi_address_as_target(self) -> None:
        controller = NetworkController(FakeRunner(), FakeAudit())
        config = NetworkConfig(
            mode="arp_assisted",
            interface="wlan0",
            gateway_ip=ip_address("192.168.1.1"),
            arp_assisted_enabled=True,
            arp_assisted_targets=(ip_address("192.168.1.106"),),
        )

        with patch("pi_circle.network.os.geteuid", return_value=0), \
            patch("pi_circle.network._binary_path", return_value="/usr/sbin/arpspoof"), \
            patch("pi_circle.network._interface_ipv4_addresses", return_value={ip_address("192.168.1.106")}):
            result = controller.apply_arp_assisted(config)

        self.assertFalse(result.healthy)
        self.assertIn("cannot be the Pi address", result.summary)

    def test_failed_arpspoof_start_raises_and_is_audited(self) -> None:
        audit = FakeAudit()
        controller = NetworkController(FakeRunner(FailedProcess()), audit)

        with self.assertRaises(RuntimeError):
            controller._ensure_arpspoof(
                "client:192.168.4.25",
                "wlan0",
                ip_address("192.168.4.25"),
                ip_address("192.168.4.1"),
            )

        self.assertEqual(audit.events[-1].event_type, "network.arp_assisted.process_failed")


if __name__ == "__main__":
    unittest.main()
