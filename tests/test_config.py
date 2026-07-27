from __future__ import annotations

from pathlib import Path
import textwrap
import unittest


from pi_circle.config import ConfigError, load_settings


class ConfigTests(unittest.TestCase):
    def test_load_settings_accepts_safe_dns_only_config(self) -> None:
        with TemporaryPath() as tmp_path:
            config = tmp_path / "config.toml"
            config.write_text(
                textwrap.dedent(
                    """
                    [network]
                    mode = "dns_only"
                    interface = "wlan0"
                    lan_cidr = "192.168.4.0/24"
                    gateway_ip = "192.168.4.1"
                    """
                ),
                encoding="utf-8",
            )

            settings = load_settings(config)

            self.assertEqual(settings.network.mode, "dns_only")
            self.assertEqual(settings.network.interface, "wlan0")
            self.assertEqual(str(settings.network.gateway_ip), "192.168.4.1")
            self.assertTrue(settings.network.force_ipv4)
            self.assertTrue(settings.network.force_pi_dns)

    def test_force_ipv4_can_be_disabled(self) -> None:
        with TemporaryPath() as tmp_path:
            config = tmp_path / "config.toml"
            config.write_text(
                textwrap.dedent(
                    """
                    [network]
                    mode = "dns_only"
                    interface = "wlan0"
                    lan_cidr = "192.168.4.0/24"
                    gateway_ip = "192.168.4.1"
                    force_ipv4 = false
                    """
                ),
                encoding="utf-8",
            )
            settings = load_settings(config)
            self.assertFalse(settings.network.force_ipv4)

    def test_load_settings_accepts_string_config_path(self) -> None:
        with TemporaryPath() as tmp_path:
            config = tmp_path / "config.toml"
            config.write_text(
                textwrap.dedent(
                    """
                    [network]
                    mode = "dns_only"
                    lan_cidr = "192.168.4.0/24"
                    gateway_ip = "192.168.4.1"
                    """
                ),
                encoding="utf-8",
            )

            settings = load_settings(str(config))

            self.assertEqual(settings.network.mode, "dns_only")
            self.assertEqual(str(settings.network.lan_cidr), "192.168.4.0/24")

    def test_arp_assisted_requires_explicit_enable(self) -> None:
        with TemporaryPath() as tmp_path:
            config = tmp_path / "config.toml"
            config.write_text(
                textwrap.dedent(
                    """
                    [network]
                    mode = "arp_assisted"
                    lan_cidr = "192.168.4.0/24"
                    gateway_ip = "192.168.4.1"
                    arp_assisted_targets = ["192.168.4.25"]
                    """
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError):
                load_settings(config)

    def test_arp_assisted_target_must_be_inside_lan(self) -> None:
        with TemporaryPath() as tmp_path:
            config = tmp_path / "config.toml"
            config.write_text(
                textwrap.dedent(
                    """
                    [network]
                    mode = "arp_assisted"
                    lan_cidr = "192.168.4.0/24"
                    gateway_ip = "192.168.4.1"
                    arp_assisted_enabled = true
                    arp_assisted_targets = ["192.168.5.25"]
                    """
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError):
                load_settings(config)


class TemporaryPath:
    def __enter__(self) -> Path:
        from tempfile import TemporaryDirectory

        self._manager = TemporaryDirectory()
        return Path(self._manager.__enter__())

    def __exit__(self, exc_type, exc, tb) -> None:
        self._manager.__exit__(exc_type, exc, tb)
