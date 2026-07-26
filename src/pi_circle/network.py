from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import os
import signal
import shutil
import subprocess
import time

from .audit import AuditEvent, AuditLogger
from .config import NetworkConfig
from .system import CommandRunner


PI_CIRCLE_TABLE = "pi_circle"


@dataclass(frozen=True)
class HealthResult:
    healthy: bool
    summary: str


class NetworkController:
    def __init__(self, runner: CommandRunner, audit: AuditLogger) -> None:
        self.runner = runner
        self.audit = audit
        self._arp_processes: dict[str, subprocess.Popen[str]] = {}
        self._active_nft_ruleset: str | None = None

    def apply(self, config: NetworkConfig, blocked_ips: list[str] | tuple[str, ...] | None = None) -> HealthResult:
        blocked = tuple(sorted({x for x in (blocked_ips or []) if x}))
        if config.mode == "dns_only":
            self.stop_arp_assisted("system", "dns_only mode active")
            self.flush_nftables()
            self._active_nft_ruleset = None
            self._set_ipv4_forwarding(False)
            return HealthResult(True, "DNS-only mode active")

        if config.mode == "arp_assisted":
            readiness = self._arp_assisted_preflight(config)
            if not readiness.healthy:
                self.stop_arp_assisted("system", readiness.summary)
                self.flush_nftables()
                self._active_nft_ruleset = None
                return readiness

        if config.mode in {"inline_gateway", "router_integrated", "arp_assisted"}:
            self.apply_nftables(config, blocked_ips=blocked)

        if config.enable_ipv4_forwarding or config.mode in {"inline_gateway", "arp_assisted"}:
            self._configure_forwarding(config.interface)

        if config.mode == "arp_assisted":
            result = self.apply_arp_assisted(config)
            if blocked:
                return HealthResult(True, f"{result.summary}; {len(blocked)} device(s) paused/scheduled")
            return result

        self.stop_arp_assisted("system", f"{config.mode} mode active")
        return HealthResult(True, f"{config.mode} mode active")

    def apply_nftables(
        self,
        config: NetworkConfig,
        blocked_ips: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        dns_redirect = ""
        if config.dns_redirect_port_53:
            dns_redirect = f"""
    iifname "{config.interface}" ip saddr {config.lan_cidr} udp dport 53 redirect to :53
    iifname "{config.interface}" ip saddr {config.lan_cidr} tcp dport 53 redirect to :53
"""

        nat_source_match = str(config.lan_cidr)
        traffic_counters = ""
        private_dns_block = ""
        privacy_block = ""
        pause_block = ""
        if config.mode == "arp_assisted":
            target_list = ", ".join(str(target) for target in config.arp_assisted_targets)
            nat_source_match = f"{{ {target_list} }}" if target_list else "{ 0.0.0.0 }"
            # Per-target counters: allow new outbound from linked devices; inbound only from LAN
            # (WAN replies already match established/related). Blocks unsolicited internet→device.
            for target in config.arp_assisted_targets:
                traffic_counters += f"""
    iifname "{config.interface}" ip saddr {target} counter accept
    oifname "{config.interface}" ip daddr {target} ip saddr {config.lan_cidr} counter accept
"""
            if target_list:
                # Block DNS-over-TLS so Private DNS falls back to plain DNS (redirected to Pi-hole).
                private_dns_block = f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} tcp dport 853 drop
    iifname "{config.interface}" ip saddr {{ {target_list} }} udp dport 853 drop
"""
                # Drop QUIC (UDP/443) so DoH/HTTP3 cannot skip Pi-hole as easily.
                if getattr(config, "block_quic_for_linked", True):
                    privacy_block += f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} udp dport 443 drop
"""
                # Drop new WAN→device forwards (LAN inbound already accepted above).
                if getattr(config, "block_wan_inbound_for_linked", True):
                    privacy_block += f"""
    oifname "{config.interface}" ip daddr {{ {target_list} }} ip saddr != {config.lan_cidr} drop
"""
            blocked = [str(ip) for ip in (blocked_ips or []) if str(ip) in {str(t) for t in config.arp_assisted_targets}]
            if blocked:
                blocked_list = ", ".join(blocked)
                # Drop before established/related so pause/bedtime cuts active sessions too.
                pause_block = f"""
    iifname "{config.interface}" ip saddr {{ {blocked_list} }} drop
    oifname "{config.interface}" ip daddr {{ {blocked_list} }} drop
"""

        ruleset = f"""
table inet {PI_CIRCLE_TABLE} {{
  chain forward_guard {{
    type filter hook forward priority 0; policy accept;
{pause_block}
    ct state established,related accept
{private_dns_block}
{traffic_counters}
{privacy_block}
    iifname "{config.interface}" ip saddr {config.lan_cidr} accept
  }}

  chain prerouting_dns {{
    type nat hook prerouting priority dstnat; policy accept;
{dns_redirect}
  }}

  chain postrouting_nat {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{config.interface}" ip saddr {nat_source_match} masquerade
        }}
}}
"""
        # Skip rewrite when unchanged so per-target counters keep accumulating.
        if self._active_nft_ruleset == ruleset:
            return
        self.runner.run(["nft", "delete", "table", "inet", PI_CIRCLE_TABLE], check=False)
        proc = subprocess.run(["nft", "-f", "-"], input=ruleset, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to apply nftables rules: {proc.stderr.strip()}")
        self._active_nft_ruleset = ruleset

    def flush_nftables(self) -> None:
        self.runner.run(["nft", "delete", "table", "inet", PI_CIRCLE_TABLE], check=False)
        self._active_nft_ruleset = None

    def _configure_forwarding(self, interface: str) -> None:
        self._set_ipv4_forwarding(True)
        for key in (
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.default.send_redirects",
            f"net.ipv4.conf.{interface}.send_redirects",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            f"net.ipv4.conf.{interface}.rp_filter",
        ):
            self.runner.run(["sysctl", "-w", f"{key}=0"], check=False)

    def _set_ipv4_forwarding(self, enabled: bool) -> None:
        self.runner.run(["sysctl", "-w", f"net.ipv4.ip_forward={int(enabled)}"])

    def apply_arp_assisted(self, config: NetworkConfig) -> HealthResult:
        readiness = self._arp_assisted_preflight(config)
        if not readiness.healthy:
            self.stop_arp_assisted("system", readiness.summary)
            return readiness
        arpspoof_path = _binary_path("arpspoof")
        if arpspoof_path is None:
            return HealthResult(False, "arpspoof is not installed; install dsniff on the Pi")

        expected_keys = set()
        for target in config.arp_assisted_targets:
            expected_keys.add(f"client:{target}")
            expected_keys.add(f"gateway:{target}")
            self._ensure_arpspoof(f"client:{target}", config.interface, target, config.gateway_ip, arpspoof_path)
            self._ensure_arpspoof(f"gateway:{target}", config.interface, config.gateway_ip, target, arpspoof_path)

        for key in list(self._arp_processes):
            if key not in expected_keys:
                self._stop_process(key)

        return HealthResult(True, f"ARP-assisted control active for {len(config.arp_assisted_targets)} target(s)")

    def _arp_assisted_preflight(self, config: NetworkConfig) -> HealthResult:
        if not config.arp_assisted_enabled:
            return HealthResult(False, "ARP-assisted mode requested but disabled")
        if not config.arp_assisted_targets:
            return HealthResult(False, "No ARP-assisted targets configured")
        if os.geteuid() != 0:
            return HealthResult(False, "ARP-assisted mode requires root")
        if _binary_path("arpspoof") is None:
            return HealthResult(False, "arpspoof is not installed; install dsniff on the Pi")
        interface_addresses = _interface_ipv4_addresses(config.interface)
        local_targets = [target for target in config.arp_assisted_targets if target in interface_addresses]
        if local_targets:
            return HealthResult(False, f"ARP-assisted target cannot be the Pi address: {local_targets[0]}")
        return HealthResult(True, "ARP-assisted preflight passed")

    def stop_arp_assisted(self, actor: str, reason: str) -> None:
        for key in list(self._arp_processes):
            self._stop_process(key)
        self.audit.write(AuditEvent("network.arp_assisted.stopped", actor, "success", reason))

    def _ensure_arpspoof(
        self,
        key: str,
        interface: str,
        target: IPv4Address,
        host: IPv4Address,
        arpspoof_path: str = "arpspoof",
    ) -> None:
        process = self._arp_processes.get(key)
        if process and process.poll() is None:
            return
        args = [arpspoof_path, "-i", interface, "-t", str(target), str(host)]
        process = self.runner.popen(args)
        self._arp_processes[key] = process
        self.audit.write(AuditEvent("network.arp_assisted.process_started", "agent", "success", "process started", key))
        time.sleep(0.2)
        if process.poll() is not None:
            stderr = ""
            if process.stderr is not None:
                stderr = process.stderr.read().strip()
            self._arp_processes.pop(key, None)
            message = stderr or f"arpspoof exited with status {process.returncode}"
            self.audit.write(AuditEvent("network.arp_assisted.process_failed", "agent", "failure", message, key))
            raise RuntimeError(f"Failed to start ARP-assisted process {key}: {message}")

    def _stop_process(self, key: str) -> None:
        process = self._arp_processes.pop(key, None)
        if process is None:
            return
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        self.audit.write(AuditEvent("network.arp_assisted.process_stopped", "agent", "success", "process stopped", key))


def _binary_path(name: str) -> str | None:
    path = os.environ.get("PATH", "")
    search_path = os.pathsep.join(filter(None, [path, "/usr/local/sbin", "/usr/sbin", "/sbin"]))
    return shutil.which(name, path=search_path)


def _interface_ipv4_addresses(interface: str) -> set[IPv4Address]:
    completed = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return set()
    addresses: set[IPv4Address] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        raw_address = parts[3].split("/", 1)[0]
        try:
            addresses.add(IPv4Address(raw_address))
        except ValueError:
            continue
    return addresses
