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

# Public DoH/DoT bootstrap endpoints Chrome/Android often hardcode (bypass router DNS).
DOH_RESOLVER_IPS = (
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.228.168.9",
    "185.228.169.9",
    "76.76.2.0",
    "76.76.10.0",
    # Chrome Secure DNS (chrome.cloudflare-dns.com) anycast — not the same as 1.1.1.1
    "172.64.41.3",
    "162.159.61.3",
    "104.16.248.249",
    "104.16.249.249",
)

DOH_BOOTSTRAP_DOMAINS = (
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "cloudflare-dns.com",
    "dns.cloudflare.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "one.one.one.one",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.google.pki.goog",
    "dns.quad9.net",
    "dns.adguard.com",
    "dns-family.adguard.com",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
)


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
        self._force_ipv4_dns_applied: bool | None = None
        self._force_pi_dns_applied: bool | None = None
        self._doh_ips_cache: tuple[str, ...] | None = None
        self._doh_ips_cached_at: float = 0.0

    def apply(self, config: NetworkConfig, blocked_ips: list[str] | tuple[str, ...] | None = None) -> HealthResult:
        blocked = tuple(sorted({x for x in (blocked_ips or []) if x}))
        self._sync_force_ipv4_dns(bool(getattr(config, "force_ipv4", True)))
        self._sync_force_pi_dns(bool(getattr(config, "force_pi_dns", True)))
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
        nat_source_match = str(config.lan_cidr)
        traffic_counters = ""
        private_dns_block = ""
        privacy_block = ""
        pause_block = ""
        force_ipv4_block = ""
        linked_accept = ""

        if config.mode == "arp_assisted":
            target_list = ", ".join(str(target) for target in config.arp_assisted_targets)
            nat_source_match = f"{{ {target_list} }}" if target_list else "{ 0.0.0.0 }"
            # Counters only — never accept early or DoH/QUIC drops below are skipped (Circle-style).
            for target in config.arp_assisted_targets:
                traffic_counters += f"""
    iifname "{config.interface}" ip saddr {target} counter
    oifname "{config.interface}" ip daddr {target} ip saddr {config.lan_cidr} counter
"""
            if target_list:
                # DNS hijack + bypass shields ONLY for linked devices (never whole LAN).
                # Unlinked PCs/phones keep normal router DNS and are untouched by ARP.
                if config.dns_redirect_port_53 or getattr(config, "force_pi_dns", True):
                    dns_redirect = f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} udp dport 53 redirect to :53
    iifname "{config.interface}" ip saddr {{ {target_list} }} tcp dport 53 redirect to :53
"""
                if getattr(config, "force_ipv4", True):
                    # Only traffic hairpinned through the Pi (linked ARP path) hits forward.
                    # Unlinked LAN hosts never traverse this chain.
                    force_ipv4_block = """
    meta nfproto ipv6 drop
"""
                # DNS bypass shields MUST run before any linked accept / established shortcut.
                private_dns_block = f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} tcp dport 853 drop
    iifname "{config.interface}" ip saddr {{ {target_list} }} udp dport 853 drop
"""
                if getattr(config, "block_quic_for_linked", True):
                    privacy_block += f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} udp dport 443 drop
"""
                if getattr(config, "force_pi_dns", True):
                    doh_ips = ", ".join(self._doh_resolver_ips())
                    privacy_block += f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} ip daddr {{ {doh_ips} }} tcp dport 443 drop
    iifname "{config.interface}" ip saddr {{ {target_list} }} ip daddr {{ {doh_ips} }} udp dport {{ 53, 853, 443 }} drop
    iifname "{config.interface}" ip saddr {{ {target_list} }} ip daddr {{ {doh_ips} }} tcp dport {{ 53, 853 }} drop
"""
                # Do NOT drop "WAN inbound to linked IPs". On a Wi‑Fi client Pi, ARP hairpins
                # through the same interface; if masquerade misses a flow, that drop kills
                # return traffic and the whole linked phone looks offline ("nothing connects").
                # Allow remaining linked traffic after shields (keeps counters useful above).
                linked_accept = f"""
    iifname "{config.interface}" ip saddr {{ {target_list} }} accept
    oifname "{config.interface}" ip daddr {{ {target_list} }} ip saddr {config.lan_cidr} accept
"""
            blocked = [str(ip) for ip in (blocked_ips or []) if str(ip) in {str(t) for t in config.arp_assisted_targets}]
            if blocked:
                blocked_list = ", ".join(blocked)
                pause_block = f"""
    iifname "{config.interface}" ip saddr {{ {blocked_list} }} drop
    oifname "{config.interface}" ip daddr {{ {blocked_list} }} drop
"""
        else:
            # Non-ARP modes: optional whole-LAN :53 redirect only when explicitly enabled.
            if config.dns_redirect_port_53:
                dns_redirect = f"""
    iifname "{config.interface}" ip saddr {config.lan_cidr} udp dport 53 redirect to :53
    iifname "{config.interface}" ip saddr {config.lan_cidr} tcp dport 53 redirect to :53
"""
            if getattr(config, "force_ipv4", True):
                force_ipv4_block = """
    meta nfproto ipv6 drop
"""

        ruleset = f"""
table inet {PI_CIRCLE_TABLE} {{
  chain forward_guard {{
    type filter hook forward priority 0; policy accept;
{force_ipv4_block}
{pause_block}
{private_dns_block}
{privacy_block}
{traffic_counters}
{linked_accept}
    ct state established,related accept
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
        # Drop cached Secure DNS / DoH flows so kids' phones fall back without any phone settings.
        if config.mode == "arp_assisted" and getattr(config, "force_pi_dns", True):
            for target in config.arp_assisted_targets:
                subprocess.run(
                    ["conntrack", "-D", "-s", str(target)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=8,
                )

    def _doh_resolver_ips(self) -> tuple[str, ...]:
        """Static DoH IPs plus live A records for bootstrap hostnames (Chrome hardcodes many)."""
        now = time.monotonic()
        if self._doh_ips_cache is not None and now - self._doh_ips_cached_at < 3600:
            return self._doh_ips_cache

        found = set(DOH_RESOLVER_IPS)
        # Resolve via public DNS — Pi-hole may already deny these bootstrap names.
        for domain in DOH_BOOTSTRAP_DOMAINS:
            for resolver in ("208.67.222.222", "1.1.1.1"):
                try:
                    completed = subprocess.run(
                        ["dig", "+short", "+time=2", "+tries=1", domain, "A", f"@{resolver}"],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                except (subprocess.TimeoutExpired, OSError):
                    continue
                matched = False
                stdout = getattr(completed, "stdout", None)
                if not isinstance(stdout, str):
                    continue
                for line in stdout.splitlines():
                    candidate = line.strip()
                    if candidate.count(".") == 3 and all(part.isdigit() for part in candidate.split(".")):
                        found.add(candidate)
                        matched = True
                if matched:
                    break

        self._doh_ips_cache = tuple(sorted(found, key=lambda ip: tuple(int(part) for part in ip.split("."))))
        self._doh_ips_cached_at = now
        return self._doh_ips_cache

    def _sync_force_ipv4_dns(self, enabled: bool) -> None:
        """Suppress AAAA answers in Pi-hole when Force IPv4 is on (hot-apply once per change)."""
        if self._force_ipv4_dns_applied is enabled:
            return
        lines = '["filter-AAAA"]' if enabled else "[]"
        resolve_v6 = "false" if enabled else "true"
        for command in (
            ["pihole-FTL", "--config", "misc.dnsmasq_lines", lines],
            ["pihole-FTL", "--config", "resolver.resolveIPv6", resolve_v6],
        ):
            try:
                completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=15)
            except (subprocess.TimeoutExpired, OSError):
                return
            if completed.returncode != 0:
                return
        # filter-AAAA is only honored after FTL reloads its dnsmasq lines.
        try:
            subprocess.run(["systemctl", "reload", "pihole-FTL"], check=False, capture_output=True, text=True, timeout=20)
        except (subprocess.TimeoutExpired, OSError):
            try:
                subprocess.run(["systemctl", "restart", "pihole-FTL"], check=False, capture_output=True, text=True, timeout=30)
            except (subprocess.TimeoutExpired, OSError):
                return
        self._force_ipv4_dns_applied = enabled

    def _sync_force_pi_dns(self, enabled: bool) -> None:
        """Deny DoH bootstrap hostnames so phones fall back to redirected plain DNS."""
        if self._force_pi_dns_applied is enabled:
            return
        if enabled:
            command = ["pihole", "deny", "--comment", "Pi-Circle force-pi-dns", *DOH_BOOTSTRAP_DOMAINS]
        else:
            command = ["pihole", "deny", "remove", *DOH_BOOTSTRAP_DOMAINS]
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            return
        # Removal may return non-zero if domains were never denied; enabling should succeed.
        if enabled and completed.returncode != 0:
            return
        self._force_pi_dns_applied = enabled

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
