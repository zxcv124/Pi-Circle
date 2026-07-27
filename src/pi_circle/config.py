from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from os import PathLike
from pathlib import Path
import tomllib


DEFAULT_CONFIG_PATH = Path("/etc/pi-circle/config.toml")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Paths:
    state_dir: Path = Path("/var/lib/pi-circle")
    log_dir: Path = Path("/var/log/pi-circle")
    pihole_dir: Path = Path("/etc/pihole")
    database: Path = Path("/var/lib/pi-circle/pi-circle.db")
    audit_log: Path = Path("/var/log/pi-circle/audit.jsonl")


@dataclass(frozen=True)
class NetworkConfig:
    mode: str = "dns_only"
    interface: str = "wlan0"
    lan_cidr: IPv4Network = ip_network("192.168.1.0/24")
    gateway_ip: IPv4Address = ip_address("192.168.1.1")
    enable_ipv4_forwarding: bool = False
    dns_redirect_port_53: bool = False
    arp_assisted_enabled: bool = False
    arp_assisted_targets: tuple[IPv4Address, ...] = field(default_factory=tuple)
    unmanaged_ips: tuple[IPv4Address, ...] = field(default_factory=tuple)
    block_quic_for_linked: bool = True
    block_wan_inbound_for_linked: bool = False
    # Prefer IPv4 for linked DNS/path: suppress AAAA answers and drop forwarded IPv6.
    force_ipv4: bool = True
    # Hijack plain DNS to Pi-hole and block common DoH/DoT bypass resolvers for linked devices.
    force_pi_dns: bool = True


@dataclass(frozen=True)
class PrivacyConfig:
    enabled: bool = True
    strict: bool = False
    sync_pihole_denylist: bool = True
    alert_on_hits: bool = True


@dataclass(frozen=True)
class DiscoveryConfig:
    use_nmap: bool = True
    auto_link_android: bool = False
    nmap_interval_seconds: int = 900
    nmap_max_hosts: int = 8


@dataclass(frozen=True)
class DashboardConfig:
    host: str = "0.0.0.0"
    port: int = 8088
    trusted_proxy_cidrs: tuple[IPv4Network, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityConfig:
    require_lan_admin: bool = True
    session_minutes: int = 480
    audit_retention_days: int = 180
    alert_webhook_url: str = ""


@dataclass(frozen=True)
class PiholeConfig:
    api_base_url: str = "http://127.0.0.1/api"
    config_path: Path = Path("/etc/pihole/pihole.toml")
    gravity_db: Path = Path("/etc/pihole/gravity.db")
    ftl_db: Path = Path("/etc/pihole/pihole-FTL.db")


@dataclass(frozen=True)
class Settings:
    paths: Paths
    network: NetworkConfig
    dashboard: DashboardConfig
    security: SecurityConfig
    pihole: PiholeConfig
    privacy: PrivacyConfig
    discovery: DiscoveryConfig


def _path(value: object, default: Path) -> Path:
    if value is None:
        return default
    return Path(str(value))


def _ipv4(value: object, field_name: str) -> IPv4Address:
    try:
        parsed = ip_address(str(value))
    except ValueError as exc:
        raise ConfigError(f"{field_name} must be a valid IPv4 address") from exc
    if parsed.version != 4:
        raise ConfigError(f"{field_name} must be IPv4")
    return parsed


def _ipv4_network(value: object, field_name: str) -> IPv4Network:
    try:
        parsed = ip_network(str(value), strict=False)
    except ValueError as exc:
        raise ConfigError(f"{field_name} must be a valid IPv4 CIDR") from exc
    if parsed.version != 4:
        raise ConfigError(f"{field_name} must be IPv4")
    return parsed


def _ipv4_tuple(values: object, field_name: str) -> tuple[IPv4Address, ...]:
    if values is None:
        return tuple()
    if not isinstance(values, list):
        raise ConfigError(f"{field_name} must be an array")
    return tuple(_ipv4(value, field_name) for value in values)


def _network_tuple(values: object, field_name: str) -> tuple[IPv4Network, ...]:
    if values is None:
        return tuple()
    if not isinstance(values, list):
        raise ConfigError(f"{field_name} must be an array")
    return tuple(_ipv4_network(value, field_name) for value in values)


def load_settings(path: str | PathLike[str] | Path = DEFAULT_CONFIG_PATH) -> Settings:
    raw: dict[str, object] = {}
    path = Path(path)
    if path.exists():
        raw = tomllib.loads(path.read_text(encoding="utf-8"))

    paths_raw = raw.get("paths", {})
    network_raw = raw.get("network", {})
    dashboard_raw = raw.get("dashboard", {})
    security_raw = raw.get("security", {})
    pihole_raw = raw.get("pihole", {})
    privacy_raw = raw.get("privacy", {})
    discovery_raw = raw.get("discovery", {})

    if not isinstance(paths_raw, dict):
        raise ConfigError("[paths] must be a table")
    if not isinstance(network_raw, dict):
        raise ConfigError("[network] must be a table")
    if not isinstance(dashboard_raw, dict):
        raise ConfigError("[dashboard] must be a table")
    if not isinstance(security_raw, dict):
        raise ConfigError("[security] must be a table")
    if not isinstance(pihole_raw, dict):
        raise ConfigError("[pihole] must be a table")
    if not isinstance(privacy_raw, dict):
        raise ConfigError("[privacy] must be a table")
    if not isinstance(discovery_raw, dict):
        raise ConfigError("[discovery] must be a table")

    paths = Paths(
        state_dir=_path(paths_raw.get("state_dir"), Paths.state_dir),
        log_dir=_path(paths_raw.get("log_dir"), Paths.log_dir),
        pihole_dir=_path(paths_raw.get("pihole_dir"), Paths.pihole_dir),
        database=_path(paths_raw.get("database"), Paths.database),
        audit_log=_path(paths_raw.get("audit_log"), Paths.audit_log),
    )

    mode = str(network_raw.get("mode", "dns_only"))
    if mode not in {"dns_only", "router_integrated", "inline_gateway", "arp_assisted"}:
        raise ConfigError("network.mode must be dns_only, router_integrated, inline_gateway, or arp_assisted")

    network = NetworkConfig(
        mode=mode,
        interface=str(network_raw.get("interface", "wlan0")),
        lan_cidr=_ipv4_network(network_raw.get("lan_cidr", "192.168.1.0/24"), "network.lan_cidr"),
        gateway_ip=_ipv4(network_raw.get("gateway_ip", "192.168.1.1"), "network.gateway_ip"),
        enable_ipv4_forwarding=bool(network_raw.get("enable_ipv4_forwarding", False)),
        dns_redirect_port_53=bool(network_raw.get("dns_redirect_port_53", False)),
        arp_assisted_enabled=bool(network_raw.get("arp_assisted_enabled", False)),
        arp_assisted_targets=_ipv4_tuple(network_raw.get("arp_assisted_targets", []), "network.arp_assisted_targets"),
        unmanaged_ips=_ipv4_tuple(network_raw.get("unmanaged_ips", []), "network.unmanaged_ips"),
        block_quic_for_linked=bool(network_raw.get("block_quic_for_linked", True)),
        block_wan_inbound_for_linked=bool(network_raw.get("block_wan_inbound_for_linked", False)),
        force_ipv4=bool(network_raw.get("force_ipv4", True)),
        force_pi_dns=bool(network_raw.get("force_pi_dns", True)),
    )

    if network.gateway_ip not in network.lan_cidr:
        raise ConfigError("network.gateway_ip must be inside network.lan_cidr")
    for target in network.arp_assisted_targets:
        if target not in network.lan_cidr:
            raise ConfigError(f"ARP target {target} is outside network.lan_cidr")
        if target == network.gateway_ip:
            raise ConfigError("network.arp_assisted_targets cannot include network.gateway_ip")
        if target in network.unmanaged_ips:
            raise ConfigError(f"ARP target {target} is also listed as unmanaged")
    if network.mode == "arp_assisted" and not network.arp_assisted_enabled:
        raise ConfigError("network.arp_assisted_enabled must be true when network.mode is arp_assisted")

    dashboard = DashboardConfig(
        host=str(dashboard_raw.get("host", "0.0.0.0")),
        port=int(dashboard_raw.get("port", 8088)),
        trusted_proxy_cidrs=_network_tuple(dashboard_raw.get("trusted_proxy_cidrs", []), "dashboard.trusted_proxy_cidrs"),
    )
    if dashboard.port < 1 or dashboard.port > 65535:
        raise ConfigError("dashboard.port must be between 1 and 65535")

    security = SecurityConfig(
        require_lan_admin=bool(security_raw.get("require_lan_admin", True)),
        session_minutes=int(security_raw.get("session_minutes", 480)),
        audit_retention_days=int(security_raw.get("audit_retention_days", 180)),
        alert_webhook_url=str(security_raw.get("alert_webhook_url", "") or ""),
    )
    if security.session_minutes < 5:
        raise ConfigError("security.session_minutes must be at least 5")

    pihole = PiholeConfig(
        api_base_url=str(pihole_raw.get("api_base_url", "http://127.0.0.1/api")),
        config_path=_path(pihole_raw.get("config_path"), PiholeConfig.config_path),
        gravity_db=_path(pihole_raw.get("gravity_db"), PiholeConfig.gravity_db),
        ftl_db=_path(pihole_raw.get("ftl_db"), PiholeConfig.ftl_db),
    )

    privacy = PrivacyConfig(
        enabled=bool(privacy_raw.get("enabled", True)),
        strict=bool(privacy_raw.get("strict", False)),
        sync_pihole_denylist=bool(privacy_raw.get("sync_pihole_denylist", True)),
        alert_on_hits=bool(privacy_raw.get("alert_on_hits", True)),
    )

    discovery = DiscoveryConfig(
        use_nmap=bool(discovery_raw.get("use_nmap", True)),
        auto_link_android=bool(discovery_raw.get("auto_link_android", False)),
        nmap_interval_seconds=max(60, int(discovery_raw.get("nmap_interval_seconds", 900))),
        nmap_max_hosts=max(1, min(32, int(discovery_raw.get("nmap_max_hosts", 8)))),
    )

    return Settings(
        paths=paths,
        network=network,
        dashboard=dashboard,
        security=security,
        pihole=pihole,
        privacy=privacy,
        discovery=discovery,
    )
