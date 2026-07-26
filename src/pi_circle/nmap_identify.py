from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

from .storage import DEVICE_TYPES, Store


NMAP_BIN = Path("/usr/bin/nmap")
DEFAULT_MAX_HOSTS = 8
DEFAULT_TIMEOUT_SECONDS = 90


@dataclass(frozen=True)
class NmapIdentity:
    ip_address: str
    device_type: str
    vendor: str | None
    hostname: str | None
    os_guess: str | None
    confidence: str
    reason: str


def nmap_available(binary: Path = NMAP_BIN) -> bool:
    return binary.exists() or shutil.which("nmap") is not None


def _nmap_path(binary: Path = NMAP_BIN) -> str | None:
    if binary.exists():
        return str(binary)
    return shutil.which("nmap")


def _has_token(blob: str, *tokens: str) -> bool:
    """Whole-token match so short needles like 'ios' do not hit 'bios'."""
    for token in tokens:
        if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", blob):
            return True
    return False


def classify_os_text(text: str | None) -> str:
    """Map nmap OS / service text onto Pi-Circle device_type values."""
    blob = (text or "").lower()
    if not blob:
        return "unknown"
    if _has_token(blob, "android", "dalvik", "oneplus") or "pixel phone" in blob:
        return "android"
    # Vendor hints only when OS text is otherwise ambiguous phone-class.
    if _has_token(blob, "samsung", "xiaomi", "huawei", "oppo", "realme") and not _has_token(
        blob, "tizen", "smart", "tv", "router"
    ):
        return "android"
    if _has_token(blob, "iphone") or _has_token(blob, "ios"):
        return "iphone"
    if _has_token(blob, "ipad"):
        return "ipad"
    if "mac os" in blob or _has_token(blob, "macos", "macbook", "os x"):
        return "laptop"
    if _has_token(blob, "windows"):
        return "pc"
    if _has_token(blob, "roku", "tizen", "webos", "chromecast", "bravia") or "smart tv" in blob or "apple tv" in blob:
        return "tv"
    if _has_token(blob, "xbox", "playstation", "nintendo", "switch"):
        return "game"
    if _has_token(blob, "router", "openwrt", "gateway") or "linux embedded" in blob or "dd-wrt" in blob:
        return "router"
    if _has_token(blob, "printer", "esp", "tuya", "shelly", "nest") or _has_token(blob, "iot"):
        return "iot"
    return "unknown"


def fingerprint_hosts(
    ips: list[str] | set[str],
    *,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    binary: Path = NMAP_BIN,
) -> list[NmapIdentity]:
    """Run a bounded nmap OS/service scan and return identity hints."""
    targets = sorted({str(ip) for ip in ips if ip})[: max(1, min(int(max_hosts), 32))]
    if not targets:
        return []
    nmap = _nmap_path(binary)
    if not nmap:
        return []

    # Root agent: bounded OS detect + light service probe. host-timeout keeps phones snappy.
    command = [
        nmap,
        "-n",
        "-T4",
        "-Pn",
        "-O",
        "--osscan-guess",
        "--osscan-limit",
        "--max-os-tries",
        "1",
        "--top-ports",
        "20",
        "--host-timeout",
        "12s",
        "-oX",
        "-",
        *targets,
    ]
    try:
        proc = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(25, int(timeout_seconds)),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode not in {0, 1} or not proc.stdout.strip():
        # nmap returns 1 when some hosts are down / partial results.
        if not proc.stdout.strip():
            return []
    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_text: str) -> list[NmapIdentity]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    results: list[NmapIdentity] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") not in {None, "up"}:
            continue
        address = None
        vendor = None
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                address = addr.attrib.get("addr")
            if addr.attrib.get("addrtype") == "mac":
                vendor = addr.attrib.get("vendor") or vendor
        if not address:
            continue

        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for item in hostnames.findall("hostname"):
                name = item.attrib.get("name")
                if name:
                    hostname = name
                    break

        os_guess = None
        os_node = host.find("os")
        if os_node is not None:
            matches = os_node.findall("osmatch")
            if matches:
                os_guess = matches[0].attrib.get("name")

        service_bits: list[str] = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                service = port.find("service")
                if service is None:
                    continue
                for key in ("product", "extrainfo", "name", "ostype"):
                    value = service.attrib.get(key)
                    if value:
                        service_bits.append(value)

        combined = " ".join(part for part in (os_guess, vendor, hostname, " ".join(service_bits)) if part)
        device_type = classify_os_text(combined)
        if device_type == "unknown" and vendor:
            device_type = classify_os_text(vendor)
        if device_type not in DEVICE_TYPES:
            device_type = "unknown"

        confidence = "nmap" if device_type != "unknown" or os_guess else "low"
        reason = "nmap os" if os_guess else "nmap scan"
        results.append(
            NmapIdentity(
                ip_address=address,
                device_type=device_type,
                vendor=vendor,
                hostname=hostname,
                os_guess=os_guess,
                confidence=confidence,
                reason=reason,
            )
        )
    return results


def apply_nmap_identities(store: Store, identities: list[NmapIdentity]) -> int:
    """Persist nmap hints onto non-manual device rows. Returns updated count."""
    updated = 0
    for item in identities:
        device = store.get_device(item.ip_address)
        if device is None:
            continue
        if device.identity_confidence == "manual":
            continue
        changed = store.apply_discovered_identity(
            item.ip_address,
            device_type=item.device_type if item.device_type != "unknown" else None,
            vendor=item.vendor,
            hostname=item.hostname,
            display_name=_display_name_for(item, device.display_name),
            identity_confidence="nmap" if item.device_type != "unknown" else device.identity_confidence,
        )
        if changed:
            updated += 1
    return updated


def select_scan_targets(
    store: Store,
    present_ips: set[str],
    *,
    recently_scanned: dict[str, float],
    min_interval_seconds: int = 900,
    prefer_unknown: bool = True,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> list[str]:
    """Pick present hosts that still need nmap fingerprinting."""
    now = time.time()
    candidates: list[tuple[int, str]] = []
    for device in store.list_devices():
        ip = device.ip_address
        if ip not in present_ips:
            continue
        if device.identity_confidence == "manual":
            continue
        last = recently_scanned.get(ip, 0.0)
        age = now - last
        if device.device_type in {None, "", "unknown"}:
            if age < 120:
                continue
            priority = 0 if prefer_unknown else 1
        elif age < min_interval_seconds:
            continue
        else:
            priority = 2
        candidates.append((priority, ip))
    candidates.sort()
    return [ip for _, ip in candidates[: max(1, min(int(max_hosts), 32))]]


def _display_name_for(item: NmapIdentity, current: str | None) -> str | None:
    if current and not re.match(r"^(Device|Android|Phone|Unknown)\b", current, flags=re.I):
        # Keep a meaningful existing label.
        if item.device_type == "unknown":
            return None
    if item.hostname:
        return item.hostname.split(".")[0]
    if item.device_type == "android":
        vendor = item.vendor or "Android"
        return f"{vendor} Android"
    if item.os_guess:
        return item.os_guess.split("(")[0].strip()[:40] or None
    return None
