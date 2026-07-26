from __future__ import annotations

from dataclasses import dataclass
import re


# Common LAN OUI prefixes (first 3 MAC octets). Enough for household labeling without
# shipping a full IEEE database.
OUI_VENDORS: dict[str, str] = {
    "00:03:93": "Apple",
    "00:0a:95": "Apple",
    "00:1b:63": "Apple",
    "00:1e:c2": "Apple",
    "00:23:12": "Apple",
    "00:25:00": "Apple",
    "00:26:08": "Apple",
    "00:26:b0": "Apple",
    "00:26:bb": "Apple",
    "04:0c:ce": "Apple",
    "04:15:52": "Apple",
    "14:10:9f": "Apple",
    "18:65:90": "Apple",
    "28:37:37": "Apple",
    "28:cf:e9": "Apple",
    "3c:07:54": "Apple",
    "40:33:1a": "Apple",
    "48:43:dd": "Apple",
    "50:ea:d6": "Apple",
    "58:55:ca": "Apple",
    "60:03:08": "Apple",
    "60:c5:47": "Apple",
    "64:a3:cb": "Apple",
    "68:ab:1e": "Apple",
    "70:48:0f": "Apple",
    "78:31:c1": "Apple",
    "7c:6d:62": "Apple",
    "80:e6:50": "Apple",
    "88:63:df": "Apple",
    "8c:85:90": "Apple",
    "a4:5e:60": "Apple",
    "a8:60:b6": "Apple",
    "ac:87:a3": "Apple",
    "b8:53:ac": "Apple",
    "bc:52:b7": "Apple",
    "c8:69:cd": "Apple",
    "d0:03:4b": "Apple",
    "d8:30:62": "Apple",
    "dc:a9:04": "Apple",
    "e0:ac:cb": "Apple",
    "f0:d1:a9": "Apple",
    "f4:5c:89": "Apple",
    "fc:e9:98": "Apple",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "54:60:09": "Google",
    "f4:f5:d8": "Google",
    "f4:f5:e8": "Google",
    "00:1a:79": "Samsung",
    "08:ec:a9": "Samsung",
    "14:49:e0": "Samsung",
    "18:3a:2d": "Samsung",
    "20:55:31": "Samsung",
    "24:4b:03": "Samsung",
    "28:39:5e": "Samsung",
    "34:23:ba": "Samsung",
    "38:aa:3c": "Samsung",
    "40:4e:36": "Samsung",
    "5c:0a:5b": "Samsung",
    "78:25:ad": "Samsung",
    "8c:77:12": "Samsung",
    "a0:0b:ba": "Samsung",
    "cc:07:ab": "Samsung",
    "e8:50:8b": "Samsung",
    "fc:a6:21": "Samsung",
    "00:17:fa": "Microsoft",
    "00:1d:d8": "Microsoft",
    "00:22:48": "Microsoft",
    "28:18:78": "Microsoft",
    "3c:83:75": "Microsoft",
    "60:45:bd": "Microsoft",
    "7c:1e:52": "Microsoft",
    "98:5f:d3": "Microsoft",
    "c8:3f:26": "Microsoft",
    "00:50:f2": "Microsoft",
    "00:24:d7": "Intel",
    "00:1b:21": "Intel",
    "3c:f8:62": "Intel",
    "64:5a:ed": "Intel",
    "80:86:f2": "Intel",
    "a0:36:9f": "Intel",
    "f8:63:3f": "Intel",
    "00:1e:c0": "Amazon",
    "0c:47:c9": "Amazon",
    "34:d2:70": "Amazon",
    "40:b4:cd": "Amazon",
    "44:65:0d": "Amazon",
    "50:dc:e7": "Amazon",
    "68:37:e9": "Amazon",
    "74:c2:46": "Amazon",
    "84:d6:d0": "Amazon",
    "a0:02:dc": "Amazon",
    "fc:65:de": "Amazon",
    "10:ae:60": "Amazon",
    "18:b4:30": "Nest",
    "64:16:66": "Nest",
    "00:09:2d": "HTC",
    "00:16:cf": "Liteon",
    "00:17:9a": "TP-Link",
    "14:eb:b6": "TP-Link",
    "50:c7:bf": "TP-Link",
    "60:32:b1": "TP-Link",
    "98:da:c4": "TP-Link",
    "a0:f3:c1": "TP-Link",
    "b0:be:76": "TP-Link",
    "c0:25:e9": "TP-Link",
    "00:1d:0f": "TP-Link",
    "00:24:b2": "Netgear",
    "20:4e:7f": "Netgear",
    "28:c6:8e": "Netgear",
    "a0:04:60": "Netgear",
    "00:18:e7": "Sony",
    "00:1d:ba": "Sony",
    "28:0d:fc": "Sony",
    "a8:e3:ee": "Sony",
    "00:1e:3d": "Roku",
    "b0:a7:37": "Roku",
    "c8:3a:6b": "Roku",
    "d8:31:34": "Roku",
    "08:66:98": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "34:ce:00": "Xiaomi",
    "64:cc:2e": "Xiaomi",
    "78:11:dc": "Xiaomi",
    "f8:a4:5f": "Xiaomi",
    "00:1a:22": "LG",
    "00:1e:75": "LG",
    "10:68:3f": "LG",
    "20:a2:e4": "Apple",
    "58:11:22": "Apple",
    "4e:66:79": "Phone",  # randomized locally administered often Android/iPhone
}


@dataclass(frozen=True)
class IdentitySuggestion:
    display_name: str
    device_type: str
    vendor: str | None
    confidence: str
    reason: str


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None


def lookup_vendor(mac: str | None) -> str | None:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    # Locally administered MACs (privacy MAC) often flip the U/L bit.
    if _is_randomized_mac(normalized):
        return "Private MAC"
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_VENDORS.get(prefix)


def suggest_identity(
    *,
    hostname: str | None,
    mac_address: str | None,
    ip_address: str,
    gateway_ip: str | None = None,
) -> IdentitySuggestion:
    vendor = lookup_vendor(mac_address)
    host = _clean_hostname(hostname)
    device_type = _infer_type(host, vendor, ip_address, gateway_ip)

    if gateway_ip and ip_address == gateway_ip:
        return IdentitySuggestion("Router", "router", vendor or "Network", "high", "gateway address")

    if host:
        pretty = _titleize_host(host)
        if device_type != "unknown":
            return IdentitySuggestion(pretty, device_type, vendor, "high", "hostname")
        if vendor and vendor not in {"Private MAC", "Phone"}:
            return IdentitySuggestion(f"{vendor} · {pretty}", device_type, vendor, "high", "hostname+vendor")
        return IdentitySuggestion(pretty, device_type, vendor, "medium", "hostname")

    type_label = {
        "iphone": "iPhone",
        "ipad": "iPad",
        "android": "Android",
        "laptop": "Laptop",
        "pc": "PC",
        "tv": "TV",
        "game": "Game console",
        "iot": "Smart device",
        "router": "Router",
    }.get(device_type, "Device")

    if vendor and vendor not in {"Private MAC", "Phone"}:
        suffix = ip_address.split(".")[-1]
        return IdentitySuggestion(f"{vendor} {type_label}", device_type, vendor, "medium", "mac vendor")

    if vendor == "Private MAC":
        return IdentitySuggestion(f"{type_label} {ip_address.split('.')[-1]}", device_type, vendor, "low", "privacy mac")

    return IdentitySuggestion(f"{type_label} {ip_address.split('.')[-1]}", device_type, vendor, "low", "ip fallback")


def _is_randomized_mac(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def _clean_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    value = hostname.strip()
    for suffix in (".local", ".lan", ".home", ".home.arpa"):
        if value.lower().endswith(suffix):
            value = value[: -len(suffix)]
    value = value.strip(".-_ ")
    return value or None


def _titleize_host(host: str) -> str:
    spaced = re.sub(r"[_\.-]+", " ", host)
    spaced = re.sub(r"\s+", " ", spaced).strip()
    if not spaced:
        return host
    # Keep common device tokens readable.
    return " ".join(part.upper() if part.lower() in {"tv", "pc", "xbox", "ps5"} else part.capitalize() for part in spaced.split())


def _infer_type(host: str | None, vendor: str | None, ip_address: str, gateway_ip: str | None) -> str:
    from .storage import infer_device_type

    inferred = infer_device_type(host, ip_address)
    if inferred != "unknown":
        return inferred
    if gateway_ip and ip_address == gateway_ip:
        return "router"
    vendor_l = (vendor or "").lower()
    host_l = (host or "").lower()
    if "apple" in vendor_l:
        if "ipad" in host_l:
            return "ipad"
        if "macbook" in host_l or "mac" in host_l:
            return "laptop"
        return "iphone"
    if "samsung" in vendor_l or "xiaomi" in vendor_l or "google" in vendor_l and "nest" not in vendor_l:
        return "android"
    if "amazon" in vendor_l or "roku" in vendor_l or "lg" in vendor_l or "sony" in vendor_l:
        return "tv"
    if "nest" in vendor_l or "tp-link" in vendor_l or "netgear" in vendor_l:
        return "iot"
    if "microsoft" in vendor_l or "intel" in vendor_l:
        return "pc"
    return "unknown"
