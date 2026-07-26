from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
import socket
import subprocess
import time


PI_CIRCLE_TABLE = "pi_circle"
CONNTRACK_PATH = Path("/proc/net/nf_conntrack")
CONNTRACK_BIN = Path("/usr/sbin/conntrack")
_REVERSE_DNS_CACHE: dict[str, tuple[float, str]] = {}
_REVERSE_DNS_TTL = 300.0


@dataclass(frozen=True)
class DeviceBandwidth:
    ip_address: str
    bytes_total: int
    packets_total: int
    connections: int
    source: str
    sampled_at: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def sample_device_bandwidth(ips: list[str] | set[str]) -> dict[str, DeviceBandwidth]:
    """Sample per-device traffic: prefer nft counters for volume, conntrack for connection counts."""
    wanted = {str(ip) for ip in ips}
    if not wanted:
        return {}
    nft = _sample_nft_counters(wanted)
    ct = _sample_conntrack(wanted)
    if not nft and not ct:
        return {}
    now = time.time()
    merged: dict[str, DeviceBandwidth] = {}
    for ip in wanted:
        nft_row = nft.get(ip)
        ct_row = ct.get(ip)
        if nft_row is None and ct_row is None:
            continue
        if nft_row is not None and ct_row is not None:
            merged[ip] = DeviceBandwidth(
                ip,
                nft_row.bytes_total,
                nft_row.packets_total,
                ct_row.connections,
                "nftables+conntrack",
                now,
            )
        elif nft_row is not None:
            merged[ip] = DeviceBandwidth(
                ip,
                nft_row.bytes_total,
                nft_row.packets_total,
                0,
                "nftables",
                now,
            )
        else:
            assert ct_row is not None
            merged[ip] = ct_row
    return merged


def list_active_connections(
    ip_address: str,
    *,
    limit: int = 40,
    resolve_hosts: bool = True,
) -> list[dict[str, object]]:
    """Inspect active L4 flows for a linked/on-path device (Sniffnet-style connections)."""
    limit = max(1, min(int(limit), 100))
    target = str(ip_address)
    text = _read_conntrack_text()
    if not text:
        return []
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        if f"src={target}" not in line and f"dst={target}" not in line:
            continue
        parsed = _parse_conntrack_line(line, target)
        if parsed:
            rows.append(parsed)
    rows.sort(key=lambda item: (-int(item["bytes"]), str(item["remote"]), str(item.get("remotePort") or "")))
    rows = rows[:limit]
    if resolve_hosts:
        for row in rows:
            host = reverse_lookup(str(row["remote"]))
            if host:
                row["host"] = host
    return rows


def summarize_flows(
    connections: list[dict[str, object]],
    *,
    top_limit: int = 8,
    exclude_remotes: set[str] | None = None,
) -> dict[str, object]:
    """Roll up protocol mix and top remote hosts from a connection snapshot."""
    skip = {str(ip) for ip in (exclude_remotes or set())}
    proto_counts: Counter[str] = Counter()
    proto_bytes: Counter[str] = Counter()
    remote_bytes: dict[str, dict[str, object]] = {}
    for row in connections:
        proto = str(row.get("protocol") or "unknown").lower()
        nbytes = int(row.get("bytes") or 0)
        proto_counts[proto] += 1
        proto_bytes[proto] += nbytes
        remote = str(row.get("remote") or "")
        if not remote or remote in skip:
            continue
        bucket = remote_bytes.setdefault(
            remote,
            {
                "remote": remote,
                "host": row.get("host") or "",
                "bytes": 0,
                "flows": 0,
                "serviceHint": row.get("serviceHint") or "",
            },
        )
        bucket["bytes"] = int(bucket["bytes"]) + nbytes
        bucket["flows"] = int(bucket["flows"]) + 1
        if row.get("host") and not bucket["host"]:
            bucket["host"] = row["host"]
        hint = str(row.get("serviceHint") or "")
        if hint in {"HTTPS", "HTTP", "DNS", "DoT"}:
            bucket["serviceHint"] = hint

    protocols = [
        {
            "protocol": name,
            "flows": proto_counts[name],
            "bytes": proto_bytes[name],
        }
        for name in sorted(proto_counts, key=lambda key: (-proto_counts[key], -proto_bytes[key], key))
    ]
    top_remotes = sorted(
        remote_bytes.values(),
        key=lambda item: (-int(item["flows"]), -int(item["bytes"]), str(item["remote"])),
    )[: max(1, min(int(top_limit), 20))]
    return {
        "protocols": protocols,
        "topRemotes": top_remotes,
        "flowCount": len(connections),
    }


def reverse_lookup(ip_address: str) -> str:
    """Best-effort reverse DNS with a short in-process cache."""
    now = time.time()
    cached = _REVERSE_DNS_CACHE.get(ip_address)
    if cached and now - cached[0] < _REVERSE_DNS_TTL:
        return cached[1]
    host = ""
    try:
        socket.setdefaulttimeout(0.15)
        host = socket.gethostbyaddr(ip_address)[0]
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        host = ""
    finally:
        socket.setdefaulttimeout(None)
    _REVERSE_DNS_CACHE[ip_address] = (now, host)
    return host


def ensure_conntrack_accounting() -> None:
    """Enable per-flow byte/packet counters when the sysctl is available."""
    path = Path("/proc/sys/net/netfilter/nf_conntrack_acct")
    if not path.exists():
        return
    try:
        if path.read_text(encoding="utf-8").strip() != "1":
            path.write_text("1\n", encoding="utf-8")
    except OSError:
        return


def _read_conntrack_text() -> str:
    if CONNTRACK_PATH.exists():
        try:
            return CONNTRACK_PATH.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    if CONNTRACK_BIN.exists():
        try:
            proc = subprocess.run(
                [str(CONNTRACK_BIN), "-L", "-o", "extended"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if proc.returncode == 0:
            return proc.stdout
        # Permission denied for non-root without CAP_NET_ADMIN.
        return ""
    return ""


def _sample_nft_counters(wanted: set[str]) -> dict[str, DeviceBandwidth]:
    try:
        proc = subprocess.run(
            ["nft", "-j", "list", "table", "inet", PI_CIRCLE_TABLE],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}

    now = time.time()
    totals: dict[str, list[int]] = {ip: [0, 0] for ip in wanted}
    for entry in payload.get("nftables", []):
        rule = entry.get("rule")
        if not isinstance(rule, dict):
            continue
        ip = _rule_match_ip(rule)
        if ip not in wanted:
            continue
        packets, nbytes = _rule_counter(rule)
        totals[ip][0] += nbytes
        totals[ip][1] += packets

    return {
        ip: DeviceBandwidth(ip, bytes_total, packets_total, 0, "nftables", now)
        for ip, (bytes_total, packets_total) in totals.items()
        if bytes_total or packets_total
    }


def _rule_match_ip(rule: dict) -> str | None:
    for expr in rule.get("expr", []):
        match = expr.get("match") if isinstance(expr, dict) else None
        if not isinstance(match, dict):
            continue
        right = match.get("right")
        if isinstance(right, str) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", right):
            return right
        if isinstance(right, dict) and "prefix" in right:
            continue
    return None


def _rule_counter(rule: dict) -> tuple[int, int]:
    for expr in rule.get("expr", []):
        counter = expr.get("counter") if isinstance(expr, dict) else None
        if isinstance(counter, dict):
            return int(counter.get("packets") or 0), int(counter.get("bytes") or 0)
    return 0, 0


def _sample_conntrack(wanted: set[str]) -> dict[str, DeviceBandwidth]:
    text = _read_conntrack_text()
    if not text:
        return {}
    now = time.time()
    bytes_by_ip = {ip: 0 for ip in wanted}
    packets_by_ip = {ip: 0 for ip in wanted}
    conns_by_ip = {ip: 0 for ip in wanted}
    for line in text.splitlines():
        for ip in wanted:
            if f"src={ip}" not in line and f"dst={ip}" not in line:
                continue
            conns_by_ip[ip] += 1
            for match in re.finditer(r"bytes=(\d+)", line):
                bytes_by_ip[ip] += int(match.group(1))
            for match in re.finditer(r"packets=(\d+)", line):
                packets_by_ip[ip] += int(match.group(1))
            break
    return {
        ip: DeviceBandwidth(ip, bytes_by_ip[ip], packets_by_ip[ip], conns_by_ip[ip], "conntrack", now)
        for ip in wanted
        if bytes_by_ip[ip] or conns_by_ip[ip]
    }


def _parse_conntrack_line(line: str, local_ip: str) -> dict[str, object] | None:
    # /proc and `conntrack -L -o extended`: "ipv4 2 tcp 6 ..."
    # bare `conntrack -L`: "tcp 6 ESTABLISHED ..."
    proto_match = re.match(r"^(?:ipv[46]\s+\d+\s+)?([a-zA-Z]+)", line.strip())
    protocol = proto_match.group(1).lower() if proto_match else "unknown"
    if protocol.isdigit():
        protocol = "unknown"
    srcs = re.findall(r"src=([0-9.]+)", line)
    dsts = re.findall(r"dst=([0-9.]+)", line)
    sport = re.findall(r"sport=(\d+)", line)
    dport = re.findall(r"dport=(\d+)", line)
    bytes_vals = [int(value) for value in re.findall(r"bytes=(\d+)", line)]
    if not srcs or not dsts:
        return None
    src, dst = srcs[0], dsts[0]
    if src == local_ip:
        remote = dst
        local_port = sport[0] if sport else ""
        remote_port = dport[0] if dport else ""
        direction = "out"
    elif dst == local_ip:
        remote = src
        local_port = dport[0] if dport else ""
        remote_port = sport[0] if sport else ""
        direction = "in"
    else:
        # Masqueraded reply tuples often rewrite dst to the Pi — still treat original src as local.
        if srcs[0] == local_ip or (len(srcs) > 1 and srcs[0] == local_ip):
            remote = dsts[0]
            direction = "out"
            local_port = sport[0] if sport else ""
            remote_port = dport[0] if dport else ""
        else:
            remote = dsts[0]
            local_port = sport[0] if sport else ""
            remote_port = dport[0] if dport else ""
            direction = "related"
    return {
        "protocol": protocol,
        "remote": remote,
        "localPort": local_port,
        "remotePort": remote_port,
        "direction": direction,
        "bytes": sum(bytes_vals),
        "serviceHint": _port_hint(remote_port or local_port),
    }


def _port_hint(port: str) -> str:
    mapping = {
        "53": "DNS",
        "80": "HTTP",
        "443": "HTTPS",
        "853": "DoT",
        "123": "NTP",
        "22": "SSH",
        "993": "IMAPS",
        "995": "POP3S",
        "587": "SMTP",
        "3478": "STUN",
        "5222": "XMPP",
        "5228": "GCM",
        "19302": "WebRTC",
        "8080": "HTTP-alt",
        "8443": "HTTPS-alt",
    }
    return mapping.get(str(port), f"port {port}" if port else "unknown")
