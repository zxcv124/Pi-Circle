from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
import subprocess

PIHOLE_CTL = Path("/usr/local/sbin/pi-circle-pihole-ctl")
GRAVITY_UPDATE_TIMER = "pi-circle-gravity-update.timer"
GRAVITY_UPDATE_SERVICE = "pi-circle-gravity-update.service"
DOMAIN_RE = re.compile(r"^[A-Za-z0-9._*-]{1,253}$")


@dataclass(frozen=True)
class PiholeControlStatus:
    installed: bool
    blocking_enabled: bool | None
    ftl_listening: bool | None
    raw: str
    core_version: str | None = None
    web_version: str | None = None
    ftl_version: str | None = None
    gravity_update: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PiholeControlResult:
    ok: bool
    command: str
    stdout: str
    stderr: str
    returncode: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_domain(domain: str) -> str:
    cleaned = (domain or "").strip().lower().rstrip(".")
    if not cleaned or not DOMAIN_RE.match(cleaned):
        raise ValueError(f"Invalid domain: {domain}")
    return cleaned


def validate_disable_duration(duration: str | None) -> str | None:
    if duration is None or duration == "":
        return None
    value = duration.strip().lower()
    if not re.fullmatch(r"[0-9]+[smh]?", value):
        raise ValueError("Disable duration must look like 30s, 5m, or 1h")
    return value


def read_status(*, pihole_dir: Path | None = None) -> PiholeControlStatus:
    versions = _read_versions(pihole_dir) if pihole_dir else {}
    gravity_update = read_gravity_update_status()
    if not _pihole_cli_available():
        return PiholeControlStatus(
            installed=False,
            blocking_enabled=None,
            ftl_listening=None,
            raw="Pi-hole is not installed",
            core_version=versions.get("CORE_VERSION"),
            web_version=versions.get("WEB_VERSION"),
            ftl_version=versions.get("FTL_VERSION"),
            gravity_update=gravity_update,
        )

    result = _run(["status"], timeout=30)
    text = (result.stdout or result.stderr or "").strip()
    lowered = text.lower()
    blocking: bool | None
    if "blocking is enabled" in lowered:
        blocking = True
    elif "blocking is disabled" in lowered:
        blocking = False
    else:
        blocking = None
    listening: bool | None
    if "ftl is listening" in lowered:
        listening = True
    elif "ftl is not listening" in lowered or "dns service is not running" in lowered:
        listening = False
    else:
        listening = None
    return PiholeControlStatus(
        installed=True,
        blocking_enabled=blocking,
        ftl_listening=listening,
        raw=text,
        core_version=versions.get("CORE_VERSION"),
        web_version=versions.get("WEB_VERSION"),
        ftl_version=versions.get("FTL_VERSION"),
        gravity_update=gravity_update,
    )


def read_gravity_update_status() -> dict[str, object]:
    """Return systemd timer state for automatic Pi-hole list updates."""
    timer = _systemctl_show(
        GRAVITY_UPDATE_TIMER,
        [
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "NextElapseUSecRealtime",
            "LastTriggerUSec",
            "Result",
        ],
    )
    service = _systemctl_show(
        GRAVITY_UPDATE_SERVICE,
        [
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "ExecMainStatus",
            "Result",
            "InactiveExitTimestamp",
        ],
    )
    timer_loaded = timer.get("LoadState") == "loaded"
    service_loaded = service.get("LoadState") == "loaded"
    return {
        "enabled": timer.get("UnitFileState") == "enabled",
        "active": timer.get("ActiveState") == "active",
        "installed": timer_loaded and service_loaded,
        "intervalHours": 48,
        "timerUnit": GRAVITY_UPDATE_TIMER,
        "serviceUnit": GRAVITY_UPDATE_SERVICE,
        "nextRun": _clean_systemd_time(timer.get("NextElapseUSecRealtime"))
        or _systemctl_list_timer_next(GRAVITY_UPDATE_TIMER),
        "lastRun": _clean_systemd_time(timer.get("LastTriggerUSec") or service.get("InactiveExitTimestamp")),
        "lastResult": service.get("Result") or timer.get("Result") or "unknown",
        "lastExitStatus": _parse_int(service.get("ExecMainStatus")),
        "detail": (
            "Automatic Pi-hole list updates run every 48 hours."
            if timer_loaded and service_loaded
            else "Automatic Pi-hole list update timer is not installed."
        ),
    }


def enable_blocking() -> PiholeControlResult:
    return _run(["enable"], timeout=60)


def disable_blocking(duration: str | None = None) -> PiholeControlResult:
    validated = validate_disable_duration(duration)
    args = ["disable"]
    if validated:
        args.append(validated)
    return _run(args, timeout=60)


def update_gravity(*, force: bool = False) -> PiholeControlResult:
    args = ["update-gravity"]
    if force:
        args.append("--force")
    return _run(args, timeout=900)


def reload_dns() -> PiholeControlResult:
    return _run(["reload-dns"], timeout=120)


def reload_lists() -> PiholeControlResult:
    return _run(["reload-lists"], timeout=120)


def flush_log() -> PiholeControlResult:
    return _run(["flush-log"], timeout=120)


def allow_domains(domains: list[str]) -> PiholeControlResult:
    cleaned = [validate_domain(item) for item in domains]
    if not cleaned:
        raise ValueError("At least one domain is required")
    return _run(["allow", *cleaned], timeout=120)


def deny_domains(domains: list[str]) -> PiholeControlResult:
    cleaned = [validate_domain(item) for item in domains]
    if not cleaned:
        raise ValueError("At least one domain is required")
    return _run(["deny", *cleaned], timeout=120)


def remove_allow_domains(domains: list[str]) -> PiholeControlResult:
    cleaned = [validate_domain(item) for item in domains]
    if not cleaned:
        raise ValueError("At least one domain is required")
    return _run(["allow-remove", *cleaned], timeout=120)


def remove_deny_domains(domains: list[str]) -> PiholeControlResult:
    cleaned = [validate_domain(item) for item in domains]
    if not cleaned:
        raise ValueError("At least one domain is required")
    return _run(["deny-remove", *cleaned], timeout=120)


def _pihole_cli_available() -> bool:
    if PIHOLE_CTL.exists():
        return True
    return Path("/usr/local/bin/pihole").exists() or Path("/usr/bin/pihole").exists()


def _run(args: list[str], *, timeout: int) -> PiholeControlResult:
    # Prefer the restricted helper when installed; otherwise call pihole directly.
    # Do not use sudo — the dashboard unit bounds capabilities and cannot elevate.
    if PIHOLE_CTL.exists():
        command = [str(PIHOLE_CTL), *args]
    else:
        command = ["pihole", *_map_direct(args)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return PiholeControlResult(
            ok=False,
            command=" ".join(command),
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr="Timed out waiting for Pi-hole control command",
            returncode=124,
        )
    except OSError as exc:
        return PiholeControlResult(
            ok=False,
            command=" ".join(command),
            stdout="",
            stderr=str(exc),
            returncode=127,
        )
    return PiholeControlResult(
        ok=completed.returncode == 0,
        command=" ".join(command),
        stdout=(completed.stdout or "").strip(),
        stderr=(completed.stderr or "").strip(),
        returncode=int(completed.returncode),
    )


def _systemctl_show(unit: str, properties: list[str]) -> dict[str, str]:
    command = ["systemctl", "show", unit, *[f"--property={item}" for item in properties], "--no-pager"]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    if completed.returncode != 0:
        return {}
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _systemctl_list_timer_next(unit: str) -> str | None:
    command = ["systemctl", "list-timers", unit, "--all", "--no-legend", "--no-pager"]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if completed.returncode != 0:
        return None
    line = completed.stdout.strip().splitlines()
    if not line:
        return None
    parts = line[0].split()
    if len(parts) < 4 or parts[0].lower() == "n/a":
        return None
    return " ".join(parts[:4])


def _clean_systemd_time(value: str | None) -> str | None:
    if not value or value in {"0", "n/a"}:
        return None
    return value


def _parse_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _map_direct(args: list[str]) -> list[str]:
    """Fallback mapping when the helper script is not installed yet."""
    if not args:
        return args
    head, *rest = args
    mapping = {
        "update-gravity": ["-g"],
        "reload-dns": ["reloaddns"],
        "reload-lists": ["reloadlists"],
        "flush-log": ["-f"],
        "allow-remove": ["allow", "remove"],
        "deny-remove": ["deny", "remove"],
    }
    if head in mapping:
        mapped = mapping[head]
        if head == "update-gravity" and rest == ["--force"]:
            return ["-g", "-f"]
        return [*mapped, *rest]
    return [head, *rest]


def _read_versions(pihole_dir: Path) -> dict[str, str]:
    versions_file = pihole_dir / "versions"
    if not versions_file.exists():
        return {}
    versions: dict[str, str] = {}
    for line in versions_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        versions[key.strip()] = value.strip()
    return versions
