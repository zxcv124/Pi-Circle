from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import contextlib
import os
import sqlite3
import time


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  ip_address TEXT NOT NULL UNIQUE,
  mac_address TEXT,
  hostname TEXT,
  display_name TEXT,
  vendor TEXT,
  device_type TEXT NOT NULL DEFAULT 'unknown',
  profile_id INTEGER,
  identity_confidence TEXT NOT NULL DEFAULT 'low',
  managed INTEGER NOT NULL DEFAULT 0,
  paused INTEGER NOT NULL DEFAULT 0,
  transparent_control INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  bedtime_start TEXT,
  bedtime_end TEXT,
  daily_minutes INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_events (
  id INTEGER PRIMARY KEY,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  subject TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_health (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,
  healthy INTEGER NOT NULL,
  summary TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bandwidth_samples (
  id INTEGER PRIMARY KEY,
  ip_address TEXT NOT NULL,
  sampled_at REAL NOT NULL,
  bytes_total INTEGER NOT NULL,
  packets_total INTEGER NOT NULL,
  connections INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'unknown'
);
CREATE INDEX IF NOT EXISTS idx_bandwidth_samples_ip_time
  ON bandwidth_samples(ip_address, sampled_at DESC);

CREATE TABLE IF NOT EXISTS device_usage (
  day TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  minutes REAL NOT NULL DEFAULT 0,
  PRIMARY KEY(day, ip_address)
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  alert_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  subject TEXT,
  created_at TEXT NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type_subject ON alerts(alert_type, subject, created_at DESC);

CREATE TABLE IF NOT EXISTS access_requests (
  id INTEGER PRIMARY KEY,
  device_ip TEXT NOT NULL,
  domain TEXT NOT NULL,
  service TEXT,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_requests_status_created
  ON access_requests(status, created_at DESC);

CREATE TABLE IF NOT EXISTS community_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL DEFAULT 'private',
  organization_name TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retention_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  detailed_activity_days INTEGER NOT NULL DEFAULT 30,
  alert_days INTEGER NOT NULL DEFAULT 180,
  health_history_days INTEGER NOT NULL DEFAULT 30,
  audit_log_days INTEGER NOT NULL DEFAULT 180,
  report_days INTEGER NOT NULL DEFAULT 365,
  updated_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Device:
    ip_address: str
    mac_address: str | None
    hostname: str | None
    display_name: str | None
    vendor: str | None
    device_type: str
    profile_id: int | None
    profile_name: str | None
    identity_confidence: str
    managed: bool
    paused: bool
    transparent_control: bool
    last_seen: str


@dataclass(frozen=True)
class Profile:
    id: int
    name: str
    description: str
    bedtime_start: str | None
    bedtime_end: str | None
    daily_minutes: int | None
    device_count: int


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        self._restrict_database_files()
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _restrict_database_files(self) -> None:
        for path in (self.path, self.path.with_name(f"{self.path.name}-wal"), self.path.with_name(f"{self.path.name}-shm")):
            with contextlib.suppress(FileNotFoundError, PermissionError, OSError):
                os.chmod(path, 0o660)

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            _ensure_column(conn, "devices", "device_type", "TEXT NOT NULL DEFAULT 'unknown'")
            _ensure_column(conn, "devices", "vendor", "TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices(mac_address)")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_access_requests_device_created
                  ON access_requests(device_ip, created_at DESC)
                """
            )
            now = _now()
            conn.execute(
                """
                INSERT INTO community_settings(id, mode, organization_name, updated_at)
                VALUES(1, 'private', '', ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO retention_settings(
                    id,
                    detailed_activity_days,
                    alert_days,
                    health_history_days,
                    audit_log_days,
                    report_days,
                    updated_at
                )
                VALUES(1, 30, 180, 30, 180, 365, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (now,),
            )
            for name, description, bedtime_start, bedtime_end, daily_minutes in DEFAULT_PROFILES:
                conn.execute(
                    """
                    INSERT INTO profiles(name, description, bedtime_start, bedtime_end, daily_minutes, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO NOTHING
                    """,
                    (name, description, bedtime_start, bedtime_end, daily_minutes, now, now),
                )
            # Ensure Circle-like defaults if an older DB created profiles empty.
            conn.execute(
                """
                UPDATE profiles
                SET bedtime_start = COALESCE(bedtime_start, '21:00'),
                    bedtime_end = COALESCE(bedtime_end, '07:00'),
                    daily_minutes = COALESCE(daily_minutes, 120),
                    updated_at = ?
                WHERE name = 'Kids'
                  AND (bedtime_start IS NULL OR bedtime_end IS NULL OR daily_minutes IS NULL)
                """,
                (now,),
            )
            conn.execute(
                """
                UPDATE profiles
                SET bedtime_start = COALESCE(bedtime_start, '23:00'),
                    bedtime_end = COALESCE(bedtime_end, '07:00'),
                    daily_minutes = COALESCE(daily_minutes, 180),
                    updated_at = ?
                WHERE name = 'Guests'
                  AND (bedtime_start IS NULL OR bedtime_end IS NULL OR daily_minutes IS NULL)
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO network_health(id, mode, healthy, summary, updated_at)
                VALUES(1, 'dns_only', 1, 'Initialized', ?)
                ON CONFLICT(id) DO NOTHING
                """,
                (now,),
            )

    def upsert_device(
        self,
        ip_address: str,
        mac_address: str | None,
        hostname: str | None,
        confidence: str,
        *,
        gateway_ip: str | None = None,
    ) -> None:
        now = _now()
        inferred_type = infer_device_type(hostname, ip_address)
        normalized_mac = mac_address.lower() if mac_address else None
        with self.connect() as conn:
            if normalized_mac and self._migrate_device_ip(conn, ip_address, normalized_mac, hostname, inferred_type, confidence, now):
                self._auto_label_device(conn, ip_address, gateway_ip=gateway_ip)
                return
            conn.execute(
                """
                INSERT INTO devices(ip_address, mac_address, hostname, device_type, identity_confidence, first_seen, last_seen)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                  mac_address=COALESCE(excluded.mac_address, devices.mac_address),
                  hostname=COALESCE(excluded.hostname, devices.hostname),
                  device_type=CASE
                    WHEN devices.device_type = 'unknown' THEN excluded.device_type
                    ELSE devices.device_type
                  END,
                  identity_confidence=CASE
                    WHEN devices.identity_confidence = 'manual' THEN devices.identity_confidence
                    ELSE excluded.identity_confidence
                  END,
                  last_seen=excluded.last_seen
                """,
                (ip_address, normalized_mac, hostname, inferred_type, confidence, now, now),
            )
            self._auto_label_device(conn, ip_address, gateway_ip=gateway_ip)

    @staticmethod
    def _migrate_device_ip(
        conn: sqlite3.Connection,
        ip_address: str,
        mac_address: str,
        hostname: str | None,
        inferred_type: str,
        confidence: str,
        now: str,
    ) -> bool:
        mac_row = conn.execute(
            """
            SELECT id, ip_address
            FROM devices
            WHERE mac_address = ? AND ip_address != ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (mac_address, ip_address),
        ).fetchone()
        if mac_row is None:
            return False

        conflict = conn.execute(
            "SELECT id, mac_address FROM devices WHERE ip_address = ?",
            (ip_address,),
        ).fetchone()
        if conflict is not None and int(conflict["id"]) != int(mac_row["id"]):
            conflict_mac = str(conflict["mac_address"]).lower() if conflict["mac_address"] else None
            if conflict_mac and conflict_mac != mac_address:
                # Different hardware already owns this IP; leave it alone.
                return False
            conn.execute("DELETE FROM devices WHERE id = ?", (int(conflict["id"]),))

        conn.execute(
            """
            UPDATE devices
            SET ip_address = ?,
                hostname = COALESCE(?, hostname),
                device_type = CASE
                  WHEN device_type = 'unknown' THEN ?
                  ELSE device_type
                END,
                identity_confidence = CASE
                  WHEN identity_confidence = 'manual' THEN identity_confidence
                  ELSE ?
                END,
                last_seen = ?
            WHERE id = ?
            """,
            (ip_address, hostname, inferred_type, confidence, now, int(mac_row["id"])),
        )
        return True

    def _auto_label_device(self, conn: sqlite3.Connection, ip_address: str, *, gateway_ip: str | None = None) -> None:
        from .identity import suggest_identity

        row = conn.execute(
            """
            SELECT mac_address, hostname, display_name, device_type, identity_confidence
            FROM devices WHERE ip_address = ?
            """,
            (ip_address,),
        ).fetchone()
        if row is None:
            return
        if row["identity_confidence"] == "manual":
            # Still refresh vendor for display.
            suggestion = suggest_identity(
                hostname=row["hostname"],
                mac_address=row["mac_address"],
                ip_address=ip_address,
                gateway_ip=gateway_ip,
            )
            conn.execute("UPDATE devices SET vendor = ? WHERE ip_address = ?", (suggestion.vendor, ip_address))
            return

        suggestion = suggest_identity(
            hostname=row["hostname"],
            mac_address=row["mac_address"],
            ip_address=ip_address,
            gateway_ip=gateway_ip,
        )
        device_type = row["device_type"] if row["device_type"] not in {None, "", "unknown"} else suggestion.device_type
        conn.execute(
            """
            UPDATE devices
            SET display_name = ?,
                vendor = ?,
                device_type = ?,
                identity_confidence = ?
            WHERE ip_address = ?
            """,
            (suggestion.display_name, suggestion.vendor, device_type, suggestion.confidence, ip_address),
        )

    def relabel_discovered_devices(self, *, gateway_ip: str | None = None) -> int:
        updated = 0
        with self.connect() as conn:
            rows = conn.execute("SELECT ip_address FROM devices WHERE identity_confidence != 'manual'").fetchall()
            for row in rows:
                self._auto_label_device(conn, row["ip_address"], gateway_ip=gateway_ip)
                updated += 1
        return updated

    def get_device(self, ip_address: str) -> Device | None:
        for device in self.list_devices():
            if device.ip_address == ip_address:
                return device
        return None

    def set_device_paused(self, ip_address: str, paused: bool) -> Device:
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,)).fetchone()
            if row is None:
                raise LookupError(ip_address)
            conn.execute(
                "UPDATE devices SET paused = ? WHERE ip_address = ?",
                (int(paused), ip_address),
            )
        for device in self.list_devices():
            if device.ip_address == ip_address:
                return device
        raise LookupError(ip_address)

    def update_profile(
        self,
        profile_id: int,
        *,
        description: str | None = None,
        bedtime_start: str | None = None,
        bedtime_end: str | None = None,
        daily_minutes: int | None = None,
        clear_bedtime: bool = False,
        clear_daily_minutes: bool = False,
    ) -> Profile:
        from .policy import parse_hhmm

        with self.connect() as conn:
            row = conn.execute("SELECT id FROM profiles WHERE id = ?", (profile_id,)).fetchone()
            if row is None:
                raise LookupError(profile_id)
            if description is not None:
                normalized = description.strip()
                if len(normalized) > 160:
                    raise ValueError("Profile description must be 160 characters or fewer")
                conn.execute(
                    "UPDATE profiles SET description = ?, updated_at = ? WHERE id = ?",
                    (normalized, _now(), profile_id),
                )
            if clear_bedtime:
                conn.execute(
                    "UPDATE profiles SET bedtime_start = NULL, bedtime_end = NULL, updated_at = ? WHERE id = ?",
                    (_now(), profile_id),
                )
            elif bedtime_start is not None or bedtime_end is not None:
                start = parse_hhmm(bedtime_start) if bedtime_start is not None else None
                end = parse_hhmm(bedtime_end) if bedtime_end is not None else None
                if bedtime_start is not None and start is None:
                    raise ValueError("bedtime_start must be HH:MM")
                if bedtime_end is not None and end is None:
                    raise ValueError("bedtime_end must be HH:MM")
                # Load existing for partial updates
                current = conn.execute(
                    "SELECT bedtime_start, bedtime_end FROM profiles WHERE id = ?",
                    (profile_id,),
                ).fetchone()
                next_start = bedtime_start if bedtime_start is not None else current["bedtime_start"]
                next_end = bedtime_end if bedtime_end is not None else current["bedtime_end"]
                if (next_start and not next_end) or (next_end and not next_start):
                    raise ValueError("Both bedtime_start and bedtime_end are required")
                if next_start and parse_hhmm(next_start) is None:
                    raise ValueError("bedtime_start must be HH:MM")
                if next_end and parse_hhmm(next_end) is None:
                    raise ValueError("bedtime_end must be HH:MM")
                conn.execute(
                    """
                    UPDATE profiles
                    SET bedtime_start = ?, bedtime_end = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (next_start, next_end, _now(), profile_id),
                )
            if clear_daily_minutes:
                conn.execute(
                    "UPDATE profiles SET daily_minutes = NULL, updated_at = ? WHERE id = ?",
                    (_now(), profile_id),
                )
            elif daily_minutes is not None:
                if daily_minutes < 0 or daily_minutes > 24 * 60:
                    raise ValueError("daily_minutes must be between 0 and 1440")
                conn.execute(
                    "UPDATE profiles SET daily_minutes = ?, updated_at = ? WHERE id = ?",
                    (int(daily_minutes) or None, _now(), profile_id),
                )
        for profile in self.list_profiles():
            if profile.id == profile_id:
                return profile
        raise LookupError(profile_id)

    def get_usage_minutes(self, ip_address: str, day: str) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT minutes FROM device_usage WHERE day = ? AND ip_address = ?",
                (day, ip_address),
            ).fetchone()
        if row is None:
            return 0
        return int(float(row["minutes"]))

    def add_usage_minutes(self, ip_address: str, day: str, minutes: float) -> int:
        if minutes <= 0:
            return self.get_usage_minutes(ip_address, day)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO device_usage(day, ip_address, minutes)
                VALUES(?, ?, ?)
                ON CONFLICT(day, ip_address) DO UPDATE SET
                  minutes = device_usage.minutes + excluded.minutes
                """,
                (day, ip_address, float(minutes)),
            )
            row = conn.execute(
                "SELECT minutes FROM device_usage WHERE day = ? AND ip_address = ?",
                (day, ip_address),
            ).fetchone()
        return int(float(row["minutes"])) if row else 0

    def set_device_enrollment(self, ip_address: str, enrolled: bool) -> Device:
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,)).fetchone()
            if row is None:
                raise LookupError(ip_address)
            conn.execute(
                """
                UPDATE devices
                SET managed = ?, transparent_control = ?
                WHERE ip_address = ?
                """,
                (int(enrolled), int(enrolled), ip_address),
            )
        for device in self.list_devices():
            if device.ip_address == ip_address:
                return device
        raise LookupError(ip_address)

    def clear_device_enrollments(self) -> int:
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE devices
                SET managed = 0,
                    transparent_control = 0
                WHERE managed != 0 OR transparent_control != 0
                """
            )
            return int(cursor.rowcount)

    def list_active_enrolled_ips(
        self,
        observed_ips: set[str] | None = None,
        max_age_seconds: int = 1800,
    ) -> list[str]:
        active: list[str] = []
        for device in self.list_devices():
            if not device.transparent_control:
                continue
            if observed_ips is not None:
                # Live inventory is authoritative: only reconnect devices currently on-LAN.
                if device.ip_address in observed_ips:
                    active.append(device.ip_address)
                continue
            try:
                age = _age_seconds(device.last_seen)
            except ValueError:
                continue
            if age <= max_age_seconds:
                active.append(device.ip_address)
        return sorted(set(active), key=lambda value: tuple(int(part) for part in value.split(".")))

    def list_devices(
        self,
        *,
        present_ips: set[str] | None = None,
        include_enrolled_offline: bool = False,
    ) -> list[Device]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT d.ip_address, d.mac_address, d.hostname, d.display_name, d.vendor, d.device_type,
                       d.profile_id, p.name AS profile_name, d.identity_confidence,
                       d.managed, d.paused, d.transparent_control, d.last_seen
                FROM devices d
                LEFT JOIN profiles p ON p.id = d.profile_id
                ORDER BY d.managed DESC, d.last_seen DESC, d.ip_address ASC
                """
            ).fetchall()
        devices = [
            Device(
                ip_address=row["ip_address"],
                mac_address=row["mac_address"],
                hostname=row["hostname"],
                display_name=row["display_name"],
                vendor=row["vendor"],
                device_type=row["device_type"],
                profile_id=row["profile_id"],
                profile_name=row["profile_name"],
                identity_confidence=row["identity_confidence"],
                managed=bool(row["managed"]),
                paused=bool(row["paused"]),
                transparent_control=bool(row["transparent_control"]),
                last_seen=row["last_seen"],
            )
            for row in rows
        ]
        if present_ips is None:
            return devices
        visible: list[Device] = []
        for device in devices:
            if device.ip_address in present_ips:
                visible.append(device)
            elif include_enrolled_offline and (device.managed or device.transparent_control):
                visible.append(device)
        return visible

    def prune_absent_devices(self, present_ips: set[str], *, keep_enrolled: bool = True) -> int:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, ip_address, managed, transparent_control FROM devices"
            ).fetchall()
            removed = 0
            for row in rows:
                if row["ip_address"] in present_ips:
                    continue
                if keep_enrolled and (bool(row["managed"]) or bool(row["transparent_control"])):
                    continue
                conn.execute("DELETE FROM devices WHERE id = ?", (int(row["id"]),))
                removed += 1
        return removed

    def apply_discovered_identity(
        self,
        ip_address: str,
        *,
        device_type: str | None = None,
        vendor: str | None = None,
        hostname: str | None = None,
        display_name: str | None = None,
        identity_confidence: str | None = None,
    ) -> bool:
        """Apply non-manual discovery hints (nmap/OUI). Returns True when a row changed."""
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT device_type, vendor, hostname, display_name, identity_confidence
                FROM devices WHERE ip_address = ?
                """,
                (ip_address,),
            ).fetchone()
            if row is None or row["identity_confidence"] == "manual":
                return False

            next_type = row["device_type"]
            if device_type and device_type in DEVICE_TYPES:
                if row["device_type"] in {None, "", "unknown"} or (
                    identity_confidence == "nmap" and device_type != "unknown"
                ):
                    next_type = device_type

            next_vendor = vendor or row["vendor"]
            next_hostname = hostname or row["hostname"]
            next_name = display_name or row["display_name"]
            next_confidence = identity_confidence or row["identity_confidence"]

            if (
                next_type == row["device_type"]
                and next_vendor == row["vendor"]
                and next_hostname == row["hostname"]
                and next_name == row["display_name"]
                and next_confidence == row["identity_confidence"]
            ):
                return False

            conn.execute(
                """
                UPDATE devices
                SET device_type = ?,
                    vendor = ?,
                    hostname = ?,
                    display_name = ?,
                    identity_confidence = ?
                WHERE ip_address = ?
                """,
                (next_type, next_vendor, next_hostname, next_name, next_confidence, ip_address),
            )
            return True

    def update_device_identity(self, ip_address: str, display_name: str | None, device_type: str) -> Device:
        normalized_name = display_name.strip() if display_name else None
        if normalized_name == "":
            normalized_name = None
        if device_type not in DEVICE_TYPES:
            raise ValueError(f"Unsupported device_type: {device_type}")
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,)).fetchone()
            if row is None:
                now = _now()
                conn.execute(
                    """
                    INSERT INTO devices(ip_address, display_name, device_type, identity_confidence, first_seen, last_seen)
                    VALUES(?, ?, ?, 'manual', ?, ?)
                    """,
                    (ip_address, normalized_name, device_type, now, now),
                )
            else:
                conn.execute(
                    """
                    UPDATE devices
                    SET display_name = ?, device_type = ?, identity_confidence = 'manual'
                    WHERE ip_address = ?
                    """,
                    (normalized_name, device_type, ip_address),
                )
        for device in self.list_devices():
            if device.ip_address == ip_address:
                return device
        raise LookupError(ip_address)

    def assign_device_profile(self, ip_address: str, profile_id: int | None) -> Device:
        with self.connect() as conn:
            if profile_id is not None:
                profile = conn.execute("SELECT id FROM profiles WHERE id = ?", (profile_id,)).fetchone()
                if profile is None:
                    raise ValueError(f"Unknown profile_id: {profile_id}")
            row = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,)).fetchone()
            if row is None:
                now = _now()
                conn.execute(
                    """
                    INSERT INTO devices(ip_address, profile_id, identity_confidence, first_seen, last_seen)
                    VALUES(?, ?, 'manual', ?, ?)
                    """,
                    (ip_address, profile_id, now, now),
                )
            else:
                conn.execute("UPDATE devices SET profile_id = ? WHERE ip_address = ?", (profile_id, ip_address))
        for device in self.list_devices():
            if device.ip_address == ip_address:
                return device
        raise LookupError(ip_address)

    def list_profiles(self) -> list[Profile]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT p.id, p.name, p.description, p.bedtime_start, p.bedtime_end, p.daily_minutes,
                       count(d.id) AS device_count
                FROM profiles p
                LEFT JOIN devices d ON d.profile_id = p.id
                GROUP BY p.id
                ORDER BY CASE p.name
                  WHEN 'Default' THEN 0
                  WHEN 'Parents' THEN 1
                  WHEN 'Kids' THEN 2
                  WHEN 'Guests' THEN 3
                  ELSE 10
                END, p.name
                """
            ).fetchall()
        return [
            Profile(
                id=int(row["id"]),
                name=row["name"],
                description=row["description"],
                bedtime_start=row["bedtime_start"],
                bedtime_end=row["bedtime_end"],
                daily_minutes=row["daily_minutes"],
                device_count=int(row["device_count"]),
            )
            for row in rows
        ]

    def create_profile(self, name: str, description: str = "") -> Profile:
        normalized_name = name.strip()
        normalized_description = description.strip()
        if not normalized_name:
            raise ValueError("Profile name is required")
        if len(normalized_name) > 48:
            raise ValueError("Profile name must be 48 characters or fewer")
        if len(normalized_description) > 160:
            raise ValueError("Profile description must be 160 characters or fewer")
        now = _now()
        with self.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO profiles(name, description, created_at, updated_at)
                    VALUES(?, ?, ?, ?)
                    """,
                    (normalized_name, normalized_description, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"Profile already exists: {normalized_name}") from exc
        return next(profile for profile in self.list_profiles() if profile.name == normalized_name)

    def record_bandwidth_sample(
        self,
        ip_address: str,
        *,
        bytes_total: int,
        packets_total: int,
        connections: int,
        source: str,
        sampled_at: float,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO bandwidth_samples(ip_address, sampled_at, bytes_total, packets_total, connections, source)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (ip_address, float(sampled_at), int(bytes_total), int(packets_total), int(connections), source),
            )
            # Keep ~24h of samples per linked device (agent ticks ~5s → ~2k rows max).
            conn.execute(
                """
                DELETE FROM bandwidth_samples
                WHERE sampled_at < ? OR id IN (
                  SELECT id FROM bandwidth_samples
                  WHERE ip_address = ?
                  ORDER BY sampled_at DESC
                  LIMIT -1 OFFSET 2200
                )
                """,
                (float(sampled_at) - 86400.0, ip_address),
            )

    def bandwidth_rates(self, ips: set[str] | list[str] | None = None) -> dict[str, dict[str, object]]:
        """Return bytes/sec rates from the latest two samples per IP."""
        wanted = set(ips) if ips is not None else None
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT ip_address, sampled_at, bytes_total, packets_total, connections, source
                FROM bandwidth_samples
                ORDER BY ip_address, sampled_at DESC
                """
            ).fetchall()
        latest: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            ip = str(row["ip_address"])
            if wanted is not None and ip not in wanted:
                continue
            bucket = latest.setdefault(ip, [])
            if len(bucket) < 2:
                bucket.append(row)
        rates: dict[str, dict[str, object]] = {}
        for ip, samples in latest.items():
            current = samples[0]
            previous = samples[1] if len(samples) > 1 else None
            bytes_per_sec = 0.0
            if previous is not None:
                elapsed = float(current["sampled_at"]) - float(previous["sampled_at"])
                delta = int(current["bytes_total"]) - int(previous["bytes_total"])
                if elapsed > 0 and delta >= 0:
                    bytes_per_sec = delta / elapsed
            rates[ip] = {
                "ip_address": ip,
                "bytesTotal": int(current["bytes_total"]),
                "packetsTotal": int(current["packets_total"]),
                "connections": int(current["connections"]),
                "bytesPerSec": round(bytes_per_sec, 1),
                "source": current["source"],
                "sampledAt": float(current["sampled_at"]),
            }
        return rates

    def bandwidth_series(
        self,
        ip_address: str,
        *,
        window_seconds: int = 600,
        bucket_seconds: int = 15,
    ) -> list[dict[str, object]]:
        """Return time-bucketed bytes/sec series for a linked device."""
        window_seconds = max(60, min(int(window_seconds), 86400))
        bucket_seconds = max(5, min(int(bucket_seconds), 3600))
        now = time.time()
        start = now - window_seconds
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT sampled_at, bytes_total, packets_total, connections
                FROM bandwidth_samples
                WHERE ip_address = ? AND sampled_at >= ?
                ORDER BY sampled_at ASC
                """,
                (ip_address, start - bucket_seconds),
            ).fetchall()
        if len(rows) < 2:
            return []

        # Instantaneous rates between consecutive samples, then bucket.
        rates: list[tuple[float, float, int]] = []
        previous = rows[0]
        for current in rows[1:]:
            elapsed = float(current["sampled_at"]) - float(previous["sampled_at"])
            delta = int(current["bytes_total"]) - int(previous["bytes_total"])
            if elapsed > 0 and delta >= 0:
                rates.append((float(current["sampled_at"]), delta / elapsed, int(current["connections"] or 0)))
            previous = current

        if not rates:
            return []

        first_bucket = int(start // bucket_seconds) * bucket_seconds
        last_bucket = int(now // bucket_seconds) * bucket_seconds
        buckets: dict[int, list[float]] = {}
        conn_buckets: dict[int, list[int]] = {}
        for sampled_at, bytes_per_sec, connections in rates:
            if sampled_at < start:
                continue
            key = int(sampled_at // bucket_seconds) * bucket_seconds
            buckets.setdefault(key, []).append(bytes_per_sec)
            conn_buckets.setdefault(key, []).append(connections)

        series: list[dict[str, object]] = []
        cursor = first_bucket
        while cursor <= last_bucket:
            values = buckets.get(cursor) or []
            conns = conn_buckets.get(cursor) or []
            series.append(
                {
                    "timestamp": cursor,
                    "bytesPerSec": round(sum(values) / len(values), 1) if values else 0.0,
                    "connections": int(round(sum(conns) / len(conns))) if conns else 0,
                }
            )
            cursor += bucket_seconds
        return series

    def add_alert(
        self,
        *,
        alert_type: str,
        severity: str,
        title: str,
        detail: str,
        subject: str | None = None,
    ) -> dict[str, object]:
        now = _now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts(alert_type, severity, title, detail, subject, created_at, acked)
                VALUES(?, ?, ?, ?, ?, ?, 0)
                """,
                (alert_type, severity, title, detail, subject, now),
            )
            alert_id = int(cursor.lastrowid)
            # Keep the inbox bounded.
            conn.execute(
                """
                DELETE FROM alerts WHERE id NOT IN (
                  SELECT id FROM alerts ORDER BY created_at DESC LIMIT 500
                )
                """
            )
        return {
            "id": alert_id,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "detail": detail,
            "subject": subject,
            "created_at": now,
            "acked": False,
        }

    def list_alerts(self, *, include_acked: bool = False, limit: int = 50) -> list[dict[str, object]]:
        limit = max(1, min(int(limit), 200))
        with self.connect() as conn:
            if include_acked:
                rows = conn.execute(
                    """
                    SELECT id, alert_type, severity, title, detail, subject, created_at, acked
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, alert_type, severity, title, detail, subject, created_at, acked
                    FROM alerts
                    WHERE acked = 0
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "alert_type": row["alert_type"],
                "severity": row["severity"],
                "title": row["title"],
                "detail": row["detail"],
                "subject": row["subject"],
                "created_at": row["created_at"],
                "acked": bool(row["acked"]),
            }
            for row in rows
        ]

    def ack_alert(self, alert_id: int) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("UPDATE alerts SET acked = 1 WHERE id = ?", (alert_id,))
            return cursor.rowcount > 0

    def ack_all_alerts(self) -> int:
        with self.connect() as conn:
            cursor = conn.execute("UPDATE alerts SET acked = 1 WHERE acked = 0")
            return int(cursor.rowcount)

    def has_recent_alert(self, alert_type: str, subject: str | None, *, within_seconds: int) -> bool:
        cutoff = datetime.now(timezone.utc).timestamp() - max(30, within_seconds)
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at FROM alerts
                WHERE alert_type = ? AND IFNULL(subject, '') = IFNULL(?, '')
                ORDER BY created_at DESC
                LIMIT 8
                """,
                (alert_type, subject),
            ).fetchall()
        for row in rows:
            try:
                created = datetime.fromisoformat(str(row["created_at"]))
            except ValueError:
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if created.timestamp() >= cutoff:
                return True
        return False

    def create_access_request(
        self,
        *,
        device_ip: str,
        domain: str,
        service: str | None = None,
        reason: str = "",
    ) -> dict[str, object]:
        normalized_domain = domain.strip().lower().rstrip(".")
        normalized_reason = reason.strip()
        if not normalized_domain:
            raise ValueError("Domain is required")
        if len(normalized_reason) > 240:
            raise ValueError("Reason must be 240 characters or fewer")
        now = _now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO access_requests(device_ip, domain, service, reason, status, created_at)
                VALUES(?, ?, ?, ?, 'pending', ?)
                """,
                (device_ip, normalized_domain, (service or "").strip() or None, normalized_reason, now),
            )
            request_id = int(cursor.lastrowid)
        return self.get_access_request(request_id) or {}

    def get_access_request(self, request_id: int) -> dict[str, object] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, device_ip, domain, service, reason, status, decision, created_at, decided_at, expires_at
                FROM access_requests
                WHERE id = ?
                """,
                (request_id,),
            ).fetchone()
        return _serialize_access_request(row) if row else None

    def list_access_requests(self, *, include_decided: bool = False, limit: int = 50) -> list[dict[str, object]]:
        limit = max(1, min(int(limit), 100))
        with self.connect() as conn:
            if include_decided:
                rows = conn.execute(
                    """
                    SELECT id, device_ip, domain, service, reason, status, decision, created_at, decided_at, expires_at
                    FROM access_requests
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, device_ip, domain, service, reason, status, decision, created_at, decided_at, expires_at
                    FROM access_requests
                    WHERE status = 'pending'
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [_serialize_access_request(row) for row in rows]

    def decide_access_request(self, request_id: int, *, decision: str, expires_at: str | None = None) -> dict[str, object]:
        allowed = {"allow_once", "allow_15m", "allow_1h", "always_allow", "deny"}
        if decision not in allowed:
            raise ValueError("Unsupported access request decision")
        status = "approved" if decision.startswith("allow") else "denied"
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE access_requests
                SET status = ?, decision = ?, decided_at = ?, expires_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (status, decision, _now(), expires_at, request_id),
            )
            if cursor.rowcount == 0:
                row = conn.execute("SELECT id FROM access_requests WHERE id = ?", (request_id,)).fetchone()
                if row is None:
                    raise LookupError(request_id)
                raise ValueError("Access request has already been decided")
        item = self.get_access_request(request_id)
        if item is None:
            raise LookupError(request_id)
        return item

    def get_community_settings(self) -> dict[str, object]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT mode, organization_name, updated_at FROM community_settings WHERE id = 1"
            ).fetchone()
        if row is None:
            return {"mode": "private", "organizationName": "", "updatedAt": None, "enabled": False}
        mode = row["mode"] if row["mode"] in {"private", "anonymous", "organization"} else "private"
        return {
            "mode": mode,
            "organizationName": row["organization_name"] or "",
            "updatedAt": row["updated_at"],
            "enabled": mode != "private",
        }

    def update_community_settings(self, *, mode: str, organization_name: str = "") -> dict[str, object]:
        normalized_mode = mode.strip().lower()
        if normalized_mode not in {"private", "anonymous", "organization"}:
            raise ValueError("Community mode must be private, anonymous, or organization")
        normalized_org = organization_name.strip()
        if len(normalized_org) > 80:
            raise ValueError("Organization name must be 80 characters or fewer")
        if normalized_mode != "organization":
            normalized_org = ""
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE community_settings
                SET mode = ?, organization_name = ?, updated_at = ?
                WHERE id = 1
                """,
                (normalized_mode, normalized_org, _now()),
            )
        return self.get_community_settings()

    def get_retention_settings(self) -> dict[str, object]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT detailed_activity_days, alert_days, health_history_days, audit_log_days, report_days, updated_at
                FROM retention_settings
                WHERE id = 1
                """
            ).fetchone()
        if row is None:
            return {
                "detailedActivityDays": 30,
                "alertDays": 180,
                "healthHistoryDays": 30,
                "auditLogDays": 180,
                "reportDays": 365,
                "updatedAt": None,
            }
        return {
            "detailedActivityDays": int(row["detailed_activity_days"]),
            "alertDays": int(row["alert_days"]),
            "healthHistoryDays": int(row["health_history_days"]),
            "auditLogDays": int(row["audit_log_days"]),
            "reportDays": int(row["report_days"]),
            "updatedAt": row["updated_at"],
        }

    def update_retention_settings(
        self,
        *,
        detailed_activity_days: int | None = None,
        alert_days: int | None = None,
        health_history_days: int | None = None,
        audit_log_days: int | None = None,
        report_days: int | None = None,
    ) -> dict[str, object]:
        current = self.get_retention_settings()
        values = {
            "detailed_activity_days": _retention_days(
                detailed_activity_days, int(current["detailedActivityDays"]), "Detailed activity"
            ),
            "alert_days": _retention_days(alert_days, int(current["alertDays"]), "Alert"),
            "health_history_days": _retention_days(
                health_history_days, int(current["healthHistoryDays"]), "Health history"
            ),
            "audit_log_days": _retention_days(audit_log_days, int(current["auditLogDays"]), "Audit log"),
            "report_days": _retention_days(report_days, int(current["reportDays"]), "Report"),
        }
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE retention_settings
                SET detailed_activity_days = ?,
                    alert_days = ?,
                    health_history_days = ?,
                    audit_log_days = ?,
                    report_days = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (
                    values["detailed_activity_days"],
                    values["alert_days"],
                    values["health_history_days"],
                    values["audit_log_days"],
                    values["report_days"],
                    _now(),
                ),
            )
        return self.get_retention_settings()

    def retention_summary(self) -> dict[str, object]:
        settings = self.get_retention_settings()
        now_ts = time.time()
        detailed_cutoff = now_ts - int(settings["detailedActivityDays"]) * 86400
        health_cutoff_day = _epoch_iso(now_ts - int(settings["healthHistoryDays"]) * 86400)[:10]
        alert_cutoff = _epoch_iso(now_ts - int(settings["alertDays"]) * 86400)
        with self.connect() as conn:
            bandwidth_old = conn.execute(
                "SELECT COUNT(*) FROM bandwidth_samples WHERE sampled_at < ?", (detailed_cutoff,)
            ).fetchone()[0]
            usage_old = conn.execute("SELECT COUNT(*) FROM device_usage WHERE day < ?", (health_cutoff_day,)).fetchone()[0]
            alerts_old = conn.execute("SELECT COUNT(*) FROM alerts WHERE created_at < ?", (alert_cutoff,)).fetchone()[0]
        return {
            "settings": settings,
            "dryRun": True,
            "wouldPrune": {
                "bandwidthSamples": int(bandwidth_old),
                "deviceUsageRows": int(usage_old),
                "alerts": int(alerts_old),
            },
            "note": "Pi-Circle does not prune Pi-hole FTL query history from this setting.",
        }

    def set_network_health(self, mode: str, healthy: bool, summary: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE network_health
                SET mode = ?, healthy = ?, summary = ?, updated_at = ?
                WHERE id = 1
                """,
                (mode, int(healthy), summary, _now()),
            )

    def get_network_health(self) -> dict[str, object]:
        with self.connect() as conn:
            row = conn.execute("SELECT mode, healthy, summary, updated_at FROM network_health WHERE id = 1").fetchone()
        if row is None:
            return {"mode": "unknown", "healthy": False, "summary": "Not initialized", "updated_at": None}
        return {
            "mode": row["mode"],
            "healthy": bool(row["healthy"]),
            "summary": row["summary"],
            "updated_at": row["updated_at"],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _epoch_iso(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0).isoformat()


def _retention_days(value: int | None, fallback: int, label: str) -> int:
    if value is None:
        return fallback
    normalized = int(value)
    if normalized < 1 or normalized > 3650:
        raise ValueError(f"{label} retention must be between 1 and 3650 days")
    return normalized


def _age_seconds(value: str, *, now: datetime | None = None) -> float:
    current = now or datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (current - parsed.astimezone(timezone.utc)).total_seconds())


def _serialize_access_request(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": int(row["id"]),
        "device_ip": row["device_ip"],
        "domain": row["domain"],
        "service": row["service"],
        "reason": row["reason"],
        "status": row["status"],
        "decision": row["decision"],
        "created_at": row["created_at"],
        "decided_at": row["decided_at"],
        "expires_at": row["expires_at"],
    }


DEVICE_TYPES = frozenset({"unknown", "router", "iphone", "ipad", "android", "pc", "laptop", "tv", "game", "iot"})

# name, description, bedtime_start, bedtime_end, daily_minutes
DEFAULT_PROFILES = (
    ("Default", "Devices without a specific household profile.", None, None, None),
    ("Parents", "Adult devices with unrestricted policy by default.", None, None, None),
    ("Kids", "Child devices with bedtime and a daily screen budget.", "21:00", "07:00", 120),
    ("Guests", "Temporary devices on the household network.", "23:00", "07:00", 180),
)


def infer_device_type(hostname: str | None, ip_address: str) -> str:
    lowered = (hostname or "").lower()
    if "iphone" in lowered:
        return "iphone"
    if "ipad" in lowered:
        return "ipad"
    if "android" in lowered or "pixel" in lowered or "galaxy" in lowered:
        return "android"
    if "macbook" in lowered or "laptop" in lowered:
        return "laptop"
    if "desktop" in lowered or "windows" in lowered or "pc" in lowered:
        return "pc"
    if "roku" in lowered or "tv" in lowered or "chromecast" in lowered or "appletv" in lowered:
        return "tv"
    if "xbox" in lowered or "playstation" in lowered or "ps5" in lowered or "nintendo" in lowered:
        return "game"
    if "router" in lowered or ip_address.endswith(".1"):
        return "router"
    return "unknown"


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {str(row["name"] if isinstance(row, sqlite3.Row) else row[1]) for row in rows}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
