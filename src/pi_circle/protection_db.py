from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import time


@dataclass(frozen=True)
class ProtectionDatabaseSummary:
    available: bool
    database_path: str
    database_bytes: int
    total_active_entries: int
    domain_count: int | None
    duplicate_count: int | None
    list_source_count: int
    enabled_list_source_count: int
    disabled_list_source_count: int
    domain_rule_count: int
    exact_deny_count: int
    regex_deny_count: int
    allow_count: int
    last_modified: int | None
    lookup_supported: bool
    exact_unique_counts: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProtectionDatabaseReader:
    def __init__(self, gravity_db: Path) -> None:
        self.gravity_db = gravity_db

    def summary(self) -> ProtectionDatabaseSummary:
        if not self.gravity_db.exists():
            return self._unavailable("Pi-hole gravity database is not present")
        try:
            stat = self.gravity_db.stat()
            with self._connect() as conn:
                gravity_columns = _columns(conn, "gravity")
                adlist_columns = _columns(conn, "adlist")
                domainlist_columns = _columns(conn, "domainlist")
                total_entries = _count(conn, "gravity")
                list_source_count = _count(conn, "adlist")
                enabled_sources = _count_where(conn, "adlist", "enabled = 1") if "enabled" in adlist_columns else 0
                disabled_sources = _count_where(conn, "adlist", "enabled = 0") if "enabled" in adlist_columns else 0
                domain_rule_count = _count(conn, "domainlist")
                exact_deny_count = self._domainlist_count(conn, domainlist_columns, "deny_exact")
                regex_deny_count = self._domainlist_count(conn, domainlist_columns, "deny_regex")
                allow_count = self._domainlist_count(conn, domainlist_columns, "allow")
            return ProtectionDatabaseSummary(
                available=True,
                database_path=str(self.gravity_db),
                database_bytes=int(stat.st_size),
                total_active_entries=total_entries,
                domain_count=None,
                duplicate_count=None,
                list_source_count=list_source_count,
                enabled_list_source_count=enabled_sources,
                disabled_list_source_count=disabled_sources,
                domain_rule_count=domain_rule_count,
                exact_deny_count=exact_deny_count,
                regex_deny_count=regex_deny_count,
                allow_count=allow_count,
                last_modified=int(stat.st_mtime),
                lookup_supported="domain" in gravity_columns,
                exact_unique_counts=False,
            )
        except sqlite3.Error as exc:
            return self._unavailable(f"Unable to read Pi-hole gravity database: {exc}")
        except OSError as exc:
            return self._unavailable(f"Unable to stat Pi-hole gravity database: {exc}")

    def blocklists(self, *, limit: int = 100) -> list[dict[str, object]]:
        limit = max(1, min(int(limit), 250))
        if not self.gravity_db.exists():
            return []
        with self._connect() as conn:
            adlist_columns = _columns(conn, "adlist")
            if not adlist_columns:
                return []
            wanted = [
                "id",
                "address",
                "enabled",
                "comment",
                "date_added",
                "date_modified",
                "date_updated",
                "number",
                "invalid_domains",
                "status",
                "abp_entries",
                "type",
            ]
            selected = [column for column in wanted if column in adlist_columns]
            if not selected:
                return []
            select_sql = ", ".join(f"a.{column}" for column in selected)
            order_expr = "COALESCE(a.enabled, 0) DESC"
            if "number" in adlist_columns:
                order_expr += ", COALESCE(a.number, 0) DESC"
            elif "abp_entries" in adlist_columns:
                order_expr += ", COALESCE(a.abp_entries, 0) DESC"
            sql = f"""
                SELECT {select_sql}
                FROM adlist a
                ORDER BY {order_expr}, a.id ASC
                LIMIT ?
            """
            rows = conn.execute(sql, (limit,)).fetchall()
        return [_serialize_blocklist(row) for row in rows]

    def lookup(self, domain: str, *, limit: int = 50) -> dict[str, object]:
        cleaned = domain.strip().lower().rstrip(".")
        if not cleaned:
            raise ValueError("Domain is required")
        if len(cleaned) > 253:
            raise ValueError("Domain is too long")
        limit = max(1, min(int(limit), 100))
        result: dict[str, object] = {
            "domain": cleaned,
            "gravityMatches": [],
            "domainRules": [],
            "available": self.gravity_db.exists(),
        }
        if not self.gravity_db.exists():
            return result
        with self._connect() as conn:
            gravity_columns = _columns(conn, "gravity")
            adlist_columns = _columns(conn, "adlist")
            domainlist_columns = _columns(conn, "domainlist")
            if "domain" in gravity_columns:
                if "adlist_id" in gravity_columns and {"id", "address"}.issubset(adlist_columns):
                    rows = conn.execute(
                        """
                        SELECT g.domain, g.adlist_id, a.address, a.enabled
                        FROM gravity g
                        LEFT JOIN adlist a ON a.id = g.adlist_id
                        WHERE g.domain = ?
                        LIMIT ?
                        """,
                        (cleaned, limit),
                    ).fetchall()
                else:
                    rows = conn.execute("SELECT domain FROM gravity WHERE domain = ? LIMIT ?", (cleaned, limit)).fetchall()
                result["gravityMatches"] = [_serialize_lookup_row(row) for row in rows]
            if "domain" in domainlist_columns:
                selected = [column for column in ("id", "type", "domain", "enabled", "comment", "date_added") if column in domainlist_columns]
                sql = f"SELECT {', '.join(selected)} FROM domainlist WHERE domain = ? LIMIT ?"
                rows = conn.execute(sql, (cleaned, limit)).fetchall()
                result["domainRules"] = [_row_dict(row) for row in rows]
        return result

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{self.gravity_db}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _unavailable(self, error: str) -> ProtectionDatabaseSummary:
        return ProtectionDatabaseSummary(
            available=False,
            database_path=str(self.gravity_db),
            database_bytes=0,
            total_active_entries=0,
            domain_count=0,
            duplicate_count=0,
            list_source_count=0,
            enabled_list_source_count=0,
            disabled_list_source_count=0,
            domain_rule_count=0,
            exact_deny_count=0,
            regex_deny_count=0,
            allow_count=0,
            last_modified=None,
            lookup_supported=False,
            exact_unique_counts=False,
            error=error,
        )

    @staticmethod
    def _domainlist_count(conn: sqlite3.Connection, columns: set[str], kind: str) -> int:
        if not {"type", "enabled"}.issubset(columns):
            return 0
        type_values = {
            "allow": (0, 2),
            "deny_exact": (1,),
            "deny_regex": (3,),
        }[kind]
        placeholders = ", ".join("?" for _ in type_values)
        row = conn.execute(
            f"SELECT COUNT(*) AS count FROM domainlist WHERE enabled = 1 AND type IN ({placeholders})",
            type_values,
        ).fetchone()
        return int(row["count"] or 0) if row else 0


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return set()
    return {str(row["name"]) for row in rows}


def _count(conn: sqlite3.Connection, table: str) -> int:
    try:
        row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    except sqlite3.Error:
        return 0
    return int(row["count"] or 0) if row else 0


def _count_where(conn: sqlite3.Connection, table: str, where_sql: str) -> int:
    try:
        row = conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {where_sql}").fetchone()
    except sqlite3.Error:
        return 0
    return int(row["count"] or 0) if row else 0


def _serialize_blocklist(row: sqlite3.Row) -> dict[str, object]:
    values = _row_dict(row)
    return {
        "id": values.get("id"),
        "address": values.get("address") or "",
        "enabled": bool(values.get("enabled")) if values.get("enabled") is not None else None,
        "comment": values.get("comment") or "",
        "dateAdded": _epoch_or_none(values.get("date_added")),
        "dateModified": _epoch_or_none(values.get("date_modified")),
        "dateUpdated": _epoch_or_none(values.get("date_updated")),
        "entryCount": _entry_count(values),
        "invalidDomains": values.get("invalid_domains"),
        "status": values.get("status"),
        "abpEntries": values.get("abp_entries"),
        "type": values.get("type"),
        "reliability": _reliability_label(values),
    }


def _serialize_lookup_row(row: sqlite3.Row) -> dict[str, object]:
    values = _row_dict(row)
    return {
        "domain": values.get("domain"),
        "adlistId": values.get("adlist_id"),
        "source": values.get("address"),
        "sourceEnabled": bool(values.get("enabled")) if values.get("enabled") is not None else None,
    }


def _row_dict(row: sqlite3.Row) -> dict[str, object]:
    return {key: row[key] for key in row.keys()}


def _epoch_or_none(value: object) -> int | None:
    try:
        parsed = int(value) if value is not None else 0
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _entry_count(values: dict[str, object]) -> int | None:
    for key in ("number", "abp_entries"):
        try:
            value = int(values.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return None


def _reliability_label(values: dict[str, object]) -> str:
    enabled = values.get("enabled")
    status = values.get("status")
    invalid = values.get("invalid_domains")
    updated = _epoch_or_none(values.get("date_updated"))
    if enabled == 0:
        return "disabled"
    if status not in (None, 0):
        return "needs attention"
    try:
        if int(invalid or 0) > 0:
            return "has invalid domains"
    except (TypeError, ValueError):
        pass
    if updated and time.time() - updated > 14 * 24 * 60 * 60:
        return "stale"
    return "healthy"
