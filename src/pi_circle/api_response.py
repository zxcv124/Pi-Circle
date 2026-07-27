from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def success(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data, "error": None, "timestamp": timestamp()}


def failure(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "data": None,
        "error": {"code": code, "message": message, "details": details or {}},
        "timestamp": timestamp(),
    }
