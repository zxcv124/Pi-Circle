from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    actor: str
    result: str
    reason: str
    subject: str | None = None
    source_ip: str | None = None


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = asdict(event)
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
