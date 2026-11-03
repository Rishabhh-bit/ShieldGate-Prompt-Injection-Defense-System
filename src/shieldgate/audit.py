"""Append-only application log; hash chaining detects edits, not privileged rewrites.

Single-process writer. Pin a head hash externally to detect truncation/wholesale rewriting.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from .output_guard import redact_secrets

LOCK = RLock()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def verify_chain(path: str | Path, expected_head: str | None = None) -> bool:
    previous = "0" * 64
    try:
        for line in Path(path).read_text().splitlines():
            row = json.loads(line)
            current = row.pop("hash")
            if row["prev_hash"] != previous or digest(row) != current:
                return False
            previous = current
        return expected_head is None or previous == expected_head
    except (OSError, ValueError, KeyError, TypeError):
        return False


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.head = "0" * 64
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(exist_ok=True)
            if not verify_chain(self.path):
                raise ValueError("Invalid audit chain; refusing to append")
            lines = self.path.read_text().splitlines()
            if lines:
                self.head = json.loads(lines[-1])["hash"]

    def append(
        self, session_id: str, event: str, data: dict[str, Any], secrets: list[str] | None = None
    ) -> dict[str, Any]:
        with LOCK:
            if self.path:
                lines = self.path.read_text().splitlines()
                self.head = json.loads(lines[-1])["hash"] if lines else "0" * 64

            def redact(value: Any) -> Any:
                # Redact before JSON escaping, including multiline secrets and nested values.
                if isinstance(value, str):
                    return redact_secrets(value, secrets)
                if isinstance(value, dict):
                    return {
                        redact_secrets(str(key), secrets): redact(item)
                        for key, item in value.items()
                    }
                if isinstance(value, (list, tuple)):
                    return [redact(item) for item in value]
                return value

            safe_data = redact(data)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "event": event,
                "data": safe_data,
                "prev_hash": self.head,
            }
            record["hash"] = digest(record)
            self.head = record["hash"]
            if self.path:
                with self.path.open("a") as file:
                    file.write(canonical(record) + "\n")
            return record
