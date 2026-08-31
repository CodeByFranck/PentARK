"""Timestamped, append-only audit log.

Every meaningful action (a request, a check, a refusal) is appended as one JSON
line with a UTC timestamp, the target, the module/action, and the result. This
gives the engagement a replayable trail — and, importantly, records *refusals*
(off-scope attempts) too, which is exactly what an authorization story needs.

Kept deliberately simple (plain JSONL). If you later want tamper-evidence, a
hash chain can be layered on without changing callers.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from pathlib import Path
from typing import Any, Callable, Iterator


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class AuditLog:
    """Append-only JSONL audit log. Thread-safe."""

    def __init__(self, path: str | Path, *, clock: Callable[[], _dt.datetime] = _utcnow) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, *, target: str | None = None, **fields: Any) -> dict[str, Any]:
        """Append one record and return it."""
        record: dict[str, Any] = {
            "ts": self._clock().isoformat(),
            "action": action,
            "target": target,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        return record


class NullAuditLog:
    """No-op audit log for tests / dry contexts."""

    def log(self, action: str, *, target: str | None = None, **fields: Any) -> dict[str, Any]:
        return {"ts": None, "action": action, "target": target, **fields}


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        return
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


__all__ = ["AuditLog", "NullAuditLog", "read_records"]
