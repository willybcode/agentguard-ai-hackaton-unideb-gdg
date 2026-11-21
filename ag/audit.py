"""Append-only, hash-chained audit log.

Each entry stores the SHA-256 of the previous entry, so silently editing or
removing a row breaks every hash after it. ``verify()`` walks the chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


@dataclass
class Entry:
    seq: int
    ts: float
    tool: str
    args: dict[str, Any]
    verdict: str
    rule: str
    reason: str
    asi: str | None
    prev: str
    hash: str = ""

    def digest(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "hash"}
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[Entry] = []
        self._last = GENESIS

    def append(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        verdict: str,
        rule: str,
        reason: str,
        asi: str | None,
    ) -> Entry:
        entry = Entry(
            seq=len(self.entries),
            ts=time.time(),
            tool=tool,
            args=args,
            verdict=verdict,
            rule=rule,
            reason=reason,
            asi=asi,
            prev=self._last,
        )
        entry.hash = entry.digest()
        self._last = entry.hash
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), default=str) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (intact, first_bad_seq)."""
        prev = GENESIS
        for entry in self.entries:
            if entry.prev != prev or entry.digest() != entry.hash:
                return False, entry.seq
            prev = entry.hash
        return True, None

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self.entries)
