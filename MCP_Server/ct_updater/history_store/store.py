from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class HistoryEntry:
    hook: str
    symbol: str
    pattern: str
    range_value: int | None
    source: str
    notes: str = ""


class HistoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _load(self) -> dict:
        if not self.path.exists():
            return {"entries": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, payload: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def list_entries(self) -> list[HistoryEntry]:
        payload = self._load()
        return [HistoryEntry(**item) for item in payload.get("entries") or []]

    def append(self, entry: HistoryEntry) -> None:
        payload = self._load()
        payload.setdefault("entries", []).append(asdict(entry))
        self._save(payload)

    def promote_latest(self, hook: str) -> HistoryEntry | None:
        entries = self.list_entries()
        for entry in reversed(entries):
            if entry.hook == hook:
                return entry
        return None
