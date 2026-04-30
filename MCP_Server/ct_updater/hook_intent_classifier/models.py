from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IntentClassification:
    label: str
    confidence: float
    reason_codes: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    instructions: list[str] = field(default_factory=list)
