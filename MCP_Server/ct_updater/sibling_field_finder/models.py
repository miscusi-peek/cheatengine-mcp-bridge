from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SiblingReference:
    description: str
    symbol: str
    address: int | None
    offset: int | None
    instruction: str
    base_register: str = ""
    field_offset: str = ""


@dataclass
class SiblingCandidate:
    address: int
    instruction: str
    base_register: str
    field_offset: str
    relationship: str
    confidence: float
    notes: list[str] = field(default_factory=list)


@dataclass
class SiblingReport:
    reference: SiblingReference
    candidates: list[SiblingCandidate] = field(default_factory=list)
    error: str | None = None
