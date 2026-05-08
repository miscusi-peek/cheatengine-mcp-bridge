from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IntentSummary:
    label: str
    confidence: float
    reason_codes: list[str] = field(default_factory=list)


@dataclass
class SiblingSummary:
    address: int
    instruction: str
    field_offset: str
    confidence: float
    relationship: str
    notes: list[str] = field(default_factory=list)


@dataclass
class ReferenceWindow:
    description: str
    name: str
    symbol: str
    address: int | None
    offset: int | None
    pattern: str
    instructions: list[str] = field(default_factory=list)
    intent: Optional[IntentSummary] = None


@dataclass
class FeatureCandidate:
    address: int
    offset: int
    scan_range: int
    byte_score: float
    confidence: float
    recommended_pattern: str | None
    uniqueness: str
    stability_score: float
    reason_codes: list[str] = field(default_factory=list)
    method_diff_summary: list[str] = field(default_factory=list)
    method_diff: str = ""
    instructions: list[str] = field(default_factory=list)
    intent: Optional[IntentSummary] = None


@dataclass
class FeaturePacket:
    mode: str
    target_symbol: str
    target_range: int
    reference: ReferenceWindow
    candidates: list[FeatureCandidate] = field(default_factory=list)
    sibling_candidates: list[SiblingSummary] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None
