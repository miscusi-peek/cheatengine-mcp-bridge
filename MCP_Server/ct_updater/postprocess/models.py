from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MethodDiffData:
    summary: list[str] = field(default_factory=list)
    unified_diff: str = ""


@dataclass
class CandidateInput:
    offset: int
    address: int
    byte_score: float
    confidence: float
    diff_count: int
    exact: bool
    within_range: bool
    tags: list[str]
    notes: list[str]
    actual_bytes: str
    replacement_pattern: Optional[str]
    wildcard_pattern: Optional[str]
    suggested_range: Optional[int]
    instructions: list[dict]
    uniqueness_classification: str = ""
    uniqueness_match_count: int = 0
    stability_score: float = 0.0


@dataclass
class HookInput:
    name: str
    description: str
    symbol: str
    scan_range: int
    pattern: str
    method_addr: Optional[int]
    status: str
    summary: str
    error: Optional[str]
    history_pattern: Optional[str] = None
    history_range: Optional[int] = None
    candidates: list[CandidateInput] = field(default_factory=list)


@dataclass
class ScoredCandidate:
    candidate: CandidateInput
    final_score: float
    mnemonic_score: float
    structural_score: float
    uniqueness_score: float
    stability_score: float
    history_score: float
    reason_codes: list[str] = field(default_factory=list)
    recommended_pattern: Optional[str] = None
    suggested_range: Optional[int] = None
    rejected_reason: Optional[str] = None


@dataclass
class HookDecision:
    hook: HookInput
    best_candidate: Optional[ScoredCandidate]
    backups: list[ScoredCandidate] = field(default_factory=list)
    summary: str = ""
    manual_review_flags: list[str] = field(default_factory=list)
    method_diff: Optional[MethodDiffData] = None


@dataclass
class PostprocessReport:
    source_report: str
    hook_count: int
    decisions: list[HookDecision] = field(default_factory=list)
