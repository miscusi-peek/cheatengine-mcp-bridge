from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..parser import AOBEntry, Pattern


@dataclass
class InstructionSummary:
    address: int
    raw: str
    normalized: str
    bytes_hex: str = ""


@dataclass
class CandidateMatch:
    offset: int
    address: int
    byte_score: float
    confidence: float
    diff_count: int
    exact: bool
    within_range: bool
    actual_bytes: bytes
    replacement_pattern: Optional[Pattern] = None
    wildcard_pattern: Optional[Pattern] = None
    suggested_range: Optional[int] = None
    tags: list[str] = field(default_factory=list)
    instructions: list[InstructionSummary] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    match_offsets: list[int] = field(default_factory=list)


@dataclass
class HookPreprocessResult:
    entry: AOBEntry
    method_addr: Optional[int]
    read_size: int
    search_limit: int
    status: str
    summary: str
    candidates: list[CandidateMatch] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class PreprocessRunReport:
    ct_path: str
    aob_count: int
    results: list[HookPreprocessResult] = field(default_factory=list)
