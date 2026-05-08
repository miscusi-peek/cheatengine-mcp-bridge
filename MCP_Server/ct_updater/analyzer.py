"""
Pattern analysis — verifies AOB entries against a live process via the CE bridge,
diagnoses failures, and suggests fixes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .parser import AOBEntry, AssertEntry, Pattern, pattern_to_str


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class Status(Enum):
    OK           = 'OK'           # pattern found within original scan range
    RANGE_MISS   = 'RANGE_MISS'   # pattern present but outside scan range
    BYTE_CHANGE  = 'BYTE_CHANGE'  # high similarity — a few bytes differ
    PARTIAL      = 'PARTIAL'      # some bytes match — structure likely changed
    NOT_FOUND    = 'NOT_FOUND'    # no trace of pattern in method
    NO_SYMBOL    = 'NO_SYMBOL'    # Mono symbol not resolved
    READ_FAIL    = 'READ_FAIL'    # memory read failed


@dataclass
class Diff:
    """Describes one byte difference between expected and actual."""
    offset: int     # offset within pattern
    expected: int   # None = wildcard (shouldn't appear in diffs)
    actual: int


@dataclass
class AOBResult:
    entry: AOBEntry
    status: Status
    method_addr: Optional[int]    = None
    found_offset: Optional[int]   = None  # offset from method start where pattern starts
    match_score: float            = 0.0   # 0.0–1.0 fraction of non-wildcard bytes that match
    diffs: list[Diff]             = field(default_factory=list)
    actual_bytes: Optional[bytes] = None  # bytes at best-match position
    suggested_range: Optional[int] = None # recommended new scan range (for RANGE_MISS)
    # Auto-fix fields
    can_auto_fix: bool            = False
    fix_description: str          = ''
    new_pattern: Optional[Pattern] = None  # for BYTE_CHANGE fixes
    new_range: Optional[int]       = None  # for RANGE_MISS fixes


@dataclass
class AssertResult:
    entry: AssertEntry
    status: Status
    check_addr: Optional[int]     = None
    actual_bytes: Optional[bytes] = None
    can_auto_fix: bool            = False


# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------

def _non_wildcard_count(pattern: Pattern) -> int:
    return sum(1 for b in pattern if b is not None)


def _match_at(mem: bytes, offset: int, pattern: Pattern) -> tuple[bool, float, list[Diff]]:
    """
    Check if `pattern` matches `mem` at `offset`.
    Returns (exact_match, score, diffs).
    score = fraction of non-wildcard bytes that match.
    """
    pat_len = len(pattern)
    if offset + pat_len > len(mem):
        return False, 0.0, []

    diffs: list[Diff] = []
    matches = 0
    total = 0

    for i, expected in enumerate(pattern):
        if expected is None:  # wildcard
            continue
        total += 1
        actual = mem[offset + i]
        if actual == expected:
            matches += 1
        else:
            diffs.append(Diff(offset=i, expected=expected, actual=actual))

    score = matches / total if total else 1.0
    return len(diffs) == 0, score, diffs


def _find_best_match(mem: bytes, pattern: Pattern, search_up_to: int
                     ) -> tuple[int, float, list[Diff]]:
    """
    Slide `pattern` over `mem[0:search_up_to]`, return the position with
    the highest match score. Returns (offset, score, diffs).
    """
    pat_len = len(pattern)
    limit = min(search_up_to, len(mem) - pat_len)
    if limit < 0:
        return -1, 0.0, []

    best_pos, best_score, best_diffs = -1, -1.0, []
    for i in range(limit + 1):
        _, score, diffs = _match_at(mem, i, pattern)
        if score > best_score:
            best_score = score
            best_pos = i
            best_diffs = diffs

    return best_pos, best_score, best_diffs


# ---------------------------------------------------------------------------
# AOB analysis
# ---------------------------------------------------------------------------

# How far beyond the original range to search for the pattern
SEARCH_MULTIPLIER = 4
# Score thresholds
BYTE_CHANGE_THRESHOLD = 0.85   # ≥85% matching → likely same logic, few bytes changed
PARTIAL_THRESHOLD     = 0.50   # ≥50% matching → partial structural match


def analyze_aob(bridge, entry: AOBEntry) -> AOBResult:
    result = AOBResult(entry=entry, status=Status.NO_SYMBOL)

    # 1. Resolve method address
    addr = bridge.get_symbol_addr(entry.symbol)
    if not addr:
        return result
    result.method_addr = addr

    pat_len = len(entry.pattern)
    # Read generously beyond the original range
    read_size = max(entry.scan_range + pat_len + 32,
                    entry.scan_range * SEARCH_MULTIPLIER)
    mem = bridge.read_memory(addr, read_size)
    if not mem:
        result.status = Status.READ_FAIL
        return result

    # 2. Exact match within original range
    for i in range(min(entry.scan_range, len(mem) - pat_len + 1)):
        exact, score, diffs = _match_at(mem, i, entry.pattern)
        if exact:
            result.status = Status.OK
            result.found_offset = i
            result.match_score = 1.0
            return result

    # 3. Exact match beyond original range (pattern present, range too small)
    search_limit = min(len(mem) - pat_len, entry.scan_range * SEARCH_MULTIPLIER)
    for i in range(entry.scan_range, search_limit + 1):
        exact, score, diffs = _match_at(mem, i, entry.pattern)
        if exact:
            new_range = i + pat_len + 16  # a little headroom
            result.status = Status.RANGE_MISS
            result.found_offset = i
            result.match_score = 1.0
            result.suggested_range = new_range
            result.can_auto_fix = True
            result.new_range = new_range
            result.fix_description = (
                f'Pattern found at method+{i:#x} (scan range was {entry.scan_range}). '
                f'Increase range to {new_range}.'
            )
            return result

    # 4. Find best partial match
    best_pos, best_score, best_diffs = _find_best_match(mem, entry.pattern, search_limit)
    actual = mem[best_pos:best_pos + pat_len] if best_pos >= 0 else None

    result.found_offset = best_pos if best_pos >= 0 else None
    result.match_score = best_score
    result.diffs = best_diffs
    result.actual_bytes = actual

    if best_score >= BYTE_CHANGE_THRESHOLD:
        result.status = Status.BYTE_CHANGE
        # Build a new pattern by substituting the differing bytes with actuals
        new_pat = list(entry.pattern)
        for d in best_diffs:
            new_pat[d.offset] = d.actual
        result.new_pattern = new_pat
        result.can_auto_fix = True
        result.fix_description = (
            f'Pattern found at method+{best_pos:#x} with {len(best_diffs)} byte(s) changed.'
        )
        if best_pos >= entry.scan_range:
            result.new_range = best_pos + pat_len + 16
    elif best_score >= PARTIAL_THRESHOLD:
        result.status = Status.PARTIAL
    else:
        result.status = Status.NOT_FOUND

    return result


# ---------------------------------------------------------------------------
# Assert analysis
# ---------------------------------------------------------------------------

def analyze_assert(bridge, entry: AssertEntry) -> AssertResult:
    result = AssertResult(entry=entry, status=Status.NO_SYMBOL)

    addr = bridge.get_symbol_addr(entry.symbol)
    if not addr:
        return result

    check_addr = addr + entry.offset
    result.check_addr = check_addr

    pat_len = len(entry.expected)
    mem = bridge.read_memory(check_addr, pat_len)
    if not mem:
        result.status = Status.READ_FAIL
        return result

    result.actual_bytes = mem
    exact, _, _ = _match_at(mem, 0, entry.expected)
    result.status = Status.OK if exact else Status.BYTE_CHANGE
    return result


# ---------------------------------------------------------------------------
# Pointer verification
# ---------------------------------------------------------------------------

def verify_pointer(bridge, symbol: str, offsets: list[int]) -> tuple[bool, Optional[int]]:
    """
    Walk a pointer chain from `symbol` through `offsets`.
    Returns (success, final_address).
    """
    addr = bridge.get_symbol_addr(symbol)
    if not addr:
        return False, None

    current = addr
    for off in offsets:
        mem = bridge.read_memory(current + off, 8)
        if not mem:
            return False, None
        import struct
        current = struct.unpack('<Q', mem[:8])[0]
        if current == 0:
            return False, None

    return True, current
