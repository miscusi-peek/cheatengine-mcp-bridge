from __future__ import annotations

from dataclasses import dataclass

from ..parser import Pattern, parse_ct, parse_pattern, pattern_to_str


@dataclass
class UniquenessResult:
    description: str
    symbol: str
    pattern: str
    method_addr: int | None
    search_size: int
    match_count: int
    offsets: list[int]
    classification: str


def _match_at(mem: bytes, offset: int, pattern: Pattern) -> bool:
    if offset + len(pattern) > len(mem):
        return False
    for i, expected in enumerate(pattern):
        if expected is None:
            continue
        if mem[offset + i] != expected:
            return False
    return True


def count_pattern_matches(mem: bytes, pattern: Pattern) -> list[int]:
    if not pattern or not mem or len(mem) < len(pattern):
        return []
    return [offset for offset in range(len(mem) - len(pattern) + 1) if _match_at(mem, offset, pattern)]


def classify_uniqueness(match_count: int) -> str:
    if match_count == 0:
        return "not_found"
    if match_count == 1:
        return "unique"
    if match_count <= 3:
        return "ambiguous"
    return "unsafe"


def evaluate_ct_uniqueness(bridge, ct_path: str, *, search_multiplier: int = 8) -> list[UniquenessResult]:
    aob_entries, _assert_entries, _pointer_entries = parse_ct(ct_path)
    results: list[UniquenessResult] = []

    for entry in aob_entries:
        method_addr = bridge.get_symbol_addr(entry.symbol)
        if not method_addr:
            results.append(UniquenessResult(
                description=entry.description or entry.name,
                symbol=entry.symbol,
                pattern=pattern_to_str(entry.pattern),
                method_addr=None,
                search_size=0,
                match_count=0,
                offsets=[],
                classification="no_symbol",
            ))
            continue

        read_size = max(entry.scan_range * search_multiplier, len(entry.pattern) + 64)
        mem = bridge.read_memory(method_addr, read_size) or b""
        offsets = count_pattern_matches(mem, entry.pattern)
        results.append(UniquenessResult(
            description=entry.description or entry.name,
            symbol=entry.symbol,
            pattern=pattern_to_str(entry.pattern),
            method_addr=method_addr,
            search_size=len(mem),
            match_count=len(offsets),
            offsets=offsets[:8],
            classification=classify_uniqueness(len(offsets)),
        ))

    return results
