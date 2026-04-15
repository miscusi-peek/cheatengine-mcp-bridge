from __future__ import annotations

from dataclasses import dataclass

from ..parser import Pattern, parse_pattern, pattern_to_str


@dataclass
class StabilityReport:
    original_pattern: str
    actual_bytes: str
    wildcard_indexes: list[int]
    stable_indexes: list[int]
    replacement_pattern: str
    wildcard_pattern: str
    stability_score: float


def analyze_stability(pattern: Pattern, actual: bytes) -> StabilityReport:
    wildcard_indexes: list[int] = []
    stable_indexes: list[int] = []
    replacement = list(pattern)
    wildcarded = list(pattern)

    for idx, expected in enumerate(pattern):
        if idx >= len(actual):
            wildcard_indexes.append(idx)
            wildcarded[idx] = None
            continue
        if expected is None:
            wildcard_indexes.append(idx)
            continue
        if actual[idx] == expected:
            stable_indexes.append(idx)
        else:
            wildcard_indexes.append(idx)
            replacement[idx] = actual[idx]
            wildcarded[idx] = None

    total = len([byte for byte in pattern if byte is not None]) or 1
    stability_score = len(stable_indexes) / total
    return StabilityReport(
        original_pattern=pattern_to_str(pattern),
        actual_bytes=actual.hex(" ").upper(),
        wildcard_indexes=wildcard_indexes,
        stable_indexes=stable_indexes,
        replacement_pattern=pattern_to_str(replacement),
        wildcard_pattern=pattern_to_str(wildcarded),
        stability_score=stability_score,
    )


def analyze_pattern_strings(pattern: str, actual_bytes: str) -> StabilityReport:
    actual = bytes(int(part, 16) for part in actual_bytes.split()) if actual_bytes.strip() else b""
    return analyze_stability(parse_pattern(pattern), actual)
