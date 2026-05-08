from __future__ import annotations

from typing import Iterable

from ..parser import AOBEntry, Pattern
from .models import CandidateMatch, HookPreprocessResult
from .normalize import instruction_from_bridge


DEFAULT_SEARCH_MULTIPLIER = 8
DEFAULT_TOP_CANDIDATES = 4
HIGH_CONFIDENCE_THRESHOLD = 0.85
MEDIUM_CONFIDENCE_THRESHOLD = 0.60


def _match_window(mem: bytes, offset: int, pattern: Pattern) -> tuple[bool, float, list[int]]:
    pat_len = len(pattern)
    if offset < 0 or offset + pat_len > len(mem):
        return False, 0.0, []

    matches = 0
    total = 0
    diff_indexes: list[int] = []
    for i, expected in enumerate(pattern):
        if expected is None:
            continue
        total += 1
        actual = mem[offset + i]
        if actual == expected:
            matches += 1
        else:
            diff_indexes.append(i)

    score = matches / total if total else 1.0
    return len(diff_indexes) == 0, score, diff_indexes


def _build_relaxed_pattern(pattern: Pattern, actual: bytes, diff_indexes: Iterable[int], mode: str) -> Pattern:
    new_pattern = list(pattern)
    for idx in diff_indexes:
        new_pattern[idx] = None if mode == "wildcard" else actual[idx]
    return new_pattern


def _candidate_confidence(score: float, exact: bool, within_range: bool, diff_count: int) -> float:
    confidence = score
    if exact:
        confidence += 0.10
    if within_range:
        confidence += 0.05
    if diff_count <= 2:
        confidence += 0.05
    return max(0.0, min(confidence, 1.0))


def _candidate_tags(exact: bool, within_range: bool, score: float, diff_count: int) -> list[str]:
    tags: list[str] = []
    if exact and within_range:
        tags.append("exact-in-range")
    elif exact:
        tags.append("exact-out-of-range")
    elif score >= HIGH_CONFIDENCE_THRESHOLD:
        tags.append("high-similarity")
    elif score >= MEDIUM_CONFIDENCE_THRESHOLD:
        tags.append("partial-similarity")
    else:
        tags.append("weak-similarity")

    if not within_range:
        tags.append("range-extension-candidate")
    if diff_count:
        tags.append(f"{diff_count}-byte-diff")
    return tags


def _candidate_notes(entry: AOBEntry, offset: int, exact: bool, within_range: bool, score: float) -> list[str]:
    notes: list[str] = []
    if exact and within_range:
        notes.append("Pattern still matches exactly within the original scan window.")
    elif exact:
        notes.append("Pattern still matches exactly, but only after expanding the original scan window.")
    elif score >= HIGH_CONFIDENCE_THRESHOLD:
        notes.append("High-similarity candidate: likely same logic with a few changed bytes.")
    elif score >= MEDIUM_CONFIDENCE_THRESHOLD:
        notes.append("Medium-similarity candidate: useful shortlist item for Claude/manual review.")
    else:
        notes.append("Weak similarity; keep only as a fallback.")

    if offset >= entry.scan_range:
        notes.append("Candidate starts beyond the original aobscanregion end offset.")
    return notes


def _find_ranked_offsets(mem: bytes, pattern: Pattern, search_limit: int, top_n: int) -> list[tuple[int, bool, float, list[int]]]:
    pat_len = len(pattern)
    ranked: list[tuple[int, bool, float, list[int]]] = []

    for offset in range(max(0, search_limit) + 1):
        exact, score, diff_indexes = _match_window(mem, offset, pattern)
        ranked.append((offset, exact, score, diff_indexes))

    ranked.sort(key=lambda item: (item[1], item[2], -len(item[3])), reverse=True)

    selected: list[tuple[int, bool, float, list[int]]] = []
    for candidate in ranked:
        offset = candidate[0]
        if any(abs(offset - picked[0]) < pat_len for picked in selected):
            continue
        selected.append(candidate)
        if len(selected) >= top_n:
            break

    selected.sort(key=lambda item: item[0])
    return selected


def preprocess_entry(
    bridge,
    entry: AOBEntry,
    *,
    search_multiplier: int = DEFAULT_SEARCH_MULTIPLIER,
    top_n: int = DEFAULT_TOP_CANDIDATES,
    disasm_count: int = 8,
) -> HookPreprocessResult:
    method_addr = bridge.get_symbol_addr(entry.symbol)
    if not method_addr:
        return HookPreprocessResult(
            entry=entry,
            method_addr=None,
            read_size=0,
            search_limit=0,
            status="no_symbol",
            summary="Mono symbol did not resolve; preprocessing cannot narrow candidates.",
            error="symbol_not_found",
        )

    pat_len = len(entry.pattern)
    read_size = max(entry.scan_range + pat_len + 64, entry.scan_range * search_multiplier, pat_len + 64)
    mem = bridge.read_memory(method_addr, read_size)
    if not mem:
        return HookPreprocessResult(
            entry=entry,
            method_addr=method_addr,
            read_size=read_size,
            search_limit=0,
            status="read_fail",
            summary="Method memory could not be read from the CE bridge.",
            error="memory_read_failed",
        )

    search_limit = max(0, min(len(mem) - pat_len, entry.scan_range * search_multiplier))
    ranked_offsets = _find_ranked_offsets(mem, entry.pattern, search_limit, top_n)

    candidates: list[CandidateMatch] = []
    for offset, exact, score, diff_indexes in ranked_offsets:
        actual = mem[offset:offset + pat_len]
        within_range = offset < entry.scan_range
        replacement = _build_relaxed_pattern(entry.pattern, actual, diff_indexes, "replace") if diff_indexes else list(entry.pattern)
        wildcarded = _build_relaxed_pattern(entry.pattern, actual, diff_indexes, "wildcard") if diff_indexes else list(entry.pattern)
        suggested_range = (offset + pat_len + 16) if offset >= entry.scan_range else None
        instructions = [
            instruction_from_bridge(item)
            for item in bridge.disassemble(method_addr + offset, disasm_count)
        ]

        candidates.append(CandidateMatch(
            offset=offset,
            address=method_addr + offset,
            byte_score=score,
            confidence=_candidate_confidence(score, exact, within_range, len(diff_indexes)),
            diff_count=len(diff_indexes),
            exact=exact,
            within_range=within_range,
            actual_bytes=actual,
            replacement_pattern=replacement,
            wildcard_pattern=wildcarded,
            suggested_range=suggested_range,
            tags=_candidate_tags(exact, within_range, score, len(diff_indexes)),
            instructions=instructions,
            notes=_candidate_notes(entry, offset, exact, within_range, score),
        ))

    if not candidates:
        status = "no_candidates"
        summary = "No viable candidate windows were found in the sampled method memory."
    elif candidates[0].exact and candidates[0].within_range:
        status = "exact_match"
        summary = "Pattern already matches exactly; Claude can skip raw search and focus on confirmation."
    elif candidates[0].exact:
        status = "range_miss"
        summary = "Best candidate is an exact match outside the original scan window; expand the range first."
    elif candidates[0].byte_score >= HIGH_CONFIDENCE_THRESHOLD:
        status = "high_similarity"
        summary = "Best candidate is a high-similarity byte match; review the top replacement/wildcard suggestion."
    elif candidates[0].byte_score >= MEDIUM_CONFIDENCE_THRESHOLD:
        status = "partial_similarity"
        summary = "Best candidates narrow review to a short list, but still need judgment."
    else:
        status = "low_similarity"
        summary = "Only weak candidates were found; Claude will still need deeper manual reasoning."

    return HookPreprocessResult(
        entry=entry,
        method_addr=method_addr,
        read_size=read_size,
        search_limit=search_limit,
        status=status,
        summary=summary,
        candidates=candidates,
    )
