from __future__ import annotations


def synthesize_signature(candidate) -> str | None:
    """
    Prefer the wildcarded pattern when available since it is usually more
    resilient than the byte-for-byte replacement pattern.
    """
    if candidate.wildcard_pattern and candidate.uniqueness_classification in ("unique", "ambiguous", ""):
        return candidate.wildcard_pattern
    if candidate.replacement_pattern:
        return candidate.replacement_pattern
    return None


def uniqueness_score(candidate) -> float:
    if candidate.uniqueness_classification == "unique":
        return 1.0
    if candidate.uniqueness_classification == "ambiguous":
        return 0.6
    if candidate.uniqueness_classification == "unsafe":
        return 0.2
    if candidate.uniqueness_classification == "not_found":
        return 0.0
    if candidate.exact and candidate.within_range:
        return 1.0
    if candidate.exact:
        return 0.9
    if candidate.diff_count <= 2:
        return 0.8
    if candidate.diff_count <= 4:
        return 0.65
    return 0.5
