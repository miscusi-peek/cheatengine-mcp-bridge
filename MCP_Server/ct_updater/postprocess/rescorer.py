from __future__ import annotations

from .instruction_compare import mnemonic_similarity, structural_similarity
from .models import HookInput, ScoredCandidate
from .signature_synthesizer import synthesize_signature, uniqueness_score


def _history_alignment_score(hook: HookInput, candidate) -> float:
    if not hook.history_pattern:
        return 0.5
    if candidate.wildcard_pattern == hook.history_pattern:
        return 1.0
    if candidate.replacement_pattern == hook.history_pattern:
        return 0.9
    if hook.history_pattern in (candidate.wildcard_pattern or "", candidate.replacement_pattern or ""):
        return 0.8
    return 0.4


def _reason_codes(candidate, hook: HookInput, mnemonic_score: float, structural_score: float) -> list[str]:
    codes: list[str] = []
    if candidate.exact and candidate.within_range:
        codes.append("exact_in_range")
    elif candidate.exact:
        codes.append("exact_out_of_range")
    if candidate.byte_score >= 0.85:
        codes.append("high_byte_similarity")
    elif candidate.byte_score >= 0.60:
        codes.append("medium_byte_similarity")
    if mnemonic_score >= 0.6:
        codes.append("stable_mnemonic_shape")
    if structural_score >= 0.6:
        codes.append("control_flow_markers_present")
    if candidate.suggested_range is not None:
        codes.append("range_extension_available")
    if candidate.diff_count <= 2:
        codes.append("low_byte_drift")
    if candidate.uniqueness_classification:
        codes.append(f"uniqueness_{candidate.uniqueness_classification}")
    if candidate.stability_score >= 0.8:
        codes.append("stable_signature")
    elif candidate.stability_score > 0:
        codes.append("mixed_signature_stability")
    if hook.history_pattern:
        codes.append("history_baseline_available")
    return codes


def _rejected_reason(candidate, final_score: float) -> str | None:
    if final_score >= 0.75:
        return None
    if not candidate.within_range and not candidate.exact:
        return "low_confidence_and_out_of_range"
    if candidate.diff_count > 4:
        return "too_many_byte_differences"
    return "weak_overall_match"


def rescore_hook(hook: HookInput) -> list[ScoredCandidate]:
    rescored: list[ScoredCandidate] = []

    for candidate in hook.candidates:
        mnemonic_score = mnemonic_similarity(candidate.instructions)
        structural_score = structural_similarity(candidate.instructions)
        uniqueness = uniqueness_score(candidate)
        stability = candidate.stability_score
        history_score = _history_alignment_score(hook, candidate)

        final_score = (
            candidate.byte_score * 0.35 +
            candidate.confidence * 0.20 +
            mnemonic_score * 0.15 +
            structural_score * 0.10 +
            uniqueness * 0.10 +
            stability * 0.05 +
            history_score * 0.05
        )

        rescored.append(ScoredCandidate(
            candidate=candidate,
            final_score=round(final_score, 4),
            mnemonic_score=round(mnemonic_score, 4),
            structural_score=round(structural_score, 4),
            uniqueness_score=round(uniqueness, 4),
            stability_score=round(stability, 4),
            history_score=round(history_score, 4),
            reason_codes=_reason_codes(candidate, hook, mnemonic_score, structural_score),
            recommended_pattern=synthesize_signature(candidate),
            suggested_range=candidate.suggested_range,
            rejected_reason=_rejected_reason(candidate, final_score),
        ))

    rescored.sort(key=lambda item: item.final_score, reverse=True)
    return rescored
