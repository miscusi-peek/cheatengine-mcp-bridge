from __future__ import annotations

from collections import Counter

from .instruction_compare import mnemonic_similarity, structural_similarity
from .models import HookInput, ScoredCandidate
from .signature_synthesizer import synthesize_signature, uniqueness_score


def _majority_intent(candidates) -> str:
    """Return the plurality intent label across all candidates, ignoring empty and 'mixed'."""
    labels = [c.intent_label for c in candidates if c.intent_label and c.intent_label != "mixed"]
    if not labels:
        return ""
    return Counter(labels).most_common(1)[0][0]


def _intent_consistency_score(candidate, majority_intent: str) -> float:
    """Score how well this candidate's intent aligns with the plurality intent."""
    if not majority_intent or not candidate.intent_label:
        return 0.5  # neutral when unknown
    if candidate.intent_label == majority_intent:
        return 1.0
    if candidate.intent_label == "mixed":
        return 0.65  # mixed is ambiguous, not necessarily wrong
    return 0.2  # clearly different intent


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
    if candidate.intent_label:
        codes.append(f"intent_{candidate.intent_label}")
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
    majority_intent = _majority_intent(hook.candidates)

    for candidate in hook.candidates:
        mnemonic_score = mnemonic_similarity(candidate.instructions)
        structural_score = structural_similarity(candidate.instructions)
        uniqueness = uniqueness_score(candidate)
        stability = candidate.stability_score
        history_score = _history_alignment_score(hook, candidate)
        intent_score = _intent_consistency_score(candidate, majority_intent)

        final_score = (
            candidate.byte_score * 0.33 +
            candidate.confidence * 0.19 +
            mnemonic_score * 0.15 +
            structural_score * 0.10 +
            uniqueness * 0.10 +
            stability * 0.05 +
            history_score * 0.05 +
            intent_score * 0.03
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

    # Flag if the top two candidates disagree on intent — the human should pick
    if (
        len(rescored) >= 2
        and rescored[0].candidate.intent_label
        and rescored[1].candidate.intent_label
        and rescored[0].candidate.intent_label != "mixed"
        and rescored[1].candidate.intent_label != "mixed"
        and rescored[0].candidate.intent_label != rescored[1].candidate.intent_label
    ):
        rescored[0].reason_codes.append("intent_conflict_with_backup")

    return rescored
