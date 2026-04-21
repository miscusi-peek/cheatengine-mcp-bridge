from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .analyzer import AOBResult, analyze_aob
from .parser import AOBEntry, parse_pattern, pattern_to_str
from .history_store.store import HistoryStore
from .hook_intent_classifier.classifier import classify_instruction_window
from .method_diff.service import diff_instruction_windows
from .preprocess.models import HookPreprocessResult
from .preprocess.matcher import preprocess_entry
from .postprocess.decision import decide_hook
from .postprocess.models import CandidateInput, HookDecision, HookInput, MethodDiffData
from .stability.service import analyze_stability
from .uniqueness.service import classify_uniqueness, count_pattern_matches


HIGH_CONFIDENCE_AUTO_FIX = 0.90
POSTPROCESS_FIX_THRESHOLD = 0.85


class WorkflowAction(Enum):
    FAST_PATH_OK = "fast_path_ok"
    AUTO_FIX = "auto_fix"
    POSTPROCESS_FIX = "postprocess_fix"
    ESCALATE_POSTPROCESS = "escalate_postprocess"
    MANUAL_REVIEW = "manual_review"


@dataclass
class AOBWorkflowOutcome:
    entry: AOBEntry
    analysis: AOBResult
    action: WorkflowAction
    preprocess_status: str | None = None
    preprocess_result: HookPreprocessResult | None = None
    decision: HookDecision | None = None


def _to_candidate_input(candidate) -> CandidateInput:
    uniqueness_classification = ""
    uniqueness_match_count = 0
    if getattr(candidate, "match_offsets", None) is not None:
        uniqueness_match_count = len(candidate.match_offsets)
        uniqueness_classification = classify_uniqueness(uniqueness_match_count)

    stability = analyze_stability(
        candidate.wildcard_pattern or candidate.replacement_pattern or [],
        candidate.actual_bytes,
    ) if candidate.actual_bytes else None

    raw_instructions = [item.raw for item in candidate.instructions]
    intent = classify_instruction_window(raw_instructions) if raw_instructions else None

    return CandidateInput(
        offset=candidate.offset,
        address=candidate.address,
        byte_score=candidate.byte_score,
        confidence=candidate.confidence,
        diff_count=candidate.diff_count,
        exact=candidate.exact,
        within_range=candidate.within_range,
        tags=list(candidate.tags),
        notes=list(candidate.notes),
        actual_bytes=candidate.actual_bytes.hex(" ").upper(),
        replacement_pattern=pattern_to_str(candidate.replacement_pattern) if candidate.replacement_pattern else None,
        wildcard_pattern=pattern_to_str(candidate.wildcard_pattern) if candidate.wildcard_pattern else None,
        suggested_range=candidate.suggested_range,
        uniqueness_classification=uniqueness_classification,
        uniqueness_match_count=uniqueness_match_count,
        stability_score=stability.stability_score if stability else 0.0,
        intent_label=intent.label if intent else "",
        instructions=[
            {
                "address": hex(item.address),
                "bytes": item.bytes_hex,
                "raw": item.raw,
                "normalized": item.normalized,
            }
            for item in candidate.instructions
        ],
    )


def _to_hook_input(pre_result, history_store: HistoryStore | None = None) -> HookInput:
    history_pattern = None
    history_range = None
    if history_store:
        latest = history_store.promote_latest(pre_result.entry.description or pre_result.entry.name)
        if latest:
            history_pattern = latest.pattern
            history_range = latest.range_value

    return HookInput(
        name=pre_result.entry.name,
        description=pre_result.entry.description,
        symbol=pre_result.entry.symbol,
        scan_range=pre_result.entry.scan_range,
        pattern=pattern_to_str(pre_result.entry.pattern),
        method_addr=pre_result.method_addr,
        status=pre_result.status,
        summary=pre_result.summary,
        error=pre_result.error,
        history_pattern=history_pattern,
        history_range=history_range,
        candidates=[_to_candidate_input(candidate) for candidate in pre_result.candidates],
    )


def _apply_postprocess_fix(analysis: AOBResult, decision: HookDecision) -> bool:
    best = decision.best_candidate
    if not best or not best.recommended_pattern:
        return False

    analysis.new_pattern = parse_pattern(best.recommended_pattern)
    analysis.new_range = best.suggested_range
    analysis.can_auto_fix = True
    analysis.fix_description = (
        f'Post-process recommendation selected method+{best.candidate.offset:#x} '
        f'with score {best.final_score:.0%}.'
    )
    return True


def _build_method_diff(bridge, analysis: AOBResult, decision: HookDecision) -> MethodDiffData | None:
    best = decision.best_candidate
    if not best or analysis.method_addr is None or analysis.found_offset is None:
        return None

    old_addr = analysis.method_addr + analysis.found_offset
    old_instructions = [
        item.get("instruction") or item.get("disasm") or ""
        for item in bridge.disassemble(old_addr, 8)
    ]
    new_instructions = [item.get("raw", "") for item in best.candidate.instructions]
    report = diff_instruction_windows(old_instructions, new_instructions)
    return MethodDiffData(summary=report.summary, unified_diff=report.unified_diff)


def run_aob_workflow(
    bridge,
    entry: AOBEntry,
    *,
    top_n: int = 4,
    disasm_count: int = 8,
    search_multiplier: int = 8,
    apply_postprocess_fix: bool = False,
    history_store: HistoryStore | None = None,
) -> AOBWorkflowOutcome:
    analysis = analyze_aob(bridge, entry)

    if analysis.status.name == "OK":
        return AOBWorkflowOutcome(entry=entry, analysis=analysis, action=WorkflowAction.FAST_PATH_OK)

    if analysis.status.name in ("RANGE_MISS",):
        return AOBWorkflowOutcome(entry=entry, analysis=analysis, action=WorkflowAction.AUTO_FIX)

    if analysis.status.name == "BYTE_CHANGE" and analysis.can_auto_fix and analysis.match_score >= HIGH_CONFIDENCE_AUTO_FIX:
        return AOBWorkflowOutcome(entry=entry, analysis=analysis, action=WorkflowAction.AUTO_FIX)

    if analysis.status.name in ("BYTE_CHANGE", "PARTIAL", "NOT_FOUND"):
        pre_result = preprocess_entry(
            bridge,
            entry,
            search_multiplier=search_multiplier,
            top_n=top_n,
            disasm_count=disasm_count,
        )
        if pre_result.method_addr:
            mem = bridge.read_memory(pre_result.method_addr, pre_result.read_size) or b""
            for candidate in pre_result.candidates:
                test_pattern = candidate.wildcard_pattern or candidate.replacement_pattern or entry.pattern
                candidate.match_offsets = count_pattern_matches(mem, test_pattern) if mem else []
        decision = decide_hook(_to_hook_input(pre_result, history_store=history_store), backup_count=2)

        decision.method_diff = _build_method_diff(bridge, analysis, decision)

        if (
            apply_postprocess_fix and
            decision.best_candidate and
            decision.best_candidate.final_score >= POSTPROCESS_FIX_THRESHOLD and
            _apply_postprocess_fix(analysis, decision)
        ):
            action = WorkflowAction.POSTPROCESS_FIX
        elif decision.best_candidate and decision.best_candidate.final_score >= 0.75:
            action = WorkflowAction.ESCALATE_POSTPROCESS
        else:
            action = WorkflowAction.MANUAL_REVIEW

        return AOBWorkflowOutcome(
            entry=entry,
            analysis=analysis,
            action=action,
            preprocess_status=pre_result.status,
            preprocess_result=pre_result,
            decision=decision,
        )

    return AOBWorkflowOutcome(entry=entry, analysis=analysis, action=WorkflowAction.MANUAL_REVIEW)
