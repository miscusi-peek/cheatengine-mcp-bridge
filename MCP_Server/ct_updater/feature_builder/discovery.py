from __future__ import annotations

from dataclasses import replace

from ..analyzer import analyze_aob
from ..method_diff.service import diff_instruction_windows
from ..hook_intent_classifier.classifier import classify_instruction_window
from ..parser import AOBEntry, parse_ct, parse_pattern, pattern_to_str
from ..postprocess.decision import decide_hook
from ..preprocess.matcher import preprocess_entry
from ..sibling_field_finder.finder import build_sibling_report
from ..workflow import _to_hook_input
from .models import FeatureCandidate, FeaturePacket, IntentSummary, ReferenceWindow, SiblingSummary
from .reference_lookup import find_reference_entry


def _instruction_texts(bridge, address: int | None, count: int) -> list[str]:
    if not address:
        return []
    return [
        item.get("instruction") or item.get("disasm") or ""
        for item in bridge.disassemble(address, count)
    ]


def _reference_window(bridge, entry: AOBEntry, disasm_count: int) -> ReferenceWindow:
    analysis = analyze_aob(bridge, entry)
    address = (analysis.method_addr + analysis.found_offset) if analysis.method_addr is not None and analysis.found_offset is not None else None
    instructions = _instruction_texts(bridge, address, disasm_count)
    intent = classify_instruction_window(instructions) if instructions else None
    return ReferenceWindow(
        description=entry.description,
        name=entry.name,
        symbol=entry.symbol,
        address=address,
        offset=analysis.found_offset,
        pattern=pattern_to_str(entry.pattern),
        instructions=instructions,
        intent=IntentSummary(intent.label, intent.confidence, intent.reason_codes) if intent else None,
    )


def build_feature_packet(
    bridge,
    *,
    ct_path: str | None,
    reference_query: str | None,
    target_symbol: str | None,
    target_range: int | None,
    custom_pattern: str | None,
    top_n: int = 4,
    disasm_count: int = 8,
    search_multiplier: int = 8,
) -> FeaturePacket:
    if reference_query:
        if not ct_path:
            return FeaturePacket(
                mode="reference",
                target_symbol=target_symbol or "",
                target_range=target_range or 0,
                reference=ReferenceWindow("", "", "", None, None, ""),
                error="ct_path_required_for_reference_lookup",
            )
        reference = find_reference_entry(ct_path, reference_query)
        if not reference:
            return FeaturePacket(
                mode="reference",
                target_symbol=target_symbol or "",
                target_range=target_range or 0,
                reference=ReferenceWindow("", "", "", None, None, ""),
                error="reference_not_found",
            )
        mode = "reference"
        base_entry = reference
    else:
        if not custom_pattern or not target_symbol:
            return FeaturePacket(
                mode="custom",
                target_symbol=target_symbol or "",
                target_range=target_range or 0,
                reference=ReferenceWindow("", "", "", None, None, ""),
                error="custom_pattern_and_target_symbol_required",
            )
        base_entry = AOBEntry(
            name="CustomReference",
            symbol=target_symbol,
            scan_range=target_range or 256,
            pattern=parse_pattern(custom_pattern),
            description="Custom Reference",
        )
        mode = "custom"

    target_entry = replace(
        base_entry,
        symbol=target_symbol or base_entry.symbol,
        scan_range=target_range or base_entry.scan_range,
    )
    reference_window = _reference_window(bridge, base_entry, disasm_count)
    pre_result = preprocess_entry(
        bridge,
        target_entry,
        search_multiplier=search_multiplier,
        top_n=top_n,
        disasm_count=disasm_count,
    )
    decision = decide_hook(_to_hook_input(pre_result), backup_count=max(0, top_n - 1))

    packet = FeaturePacket(
        mode=mode,
        target_symbol=target_entry.symbol,
        target_range=target_entry.scan_range,
        reference=reference_window,
        notes=[
            "Use this packet to compare a known working hook against nearby candidate windows.",
            "Recommended patterns are ranking outputs, not guaranteed final scripts.",
        ],
        error=pre_result.error,
    )

    if ct_path and reference_query:
        sibling_report = build_sibling_report(bridge, ct_path, reference_query, scan_instructions=max(20, disasm_count * 4))
        packet.sibling_candidates = [
            SiblingSummary(
                address=item.address,
                instruction=item.instruction,
                field_offset=item.field_offset,
                confidence=item.confidence,
                relationship=item.relationship,
                notes=item.notes,
            )
            for item in sibling_report.candidates[:5]
        ]

    scored = [decision.best_candidate] if decision.best_candidate else []
    scored.extend(decision.backups)
    for item in [candidate for candidate in scored if candidate is not None]:
        diff = diff_instruction_windows(reference_window.instructions, [inst.get("raw", "") for inst in item.candidate.instructions])
        candidate_intent = classify_instruction_window([inst.get("raw", "") for inst in item.candidate.instructions])
        packet.candidates.append(FeatureCandidate(
            address=item.candidate.address,
            offset=item.candidate.offset,
            scan_range=item.suggested_range or target_entry.scan_range,
            byte_score=item.candidate.byte_score,
            confidence=item.final_score,
            recommended_pattern=item.recommended_pattern,
            uniqueness=item.candidate.uniqueness_classification,
            stability_score=item.candidate.stability_score,
            reason_codes=item.reason_codes,
            method_diff_summary=diff.summary,
            method_diff=diff.unified_diff,
            instructions=[inst.get("raw", "") for inst in item.candidate.instructions],
            intent=IntentSummary(candidate_intent.label, candidate_intent.confidence, candidate_intent.reason_codes),
        ))

    return packet
