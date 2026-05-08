from __future__ import annotations

import re

from ..analyzer import analyze_aob
from ..feature_builder.reference_lookup import find_reference_entry
from .models import SiblingCandidate, SiblingReference, SiblingReport


_MEM_ACCESS_RE = re.compile(
    r"\[(?P<base>[a-z0-9]+)\s*(?P<sign>[+-])?\s*(?P<offset>(?:0x)?[0-9a-fA-F]+)?\]",
    re.IGNORECASE,
)


def _parse_mem_access(instruction: str) -> tuple[str, str] | None:
    match = _MEM_ACCESS_RE.search(instruction)
    if not match:
        return None
    base = (match.group("base") or "").lower()
    sign = match.group("sign") or "+"
    offset = match.group("offset") or "0"
    if offset == "0":
        return base, "0"
    return base, f"{sign}{offset.lower()}"


def _score_relationship(ref_offset: str, cand_offset: str, same_base: bool) -> tuple[str, float, list[str]]:
    notes: list[str] = []
    if not same_base:
        return "different-base", 0.2, ["candidate uses a different base register"]

    if cand_offset == ref_offset:
        return "same-field", 0.1, ["candidate appears to access the exact same field offset"]

    notes.append("candidate uses the same base register with a different displacement")
    relationship = "sibling-field"
    score = 0.85

    try:
        ref_int = int(ref_offset.replace("+", ""), 16)
        cand_int = int(cand_offset.replace("+", ""), 16)
        delta = abs(cand_int - ref_int)
        notes.append(f"field delta appears to be 0x{delta:X}")
        if delta <= 0x20:
            score = 0.95
        elif delta <= 0x80:
            score = 0.85
        else:
            score = 0.70
    except ValueError:
        notes.append("field delta could not be parsed numerically")

    return relationship, score, notes


def build_sibling_report(
    bridge,
    ct_path: str,
    reference_query: str,
    *,
    scan_instructions: int = 40,
) -> SiblingReport:
    entry = find_reference_entry(ct_path, reference_query)
    if not entry:
        return SiblingReport(
            reference=SiblingReference("", "", None, None, ""),
            error="reference_not_found",
        )

    analysis = analyze_aob(bridge, entry)
    if analysis.method_addr is None or analysis.found_offset is None:
        return SiblingReport(
            reference=SiblingReference(entry.description, entry.symbol, analysis.method_addr, analysis.found_offset, ""),
            error="reference_not_resolved",
        )

    ref_addr = analysis.method_addr + analysis.found_offset
    ref_window = bridge.disassemble(ref_addr, 1)
    ref_instruction = (ref_window[0].get("instruction") or ref_window[0].get("disasm") or "") if ref_window else ""
    ref_access = _parse_mem_access(ref_instruction)
    if not ref_access:
        return SiblingReport(
            reference=SiblingReference(entry.description, entry.symbol, ref_addr, analysis.found_offset, ref_instruction),
            error="reference_has_no_memory_access",
        )

    ref_base, ref_offset = ref_access
    report = SiblingReport(
        reference=SiblingReference(
            description=entry.description,
            symbol=entry.symbol,
            address=ref_addr,
            offset=analysis.found_offset,
            instruction=ref_instruction,
            base_register=ref_base,
            field_offset=ref_offset,
        )
    )

    window = bridge.disassemble(analysis.method_addr, scan_instructions)
    seen: set[tuple[str, str]] = set()
    for item in window:
        address = item.get("address", 0)
        if isinstance(address, str):
            try:
                address = int(address, 16)
            except ValueError:
                address = 0
        instruction = item.get("instruction") or item.get("disasm") or ""
        parsed = _parse_mem_access(instruction)
        if not parsed:
            continue
        base, offset = parsed
        key = (base, offset)
        if key in seen:
            continue
        seen.add(key)

        relationship, confidence, notes = _score_relationship(ref_offset, offset, base == ref_base)
        if relationship == "different-base":
            continue

        report.candidates.append(SiblingCandidate(
            address=address,
            instruction=instruction,
            base_register=base,
            field_offset=offset,
            relationship=relationship,
            confidence=confidence,
            notes=notes,
        ))

    report.candidates.sort(key=lambda item: item.confidence, reverse=True)
    return report
