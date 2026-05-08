from __future__ import annotations

import json
from pathlib import Path

from .models import SiblingReport


def report_to_dict(report: SiblingReport) -> dict:
    return {
        "error": report.error,
        "reference": {
            "description": report.reference.description,
            "symbol": report.reference.symbol,
            "address": hex(report.reference.address) if report.reference.address else None,
            "offset": report.reference.offset,
            "instruction": report.reference.instruction,
            "base_register": report.reference.base_register,
            "field_offset": report.reference.field_offset,
        },
        "candidates": [
            {
                "address": hex(candidate.address),
                "instruction": candidate.instruction,
                "base_register": candidate.base_register,
                "field_offset": candidate.field_offset,
                "relationship": candidate.relationship,
                "confidence": candidate.confidence,
                "notes": candidate.notes,
            }
            for candidate in report.candidates
        ],
    }


def write_json(report: SiblingReport, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path


def write_markdown(report: SiblingReport, path: str | Path) -> Path:
    lines: list[str] = []
    lines.append("# Sibling Field Report")
    lines.append("")
    if report.error:
        lines.append(f"- Error: `{report.error}`")
        lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append(f"- Description: `{report.reference.description}`")
    lines.append(f"- Symbol: `{report.reference.symbol}`")
    if report.reference.address is not None:
        lines.append(f"- Address: `{report.reference.address:#x}`")
    lines.append(f"- Instruction: `{report.reference.instruction}`")
    lines.append(f"- Base register: `{report.reference.base_register}`")
    lines.append(f"- Field offset: `{report.reference.field_offset}`")
    lines.append("")

    for idx, candidate in enumerate(report.candidates, start=1):
        lines.append(f"## Candidate {idx}")
        lines.append("")
        lines.append(f"- Address: `{candidate.address:#x}`")
        lines.append(f"- Instruction: `{candidate.instruction}`")
        lines.append(f"- Relationship: `{candidate.relationship}`")
        lines.append(f"- Confidence: `{candidate.confidence:.1%}`")
        lines.append(f"- Base register: `{candidate.base_register}`")
        lines.append(f"- Field offset: `{candidate.field_offset}`")
        for note in candidate.notes:
            lines.append(f"- Note: {note}")
        lines.append("")

    out_path = Path(path)
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out_path
