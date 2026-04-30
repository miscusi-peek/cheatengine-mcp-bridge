from __future__ import annotations

import json
from pathlib import Path

from .models import FeaturePacket


def packet_to_dict(packet: FeaturePacket) -> dict:
    return {
        "mode": packet.mode,
        "target_symbol": packet.target_symbol,
        "target_range": packet.target_range,
        "error": packet.error,
        "notes": packet.notes,
        "reference": {
            "description": packet.reference.description,
            "name": packet.reference.name,
            "symbol": packet.reference.symbol,
            "address": hex(packet.reference.address) if packet.reference.address else None,
            "offset": packet.reference.offset,
            "pattern": packet.reference.pattern,
            "instructions": packet.reference.instructions,
            "intent": {
                "label": packet.reference.intent.label,
                "confidence": packet.reference.intent.confidence,
                "reason_codes": packet.reference.intent.reason_codes,
            } if packet.reference.intent else None,
        },
        "sibling_candidates": [
            {
                "address": hex(candidate.address),
                "instruction": candidate.instruction,
                "field_offset": candidate.field_offset,
                "confidence": candidate.confidence,
                "relationship": candidate.relationship,
                "notes": candidate.notes,
            }
            for candidate in packet.sibling_candidates
        ],
        "candidates": [
            {
                "address": hex(candidate.address),
                "offset": candidate.offset,
                "scan_range": candidate.scan_range,
                "byte_score": candidate.byte_score,
                "confidence": candidate.confidence,
                "recommended_pattern": candidate.recommended_pattern,
                "uniqueness": candidate.uniqueness,
                "stability_score": candidate.stability_score,
                "reason_codes": candidate.reason_codes,
                "method_diff_summary": candidate.method_diff_summary,
                "method_diff": candidate.method_diff,
                "instructions": candidate.instructions,
                "intent": {
                    "label": candidate.intent.label,
                    "confidence": candidate.intent.confidence,
                    "reason_codes": candidate.intent.reason_codes,
                } if candidate.intent else None,
            }
            for candidate in packet.candidates
        ],
    }


def write_json(packet: FeaturePacket, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(packet_to_dict(packet), indent=2), encoding="utf-8")
    return out_path


def write_markdown(packet: FeaturePacket, path: str | Path) -> Path:
    lines: list[str] = []
    lines.append("# CT Feature Packet")
    lines.append("")
    lines.append(f"- Mode: `{packet.mode}`")
    lines.append(f"- Target symbol: `{packet.target_symbol}`")
    lines.append(f"- Target range: `+{packet.target_range:#x}`")
    if packet.error:
        lines.append(f"- Error: `{packet.error}`")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append(f"- Description: `{packet.reference.description or packet.reference.name}`")
    lines.append(f"- Symbol: `{packet.reference.symbol}`")
    lines.append(f"- Pattern: `{packet.reference.pattern}`")
    if packet.reference.address:
        lines.append(f"- Address: `{packet.reference.address:#x}`")
    if packet.reference.intent:
        lines.append(f"- Intent: `{packet.reference.intent.label}` ({packet.reference.intent.confidence:.1%})")
        lines.append(f"- Intent reasons: `{', '.join(packet.reference.intent.reason_codes)}`")
    lines.append("")
    if packet.reference.instructions:
        lines.append("```text")
        lines.extend(packet.reference.instructions)
        lines.append("```")
        lines.append("")

    if packet.sibling_candidates:
        lines.append("## Sibling Candidates")
        lines.append("")
        for sibling in packet.sibling_candidates:
            lines.append(f"- `{sibling.address:#x}` offset={sibling.field_offset} confidence={sibling.confidence:.1%} relationship={sibling.relationship}")
            lines.append(f"  instruction: `{sibling.instruction}`")
        lines.append("")

    for idx, candidate in enumerate(packet.candidates, start=1):
        lines.append(f"## Candidate {idx}")
        lines.append("")
        lines.append(f"- Address: `{candidate.address:#x}`")
        lines.append(f"- Offset: `method+{candidate.offset:#x}`")
        lines.append(f"- Suggested scan range: `+{candidate.scan_range:#x}`")
        lines.append(f"- Confidence: `{candidate.confidence:.1%}`")
        lines.append(f"- Byte score: `{candidate.byte_score:.1%}`")
        lines.append(f"- Uniqueness: `{candidate.uniqueness}`")
        lines.append(f"- Stability score: `{candidate.stability_score:.1%}`")
        lines.append(f"- Recommended pattern: `{candidate.recommended_pattern or ''}`")
        lines.append(f"- Reason codes: `{', '.join(candidate.reason_codes)}`")
        if candidate.intent:
            lines.append(f"- Intent: `{candidate.intent.label}` ({candidate.intent.confidence:.1%})")
            lines.append(f"- Intent reasons: `{', '.join(candidate.intent.reason_codes)}`")
        for item in candidate.method_diff_summary:
            lines.append(f"- Method diff: {item}")
        if candidate.instructions:
            lines.append("")
            lines.append("```text")
            lines.extend(candidate.instructions)
            lines.append("```")
        if candidate.method_diff:
            lines.append("")
            lines.append("```diff")
            lines.extend(candidate.method_diff.splitlines())
            lines.append("```")
        lines.append("")

    out_path = Path(path)
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out_path
