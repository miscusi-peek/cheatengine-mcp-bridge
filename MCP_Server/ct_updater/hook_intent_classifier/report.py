from __future__ import annotations

import json
from pathlib import Path

from .models import IntentClassification


def report_to_dict(report: IntentClassification) -> dict:
    return {
        "label": report.label,
        "confidence": report.confidence,
        "reason_codes": report.reason_codes,
        "counts": report.counts,
        "instructions": report.instructions,
    }


def write_json(report: IntentClassification, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path


def write_markdown(report: IntentClassification, path: str | Path) -> Path:
    lines: list[str] = []
    lines.append("# Hook Intent Classification")
    lines.append("")
    lines.append(f"- Label: `{report.label}`")
    lines.append(f"- Confidence: `{report.confidence:.1%}`")
    lines.append(f"- Reason codes: `{', '.join(report.reason_codes)}`")
    lines.append(f"- Counts: `{', '.join(f'{k}={v}' for k, v in report.counts.items())}`")
    lines.append("")
    lines.append("```text")
    lines.extend(report.instructions)
    lines.append("```")
    out_path = Path(path)
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out_path
