from __future__ import annotations

import json
from pathlib import Path

from .models import PostprocessReport, ScoredCandidate


def _candidate_to_dict(scored: ScoredCandidate) -> dict:
    candidate = scored.candidate
    return {
        "address": hex(candidate.address),
        "offset": candidate.offset,
        "byte_score": candidate.byte_score,
        "confidence": candidate.confidence,
        "final_score": scored.final_score,
        "mnemonic_score": scored.mnemonic_score,
        "structural_score": scored.structural_score,
        "uniqueness_score": scored.uniqueness_score,
        "stability_score": scored.stability_score,
        "history_score": scored.history_score,
        "reason_codes": scored.reason_codes,
        "recommended_pattern": scored.recommended_pattern,
        "suggested_range": scored.suggested_range,
        "rejected_reason": scored.rejected_reason,
    }


def report_to_dict(report: PostprocessReport) -> dict:
    return {
        "source_report": report.source_report,
        "hook_count": report.hook_count,
        "decisions": [
            {
                "hook": decision.hook.description or decision.hook.name,
                "symbol": decision.hook.symbol,
                "summary": decision.summary,
                "manual_review_flags": decision.manual_review_flags,
                "method_diff": {
                    "summary": decision.method_diff.summary,
                    "unified_diff": decision.method_diff.unified_diff,
                } if decision.method_diff else None,
                "best_candidate": _candidate_to_dict(decision.best_candidate) if decision.best_candidate else None,
                "backups": [_candidate_to_dict(item) for item in decision.backups],
            }
            for decision in report.decisions
        ],
    }


def write_json_report(report: PostprocessReport, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path


def write_markdown_report(report: PostprocessReport, path: str | Path) -> Path:
    lines: list[str] = []
    lines.append("# CT Updater Postprocess Report")
    lines.append("")
    lines.append(f"- Source report: `{report.source_report}`")
    lines.append(f"- Hooks processed: `{report.hook_count}`")
    lines.append("")

    for decision in report.decisions:
        hook_name = decision.hook.description or decision.hook.name
        lines.append(f"## {hook_name}")
        lines.append("")
        lines.append(f"- Symbol: `{decision.hook.symbol}`")
        lines.append(f"- Summary: {decision.summary}")
        if decision.manual_review_flags:
            lines.append(f"- Manual review flags: `{', '.join(decision.manual_review_flags)}`")

        best = decision.best_candidate
        if best:
            lines.append("")
            lines.append("### Best Candidate")
            lines.append("")
            lines.append(f"- Address: `{best.candidate.address:#x}`")
            lines.append(f"- Offset: `method+{best.candidate.offset:#x}`")
            lines.append(f"- Final score: `{best.final_score:.1%}`")
            lines.append(f"- Byte score: `{best.candidate.byte_score:.1%}`")
            lines.append(f"- Stability score: `{best.stability_score:.1%}`")
            lines.append(f"- History score: `{best.history_score:.1%}`")
            lines.append(f"- Recommended pattern: `{best.recommended_pattern or ''}`")
            if best.suggested_range is not None:
                lines.append(f"- Suggested range: `+{best.suggested_range:#x}`")
            lines.append(f"- Reason codes: `{', '.join(best.reason_codes)}`")

        if decision.method_diff:
            lines.append("")
            lines.append("### Method Diff")
            lines.append("")
            for item in decision.method_diff.summary:
                lines.append(f"- {item}")
            if decision.method_diff.unified_diff:
                lines.append("")
                lines.append("```diff")
                lines.extend(decision.method_diff.unified_diff.splitlines())
                lines.append("```")

        if decision.backups:
            lines.append("")
            lines.append("### Backups")
            lines.append("")
            for backup in decision.backups:
                lines.append(f"- `{backup.candidate.address:#x}` final={backup.final_score:.1%} rejected={backup.rejected_reason or 'keep as fallback'}")
        lines.append("")

    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return Path(path)
