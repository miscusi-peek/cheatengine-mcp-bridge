from __future__ import annotations

import json
from pathlib import Path

from ..parser import pattern_to_str
from .models import CandidateMatch, HookPreprocessResult, PreprocessRunReport


def _candidate_to_dict(candidate: CandidateMatch) -> dict:
    return {
        "offset": candidate.offset,
        "address": hex(candidate.address),
        "byte_score": round(candidate.byte_score, 4),
        "confidence": round(candidate.confidence, 4),
        "diff_count": candidate.diff_count,
        "exact": candidate.exact,
        "within_range": candidate.within_range,
        "tags": candidate.tags,
        "notes": candidate.notes,
        "actual_bytes": candidate.actual_bytes.hex(" ").upper(),
        "replacement_pattern": pattern_to_str(candidate.replacement_pattern) if candidate.replacement_pattern else None,
        "wildcard_pattern": pattern_to_str(candidate.wildcard_pattern) if candidate.wildcard_pattern else None,
        "suggested_range": candidate.suggested_range,
        "match_offsets": candidate.match_offsets,
        "instructions": [
            {
                "address": hex(item.address),
                "bytes": item.bytes_hex,
                "raw": item.raw,
                "normalized": item.normalized,
            }
            for item in candidate.instructions
        ],
    }


def _result_to_dict(result: HookPreprocessResult) -> dict:
    return {
        "name": result.entry.name,
        "description": result.entry.description,
        "symbol": result.entry.symbol,
        "scan_range": result.entry.scan_range,
        "pattern": pattern_to_str(result.entry.pattern),
        "method_addr": hex(result.method_addr) if result.method_addr else None,
        "read_size": result.read_size,
        "search_limit": result.search_limit,
        "status": result.status,
        "summary": result.summary,
        "error": result.error,
        "candidates": [_candidate_to_dict(candidate) for candidate in result.candidates],
    }


def report_to_dict(report: PreprocessRunReport) -> dict:
    return {
        "ct_path": report.ct_path,
        "aob_count": report.aob_count,
        "results": [_result_to_dict(result) for result in report.results],
    }


def write_json_report(report: PreprocessRunReport, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
    return out_path


def render_markdown_report(report: PreprocessRunReport) -> str:
    lines: list[str] = []
    lines.append("# CT Updater Preprocess Report")
    lines.append("")
    lines.append(f"- CT file: `{report.ct_path}`")
    lines.append(f"- AOB entries: `{report.aob_count}`")
    lines.append("")

    for result in report.results:
        lines.append(f"## {result.entry.description or result.entry.name}")
        lines.append("")
        lines.append(f"- Symbol: `{result.entry.symbol}`")
        lines.append(f"- Original range: `+{result.entry.scan_range:#x}`")
        lines.append(f"- Pattern: `{pattern_to_str(result.entry.pattern)}`")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Summary: {result.summary}")
        if result.error:
            lines.append(f"- Error: `{result.error}`")
        lines.append("")

        if not result.candidates:
            continue

        for index, candidate in enumerate(result.candidates, start=1):
            lines.append(f"### Candidate {index}")
            lines.append("")
            lines.append(f"- Address: `{candidate.address:#x}`")
            lines.append(f"- Offset: `method+{candidate.offset:#x}`")
            lines.append(f"- Byte score: `{candidate.byte_score:.1%}`")
            lines.append(f"- Confidence: `{candidate.confidence:.1%}`")
            lines.append(f"- Exact: `{candidate.exact}`")
            lines.append(f"- Within range: `{candidate.within_range}`")
            lines.append(f"- Tags: `{', '.join(candidate.tags)}`")
            lines.append(f"- Actual bytes: `{candidate.actual_bytes.hex(' ').upper()}`")
            if candidate.replacement_pattern:
                lines.append(f"- Replacement pattern: `{pattern_to_str(candidate.replacement_pattern)}`")
            if candidate.wildcard_pattern:
                lines.append(f"- Wildcard pattern: `{pattern_to_str(candidate.wildcard_pattern)}`")
            if candidate.suggested_range is not None:
                lines.append(f"- Suggested range: `+{candidate.suggested_range:#x}`")
            if candidate.match_offsets:
                lines.append(f"- Match offsets: `{', '.join(hex(x) for x in candidate.match_offsets[:8])}`")
            for note in candidate.notes:
                lines.append(f"- Note: {note}")
            lines.append("")

            if candidate.instructions:
                lines.append("```text")
                for instruction in candidate.instructions:
                    lines.append(f"{instruction.address:#x}: {instruction.raw}")
                lines.append("```")
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(report: PreprocessRunReport, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(render_markdown_report(report), encoding="utf-8")
    return out_path
