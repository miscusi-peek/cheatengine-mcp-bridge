from __future__ import annotations

import json
from pathlib import Path

from .decision import decide_hook
from .models import CandidateInput, HookInput, PostprocessReport


def _parse_candidate(payload: dict) -> CandidateInput:
    return CandidateInput(
        offset=int(payload.get("offset", 0)),
        address=int(str(payload.get("address", "0")), 16),
        byte_score=float(payload.get("byte_score", 0.0)),
        confidence=float(payload.get("confidence", 0.0)),
        diff_count=int(payload.get("diff_count", 0)),
        exact=bool(payload.get("exact", False)),
        within_range=bool(payload.get("within_range", False)),
        tags=list(payload.get("tags") or []),
        notes=list(payload.get("notes") or []),
        actual_bytes=str(payload.get("actual_bytes", "")),
        replacement_pattern=payload.get("replacement_pattern"),
        wildcard_pattern=payload.get("wildcard_pattern"),
        suggested_range=payload.get("suggested_range"),
        instructions=list(payload.get("instructions") or []),
    )


def _parse_hook(payload: dict) -> HookInput:
    method_addr = payload.get("method_addr")
    return HookInput(
        name=str(payload.get("name", "")),
        description=str(payload.get("description", "")),
        symbol=str(payload.get("symbol", "")),
        scan_range=int(payload.get("scan_range", 0)),
        pattern=str(payload.get("pattern", "")),
        method_addr=int(method_addr, 16) if method_addr else None,
        status=str(payload.get("status", "")),
        summary=str(payload.get("summary", "")),
        error=payload.get("error"),
        candidates=[_parse_candidate(item) for item in payload.get("candidates") or []],
    )


def postprocess_report(preprocess_json: str | Path, *, backup_count: int = 2) -> PostprocessReport:
    source = Path(preprocess_json)
    payload = json.loads(source.read_text(encoding="utf-8"))
    hooks = [_parse_hook(item) for item in payload.get("results") or []]

    report = PostprocessReport(
        source_report=str(source),
        hook_count=len(hooks),
    )
    for hook in hooks:
        report.decisions.append(decide_hook(hook, backup_count=backup_count))
    return report
