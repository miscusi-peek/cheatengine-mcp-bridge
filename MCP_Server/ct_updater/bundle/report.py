from __future__ import annotations

import json
from pathlib import Path

from ..postprocess.report import report_to_dict as postprocess_report_to_dict
from ..preprocess.report import report_to_dict as preprocess_report_to_dict


def build_ai_bundle(ct_path: str, preprocess_report, postprocess_report, *, flow_summary: dict | None = None) -> dict:
    return {
        "ct_path": ct_path,
        "summary": {
            "escalated_hooks": preprocess_report.aob_count,
            "flow_summary": flow_summary or {},
        },
        "preprocess": preprocess_report_to_dict(preprocess_report),
        "decision": postprocess_report_to_dict(postprocess_report),
    }


def write_ai_bundle_json(bundle: dict, path: str | Path) -> Path:
    out_path = Path(path)
    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return out_path


def write_ai_bundle_markdown(bundle: dict, path: str | Path) -> Path:
    lines: list[str] = []
    lines.append("# CT Updater AI Bundle")
    lines.append("")
    lines.append(f"- CT file: `{bundle['ct_path']}`")
    lines.append(f"- Escalated hooks: `{bundle['summary']['escalated_hooks']}`")
    flow_summary = bundle["summary"].get("flow_summary") or {}
    if flow_summary:
        lines.append(f"- Flow summary: `{', '.join(f'{k}={v}' for k, v in flow_summary.items())}`")
    lines.append("")

    for decision in bundle["decision"]["decisions"]:
        lines.append(f"## {decision['hook']}")
        lines.append("")
        lines.append(f"- Symbol: `{decision['symbol']}`")
        lines.append(f"- Summary: {decision['summary']}")
        best = decision.get("best_candidate")
        if best:
            lines.append(f"- Best address: `{best['address']}`")
            lines.append(f"- Final score: `{best['final_score']:.1%}`")
            lines.append(f"- Recommended pattern: `{best.get('recommended_pattern') or ''}`")
            lines.append(f"- Reason codes: `{', '.join(best.get('reason_codes') or [])}`")
        method_diff = decision.get("method_diff")
        if method_diff and method_diff.get("summary"):
            for item in method_diff["summary"]:
                lines.append(f"- Method diff: {item}")
        lines.append("")

    out_path = Path(path)
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out_path
