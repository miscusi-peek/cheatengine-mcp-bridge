from __future__ import annotations

from .models import LintReport


def render_lint_report(report: LintReport) -> str:
    lines: list[str] = []
    lines.append("Lint Results")
    lines.append("-" * 60)
    if not report.issues:
        lines.append("No lint issues found.")
        return "\n".join(lines)

    for issue in report.issues:
        target = f" [{issue.target}]" if issue.target else ""
        lines.append(f"{issue.severity.upper():7s} {issue.code}{target}")
        lines.append(f"  {issue.message}")
    return "\n".join(lines)
