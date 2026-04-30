from __future__ import annotations

from collections import Counter

from ..parser import parse_ct, pattern_to_str
from .models import LintIssue, LintReport


def lint_ct(bridge, ct_path: str) -> LintReport:
    aob_entries, assert_entries, _pointer_entries = parse_ct(ct_path)
    report = LintReport(ct_path=ct_path)

    pattern_counts = Counter(pattern_to_str(entry.pattern) for entry in aob_entries)
    for entry in aob_entries:
        target = entry.description or entry.name
        non_wildcards = sum(1 for byte in entry.pattern if byte is not None)
        wildcards = sum(1 for byte in entry.pattern if byte is None)

        if non_wildcards > 10 and wildcards == 0:
            report.issues.append(LintIssue(
                severity="warning",
                code="ZERO_WILDCARDS",
                message="Long pattern has no wildcards and may be brittle across updates.",
                target=target,
            ))

        if entry.scan_range < 100:
            report.issues.append(LintIssue(
                severity="warning",
                code="TIGHT_SCAN_RANGE",
                message=f"Scan range {entry.scan_range} is under 100 bytes and may miss harmless method growth.",
                target=target,
            ))

        if pattern_counts[pattern_to_str(entry.pattern)] > 1:
            report.issues.append(LintIssue(
                severity="warning",
                code="DUPLICATE_AOB",
                message="Pattern appears multiple times in this CT; verify that both hooks really need the same signature.",
                target=target,
            ))

    for entry in assert_entries:
        addr = bridge.get_symbol_addr(entry.symbol) if bridge else None
        if not addr:
            report.issues.append(LintIssue(
                severity="error",
                code="ASSERT_UNRESOLVED",
                message=f"Assert symbol '{entry.symbol}' did not resolve.",
                target=entry.description or entry.symbol,
            ))

    return report
