from __future__ import annotations

from ..parser import parse_ct
from .matcher import preprocess_entry
from .models import PreprocessRunReport


def preprocess_ct(
    bridge,
    ct_path: str,
    *,
    search_multiplier: int,
    top_n: int,
    disasm_count: int,
) -> PreprocessRunReport:
    aob_entries, _assert_entries, _pointer_entries = parse_ct(ct_path)
    report = PreprocessRunReport(ct_path=ct_path, aob_count=len(aob_entries))

    for entry in aob_entries:
        result = preprocess_entry(
            bridge,
            entry,
            search_multiplier=search_multiplier,
            top_n=top_n,
            disasm_count=disasm_count,
        )
        report.results.append(result)

    return report
