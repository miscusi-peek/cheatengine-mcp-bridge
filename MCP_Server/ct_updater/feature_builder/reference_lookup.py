from __future__ import annotations

from ..parser import AOBEntry, parse_ct


def find_reference_entry(ct_path: str, query: str) -> AOBEntry | None:
    aob_entries, _assert_entries, _pointer_entries = parse_ct(ct_path)
    q = query.strip().lower()

    exact = [
        entry for entry in aob_entries
        if entry.name.lower() == q or entry.description.lower() == q
    ]
    if exact:
        return exact[0]

    fuzzy = [
        entry for entry in aob_entries
        if q in entry.name.lower() or q in entry.description.lower()
    ]
    return fuzzy[0] if fuzzy else None
