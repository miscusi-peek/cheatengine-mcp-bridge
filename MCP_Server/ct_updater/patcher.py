"""
CT file patcher — applies auto-fixes to the raw .CT file text and writes
a new .updated.CT file. Operates on raw text (not re-serialized XML) to
preserve all formatting, comments, and CDATA sections exactly.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from .analyzer import AOBResult, AssertResult, Status
from .parser import pattern_to_str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _escape_for_re(s: str) -> str:
    """Escape a literal string for use in re.sub."""
    return re.escape(s)


# ---------------------------------------------------------------------------
# Range fix
# ---------------------------------------------------------------------------

def _apply_range_fix(text: str, result: AOBResult) -> tuple[str, bool]:
    """Replace the old range in an aobscanregion with the new range."""
    entry = result.entry
    old_line = entry.raw_line

    # Build the new end expression by replacing the numeric suffix
    # Old end expr: "Symbol+OLD"  →  new: "Symbol+NEW"
    end_re = re.compile(
        r'(aobscanregion\s*\(\s*' + re.escape(entry.name) + r'\s*,\s*'
        + re.escape(entry.symbol) + r'\s*,\s*'
        + re.escape(entry.symbol) + r'\s*\+\s*)'
        r'(\d+|0x[0-9A-Fa-f]+)',
        re.IGNORECASE,
    )
    new_range_str = str(result.new_range)
    new_text, count = end_re.subn(r'\g<1>' + new_range_str, text, count=1)
    return new_text, count > 0


# ---------------------------------------------------------------------------
# Pattern (byte-change) fix
# ---------------------------------------------------------------------------

def _apply_pattern_fix(text: str, result: AOBResult) -> tuple[str, bool]:
    """Replace the old byte pattern in an aobscanregion with the new one."""
    entry = result.entry
    old_pat_str = pattern_to_str(entry.pattern)
    new_pat_str = pattern_to_str(result.new_pattern)

    # Escape whitespace variability in the pattern string
    old_pat_escaped = r'\s+'.join(re.escape(b) for b in old_pat_str.split())
    full_re = re.compile(
        r'(aobscanregion\s*\(\s*' + re.escape(entry.name) + r'[^)]*?,\s*)'
        + old_pat_escaped
        + r'(\s*\))',
        re.IGNORECASE,
    )
    new_text, count = full_re.subn(r'\g<1>' + new_pat_str + r'\g<2>', text, count=1)

    # Fallback: plain string replacement if regex didn't match (e.g. wildcards)
    if count == 0 and old_pat_str in text:
        new_text = text.replace(old_pat_str, new_pat_str, 1)
        count = 1

    # Also update range if needed
    if count > 0 and result.new_range and result.new_range > entry.scan_range:
        new_text, _ = _apply_range_fix(new_text, result)

    return new_text, count > 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_fixes(
    ct_path: str,
    aob_results: list[AOBResult],
    assert_results: list[AssertResult],
    dry_run: bool = False,
) -> tuple[str, list[str]]:
    """
    Apply all auto-fixable results to the CT file text.

    Returns:
        (output_path, list_of_applied_fix_descriptions)

    If dry_run=True, the file is not written; output_path will be ''.
    """
    source = Path(ct_path)
    text = source.read_text(encoding='utf-8', errors='replace')
    original = text

    applied: list[str] = []
    skipped: list[str] = []

    for r in aob_results:
        if not r.can_auto_fix:
            continue
        entry = r.entry
        prev_text = text

        if r.status == Status.RANGE_MISS and r.new_range:
            text, ok = _apply_range_fix(text, r)
            if ok:
                applied.append(
                    f'[RANGE]  {entry.description} / {entry.name}: '
                    f'range {entry.scan_range} -> {r.new_range}'
                )
            else:
                skipped.append(f'[RANGE-FAIL] {entry.name}: could not find pattern in file')

        elif r.status == Status.BYTE_CHANGE and r.new_pattern:
            text, ok = _apply_pattern_fix(text, r)
            diffs = ', '.join(
                f'byte[{d.offset}]: {d.expected:02X}->{d.actual:02X}'
                for d in r.diffs
            )
            if ok:
                applied.append(
                    f'[BYTES]  {entry.description} / {entry.name}: {diffs}'  # ASCII diffs
                )
                if r.new_range and r.new_range > entry.scan_range:
                    applied.append(
                        f'         also extended range to {r.new_range}'
                    )
            else:
                skipped.append(f'[BYTES-FAIL] {entry.name}: could not replace pattern in file')

    if skipped:
        print('\nWarnings (could not apply):')
        for s in skipped:
            print(f'  {s}')

    if dry_run or text == original:
        return '', applied

    out_path = source.with_suffix('.updated.CT')
    # Back up if an .updated.CT already exists
    if out_path.exists():
        out_path.with_suffix('.bak.CT').write_bytes(out_path.read_bytes())
    out_path.write_text(text, encoding='utf-8')
    return str(out_path), applied
