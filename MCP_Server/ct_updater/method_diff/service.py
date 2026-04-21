from __future__ import annotations

import difflib
from dataclasses import dataclass

from ..preprocess.normalize import normalize_instruction


@dataclass
class MethodDiffReport:
    old_count: int
    new_count: int
    summary: list[str]
    unified_diff: str


def _mnemonics(lines: list[str]) -> list[str]:
    return [normalize_instruction(line) for line in lines if line.strip()]


def diff_instruction_windows(old_lines: list[str], new_lines: list[str]) -> MethodDiffReport:
    old_norm = _mnemonics(old_lines)
    new_norm = _mnemonics(new_lines)

    summary: list[str] = []
    if old_norm == new_norm:
        summary.append("normalized instruction windows match exactly")
    else:
        shared = len(set(old_norm) & set(new_norm))
        summary.append(f"shared normalized instructions: {shared}")
        if len(old_norm) != len(new_norm):
            summary.append(f"instruction count changed: {len(old_norm)} -> {len(new_norm)}")

    diff = "\n".join(difflib.unified_diff(
        old_norm,
        new_norm,
        fromfile="old",
        tofile="new",
        lineterm="",
    ))
    return MethodDiffReport(
        old_count=len(old_norm),
        new_count=len(new_norm),
        summary=summary,
        unified_diff=diff,
    )
