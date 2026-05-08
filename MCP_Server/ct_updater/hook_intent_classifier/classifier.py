from __future__ import annotations

import re

from .models import IntentClassification


_COMPARE_RE = re.compile(r"^(cmp|test|ucomiss|comiss)\b", re.IGNORECASE)
_BRANCH_RE = re.compile(r"^j[a-z]+\b", re.IGNORECASE)
_CALL_RE = re.compile(r"^call\b", re.IGNORECASE)
_MEM_RE = re.compile(r"\[[^\]]+\]")
_DISASM_PREFIX_RE = re.compile(r"^[0-9a-f`]+\s*-\s*[0-9a-f ]+\s*-\s*", re.IGNORECASE)


def _instruction_core(line: str) -> str:
    text = line.strip()
    if not text:
        return ""
    return _DISASM_PREFIX_RE.sub("", text).strip()


def _split_instruction(text: str) -> tuple[str, list[str]]:
    if not text:
        return "", []
    parts = text.split(None, 1)
    mnemonic = parts[0].lower()
    operands = []
    if len(parts) > 1:
        operands = [item.strip().lower() for item in parts[1].split(",")]
    return mnemonic, operands


def _classify_instruction(line: str) -> str | None:
    text = _instruction_core(line).lower()
    if not text:
        return None
    if _BRANCH_RE.match(text):
        return "branch"
    if _CALL_RE.match(text):
        return "call"
    if _COMPARE_RE.match(text):
        return "compare"

    mnemonic, operands = _split_instruction(text)
    if operands and _MEM_RE.search(operands[0]):
        return "write"
    if any(_MEM_RE.search(operand) for operand in operands[1:]):
        return "read"
    if operands and _MEM_RE.search(operands[0]) and mnemonic in {"push", "lea"}:
        return "read"
    if _MEM_RE.search(text):
        return "read"
    return "other"


def classify_instruction_window(lines: list[str]) -> IntentClassification:
    counts = {
        "write": 0,
        "read": 0,
        "compare": 0,
        "branch": 0,
        "call": 0,
        "other": 0,
    }
    for line in lines:
        label = _classify_instruction(line) or "other"
        counts[label] += 1

    reason_codes: list[str] = []
    total = max(1, sum(counts.values()))

    if counts["write"] >= 1 and counts["read"] >= 1:
        label = "read_modify_write"
        confidence = min(1.0, (counts["write"] + counts["read"] + counts["compare"] * 0.5) / total)
        reason_codes.append("memory_read_then_store")
    elif counts["write"] >= 2 and counts["compare"] <= counts["write"]:
        label = "write"
        confidence = min(1.0, (counts["write"] + counts["branch"] * 0.5) / total)
        reason_codes.append("multiple_memory_writes")
    elif counts["compare"] >= 1 and counts["branch"] >= 1 and counts["write"] == 0:
        label = "branch_gate"
        confidence = min(1.0, (counts["compare"] + counts["branch"]) / total)
        reason_codes.append("compare_followed_by_branch")
    elif counts["read"] >= 2 and counts["write"] == 0:
        label = "read"
        confidence = min(1.0, counts["read"] / total)
        reason_codes.append("memory_reads_without_store")
    elif counts["call"] >= 1 and counts["write"] == 0 and counts["compare"] == 0:
        label = "callsite"
        confidence = min(1.0, counts["call"] / total)
        reason_codes.append("call_dominant_window")
    elif counts["compare"] >= 1:
        label = "compare"
        confidence = min(1.0, (counts["compare"] + counts["branch"] * 0.5) / total)
        reason_codes.append("comparison_present")
    else:
        label = "mixed"
        confidence = 0.35
        reason_codes.append("no_single_dominant_behavior")

    if counts["branch"]:
        reason_codes.append("branch_present")
    if counts["call"]:
        reason_codes.append("call_present")

    return IntentClassification(
        label=label,
        confidence=round(confidence, 4),
        reason_codes=reason_codes,
        counts=counts,
        instructions=lines,
    )
