from __future__ import annotations

import re

from .models import InstructionSummary


_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_DEC_RE = re.compile(r"\b\d+\b")
_ADDR_RE = re.compile(r"\[[^\]]+\]")


def normalize_instruction(text: str) -> str:
    """
    Produce a coarse instruction signature that survives trivial value changes.
    This is intentionally conservative: it keeps mnemonic order and masks
    immediates / concrete addresses rather than trying to fully emulate CE.
    """
    normalized = text.strip().lower()
    normalized = _HEX_RE.sub("IMM", normalized)
    normalized = _DEC_RE.sub("IMM", normalized)
    normalized = _ADDR_RE.sub("[MEM]", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def instruction_from_bridge(item: dict) -> InstructionSummary:
    address = item.get("address", 0)
    if isinstance(address, str):
        try:
            address = int(address, 16)
        except ValueError:
            address = 0

    raw = (item.get("instruction") or item.get("disasm") or "").strip()
    return InstructionSummary(
        address=address,
        raw=raw,
        normalized=normalize_instruction(raw),
        bytes_hex=(item.get("bytes") or "").strip(),
    )
