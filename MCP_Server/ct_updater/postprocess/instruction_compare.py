from __future__ import annotations

from collections import Counter


def _tokenize_instruction(raw: str) -> list[str]:
    return [token for token in raw.lower().replace(",", " ").split() if token]


def mnemonic_similarity(instructions: list[dict]) -> float:
    if not instructions:
        return 0.0

    mnemonics = [_tokenize_instruction(item.get("raw", ""))[:1] for item in instructions]
    flat = [token for group in mnemonics for token in group if token]
    if not flat:
        return 0.0

    counts = Counter(flat)
    dominant = counts.most_common(1)[0][1]
    return dominant / len(flat)


def structural_similarity(instructions: list[dict]) -> float:
    if not instructions:
        return 0.0

    has_branch = any("j" in _tokenize_instruction(item.get("raw", ""))[:1] for item in instructions)
    has_call = any(_tokenize_instruction(item.get("raw", ""))[:1] == ["call"] for item in instructions)
    has_mov = any(_tokenize_instruction(item.get("raw", ""))[:1] in (["mov"], ["movss"], ["movsd"]) for item in instructions)

    score = 0.0
    if has_mov:
        score += 0.4
    if has_branch:
        score += 0.3
    if has_call:
        score += 0.3
    return score
