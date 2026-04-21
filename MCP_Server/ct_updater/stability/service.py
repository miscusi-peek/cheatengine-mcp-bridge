from __future__ import annotations

from dataclasses import dataclass, field

from ..parser import Pattern, parse_pattern, pattern_to_str


@dataclass
class StabilityReport:
    original_pattern: str
    actual_bytes: str
    wildcard_indexes: list[int]
    stable_indexes: list[int]
    replacement_pattern: str
    wildcard_pattern: str
    stability_score: float
    # Bytes that are structurally volatile regardless of whether they currently match.
    predicted_volatile_indexes: list[int] = field(default_factory=list)
    # wildcard_pattern with both empirically changed AND structurally-volatile bytes wildcarded.
    hardened_pattern: str = ""


# ---------------------------------------------------------------------------
# Structural volatility heuristics
# ---------------------------------------------------------------------------
# These detect common x86-64 byte sequences whose payload bytes (offsets,
# displacements, immediates) routinely change between compiler builds even
# when the surrounding opcodes stay identical.
# ---------------------------------------------------------------------------

def _volatile_indexes(raw: bytes) -> frozenset[int]:
    """Return the set of byte positions that are structurally volatile."""
    volatile: set[int] = set()
    n = len(raw)
    i = 0
    while i < n:
        b = raw[i]

        # E8 <rel32>  — CALL rel32
        # E9 <rel32>  — JMP  rel32
        if b in (0xE8, 0xE9) and i + 4 < n:
            volatile.update(range(i + 1, i + 5))
            i += 5
            continue

        # EB <rel8>   — JMP short
        if b == 0xEB and i + 1 < n:
            volatile.add(i + 1)
            i += 2
            continue

        # 7x <rel8>   — Jcc short (0x70–0x7F)
        if 0x70 <= b <= 0x7F and i + 1 < n:
            volatile.add(i + 1)
            i += 2
            continue

        # 0F 8x <rel32>  — Jcc near
        if b == 0x0F and i + 1 < n and 0x80 <= raw[i + 1] <= 0x8F and i + 5 < n:
            volatile.update(range(i + 2, i + 6))
            i += 6
            continue

        # REX prefix (48–4F) then check next byte
        rex = b in range(0x48, 0x50)
        j = i + 1 if rex else i
        if j >= n:
            i += 1
            continue
        nb = raw[j]

        # [REX] 8B/8D/89 /5 <disp32>  — MOV/LEA with RIP-relative memory (ModRM = 05)
        # ModRM byte: mod=00, rm=101 → mod<<6 | reg<<3 | rm  where rm=5 means [rip+disp32]
        if nb in (0x8B, 0x8D, 0x89) and j + 1 < n and (raw[j + 1] & 0xC7) == 0x05 and j + 5 < n:
            volatile.update(range(j + 2, j + 6))
            i = j + 6
            continue

        # FF 15 <disp32>  — CALL [RIP+disp32]  (indirect call through IAT)
        if b == 0xFF and j + 1 < n and raw[j] == 0x15 and j + 5 < n:
            volatile.update(range(j + 1, j + 5))
            i = j + 5
            continue

        # [REX.W] B8+r <imm64>  — MOV reg, imm64  (often an absolute address)
        if rex and 0xB8 <= nb <= 0xBF and j + 8 < n:
            volatile.update(range(j + 1, j + 9))
            i = j + 9
            continue

        # B8+r <imm32>  — MOV r32, imm32 (without REX)
        if not rex and 0xB8 <= b <= 0xBF and i + 4 < n:
            volatile.update(range(i + 1, i + 5))
            i += 5
            continue

        # [REX] C7 /0 <imm32>  — MOV r/m64, imm32 sign-extended (common struct-field store)
        if nb == 0xC7 and j + 1 < n and (raw[j + 1] & 0x38) == 0x00 and j + 5 < n:
            volatile.update(range(j + 2, j + 6))
            i = j + 6
            continue

        i += 1

    return frozenset(volatile)


def analyze_stability(pattern: Pattern, actual: bytes) -> StabilityReport:
    wildcard_indexes: list[int] = []
    stable_indexes: list[int] = []
    replacement = list(pattern)
    wildcarded = list(pattern)

    for idx, expected in enumerate(pattern):
        if idx >= len(actual):
            wildcard_indexes.append(idx)
            wildcarded[idx] = None
            continue
        if expected is None:
            wildcard_indexes.append(idx)
            continue
        if actual[idx] == expected:
            stable_indexes.append(idx)
        else:
            wildcard_indexes.append(idx)
            replacement[idx] = actual[idx]
            wildcarded[idx] = None

    total = len([byte for byte in pattern if byte is not None]) or 1
    stability_score = len(stable_indexes) / total

    # Structural volatility — bytes likely to drift in a future build
    predicted = _volatile_indexes(actual)
    predicted_volatile = sorted(predicted)

    # Hardened pattern: wildcard both empirically changed AND structurally volatile
    hardened = list(wildcarded)
    for idx in predicted:
        if 0 <= idx < len(hardened) and hardened[idx] is not None:
            hardened[idx] = None

    return StabilityReport(
        original_pattern=pattern_to_str(pattern),
        actual_bytes=actual.hex(" ").upper(),
        wildcard_indexes=wildcard_indexes,
        stable_indexes=stable_indexes,
        replacement_pattern=pattern_to_str(replacement),
        wildcard_pattern=pattern_to_str(wildcarded),
        stability_score=stability_score,
        predicted_volatile_indexes=predicted_volatile,
        hardened_pattern=pattern_to_str(hardened),
    )


def analyze_pattern_strings(pattern: str, actual_bytes: str) -> StabilityReport:
    actual = bytes(int(part, 16) for part in actual_bytes.split()) if actual_bytes.strip() else b""
    return analyze_stability(parse_pattern(pattern), actual)
