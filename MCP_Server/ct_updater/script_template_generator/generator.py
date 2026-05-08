from __future__ import annotations

import json
from pathlib import Path


def generate_aa_script(
    *,
    feature_name: str,
    symbol: str,
    pattern: str,
    scan_range: int,
    alloc_name: str | None = None,
    aob_name: str | None = None,
) -> str:
    aob = aob_name or f"{feature_name}AOB"
    alloc = alloc_name or f"newmem_{feature_name}"
    label = f"return_{feature_name}"
    symbol_safe = feature_name.replace(" ", "_")

    return f"""[ENABLE]
// Generated scaffold for {feature_name}
aobscanregion({aob},{symbol},{symbol}+{scan_range},{pattern})
alloc({alloc},1024,{aob})
label(code)
label(return)

registersymbol({aob})
registersymbol({alloc})

{alloc}:
code:
  // TODO: insert custom logic here
  // original instructions should be copied here if needed
  jmp return

{aob}:
  jmp {alloc}
  nop
return:

[DISABLE]
{aob}:
  // TODO: restore original instructions here
unregistersymbol({aob})
unregistersymbol({alloc})
dealloc({alloc})
"""


def generate_from_feature_packet(packet_path: str | Path, candidate_index: int = 0) -> str:
    payload = json.loads(Path(packet_path).read_text(encoding="utf-8"))
    candidates = payload.get("candidates") or []
    if not candidates:
        raise ValueError("feature packet contains no candidates")
    if candidate_index < 0 or candidate_index >= len(candidates):
        raise IndexError("candidate index out of range")

    candidate = candidates[candidate_index]
    symbol = payload.get("target_symbol") or ""
    scan_range = int(candidate.get("scan_range") or payload.get("target_range") or 0)
    pattern = candidate.get("recommended_pattern") or ""
    if not symbol or not pattern or not scan_range:
        raise ValueError("packet is missing target_symbol, target_range, or recommended_pattern")

    reference = payload.get("reference") or {}
    feature_name = reference.get("description") or reference.get("name") or "GeneratedFeature"
    return generate_aa_script(
        feature_name=feature_name.replace(" ", ""),
        symbol=symbol,
        pattern=pattern,
        scan_range=scan_range,
    )
