from __future__ import annotations

from pathlib import Path

from ..analyzer import analyze_aob, analyze_assert
from ..bridge import BridgeClient
from ..parser import parse_ct
from ..patcher import preview_fixes


def preview_ct_updates(
    bridge: BridgeClient,
    ct_path: str,
    *,
    init_mono: bool = True,
    context_lines: int = 1,
) -> tuple[list[str], list[str], str]:
    aob_entries, assert_entries, _pointer_entries = parse_ct(ct_path)
    if init_mono and aob_entries:
        bridge.init_mono()

    aob_results = [analyze_aob(bridge, entry) for entry in aob_entries]
    assert_results = [analyze_assert(bridge, entry) for entry in assert_entries]
    return preview_fixes(ct_path, aob_results, assert_results, context_lines=context_lines)
