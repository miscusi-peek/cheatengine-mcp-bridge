from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .discovery import build_feature_packet
from .report import write_json, write_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.feature_builder",
        description="Build a reference-driven packet for creating a new CT feature near a known one.",
    )
    parser.add_argument("--ct-file", default=None, help="Path to the CT file when using a reference hook")
    parser.add_argument("--reference", default=None, help="Reference hook name or description from the CT")
    parser.add_argument("--target-symbol", default=None, help="Target method/symbol to search for sibling logic")
    parser.add_argument("--target-range", type=int, default=None, help="Target scan range")
    parser.add_argument("--pattern", default=None, help="Custom pattern when not using a CT reference")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--top", type=int, default=4, help="Candidates to keep")
    parser.add_argument("--disasm-count", type=int, default=8, help="Instructions per window")
    parser.add_argument("--search-multiplier", type=int, default=8, help="Sampling multiplier")
    parser.add_argument("--json-out", default=None, help="Write JSON packet to this path")
    parser.add_argument("--md-out", default=None, help="Write Markdown packet to this path")
    args = parser.parse_args(argv)

    if args.reference and args.ct_file and not Path(args.ct_file).exists():
        print(f"Error: file not found: {args.ct_file}")
        return 1

    try:
        bridge = BridgeClient(args.pipe)
        bridge.connect()
        bridge.ping()
        if not args.no_mono:
            bridge.init_mono()
        packet = build_feature_packet(
            bridge,
            ct_path=args.ct_file,
            reference_query=args.reference,
            target_symbol=args.target_symbol,
            target_range=args.target_range,
            custom_pattern=args.pattern,
            top_n=max(1, args.top),
            disasm_count=max(1, args.disasm_count),
            search_multiplier=max(1, args.search_multiplier),
        )
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    base_name = Path(args.ct_file).stem if args.ct_file else "feature_packet"
    json_path = write_json(packet, args.json_out or f"{base_name}.feature_packet.json")
    md_path = write_markdown(packet, args.md_out or f"{base_name}.feature_packet.md")
    print(f"JSON packet: {json_path}")
    print(f"Markdown packet: {md_path}")
    if packet.error:
        print(f"Packet error: {packet.error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
