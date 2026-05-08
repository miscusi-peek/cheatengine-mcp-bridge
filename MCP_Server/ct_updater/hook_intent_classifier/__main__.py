from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from ..feature_builder.discovery import find_reference_entry
from ..analyzer import analyze_aob
from .classifier import classify_instruction_window
from .report import write_json, write_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.hook_intent_classifier",
        description="Classify a hook window as write/read/compare/branch gate/callsite using simple heuristics.",
    )
    parser.add_argument("--ct-file", default=None, help="CT file used to look up a reference hook")
    parser.add_argument("--reference", default=None, help="Reference hook name or description")
    parser.add_argument("--symbol", default=None, help="Direct symbol to inspect when not using a CT reference")
    parser.add_argument("--address", default=None, help="Direct address to inspect, e.g. 0x140012340")
    parser.add_argument("--count", type=int, default=8, help="Instructions to inspect")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--json-out", default=None, help="Write JSON report to this path")
    parser.add_argument("--md-out", default=None, help="Write Markdown report to this path")
    args = parser.parse_args(argv)

    try:
        bridge = BridgeClient(args.pipe)
        bridge.connect()
        bridge.ping()
        if not args.no_mono:
            bridge.init_mono()

        if args.reference and args.ct_file:
            entry = find_reference_entry(args.ct_file, args.reference)
            if not entry:
                print("Error: reference not found")
                return 1
            analysis = analyze_aob(bridge, entry)
            if analysis.method_addr is None or analysis.found_offset is None:
                print("Error: reference did not resolve to a method window")
                return 1
            start_addr = analysis.method_addr + analysis.found_offset
            base_name = Path(args.ct_file).stem
        elif args.symbol:
            start_addr = bridge.get_symbol_addr(args.symbol)
            if not start_addr:
                print("Error: symbol did not resolve")
                return 1
            base_name = args.symbol.replace(":", "_")
        elif args.address:
            start_addr = int(args.address, 16)
            base_name = "intent_window"
        else:
            print("Error: provide --reference with --ct-file, or --symbol, or --address")
            return 1

        instructions = [
            item.get("instruction") or item.get("disasm") or ""
            for item in bridge.disassemble(start_addr, max(1, args.count))
        ]
        report = classify_instruction_window(instructions)
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    json_path = write_json(report, args.json_out or f"{base_name}.intent.json")
    md_path = write_markdown(report, args.md_out or f"{base_name}.intent.md")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
