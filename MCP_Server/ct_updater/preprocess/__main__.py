from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .matcher import DEFAULT_SEARCH_MULTIPLIER, DEFAULT_TOP_CANDIDATES
from .pipeline import preprocess_ct
from .report import write_json_report, write_markdown_report


def _default_output_paths(ct_path: Path) -> tuple[Path, Path]:
    base = ct_path.with_suffix("")
    return (
        base.with_name(base.name + ".preprocess.json"),
        base.with_name(base.name + ".preprocess.md"),
    )


def _print_summary(report) -> None:
    print(f"Preprocessed {report.aob_count} AOB entry(s)")
    for result in report.results:
        label = result.entry.description or result.entry.name
        print(f"- {label}: {result.status}")
        print(f"  {result.summary}")
        if result.candidates:
            top = result.candidates[0]
            print(
                f"  Top candidate: method+{top.offset:#x} "
                f"score={top.byte_score:.0%} confidence={top.confidence:.0%}"
            )
        elif result.error:
            print(f"  Error: {result.error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.preprocess",
        description="Generate ranked AOB candidates before asking Claude to reason about updates.",
    )
    parser.add_argument("ct_file", help="Path to the .CT file")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP_CANDIDATES, help="Candidates per AOB")
    parser.add_argument(
        "--search-multiplier",
        type=int,
        default=DEFAULT_SEARCH_MULTIPLIER,
        help="How far beyond the original scan range to sample",
    )
    parser.add_argument("--disasm-count", type=int, default=8, help="Instructions to capture per candidate")
    parser.add_argument("--json-out", default=None, help="Write JSON report to this path")
    parser.add_argument("--md-out", default=None, help="Write Markdown report to this path")
    args = parser.parse_args(argv)

    ct_path = Path(args.ct_file)
    if not ct_path.exists():
        print(f"Error: file not found: {ct_path}")
        return 1

    try:
        bridge = BridgeClient(args.pipe)
        bridge.connect()
    except BridgeError as exc:
        print(f"Error: {exc}")
        print("Make sure Cheat Engine is running with ce_mcp_bridge.lua loaded.")
        return 1

    try:
        info = bridge.ping()
        print(f"Connected: {info.get('message', 'CE bridge active')}")
        if not args.no_mono:
            print("Initialising Mono data collector (wait ~4 s) ...")
            bridge.init_mono()

        report = preprocess_ct(
            bridge,
            str(ct_path),
            search_multiplier=max(1, args.search_multiplier),
            top_n=max(1, args.top),
            disasm_count=max(1, args.disasm_count),
        )
        _print_summary(report)

        json_out, md_out = _default_output_paths(ct_path)
        json_path = write_json_report(report, args.json_out or json_out)
        md_path = write_markdown_report(report, args.md_out or md_out)
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
    finally:
        bridge.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
