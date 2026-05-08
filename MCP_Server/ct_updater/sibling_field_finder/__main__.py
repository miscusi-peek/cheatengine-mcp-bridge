from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .finder import build_sibling_report
from .report import write_json, write_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.sibling_field_finder",
        description="Find nearby sibling field/resource accesses from a known CT reference hook.",
    )
    parser.add_argument("ct_file", help="Path to the CT file")
    parser.add_argument("reference", help="Reference hook name or description")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--scan-instructions", type=int, default=40, help="Method instructions to inspect")
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
        bridge.ping()
        if not args.no_mono:
            bridge.init_mono()
        report = build_sibling_report(
            bridge,
            str(ct_path),
            args.reference,
            scan_instructions=max(1, args.scan_instructions),
        )
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    base = ct_path.stem
    json_path = write_json(report, args.json_out or f"{base}.sibling_fields.json")
    md_path = write_markdown(report, args.md_out or f"{base}.sibling_fields.md")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    if report.error:
        print(f"Report error: {report.error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
