from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .report import render_lint_report
from .service import lint_ct


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.lint",
        description="Run pre-flight lint checks against a CT file.",
    )
    parser.add_argument("ct_file")
    parser.add_argument("--pipe", default=PIPE_NAME)
    parser.add_argument("--no-mono", action="store_true")
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
        report = lint_ct(bridge, str(ct_path))
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    print(render_lint_report(report))
    return 1 if report.has_errors else 0


if __name__ == "__main__":
    sys.exit(main())
