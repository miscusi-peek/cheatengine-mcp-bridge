from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .service import diff_instruction_windows


def _read_lines(path: str) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.method_diff",
        description="Compare two instruction windows and summarize normalized changes.",
    )
    parser.add_argument("old_file", help="Text file with old instructions, one per line")
    parser.add_argument("new_file", help="Text file with new instructions, one per line")
    args = parser.parse_args(argv)

    report = diff_instruction_windows(_read_lines(args.old_file), _read_lines(args.new_file))
    for line in report.summary:
        print(f"- {line}")
    print("")
    print(report.unified_diff or "(no diff)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
