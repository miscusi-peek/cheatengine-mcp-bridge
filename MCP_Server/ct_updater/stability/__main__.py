from __future__ import annotations

import argparse
import sys

from .service import analyze_pattern_strings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.stability",
        description="Analyze which bytes in an AOB candidate should stay fixed or be wildcarded.",
    )
    parser.add_argument("pattern", help='Original pattern, e.g. "48 8B ?? 10"')
    parser.add_argument("actual_bytes", help='Actual bytes, e.g. "48 8B 33 10"')
    args = parser.parse_args(argv)

    report = analyze_pattern_strings(args.pattern, args.actual_bytes)
    print(f"stability_score={report.stability_score:.1%}")
    print(f"replacement_pattern={report.replacement_pattern}")
    print(f"wildcard_pattern={report.wildcard_pattern}")
    print(f"stable_indexes={report.stable_indexes}")
    print(f"wildcard_indexes={report.wildcard_indexes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
