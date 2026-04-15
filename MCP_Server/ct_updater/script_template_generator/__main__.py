from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .generator import generate_aa_script, generate_from_feature_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.script_template_generator",
        description="Generate a CE Auto Assembler scaffold from a feature packet or direct inputs.",
    )
    parser.add_argument("--feature-packet", default=None, help="Path to a feature packet JSON")
    parser.add_argument("--candidate-index", type=int, default=0, help="Candidate index when using --feature-packet")
    parser.add_argument("--feature-name", default=None, help="Feature name when using direct inputs")
    parser.add_argument("--symbol", default=None, help="Target symbol when using direct inputs")
    parser.add_argument("--pattern", default=None, help="Recommended AOB pattern when using direct inputs")
    parser.add_argument("--scan-range", type=int, default=None, help="Scan range when using direct inputs")
    parser.add_argument("--out", default=None, help="Write script to this path instead of stdout")
    args = parser.parse_args(argv)

    if args.feature_packet:
        script = generate_from_feature_packet(args.feature_packet, candidate_index=max(0, args.candidate_index))
        base_name = Path(args.feature_packet).stem
    else:
        if not (args.feature_name and args.symbol and args.pattern and args.scan_range):
            print("Error: provide --feature-packet or all of --feature-name/--symbol/--pattern/--scan-range")
            return 1
        script = generate_aa_script(
            feature_name=args.feature_name,
            symbol=args.symbol,
            pattern=args.pattern,
            scan_range=args.scan_range,
        )
        base_name = args.feature_name.replace(" ", "_")

    if args.out:
        Path(args.out).write_text(script, encoding="utf-8")
        print(args.out)
    else:
        print(script)
    return 0


if __name__ == "__main__":
    sys.exit(main())
