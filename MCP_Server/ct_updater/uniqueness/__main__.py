from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .service import evaluate_ct_uniqueness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.uniqueness",
        description="Check whether CT AOB patterns are unique inside sampled method memory.",
    )
    parser.add_argument("ct_file", help="Path to the .CT file")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--search-multiplier", type=int, default=8, help="Sample size multiplier")
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
        results = evaluate_ct_uniqueness(bridge, str(ct_path), search_multiplier=max(1, args.search_multiplier))
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    for result in results:
        print(f"{result.description}: {result.classification}")
        print(f"  symbol={result.symbol}")
        print(f"  matches={result.match_count} search_size={result.search_size}")
        if result.offsets:
            print(f"  offsets={', '.join(hex(offset) for offset in result.offsets)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
