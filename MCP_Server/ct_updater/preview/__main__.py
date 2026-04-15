from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..bridge import BridgeClient, BridgeError, PIPE_NAME
from .service import preview_ct_updates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.preview",
        description="Preview .CT edits without writing a .updated.CT file.",
    )
    parser.add_argument("ct_file", help="Path to the .CT file")
    parser.add_argument("--pipe", default=PIPE_NAME, help="Named pipe override")
    parser.add_argument("--no-mono", action="store_true", help="Skip LaunchMonoDataCollector")
    parser.add_argument("--context", type=int, default=1, help="Unified diff context lines")
    args = parser.parse_args(argv)

    ct_path = Path(args.ct_file)
    if not ct_path.exists():
        print(f"Error: file not found: {ct_path}")
        return 1

    try:
        bridge = BridgeClient(args.pipe)
        bridge.connect()
        bridge.ping()
        applied, skipped, diff = preview_ct_updates(
            bridge,
            str(ct_path),
            init_mono=not args.no_mono,
            context_lines=max(0, args.context),
        )
    except BridgeError as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        try:
            bridge.close()
        except Exception:
            pass

    print("Planned fixes:")
    for line in applied or ["(none)"]:
        print(f"- {line}")
    if skipped:
        print("Skipped:")
        for line in skipped:
            print(f"- {line}")
    print("")
    print(diff or "(no textual changes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
