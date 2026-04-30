from __future__ import annotations

import argparse
import sys

from .store import HistoryEntry, HistoryStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.history_store",
        description="Manage a local JSON history of accepted updater fixes.",
    )
    parser.add_argument("store", help="Path to the history JSON file")

    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="Append a new accepted fix")
    add.add_argument("hook")
    add.add_argument("symbol")
    add.add_argument("pattern")
    add.add_argument("--range", dest="range_value", type=int, default=None)
    add.add_argument("--source", default="manual")
    add.add_argument("--notes", default="")

    sub.add_parser("list", help="List stored entries")

    promote = sub.add_parser("promote", help="Show the latest stored baseline for a hook")
    promote.add_argument("hook")

    args = parser.parse_args(argv)
    store = HistoryStore(args.store)

    if args.command == "add":
        store.append(HistoryEntry(
            hook=args.hook,
            symbol=args.symbol,
            pattern=args.pattern,
            range_value=args.range_value,
            source=args.source,
            notes=args.notes,
        ))
        print("stored")
        return 0

    if args.command == "list":
        for entry in store.list_entries():
            print(f"{entry.hook}: {entry.pattern} ({entry.source})")
        return 0

    if args.command == "promote":
        entry = store.promote_latest(args.hook)
        if not entry:
            print("not found")
            return 1
        print(f"hook={entry.hook}")
        print(f"symbol={entry.symbol}")
        print(f"pattern={entry.pattern}")
        print(f"range={entry.range_value}")
        print(f"source={entry.source}")
        print(f"notes={entry.notes}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
