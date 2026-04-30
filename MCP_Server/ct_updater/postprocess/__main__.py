from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import postprocess_report
from .report import write_json_report, write_markdown_report


def _default_output_paths(source_path: Path) -> tuple[Path, Path]:
    if source_path.name.endswith(".preprocess.json"):
        stem = source_path.name[:-len(".preprocess.json")]
        base = source_path.with_name(stem)
    else:
        base = source_path.with_suffix("")
    return (
        base.with_name(base.name + ".decision.json"),
        base.with_name(base.name + ".decision.md"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ct_updater.postprocess",
        description="Reduce preprocess candidates to a best match and compact decision report.",
    )
    parser.add_argument("preprocess_json", help="Path to the preprocess JSON report")
    parser.add_argument("--backups", type=int, default=2, help="Backup candidates to keep")
    parser.add_argument("--json-out", default=None, help="Write decision JSON to this path")
    parser.add_argument("--md-out", default=None, help="Write decision Markdown to this path")
    args = parser.parse_args(argv)

    source = Path(args.preprocess_json)
    if not source.exists():
        print(f"Error: file not found: {source}")
        return 1

    report = postprocess_report(source, backup_count=max(0, args.backups))
    json_out, md_out = _default_output_paths(source)
    json_path = write_json_report(report, args.json_out or json_out)
    md_path = write_markdown_report(report, args.md_out or md_out)
    print(f"Decision JSON: {json_path}")
    print(f"Decision Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
