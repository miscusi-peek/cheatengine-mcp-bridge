#!/usr/bin/env python3
"""Split and rebuild MCP_Server/ce_mcp_bridge.lua from ordered parts.

This tool uses the existing `-- >>> BEGIN ... <<<` / `-- >>> END ... <<<`
markers in ce_mcp_bridge.lua to create an editable modular source tree without
changing the runtime Lua loading model. The generated manifest preserves exact
part ordering so the file can be rebuilt byte-for-byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = ROOT / "ce_mcp_bridge.lua"
DEFAULT_MODULE_DIR = ROOT / "ce_mcp_bridge_modular"
MANIFEST_NAME = "manifest.json"
PARTS_DIRNAME = "parts"
README_NAME = "README.md"

BEGIN_RE = re.compile(r"^-- >>> BEGIN (.+?) <<<$")
END_RE = re.compile(r"^-- >>> END (.+?) <<<$")


@dataclass
class Part:
    kind: str
    label: str
    filename: str
    content: str

    def to_manifest_entry(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "filename": self.filename,
        }


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_file_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_file_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_")
    return slug or "section"


def short_unit_tag(part: Part | None, fallback: str) -> str:
    if not part:
        return fallback
    match = re.search(r"UNIT-([0-9A-Za-z]+)", part.label)
    if match:
        return f"u{match.group(1).lower()}"
    return fallback


def raw_section_name(content: str, prev_part: Part | None, next_part: Part | None) -> str:
    stripped = content.strip()
    if "CHEATENGINE MCP BRIDGE" in content:
        return "bridge_preamble_globals"
    if "MAIN COMMAND PROCESSOR" in content or "local function executeCommand" in content:
        return "main_processor_pipe_worker_and_control"
    if "cleanupZombieState" in content or "CLEANUP & SAFETY ROUTINES" in content:
        return "cleanup_json_and_shared_runtime"

    if not stripped or stripped == "-- ============================================================================":
        if prev_part and next_part:
            return f"spacer_{short_unit_tag(prev_part, 'prev')}_{short_unit_tag(next_part, 'next')}"
        if next_part:
            return f"spacer_before_{short_unit_tag(next_part, 'next')}"
        if prev_part:
            return f"spacer_after_{short_unit_tag(prev_part, 'prev')}"
        return "spacer"

    if prev_part and next_part:
        return f"interstitial_{short_unit_tag(prev_part, 'prev')}_{short_unit_tag(next_part, 'next')}"
    if next_part:
        return f"interstitial_before_{short_unit_tag(next_part, 'next')}"
    if prev_part:
        return f"interstitial_after_{short_unit_tag(prev_part, 'prev')}"
    return "interstitial"


def assign_filenames(parts: list[Part]) -> None:
    for index, part in enumerate(parts):
        if part.kind == "unit":
            name = slugify(part.label)
        else:
            prev_part = parts[index - 1] if index > 0 else None
            next_part = parts[index + 1] if index + 1 < len(parts) else None
            name = slugify(raw_section_name(part.content, prev_part, next_part))
            part.label = name
        part.filename = f"{index:03d}_{name}.lua"


def split_parts(text: str) -> list[Part]:
    lines = text.splitlines(keepends=True)
    parts: list[Part] = []
    raw_buffer: list[str] = []
    current_unit_lines: list[str] | None = None
    current_unit_label: str | None = None
    raw_index = 0
    unit_index = 0

    def flush_raw() -> None:
        nonlocal raw_index
        if not raw_buffer:
            return
        label = f"raw_{raw_index:03d}"
        filename = f"{len(parts):03d}_{label}.lua"
        parts.append(Part("raw", label, filename, "".join(raw_buffer)))
        raw_buffer.clear()
        raw_index += 1

    for line in lines:
        line_for_match = line.rstrip("\r\n")
        begin_match = BEGIN_RE.match(line_for_match)
        end_match = END_RE.match(line_for_match)

        if current_unit_lines is None:
            if begin_match:
                flush_raw()
                current_unit_label = begin_match.group(1)
                current_unit_lines = [line]
            else:
                raw_buffer.append(line)
            continue

        current_unit_lines.append(line)
        if end_match:
            end_label = end_match.group(1)
            if current_unit_label is None:
                raise ValueError("Malformed state: end marker seen without unit label")
            filename = f"{len(parts):03d}_{slugify(current_unit_label)}.lua"
            parts.append(
                Part(
                    "unit",
                    current_unit_label,
                    filename,
                    "".join(current_unit_lines),
                )
            )
            current_unit_lines = None
            current_unit_label = None
            unit_index += 1

    if current_unit_lines is not None:
        raise ValueError(f"Unclosed unit block: {current_unit_label}")

    flush_raw()
    assign_filenames(parts)
    return parts


def write_readme(target_dir: Path, source_path: Path) -> None:
    readme = f"""# ce_mcp_bridge Modular Source

This directory is generated from `{source_path.name}` by `bridge_builder.py`.

## Layout

- `manifest.json`: ordered list of parts
- `parts/`: editable Lua sections in assembly order

## Commands

Split the current monolithic bridge into parts:

```powershell
python MCP_Server/bridge_builder.py split
```

Rebuild the monolithic bridge from the modular parts:

```powershell
python MCP_Server/bridge_builder.py build
```

Verify that the modular source round-trips to the current bridge:

```powershell
python MCP_Server/bridge_builder.py verify
```

Only edit files under `parts/` if you want those changes preserved by rebuilds.
"""
    (target_dir / README_NAME).write_text(readme, encoding="utf-8", newline="\n")


def do_split(source: Path, target_dir: Path, force: bool) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Source file not found: {source}")
    if target_dir.exists():
        if not force:
            raise FileExistsError(
                f"Target directory already exists: {target_dir}. Use --force to replace it."
            )
        shutil.rmtree(target_dir)

    text = read_file_text(source)
    parts = split_parts(text)

    parts_dir = target_dir / PARTS_DIRNAME
    parts_dir.mkdir(parents=True, exist_ok=True)
    for part in parts:
        write_file_text(parts_dir / part.filename, part.content)

    manifest = {
        "source": str(source.name),
        "source_sha256": sha256_text(text),
        "parts_dir": PARTS_DIRNAME,
        "parts": [part.to_manifest_entry() for part in parts],
    }
    write_file_text(target_dir / MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
    write_readme(target_dir, source)
    print(f"Wrote {len(parts)} parts to {target_dir}")


def load_manifest(module_dir: Path) -> tuple[dict, Path]:
    manifest_path = module_dir / MANIFEST_NAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    manifest = json.loads(read_file_text(manifest_path))
    parts_dir = module_dir / manifest.get("parts_dir", PARTS_DIRNAME)
    return manifest, parts_dir


def iter_part_texts(manifest: dict, parts_dir: Path) -> Iterable[str]:
    for part in manifest["parts"]:
        part_path = parts_dir / part["filename"]
        if not part_path.exists():
            raise FileNotFoundError(f"Missing part file: {part_path}")
        yield read_file_text(part_path)


def build_text(module_dir: Path) -> tuple[str, dict]:
    manifest, parts_dir = load_manifest(module_dir)
    text = "".join(iter_part_texts(manifest, parts_dir))
    return text, manifest


def do_build(module_dir: Path, output: Path) -> None:
    text, manifest = build_text(module_dir)
    write_file_text(output, text)
    print(
        f"Built {output} from {len(manifest['parts'])} parts "
        f"(sha256={sha256_text(text)[:12]})"
    )


def do_verify(module_dir: Path, source: Path) -> None:
    built, manifest = build_text(module_dir)
    current = read_file_text(source)
    built_hash = sha256_text(built)
    current_hash = sha256_text(current)
    manifest_hash = manifest.get("source_sha256")

    if built_hash != current_hash:
        raise SystemExit(
            "Verification failed: rebuilt output does not match current source "
            f"({built_hash[:12]} != {current_hash[:12]})"
        )

    status = "matches manifest source hash" if manifest_hash == current_hash else "differs from manifest source hash"
    print(
        f"Verification passed: rebuilt output matches {source.name} "
        f"(sha256={current_hash[:12]}, {status})"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Split and rebuild ce_mcp_bridge.lua from modular parts."
    )
    parser.add_argument(
        "command",
        choices=("split", "build", "verify"),
        help="Operation to perform.",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"Path to ce_mcp_bridge.lua (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--module-dir",
        type=Path,
        default=DEFAULT_MODULE_DIR,
        help=f"Directory for modular source (default: {DEFAULT_MODULE_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"Output file for build (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing modular source directory during split.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "split":
        do_split(args.source, args.module_dir, args.force)
    elif args.command == "build":
        do_build(args.module_dir, args.output)
    else:
        do_verify(args.module_dir, args.source)


if __name__ == "__main__":
    main()
