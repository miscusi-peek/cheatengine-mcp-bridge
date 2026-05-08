"""
ptr_walk -- Pointer chain walker.

Follows all valid heap pointers from a root object (BFS) and checks each
discovered object for your known values. Finds effective-stat objects,
sub-components, and cached copies that the root object only references.

Run from MCP_Server/:
    python -m ct_updater.tools.ptr_walk ADDRESS [options]

    ADDRESS: hex (0x...), decimal, or a CE symbol (auto-dereferenced).

Examples:
    python -m ct_updater.tools.ptr_walk CharacterPtr --known xp=36105,might=15,dex=11
    python -m ct_updater.tools.ptr_walk CharacterPtr --known might=20,con=20 --depth 3
    python -m ct_updater.tools.ptr_walk CharacterPtr --known xp=36105 --min-matches 1

Options:
    --known k=v     Values to search for (comma-separated)
    --depth N       Max pointer-chain depth (default 2)
    --window N      Bytes of each object to scan (default 0x600)
    --min-matches N Min matched values to report (default 1)
    --dump-match    Show memory table around each match
"""
import sys
import struct
import argparse
from collections import deque

from ..bridge import BridgeClient, BridgeError
from ._common import parse_comma_known, is_heap_ptr


def _find_values(mem: bytes, val_to_name: dict) -> dict:
    """Return {offset: name} for every known dword value in mem."""
    hits = {}
    for i in range(0, len(mem) - 3, 4):
        v = struct.unpack_from('<I', mem, i)[0]
        if v in val_to_name:
            hits[i] = val_to_name[v]
    return hits


def _find_pointers(mem: bytes) -> list:
    """Return [(offset, target_addr)] for all valid heap pointers."""
    ptrs = []
    for i in range(0, len(mem) - 7, 8):
        qw = struct.unpack_from('<Q', mem, i)[0]
        if is_heap_ptr(qw):
            ptrs.append((i, qw))
    return ptrs


def _dump_context(mem: bytes, hits: dict):
    """Print +-1 row context around each hit."""
    near = set()
    for off in hits:
        near.update(range(max(0, off - 4), min(len(mem) - 3, off + 8), 4))
    printed = set()
    for off in sorted(near):
        if off in printed:
            continue
        printed.add(off)
        v = struct.unpack_from('<I', mem, off)[0]
        label = f'  <- {hits[off]}' if off in hits else ''
        print(f'    +{hex(off):>7}  {v:>12}  {v:#010x}{label}')


def main():
    ap = argparse.ArgumentParser(description='Pointer chain walker')
    ap.add_argument('address', help='Root address or CE symbol')
    ap.add_argument('--known', default='', help='name=val,name=val')
    ap.add_argument('--depth', type=int, default=2)
    ap.add_argument('--window', type=lambda x: int(x, 0), default=0x600)
    ap.add_argument('--min-matches', type=int, default=1)
    ap.add_argument('--dump-match', action='store_true')
    ap.add_argument('--pipe', default=None)
    args = ap.parse_args()

    known = parse_comma_known(args.known)
    if not known:
        print('--known is required. Example: --known xp=36105,might=15')
        sys.exit(1)

    val_to_name = {}
    for name, v in known.items():
        try:
            val_to_name[int(v)] = name
        except (TypeError, ValueError):
            pass

    with BridgeClient(**({'pipe_name': args.pipe} if args.pipe else {})) as c:
        print(f"Bridge: {c.ping().get('message', 'connected')}")

        root = c.resolve_address(args.address)
        # Auto-dereference pointer symbols
        probe = c.read_memory(root, 8)
        if probe and len(probe) == 8:
            qw = struct.unpack_from('<Q', probe)[0]
            if is_heap_ptr(qw):
                print(f'  {args.address} = {hex(root)} -> {hex(qw)}')
                root = qw

        print(f'  Root   : {hex(root)}')
        print(f'  Depth  : {args.depth}  Window : {hex(args.window)}')
        print(f'  Looking: {known}\n')

        visited: set = set()
        queue = deque([(root, 0, [hex(root)])])
        found = 0

        while queue:
            addr, depth, path = queue.popleft()
            if addr in visited:
                continue
            visited.add(addr)

            mem = c.read_memory(addr, args.window)
            if not mem:
                continue

            hits = _find_values(mem, val_to_name)
            if len(hits) >= args.min_matches:
                found += 1
                print(f'  MATCH ({len(hits)}/{len(val_to_name)})  path: {" -> ".join(path)}')
                for off, name in sorted(hits.items()):
                    val = struct.unpack_from('<I', mem, off)[0]
                    print(f'    +{hex(off):>7}  {name:20s} = {val}')
                if args.dump_match:
                    _dump_context(mem, hits)
                print()

            if depth < args.depth:
                for off, target in _find_pointers(mem):
                    if target not in visited:
                        queue.append((target, depth + 1,
                                      path + [f'{hex(addr)}+{hex(off)}->{hex(target)}']))

        if found == 0:
            print(f'  Nothing found across {len(visited)} objects (depth {args.depth}).')
            print('  Try: --depth 3, --window 0x1000, --min-matches 1')
        else:
            print(f'  {found} match(es) across {len(visited)} objects visited.')


if __name__ == '__main__':
    main()
