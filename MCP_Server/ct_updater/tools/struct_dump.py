"""
struct_dump -- Annotated memory dump at a known address.

Dumps memory as a readable table, labelling known values, heap pointers,
and plausible IEEE 754 floats automatically.

Run from MCP_Server/:
    python -m ct_updater.tools.struct_dump ADDRESS [options]

    ADDRESS: hex (0x...), decimal, or a CE symbol name (auto-dereferenced).

Examples:
    python -m ct_updater.tools.struct_dump CharacterPtr --size 0x400
    python -m ct_updater.tools.struct_dump CharacterPtr --offset 0x220 --known xp=36105,might=15
    python -m ct_updater.tools.struct_dump 0x2316171DA80 --no-zero --stride 8

Options:
    --size N      Bytes to dump (default 0x300)
    --offset N    Start offset within the object (default 0)
    --known k=v   Comma-separated annotations
    --stride N    Row stride: 4 or 8 (default 4)
    --floats      Always show float column
    --no-zero     Hide zero rows
"""
import sys
import struct
import argparse

from ..bridge import BridgeClient, BridgeError
from ._common import parse_comma_known, is_heap_ptr, looks_like_float


def _print_table(mem: bytes, base_addr: int, stride: int,
                 val_to_name: dict, show_floats: bool, hide_zero: bool):
    hdr = f'  {"Offset":>8}  {"Address":>18}  {"Int":>12}  {"Hex":>10}'
    if show_floats:
        hdr += f'  {"Float":>12}'
    hdr += '  Notes'
    print(hdr)
    print('  ' + '-' * (len(hdr) - 2))

    i = 0
    while i + stride <= len(mem):
        dw = struct.unpack_from('<I', mem, i)[0]
        qw = struct.unpack_from('<Q', mem, i)[0] if i + 8 <= len(mem) else None

        if hide_zero and dw == 0 and (qw is None or qw == 0):
            i += stride
            continue

        notes = []
        if dw in val_to_name:
            notes.append(f'<- {val_to_name[dw]}')

        # Pointer detection using the full 8-byte value at this offset
        check_qw = qw if stride == 8 else (
            struct.unpack_from('<Q', mem, i)[0] if i + 8 <= len(mem) else None)
        if check_qw and is_heap_ptr(check_qw):
            notes.append(f'ptr->{hex(check_qw)}')

        ok, fval = looks_like_float(dw)
        if ok:
            notes.append(f'float~{fval:.4g}')

        row = f'  +{hex(i):>7}  {hex(base_addr + i):>18}  {dw:>12}  {dw:#010x}'
        if show_floats:
            row += f'  {fval:>12.4g}' if ok else f'  {"":>12}'
        row += f'  {", ".join(notes)}'
        print(row)
        i += stride


def main():
    ap = argparse.ArgumentParser(description='Annotated memory struct dump')
    ap.add_argument('address', help='Hex address or CE symbol')
    ap.add_argument('--size', type=lambda x: int(x, 0), default=0x300)
    ap.add_argument('--offset', type=lambda x: int(x, 0), default=0)
    ap.add_argument('--known', default='', help='name=val,name=val annotations')
    ap.add_argument('--stride', type=int, choices=[4, 8], default=4)
    ap.add_argument('--floats', action='store_true')
    ap.add_argument('--no-zero', action='store_true')
    ap.add_argument('--pipe', default=None)
    args = ap.parse_args()

    known = parse_comma_known(args.known)
    val_to_name = {int(v): k for k, v in known.items()
                   if isinstance(v, (int, float))}

    with BridgeClient(**({'pipe_name': args.pipe} if args.pipe else {})) as c:
        print(f"Bridge: {c.ping().get('message', 'connected')}")

        base = c.resolve_address(args.address)

        # Auto-dereference pointer symbols (e.g. CharacterPtr stores a pointer)
        probe = c.read_memory(base, 8)
        if probe and len(probe) == 8:
            candidate = struct.unpack_from('<Q', probe)[0]
            if is_heap_ptr(candidate):
                print(f'  Auto-deref  : {hex(base)} -> {hex(candidate)}')
                base = candidate

        start = base + args.offset
        print(f'  Object base : {hex(base)}')
        if args.offset:
            print(f'  Dump start  : {hex(start)}  (+{hex(args.offset)})')
        print(f'  Size        : {hex(args.size)}')
        if known:
            print(f'  Known       : {known}')
        print()

        mem = c.read_memory(start, args.size)
        if not mem:
            print('ERROR: read_memory failed.')
            sys.exit(1)

        _print_table(mem, start, args.stride, val_to_name,
                     args.floats, args.no_zero)


if __name__ == '__main__':
    main()
