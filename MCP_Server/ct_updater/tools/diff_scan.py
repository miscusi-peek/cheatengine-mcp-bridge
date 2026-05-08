"""
diff_scan -- Interactive differential memory scanner.

The CE equivalent of first-scan / next-scan, driven from the command line.
Works for any value observable in-game: XP, gold, HP, attributes, etc.

Run from MCP_Server/:
    python -m ct_updater.tools.diff_scan [--type dword|qword|float|double]

Workflow:
    1. Enter the current value.      -> full-process first scan, shows hit count.
    2. Change the value in-game.
    3. Enter the new value.          -> narrows to addresses that changed. shows new count.
    4. Repeat until <= 20 results.

Extra scan types (enter instead of a number at step 3):
    +   increased  (went up, exact amount unknown)
    -   decreased  (went down)
    ?   changed    (changed, direction unknown)
    =   unchanged  (hasn't changed -- eliminates noise)
"""
import sys
import struct
import argparse

from ..bridge import BridgeClient, BridgeError

SHORTCUTS = {'+': 'increased', '-': 'decreased', '?': 'changed', '=': 'unchanged'}
MAX_SHOW = 20


def _parse_val(raw: str, vtype: str):
    if vtype in ('float', 'double'):
        return float(raw)
    return int(raw, 0)


def _fmt_val(mem: bytes, vtype: str) -> str:
    if not mem:
        return '?'
    if vtype == 'float' and len(mem) >= 4:
        return str(struct.unpack_from('<f', mem)[0])
    if vtype == 'double' and len(mem) >= 8:
        return str(struct.unpack_from('<d', mem)[0])
    if vtype == 'qword' and len(mem) >= 8:
        return str(struct.unpack_from('<Q', mem)[0])
    if len(mem) >= 4:
        return str(struct.unpack_from('<I', mem)[0])
    return '?'


def _read_size(vtype: str) -> int:
    return {'qword': 8, 'double': 8, 'float': 4}.get(vtype, 4)


def main():
    ap = argparse.ArgumentParser(description='Differential memory scanner')
    ap.add_argument('--type', default='dword',
                    choices=['dword', 'qword', 'float', 'double'])
    ap.add_argument('--pipe', default=None, help='Override named pipe')
    args = ap.parse_args()
    vtype = args.type

    print(f'diff_scan  type={vtype}  (Ctrl-C to quit)')
    print('-' * 50)

    kwargs = {'pipe_name': args.pipe} if args.pipe else {}
    with BridgeClient(**kwargs) as c:
        print(f"Bridge: {c.ping().get('message', 'connected')}\n")
        step, count = 0, 0
        try:
            while True:
                if step == 0:
                    raw = input(f'Current value ({vtype}) -> ').strip()
                    if not raw:
                        continue
                    val = _parse_val(raw, vtype)
                    print(f'  Scanning for {val} ...', end='', flush=True)
                    count = c.scan_first(val, vtype)
                    print(f' {count:,} hits')
                    step = 1
                else:
                    raw = input(f'  [{count:,} hits]  New value (or +/-/?/=) -> ').strip()
                    if not raw:
                        continue
                    if raw in SHORTCUTS:
                        print(f'  Narrowing ({SHORTCUTS[raw]}) ...', end='', flush=True)
                        count = c.scan_next(scan_type=SHORTCUTS[raw])
                    else:
                        val = _parse_val(raw, vtype)
                        print(f'  Narrowing to {val} ...', end='', flush=True)
                        count = c.scan_next(value=val)
                    print(f' {count:,} hits')

                if count == 0:
                    print('  No results. Restarting scan.')
                    step = 0
                    continue

                if count <= MAX_SHOW:
                    print(f'\n  Done -- {count} address(es):')
                    sz = _read_size(vtype)
                    for i, r in enumerate(c.scan_results(limit=count)):
                        addr_s = r.get('address', '?')
                        try:
                            cur = _fmt_val(c.read_memory(int(addr_s, 16), sz), vtype)
                        except Exception:
                            cur = '?'
                        print(f'  [{i+1:2d}]  {addr_s}  =  {cur}')
                    print()
                    if input('  Continue narrowing? [y/N] -> ').strip().lower() != 'y':
                        break

        except KeyboardInterrupt:
            print('\n  Interrupted.')
        print('  Scan session ended.')


if __name__ == '__main__':
    main()
