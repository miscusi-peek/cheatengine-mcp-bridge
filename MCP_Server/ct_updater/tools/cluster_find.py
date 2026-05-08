"""
cluster_find -- Multi-value cluster finder.

Given several known values for a character/object, finds the memory region
where all (or most) of them live together.

Run from MCP_Server/:
    python -m ct_updater.tools.cluster_find name=value [name=value ...] [options]

Examples:
    python -m ct_updater.tools.cluster_find xp=36105 might=20 dex=11
    python -m ct_updater.tools.cluster_find gold=5000 level=9 --window 2048

Options:
    --window N     Cluster window in bytes (default 1024)
    --top N        Candidate base addresses to show (default 5)
    --max-hits N   Per-value scan cap for noisy values (default 100000)
"""
import sys
import struct
import argparse
from collections import defaultdict

from ..bridge import BridgeClient, BridgeError
from ._common import parse_known, vtype_for


def _bucket(addr: int, window: int) -> int:
    return (addr // window) * window


def main():
    ap = argparse.ArgumentParser(description='Multi-value cluster finder')
    ap.add_argument('values', nargs='+', help='name=value pairs')
    ap.add_argument('--window', type=lambda x: int(x, 0), default=1024)
    ap.add_argument('--top', type=int, default=5)
    ap.add_argument('--max-hits', type=int, default=100_000)
    ap.add_argument('--pipe', default=None)
    args = ap.parse_args()

    known = parse_known(args.values)
    if not known:
        print('No valid name=value pairs. Example: xp=36105 might=20')
        sys.exit(1)

    print(f'cluster_find  window=0x{args.window:X}  values={known}')
    print('-' * 60)

    addr_lists: dict = {}

    with BridgeClient(**({'pipe_name': args.pipe} if args.pipe else {})) as c:
        print(f"Bridge: {c.ping().get('message', 'connected')}\n")

        scan_names = []
        for name, val in known.items():
            vtype = vtype_for(val)
            sname = f'cf_{name}'
            scan_names.append(sname)
            try:
                c.pscan_create(sname)
                print(f'  {name}={val} ({vtype}) ...', end='', flush=True)
                count = c.pscan_first(sname, val, vtype)
                print(f' {count:,} hits', end='')
                if count == 0:
                    print(' -- skipping (not found)')
                    addr_lists[name] = []
                elif count > args.max_hits:
                    print(f' -- too noisy, skipping')
                    addr_lists[name] = []
                else:
                    addrs = c.pscan_all_results(sname, max_total=args.max_hits)
                    addr_lists[name] = sorted(addrs)
                    print(f' -- fetched {len(addrs):,}')
            except BridgeError as e:
                print(f' ERROR: {e}')
                addr_lists[name] = []

        for sn in scan_names:
            c.pscan_destroy(sn)

        active = {k: v for k, v in addr_lists.items() if v}
        if not active:
            print('\nNothing found. Verify the game state and values.')
            return

        print(f'\nActive: {list(active.keys())}')

        # Bucket addresses by window alignment
        buckets: dict = defaultdict(lambda: defaultdict(list))
        for name, addrs in active.items():
            for addr in addrs:
                buckets[_bucket(addr, args.window)][name].append(addr)

        scored = []
        for base, name_map in buckets.items():
            n = len(name_map)
            noise = max(len(v) for v in name_map.values())
            scored.append((n, -noise, base, name_map))
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)

        print(f'\nTop {args.top} candidate base addresses:\n')
        for rank, (n, _, base, name_map) in enumerate(scored[:args.top], 1):
            print(f'  [{rank}]  {hex(base)}  ({n}/{len(active)} values)')
            for name, addrs in sorted(name_map.items()):
                for addr in addrs[:3]:
                    print(f'        {name:20s}  +{hex(addr - base):>8}  ({hex(addr)})')
            print()


if __name__ == '__main__':
    main()
