"""
python -m ct_updater.tools <tool> [args]

Available tools:
    diff_scan      Interactive differential memory scanner (first/next scan)
    cluster_find   Find memory regions containing multiple known values
    struct_dump    Annotated memory dump at an address or CE symbol
    ptr_walk       Follow pointer chains looking for known values
"""
import sys

TOOLS = {
    'diff_scan':    'ct_updater.tools.diff_scan',
    'cluster_find': 'ct_updater.tools.cluster_find',
    'struct_dump':  'ct_updater.tools.struct_dump',
    'ptr_walk':     'ct_updater.tools.ptr_walk',
}


def usage():
    print(__doc__)
    sys.exit(0)


if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
    usage()

tool = sys.argv.pop(1)
if tool not in TOOLS:
    print(f"Unknown tool '{tool}'. Available: {', '.join(TOOLS)}")
    sys.exit(1)

import importlib
mod = importlib.import_module(TOOLS[tool])
mod.main()
