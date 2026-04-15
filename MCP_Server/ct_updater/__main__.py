"""
CT Table Auto-Updater
Usage: python -m ct_updater <file.CT> [options]

Options:
  --no-patch      Show report only, do not write .updated.CT
  --no-mono       Skip LaunchMonoDataCollector (faster if Mono already active)
  --pipe NAME     Override the named pipe (default: pipe\\CE_MCP_Bridge_v99)
  --verbose       Show disassembly for broken patterns
"""
from __future__ import annotations

import sys
import argparse
import textwrap
from pathlib import Path

from .bridge import BridgeClient, BridgeError
from .parser import parse_ct, pattern_to_str, AOBEntry, AssertEntry
from .analyzer import (
    analyze_aob, analyze_assert,
    AOBResult, AssertResult, Status,
)
from .patcher import apply_fixes


# ---------------------------------------------------------------------------
# Colours (Windows ANSI — enabled automatically on Win10+)
# ---------------------------------------------------------------------------

import os
if os.name == 'nt':
    os.system('')  # enable ANSI on Windows

RESET  = '\033[0m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
DIM    = '\033[2m'


def c(colour: str, text: str) -> str:
    return f'{colour}{text}{RESET}'


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

STATUS_COLOUR = {
    Status.OK:          GREEN,
    Status.RANGE_MISS:  YELLOW,
    Status.BYTE_CHANGE: YELLOW,
    Status.PARTIAL:     RED,
    Status.NOT_FOUND:   RED,
    Status.NO_SYMBOL:   RED,
    Status.READ_FAIL:   RED,
}

STATUS_LABEL = {
    Status.OK:          'OK          ',
    Status.RANGE_MISS:  'RANGE MISS  ',
    Status.BYTE_CHANGE: 'BYTE CHANGE ',
    Status.PARTIAL:     'PARTIAL     ',
    Status.NOT_FOUND:   'NOT FOUND   ',
    Status.NO_SYMBOL:   'NO SYMBOL   ',
    Status.READ_FAIL:   'READ FAIL   ',
}


def _fmt_status(status: Status) -> str:
    col = STATUS_COLOUR.get(status, '')
    return c(col, STATUS_LABEL[status])


def _print_aob_result(r: AOBResult, verbose: bool, bridge=None) -> None:
    entry = r.entry
    label = _fmt_status(r.status)
    desc = textwrap.shorten(entry.description or entry.name, width=50)
    sym  = textwrap.shorten(entry.symbol, width=40)
    print(f'  {label} {desc}')
    print(f'           Symbol : {sym}  (range +{entry.scan_range})')

    if r.method_addr:
        print(f'           Addr   : {r.method_addr:#x}')

    if r.status == Status.OK:
        print(f'           Found  : method+{r.found_offset:#x}')

    elif r.status == Status.RANGE_MISS:
        print(f'           Found  : method+{r.found_offset:#x}  (outside +{entry.scan_range})')
        print(f'           Fix    : {c(GREEN, f"extend range to +{r.new_range}")}')

    elif r.status == Status.BYTE_CHANGE:
        print(f'           Found  : method+{r.found_offset:#x}  '
              f'score={r.match_score:.0%}  ({len(r.diffs)} byte(s) differ)')
        for d in r.diffs:
            print(f'             byte[{d.offset:3d}]: '
                  f'expected {c(YELLOW, f"{d.expected:02X}")} '
                  f'actual   {c(GREEN,  f"{d.actual:02X}")}')
        old_str = pattern_to_str(entry.pattern)
        new_str = pattern_to_str(r.new_pattern) if r.new_pattern else '?'
        print(f'           Old    : {c(DIM, old_str)}')
        print(f'           New    : {c(GREEN, new_str)}')
        if r.new_range and r.new_range > entry.scan_range:
            print(f'           Range  : also extend to +{r.new_range}')

    elif r.status in (Status.PARTIAL, Status.NOT_FOUND):
        print(f'           Score  : {r.match_score:.0%}  best at method+{r.found_offset:#x}')
        if r.actual_bytes:
            print(f'           Actual : {r.actual_bytes.hex(" ").upper()}')
            print(f'           Expect : {pattern_to_str(entry.pattern)}')
        print(f'           Action : {c(RED, "manual review needed")}')
        if verbose and bridge and r.method_addr:
            _print_disasm(bridge, r.method_addr, entry.symbol)

    elif r.status == Status.NO_SYMBOL:
        print(f'           Action : {c(RED, "Mono symbol not found — is Mono collector running?")}')

    print()


def _print_assert_result(r: AssertResult) -> None:
    entry = r.entry
    label = _fmt_status(r.status)
    desc = textwrap.shorten(entry.description or entry.symbol, width=50)
    print(f'  {label} {desc}')
    print(f'           Symbol : {entry.symbol}+{entry.offset:#x}')
    if r.status == Status.BYTE_CHANGE and r.actual_bytes:
        from .parser import pattern_to_str
        print(f'           Expect : {pattern_to_str(entry.expected)}')
        print(f'           Actual : {r.actual_bytes.hex(" ").upper()}')
        print(f'           Action : {c(RED, "assert will fail — script needs manual rewrite")}')
    print()


def _print_disasm(bridge, addr: int, symbol: str) -> None:
    print(f'           --- disassembly of {symbol} ---')
    instrs = bridge.disassemble(addr, 40)
    for ins in instrs[:30]:
        ins_addr = ins.get('address', 0)
        if isinstance(ins_addr, str):
            try:
                ins_addr = int(ins_addr, 16)
            except ValueError:
                ins_addr = 0
        rel = ins_addr - addr
        mnem = ins.get('instruction') or ins.get('disasm') or ''
        raw  = ins.get('bytes', '')
        print(f'             +{rel:04X}  {raw:<22} {mnem}')
    print()


# ---------------------------------------------------------------------------
# Summary + patch report
# ---------------------------------------------------------------------------

def _print_summary(aob_results: list[AOBResult], assert_results: list[AssertResult]) -> None:
    total = len(aob_results) + len(assert_results)
    ok    = sum(1 for r in aob_results if r.status == Status.OK)
    auto  = sum(1 for r in aob_results if r.can_auto_fix)
    broken = total - ok

    print(c(BOLD, '=' * 60))
    print(c(BOLD, 'Summary'))
    print(c(BOLD, '=' * 60))
    print(f'  Total patterns : {total}')
    print(f'  OK             : {c(GREEN, str(ok))}')
    print(f'  Need attention : {c(RED if broken else GREEN, str(broken))}')
    print(f'  Auto-fixable   : {c(YELLOW if auto else GREEN, str(auto))}')
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog='python -m ct_updater',
        description='Verify and auto-update Cheat Engine table AOB patterns',
    )
    p.add_argument('ct_file', help='Path to the .CT file')
    p.add_argument('--no-patch',   action='store_true', help='Report only, no file output')
    p.add_argument('--no-mono',    action='store_true', help='Skip LaunchMonoDataCollector')
    p.add_argument('--pipe',       default=None,        help='Named pipe override')
    p.add_argument('--verbose',    action='store_true', help='Show disassembly for broken patterns')
    args = p.parse_args(argv)

    ct_path = Path(args.ct_file)
    if not ct_path.exists():
        print(f'Error: file not found: {ct_path}')
        return 1

    # ------------------------------------------------------------------
    # Parse CT file
    # ------------------------------------------------------------------
    print(c(BOLD, f'\nParsing {ct_path.name} ...'))
    aob_entries, assert_entries, pointer_entries = parse_ct(str(ct_path))
    print(f'  Found {len(aob_entries)} AOB pattern(s), '
          f'{len(assert_entries)} assert(s), '
          f'{len(pointer_entries)} pointer(s)')

    if not aob_entries and not assert_entries:
        print('Nothing to check.')
        return 0

    # ------------------------------------------------------------------
    # Connect to CE bridge
    # ------------------------------------------------------------------
    from .bridge import PIPE_NAME
    pipe = args.pipe or PIPE_NAME
    print(c(BOLD, f'\nConnecting to CE bridge ({pipe}) ...'))

    try:
        bridge = BridgeClient(pipe)
        bridge.connect()
    except BridgeError as e:
        print(f'  {c(RED, "Error:")} {e}')
        print('  Make sure Cheat Engine is running with ce_mcp_bridge.lua loaded.')
        return 1

    try:
        info = bridge.ping()
        msg = info.get('message', '?') if isinstance(info, dict) else str(info)
        print(f'  Connected: {msg}')

        if not args.no_mono and aob_entries:
            print('  Initialising Mono data collector (wait ~4 s) ...')
            bridge.init_mono()

        # ------------------------------------------------------------------
        # Analyse
        # ------------------------------------------------------------------
        print(c(BOLD, '\nAOB Pattern Results'))
        print(c(BOLD, '-' * 60))

        aob_results: list[AOBResult] = []
        for entry in aob_entries:
            r = analyze_aob(bridge, entry)
            aob_results.append(r)
            _print_aob_result(r, args.verbose, bridge if args.verbose else None)

        assert_results: list[AssertResult] = []
        if assert_entries:
            print(c(BOLD, 'Assert Results'))
            print(c(BOLD, '-' * 60))
            for entry in assert_entries:
                r = analyze_assert(bridge, entry)
                assert_results.append(r)
                _print_assert_result(r)

        _print_summary(aob_results, assert_results)

        # ------------------------------------------------------------------
        # Patch
        # ------------------------------------------------------------------
        fixable = [r for r in aob_results if r.can_auto_fix]
        if fixable and not args.no_patch:
            print(c(BOLD, f'Applying {len(fixable)} auto-fix(es) ...'))
            out_path, applied = apply_fixes(str(ct_path), aob_results, assert_results)
            if applied:
                for msg in applied:
                    print(f'  {c(GREEN, "fixed")} {msg}')
                print(f'\n  {c(GREEN, "Written:")} {out_path}')
            else:
                print(f'  {c(YELLOW, "No changes written")} (pattern text not found in file)')
        elif fixable and args.no_patch:
            print(c(YELLOW, f'{len(fixable)} fix(es) available — re-run without --no-patch to apply'))

    finally:
        bridge.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
