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
from .patcher import apply_fixes, preview_fixes
from .workflow import AOBWorkflowOutcome, WorkflowAction, run_aob_workflow
from .history_store.store import HistoryEntry, HistoryStore
from .preprocess.models import PreprocessRunReport
from .preprocess.report import (
    write_json_report as write_preprocess_json_report,
    write_markdown_report as write_preprocess_markdown_report,
)
from .postprocess.models import PostprocessReport
from .postprocess.report import (
    write_json_report as write_postprocess_json_report,
    write_markdown_report as write_postprocess_markdown_report,
)
from .bundle.report import (
    build_ai_bundle,
    write_ai_bundle_json,
    write_ai_bundle_markdown,
)
from .lint.report import render_lint_report
from .lint.service import lint_ct


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


def _print_workflow_decision(outcome: AOBWorkflowOutcome) -> None:
    if not outcome.decision or not outcome.decision.best_candidate:
        return

    best = outcome.decision.best_candidate
    print(f'           Flow   : {c(CYAN, outcome.action.value)}')
    print(f'           Decide : best method+{best.candidate.offset:#x}  score={best.final_score:.0%}')
    if best.recommended_pattern:
        print(f'           AOB    : {c(CYAN, best.recommended_pattern)}')
    if best.suggested_range is not None:
        print(f'           Range  : suggested +{best.suggested_range}')
    if best.reason_codes:
        print(f'           Why    : {", ".join(best.reason_codes)}')
    if outcome.decision.manual_review_flags:
        print(f'           Flags  : {", ".join(outcome.decision.manual_review_flags)}')
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


def _print_flow_summary(outcomes: list[AOBWorkflowOutcome]) -> None:
    if not outcomes:
        return

    counts = {
        WorkflowAction.FAST_PATH_OK: 0,
        WorkflowAction.AUTO_FIX: 0,
        WorkflowAction.POSTPROCESS_FIX: 0,
        WorkflowAction.ESCALATE_POSTPROCESS: 0,
        WorkflowAction.MANUAL_REVIEW: 0,
    }
    for outcome in outcomes:
        counts[outcome.action] += 1

    print(c(BOLD, 'Flow Summary'))
    print(c(BOLD, '-' * 60))
    print(f'  Fast path OK    : {c(GREEN, str(counts[WorkflowAction.FAST_PATH_OK]))}')
    print(f'  Auto-fix        : {c(YELLOW if counts[WorkflowAction.AUTO_FIX] else GREEN, str(counts[WorkflowAction.AUTO_FIX]))}')
    print(f'  Post-fix        : {c(CYAN if counts[WorkflowAction.POSTPROCESS_FIX] else GREEN, str(counts[WorkflowAction.POSTPROCESS_FIX]))}')
    print(f'  Post-process    : {c(CYAN if counts[WorkflowAction.ESCALATE_POSTPROCESS] else GREEN, str(counts[WorkflowAction.ESCALATE_POSTPROCESS]))}')
    print(f'  Manual review   : {c(RED if counts[WorkflowAction.MANUAL_REVIEW] else GREEN, str(counts[WorkflowAction.MANUAL_REVIEW]))}')
    print()


def _artifact_base_paths(ct_path: Path, artifact_dir: Path | None) -> tuple[Path, Path]:
    base_dir = artifact_dir or ct_path.parent
    stem = ct_path.stem
    return (
        base_dir / f'{stem}.preprocess',
        base_dir / f'{stem}.decision',
    )


def _write_escalation_artifacts(
    ct_path: Path,
    outcomes: list[AOBWorkflowOutcome],
    artifact_dir: Path | None = None,
) -> list[Path]:
    escalated = [
        outcome for outcome in outcomes
        if outcome.preprocess_result is not None and outcome.decision is not None
    ]
    if not escalated:
        return []

    preprocess_report = PreprocessRunReport(
        ct_path=str(ct_path),
        aob_count=len(escalated),
        results=[outcome.preprocess_result for outcome in escalated if outcome.preprocess_result is not None],
    )
    postprocess_report = PostprocessReport(
        source_report=str(ct_path),
        hook_count=len(escalated),
        decisions=[outcome.decision for outcome in escalated if outcome.decision is not None],
    )

    preprocess_base, decision_base = _artifact_base_paths(ct_path, artifact_dir)
    flow_summary = {
        "fast_path_ok": sum(1 for outcome in outcomes if outcome.action == WorkflowAction.FAST_PATH_OK),
        "auto_fix": sum(1 for outcome in outcomes if outcome.action == WorkflowAction.AUTO_FIX),
        "postprocess_fix": sum(1 for outcome in outcomes if outcome.action == WorkflowAction.POSTPROCESS_FIX),
        "escalate_postprocess": sum(1 for outcome in outcomes if outcome.action == WorkflowAction.ESCALATE_POSTPROCESS),
        "manual_review": sum(1 for outcome in outcomes if outcome.action == WorkflowAction.MANUAL_REVIEW),
    }
    bundle = build_ai_bundle(str(ct_path), preprocess_report, postprocess_report, flow_summary=flow_summary)
    written = [
        write_preprocess_json_report(preprocess_report, preprocess_base.with_suffix('.json')),
        write_preprocess_markdown_report(preprocess_report, preprocess_base.with_suffix('.md')),
        write_postprocess_json_report(postprocess_report, decision_base.with_suffix('.json')),
        write_postprocess_markdown_report(postprocess_report, decision_base.with_suffix('.md')),
        write_ai_bundle_json(bundle, (artifact_dir or ct_path.parent) / f'{ct_path.stem}.ai_bundle.json'),
        write_ai_bundle_markdown(bundle, (artifact_dir or ct_path.parent) / f'{ct_path.stem}.ai_bundle.md'),
    ]
    return written


def _record_history_entries(
    store: HistoryStore,
    outcomes: list[AOBWorkflowOutcome],
) -> int:
    recorded = 0
    for outcome in outcomes:
        analysis = outcome.analysis
        if not analysis.can_auto_fix or not analysis.new_pattern:
            continue
        store.append(HistoryEntry(
            hook=analysis.entry.description or analysis.entry.name,
            symbol=analysis.entry.symbol,
            pattern=pattern_to_str(analysis.new_pattern),
            range_value=analysis.new_range,
            source=outcome.action.value,
            notes=analysis.fix_description or "",
        ))
        recorded += 1
    return recorded


def _preview_risk_label(outcome: AOBWorkflowOutcome) -> str:
    if outcome.action in (WorkflowAction.AUTO_FIX, WorkflowAction.FAST_PATH_OK):
        return "low"
    if outcome.action == WorkflowAction.POSTPROCESS_FIX:
        return "medium"
    return "high"


def _print_preview_breakdown(outcomes: list[AOBWorkflowOutcome]) -> None:
    print(c(BOLD, 'Preview Scoring'))
    print(c(BOLD, '-' * 60))
    for outcome in outcomes:
        if not outcome.analysis.can_auto_fix:
            continue
        label = outcome.entry.description or outcome.entry.name
        print(f'  {label}')
        print(f'    risk       : {_preview_risk_label(outcome)}')
        print(f'    flow       : {outcome.action.value}')
        if outcome.decision and outcome.decision.best_candidate:
            best = outcome.decision.best_candidate
            print(f'    confidence : {best.final_score:.1%}')
            print(f'    reasons    : {", ".join(best.reason_codes) if best.reason_codes else "n/a"}')
        else:
            print(f'    confidence : {outcome.analysis.match_score:.1%}')
            print(f'    reasons    : direct {outcome.analysis.status.name.lower()}')
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
    p.add_argument('--lint',       action='store_true', help='Run pre-flight lint checks and exit')
    p.add_argument('--pipe',       default=None,        help='Named pipe override')
    p.add_argument('--verbose',    action='store_true', help='Show disassembly for broken patterns')
    p.add_argument('--preview-only', action='store_true',
                   help='Show the .CT patch preview and do not write .updated.CT')
    p.add_argument('--apply-postprocess-fix', action='store_true',
                   help='Allow strong post-process recommendations to be patched automatically')
    p.add_argument('--write-artifacts', action='store_true',
                   help='Write preprocess/postprocess reports for escalated entries')
    p.add_argument('--artifact-dir', default=None,
                   help='Directory for preprocess/postprocess reports (default: CT file directory)')
    p.add_argument('--history-store', default=None,
                   help='Path to a local JSON history store for ranking against past accepted fixes')
    p.add_argument('--record-history', action='store_true',
                   help='Append applied fixes to --history-store after a successful patch run')
    args = p.parse_args(argv)

    ct_path = Path(args.ct_file)
    if not ct_path.exists():
        print(f'Error: file not found: {ct_path}')
        return 1
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else None
    history_store = HistoryStore(args.history_store) if args.history_store else None

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

        if args.lint:
            print(c(BOLD, '\nLint'))
            print(c(BOLD, '-' * 60))
            report = lint_ct(bridge, str(ct_path))
            print(render_lint_report(report))
            return 1 if report.has_errors else 0

        # ------------------------------------------------------------------
        # Analyse
        # ------------------------------------------------------------------
        print(c(BOLD, '\nAOB Pattern Results'))
        print(c(BOLD, '-' * 60))

        aob_results: list[AOBResult] = []
        aob_outcomes: list[AOBWorkflowOutcome] = []
        for entry in aob_entries:
            outcome = run_aob_workflow(
                bridge,
                entry,
                apply_postprocess_fix=args.apply_postprocess_fix,
                history_store=history_store,
            )
            aob_outcomes.append(outcome)
            aob_results.append(outcome.analysis)
            _print_aob_result(outcome.analysis, args.verbose, bridge if args.verbose else None)
            if outcome.action in (
                WorkflowAction.POSTPROCESS_FIX,
                WorkflowAction.ESCALATE_POSTPROCESS,
                WorkflowAction.MANUAL_REVIEW,
            ):
                _print_workflow_decision(outcome)

        assert_results: list[AssertResult] = []
        if assert_entries:
            print(c(BOLD, 'Assert Results'))
            print(c(BOLD, '-' * 60))
            for entry in assert_entries:
                r = analyze_assert(bridge, entry)
                assert_results.append(r)
                _print_assert_result(r)

        _print_summary(aob_results, assert_results)
        _print_flow_summary(aob_outcomes)

        if args.write_artifacts:
            if artifact_dir:
                artifact_dir.mkdir(parents=True, exist_ok=True)
            written = _write_escalation_artifacts(ct_path, aob_outcomes, artifact_dir)
            if written:
                print(c(BOLD, 'Artifacts'))
                print(c(BOLD, '-' * 60))
                for path in written:
                    print(f'  wrote {path}')
                print()

        # ------------------------------------------------------------------
        # Patch
        # ------------------------------------------------------------------
        fixable = [r for r in aob_results if r.can_auto_fix]
        if fixable and args.preview_only:
            print(c(BOLD, 'Patch Preview'))
            print(c(BOLD, '-' * 60))
            _print_preview_breakdown(aob_outcomes)
            applied, skipped, diff = preview_fixes(str(ct_path), aob_results, assert_results)
            for msg in applied or ['(no changes)']:
                print(f'  {msg}')
            for msg in skipped:
                print(f'  skipped {msg}')
            print()
            print(diff or '(no textual changes)')
        elif fixable and not args.no_patch:
            print(c(BOLD, f'Applying {len(fixable)} auto-fix(es) ...'))
            out_path, applied = apply_fixes(str(ct_path), aob_results, assert_results)
            if applied:
                for msg in applied:
                    print(f'  {c(GREEN, "fixed")} {msg}')
                print(f'\n  {c(GREEN, "Written:")} {out_path}')
                if history_store and args.record_history:
                    recorded = _record_history_entries(history_store, aob_outcomes)
                    if recorded:
                        print(f'  {c(CYAN, "History:")} recorded {recorded} applied fix(es)')
            else:
                print(f'  {c(YELLOW, "No changes written")} (pattern text not found in file)')
        elif fixable and args.no_patch:
            print(c(YELLOW, f'{len(fixable)} fix(es) available — re-run without --no-patch to apply'))

    finally:
        bridge.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
