# CT Updater Pipeline

This document explains how to run the current `ct_updater` pipeline in practice, what each mode is for, and which artifacts it writes.

It is written as operator documentation, not just architecture notes.

## Goal

The updater is designed to do the cheap and safe work automatically, reduce difficult cases into ranked evidence, and only leave true edge cases for human or AI review.

The intended flow is:

1. verify the table against the live game
2. auto-fix direct range or byte drift when confidence is high
3. escalate harder cases into preprocess and postprocess
4. write artifacts that explain the best candidate and backups
5. optionally patch strong postprocess recommendations

## Requirements

Before running the updater:

- Cheat Engine must be open
- the CE bridge Lua script must be loaded
- the target game must already be attached
- if the target uses Mono, Mono data collection must be available unless you pass `--no-mono`

The main entry point is:

```powershell
python -m ct_updater "C:\path\to\Table.CT" [options]
```

## Main Command-Line Options

The updater currently supports:

- `--no-patch`
  Analyze only. Do not write `.updated.CT`.

- `--preview-only`
  Show the exact unified diff that would be written, but do not write the output file.

- `--lint`
  Run pre-flight checks and exit.

- `--apply-postprocess-fix`
  Allow strong postprocess recommendations to patch automatically.

- `--write-artifacts`
  Write preprocess, decision, and AI bundle artifacts for escalated entries.

- `--artifact-dir <dir>`
  Place report artifacts in a chosen directory.

- `--history-store <path>`
  Use a local JSON history store as a ranking hint.

- `--record-history`
  Record successful applied fixes back into the history store.

- `--no-mono`
  Skip `LaunchMonoDataCollector` if Mono is already initialized or the target does not need it.

- `--pipe <name>`
  Override the named pipe.

- `--verbose`
  Print extra disassembly for broken patterns.

## Recommended Run Modes

### 1. Lint-first

Use this before an update run if you want to spot brittle entries in the table itself.

```powershell
python -m ct_updater "C:\path\to\Table.CT" --lint
```

The lint pass currently checks for:

- long patterns with zero wildcards
- very tight scan ranges
- duplicate AOB patterns
- assert targets that do not resolve

This mode does not write `.updated.CT`.

### 2. Safe review-first run

Use this when you want to inspect everything before any file is written.

```powershell
python -m ct_updater "C:\path\to\Table.CT" `
  --preview-only `
  --write-artifacts
```

This is the best default mode while validating a new game build.

What it does:

- runs the updater
- prints the per-entry result
- prints the flow summary
- prints the exact textual diff that would be applied
- writes escalation artifacts for hard cases

### 3. Direct auto-fix run

Use this when you want direct fast-path repairs written immediately.

```powershell
python -m ct_updater "C:\path\to\Table.CT"
```

This writes `<Table>.updated.CT` when safe fixes exist.

This mode only applies direct safe fixes such as:

- extending `aobscanregion(...)` when the pattern still exists just outside the old range
- replacing changed bytes when the match is still strong enough

### 4. Strong automation run

Use this when you want the full ranking pipeline to patch strong postprocess results too.

```powershell
python -m ct_updater "C:\path\to\Table.CT" `
  --apply-postprocess-fix `
  --write-artifacts `
  --history-store "C:\path\to\ct_history.json" `
  --record-history
```

This is the most automated mode currently available.

It still stays conservative:

- postprocess patching is opt-in
- a score threshold must be met
- a concrete recommended pattern must exist

## What The Updater Prints

For each AOB, the updater prints:

- status
- symbol and current scan range
- found method offset if available
- direct fix details if a direct fix exists
- workflow decision summary for escalated cases

It also prints:

- assert results
- a top-level summary
- a flow summary with the five workflow buckets

The workflow buckets are:

- `FAST_PATH_OK`
- `AUTO_FIX`
- `POSTPROCESS_FIX`
- `ESCALATE_POSTPROCESS`
- `MANUAL_REVIEW`

## What Each Workflow Bucket Means

- `FAST_PATH_OK`
  The original pattern still works as-is.

- `AUTO_FIX`
  The updater can safely repair the entry directly from fast-path analysis.

- `POSTPROCESS_FIX`
  The fast path was not enough, but postprocess produced a strong enough recommendation to patch automatically.

- `ESCALATE_POSTPROCESS`
  Postprocess found a strong recommendation, but the updater did not auto-patch it.

- `MANUAL_REVIEW`
  Confidence is still too weak or the result is too ambiguous.

## What Gets Written

### `.updated.CT`

Written during normal patch mode when safe fixes exist.

### Preview diff

Shown only in `--preview-only` mode.

The preview uses the same patch logic as the real writer, so the preview and final write stay aligned.

### Escalation artifacts

When `--write-artifacts` is enabled, escalated entries can produce:

- `*.preprocess.json`
- `*.preprocess.md`
- `*.decision.json`
- `*.decision.md`
- `*.ai_bundle.json`
- `*.ai_bundle.md`

These are the main review artifacts for difficult cases.

## How To Read The Artifacts

### Preprocess artifact

Use it to answer:

- what candidate windows were sampled?
- which ones looked structurally close?
- what bytes and disassembly were captured?

### Decision artifact

Use it to answer:

- which candidate ranked highest?
- what range and pattern are recommended?
- why did it rank above backups?
- how similar is its instruction window?

### AI bundle artifact

Use it when handing the case to an AI or reviewing quickly yourself.

It combines:

- reference summary
- best candidate
- backups
- uniqueness signal
- stability signal
- method diff
- recommended patch information

This is the best single-file handoff artifact.

## What The Pipeline Does Internally

The internal order is:

1. parse the CT
2. connect to the live bridge
3. analyze every AOB directly
4. auto-fix fast-path cases when safe
5. escalate hard cases into `preprocess`
6. enrich candidates with uniqueness, stability, and history
7. rank them in `postprocess`
8. optionally patch strong postprocess results
9. validate `assert(...)` entries separately
10. preview or write final text changes

The supporting modules are:

- `workflow.py`
  Main decision tree for AOBs. Also classifies each candidate's instruction window using `hook_intent_classifier` and populates `intent_label` on each `CandidateInput`.

- `preprocess/`
  Candidate sampling, initial scoring, and disassembly capture.

- `postprocess/`
  Candidate rescoring using 8 signals: byte similarity (0.33), confidence (0.19), mnemonic shape (0.15), structural markers (0.10), uniqueness (0.10), stability (0.05), history alignment (0.05), intent consistency (0.03). Raises `intent_conflict_with_backup` flag when top two candidates disagree on intent class.

- `uniqueness/`
  Counts candidate pattern matches and classifies ambiguity.

- `stability/`
  Scores how durable a candidate signature appears. Also runs structural byte-encoding heuristics (`_volatile_indexes`) to predict which bytes are likely to drift between builds even when currently matching. Exposes `hardened_pattern` with both empirical and predicted wildcards.

- `hook_intent_classifier/`
  Classifies an instruction window into one of: `write`, `read`, `read_modify_write`, `branch_gate`, `callsite`, `compare`, `mixed`. Used by both `workflow.py` and `feature_builder/`.

- `method_diff/`
  Compares normalized instruction windows.

- `history_store/`
  Loads and records prior accepted fixes.

- `patcher.py`
  Writes or previews the actual CT text change.

- `lint/`
  Pre-flight CT quality scan (no bridge required for most checks). Flags zero-wildcard dense patterns, tight scan ranges, duplicate AOBs, and unresolvable assert symbols.

## Practical Interpretation

A good way to think about the updater is:

- fast path handles obvious maintenance
- preprocess reduces the search space
- postprocess reduces the shortlist into a recommendation
- artifacts reduce human and AI synthesis work

It is not meant to magically solve every broken hook in one opaque step.

It is meant to shrink the hard cases until the remaining review is small, inspectable, and defensible.
