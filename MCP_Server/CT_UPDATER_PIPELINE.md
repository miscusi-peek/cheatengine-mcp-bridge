# CT Updater Pipeline

This document explains how the `ct_updater` pipeline works after the additions of preprocess, postprocess, preview, uniqueness, stability, and history support.

## Goal

The updater is designed to spend as little model reasoning as possible on easy cases, and reserve deeper review for only the entries that cannot be repaired deterministically.

The overall strategy is:

1. do the cheapest deterministic checks first
2. auto-fix the safest cases immediately
3. reduce difficult cases into ranked candidates
4. reduce ranked candidates into a best recommendation
5. only escalate to manual review when confidence is still weak

## High-Level Flow

The main entry point is:

```bash
python -m ct_updater <file.CT> [options]
```

The pipeline runs in this order.

### 1. Parse

`parser.py` reads the `.CT` file and extracts:

- `aobscanregion(...)` entries
- `assert(...)` entries
- pointer-based entries

This phase does not modify the file. It only turns the CT into structured data.

### 2. Connect

`bridge.py` connects to the Cheat Engine named pipe and optionally initializes the Mono data collector.

This gives the updater access to:

- symbol resolution
- memory reads
- disassembly

### 3. Fast Path Analysis

For each AOB entry, `workflow.py` calls `analyze_aob()` from `analyzer.py`.

This tries the simplest outcomes first:

- exact match in the original range
- exact match outside the original range
- high-confidence byte drift within the same method

Possible early outcomes:

- `OK`
- `RANGE_MISS`
- high-confidence `BYTE_CHANGE`

These are the cheapest and safest cases. They do not need deeper candidate ranking.

### 4. Auto-Fix Path

If the result is safe enough to repair directly:

- `RANGE_MISS` extends the `aobscanregion(...)` range
- high-confidence `BYTE_CHANGE` replaces the changed bytes

These fixes are applied through `patcher.py`.

### 5. Preprocess Escalation

If the fast path does not produce a safe answer, `workflow.py` escalates the entry into `preprocess`.

`preprocess`:

- samples more memory around the target method
- scores candidate windows
- captures actual bytes
- builds replacement and wildcard variants
- collects disassembly for the top candidates

This reduces the search space from raw memory to a shortlist of plausible matches.

### 6. Candidate Enrichment

Before ranking candidates in postprocess, the workflow enriches them with extra signals:

- **uniqueness**
  `uniqueness` checks how many times the candidate pattern appears in the sampled method memory.
  This helps penalize ambiguous or unsafe signatures.

- **stability**
  `stability` measures how much of the candidate appears structurally stable versus likely needing wildcards.
  This helps prefer more durable signatures.

- **history**
  if `--history-store` is provided, the workflow loads the latest accepted baseline for the current hook and uses it as a ranking hint.

### 7. Postprocess Ranking

`postprocess` takes the enriched candidates and picks a best match plus backups.

The ranking uses:

- byte similarity
- prior candidate confidence
- normalized mnemonic similarity
- structural similarity
- uniqueness
- stability
- history alignment

The result is:

- one best candidate
- a small number of backups
- a recommended signature
- suggested range extension, if needed
- reason codes explaining why the candidate ranked well

### 8. Postprocess Auto-Fix

If `--apply-postprocess-fix` is enabled, and the postprocess result is strong enough, the workflow promotes that recommendation into a patchable fix.

This is intentionally conservative:

- it is opt-in
- it requires a score threshold
- it only applies when a concrete recommended signature exists

### 9. Assert Checking

Separately, `analyze_assert()` validates `assert(...)` lines.

These are reported, but they are not currently auto-rewritten. If an assert fails, the script usually needs manual review.

### 10. Reporting

The updater prints:

- per-entry analysis output
- workflow decision output for escalated cases
- a flow summary showing how many entries landed in each bucket

Optional report artifacts:

```bash
--write-artifacts
--artifact-dir <dir>
```

These write:

- `*.preprocess.json`
- `*.preprocess.md`
- `*.decision.json`
- `*.decision.md`

Only escalated entries are included in those artifacts.

### 11. Preview Or Write

At the end of the run, if fixes are available:

- `--preview-only` shows the exact unified diff without writing `.updated.CT`
- normal patch mode writes `.updated.CT`

The preview uses the same in-memory patch logic as the real writer, so the preview and final write stay consistent.

### 12. History Recording

If both of these are supplied:

```bash
--history-store <path>
--record-history
```

then successfully applied fixes are appended into the local JSON history store.

This gives future runs a stronger baseline for ranking difficult updates.

## Workflow States

The updater currently routes entries into these buckets:

- `FAST_PATH_OK`
- `AUTO_FIX`
- `POSTPROCESS_FIX`
- `ESCALATE_POSTPROCESS`
- `MANUAL_REVIEW`

Meaning:

- `FAST_PATH_OK`
  The original pattern still works.

- `AUTO_FIX`
  The updater can safely repair the entry from direct analysis.

- `POSTPROCESS_FIX`
  The updater could not safely repair from the fast path alone, but postprocess produced a strong enough recommendation to patch.

- `ESCALATE_POSTPROCESS`
  The updater found a strong recommendation, but did not patch automatically.

- `MANUAL_REVIEW`
  Confidence is still too weak, or the result is too ambiguous.

## Main Supporting Modules

- `parser.py`
  Parses the CT into structured entries.

- `bridge.py`
  Talks to Cheat Engine over the named pipe.

- `analyzer.py`
  Handles direct AOB/assert analysis and simple repair classification.

- `workflow.py`
  Orchestrates the full decision tree.

- `patcher.py`
  Applies or previews actual text changes to the CT.

- `preprocess/`
  Builds ranked candidate windows for difficult cases.

- `postprocess/`
  Rescores and narrows those candidates to a best recommendation.

- `preview/`
  Exposes patch preview as a standalone tool.

- `uniqueness/`
  Scores whether a candidate signature is unique or ambiguous.

- `stability/`
  Scores how stable a candidate signature appears to be.

- `method_diff/`
  Compares instruction windows for human or AI review.

- `history_store/`
  Stores and retrieves accepted historical baselines.

## Typical Runs

### Safe review-first run

```bash
python -m ct_updater "C:\path\to\Table.CT" ^
  --preview-only ^
  --write-artifacts
```

This:

- analyzes the table
- generates escalation reports
- shows the exact patch diff
- does not write `.updated.CT`

### History-aware run

```bash
python -m ct_updater "C:\path\to\Table.CT" ^
  --history-store "C:\path\to\ct_history.json" ^
  --write-artifacts
```

This adds prior accepted signatures as a ranking hint.

### Strong automation run

```bash
python -m ct_updater "C:\path\to\Table.CT" ^
  --apply-postprocess-fix ^
  --history-store "C:\path\to\ct_history.json" ^
  --record-history
```

This lets strong postprocess recommendations patch automatically and stores the accepted results back into history.

## Design Intent

The updater is not meant to solve every broken table entry by brute force.

It is meant to:

- eliminate easy maintenance work automatically
- make hard cases smaller and better structured
- keep patch generation inspectable
- reuse prior accepted fixes over time

That is why the pipeline is split into fast path, preprocess, postprocess, preview, and history, rather than one large opaque repair step.
