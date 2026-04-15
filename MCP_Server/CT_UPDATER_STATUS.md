# CT Updater Status

This document summarizes what is currently built, what is partially complete, and what is still not implemented in the local `ct_updater` workspace.

## Completed

### Core updater pipeline

- `parser.py`
- `bridge.py`
- `analyzer.py`
- `patcher.py`
- `workflow.py`
- orchestrated `ct_updater` main flow in `__main__.py`

### Preprocess and postprocess

- `preprocess/`
  - candidate generation
  - candidate scoring
  - disassembly capture
  - JSON and Markdown reports

- `postprocess/`
  - rescoring
  - recommended pattern selection
  - backup candidates
  - decision reports

### Patch and review support

- patch preview via `preview_fixes()` in `patcher.py`
- `--preview-only`
- flow summary output
- artifact writing:
  - `*.preprocess.json`
  - `*.preprocess.md`
  - `*.decision.json`
  - `*.decision.md`

### AI handoff

- `bundle/`
- AI bundle artifacts:
  - `*.ai_bundle.json`
  - `*.ai_bundle.md`

### Extra updater tooling

- `uniqueness/`
- `stability/`
- `method_diff/`
- `history_store/`

### Integrated into the updater flow

- optional postprocess-driven auto-fix
- preview scoring and risk breakdown
- history-backed ranking hint
- optional history recording
- method-diff included in decision artifacts
- AI bundle generation in artifact output

### New feature tooling

- `feature_builder/`
  - reference-driven feature packet generation

- `sibling_field_finder/`
  - sibling offset and sibling field discovery

- `hook_intent_classifier/`
  - write/read/compare/branch/callsite heuristic labeling

### Documentation

- `CT_UPDATER_PIPELINE.md`
- `CT_UPDATER_FUTURE_IMPROVEMENTS.md`
- `CT_FEATURE_DISCOVERY_GUIDE.md`

### Live test coverage

The updater pipeline was tested against `PillarsOfEternity.CT`.

Observed result:

- bridge connection worked
- preview path worked
- fast-path repair matched the existing manual `.updated.CT` range fix

## Partially Completed

### Method diff

- built
- integrated into artifacts
- currently only provides normalized instruction diffing, not semantic reasoning

### History

- built and integrated as a ranking hint and recording store
- still basic
- no accepted/rejected workflow
- no version tagging
- no confidence decay
- no promotion policy beyond latest-match lookup

### Uniqueness

- built
- used in ranking and reporting
- not a universal veto before every fast-path auto-fix
- scoped to sampled method memory rather than broader module validation

### Stability

- built
- used in ranking and signature recommendation
- still a relatively simple heuristic
- does not yet do deeper instruction-encoding-aware volatility analysis

### New feature discovery

- `feature_builder`, `sibling_field_finder`, and `hook_intent_classifier` are built
- they are still sidecar tools rather than one unified end-to-end new-feature pipeline
- no final script generation layer yet

### AI bundle

- built and useful
- not yet the sole primary artifact everywhere

## Not Completed

These items were discussed but are not implemented yet.

### Semantic and metadata layers

- hook intent metadata system
- constraint-based candidate rejection based on explicit hook intent
- feature metadata store

### Script generation and probing

- Auto Assembler script template generator
- behavior probe helper
- patch safety validator for new feature scripts

### Deeper discovery tools

- field/offset cluster scanner
- call-chain explorer
- resource pattern finder

### Validation and regression

- meaningful regression harness with real fixtures
- richer history promotion workflow
- module-wide uniqueness fallback
- stronger volatility heuristics based on instruction encoding roles
- more advanced AOB synthesizer with explicit shortness/readability objectives
- full semantic method diff

### Fully automated feature creation

- end-to-end new-feature generator

## Important Local-State Note

This status document describes what is implemented in the local workspace.

It does not imply that all of these files are committed or merged.

Also:

- `AI_Context/CT_Updater_Guidance.md` remains local-only and should not be committed publicly
