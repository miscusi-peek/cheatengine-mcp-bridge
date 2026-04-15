# CT Updater Status

This document summarizes what is currently implemented in the local `ct_updater` workspace and what is still missing.

## Completed

### Core updater pipeline

- `parser.py`
- `bridge.py`
- `analyzer.py`
- `patcher.py`
- `workflow.py`
- orchestrated updater flow in `ct_updater/__main__.py`

### Updater pipeline modules

- `preprocess/`
  Candidate generation, candidate scoring, disassembly capture, and reports.

- `postprocess/`
  Candidate rescoring, recommendation selection, backups, and decision reports.

- `preview/`
  Preview support built on the same patch logic as real writes.

- `uniqueness/`
  Pattern match counting and uniqueness classification.

- `stability/`
  Stability scoring and wildcard-oriented signature support.

- `method_diff/`
  Normalized instruction-window diffing.

- `history_store/`
  JSON-backed accepted-fix history lookup and recording.

- `bundle/`
  Combined AI handoff artifacts.

### Updater flow features

- `--preview-only`
- `--apply-postprocess-fix`
- `--write-artifacts`
- `--artifact-dir`
- `--history-store`
- `--record-history`
- `--lint`
- flow summary output
- preview risk breakdown
- AI bundle artifact generation
- method diff included in escalated decision artifacts
- intent consistency scoring in postprocess rescorer

### Feature-building tools

- `feature_builder/`
  Reference-driven packet generation for new features. Wires preprocess, postprocess, method_diff, intent classification, and sibling field scan into one call.

- `hook_intent_classifier/`
  Heuristic intent labeling for instruction windows (`write`, `read`, `read_modify_write`, `branch_gate`, `callsite`, `compare`, `mixed`). Used both in feature_builder and in the postprocess rescorer via workflow.py.

- `sibling_field_finder/`
  Nearby same-base field and offset discovery.

- `script_template_generator/`
  Auto Assembler scaffold generation from a feature packet or direct inputs.

### Offline regression harness

- `tests/`
  54 unit tests covering lint checks, stability heuristics, intent rescorer, and template generation.
  Run with: `python -m unittest discover -s ct_updater/tests -p "test_*.py"`
  No bridge or game connection required.

### Live validation completed

The current pipeline was exercised against `PillarsOfEternity.CT` with a live CE bridge connection.

Confirmed in practice:

- updater parse and bridge flow worked
- lint ran against the live target
- preview mode matched the known manual range fix
- feature packet generation worked against a live reference hook
- script scaffold generation worked from that packet
- candidate-specific scan ranges propagated into generated script output

## Partially Completed

### Method diff

- built and wired into artifacts
- currently reports normalized instruction diffs, not deeper semantic reasoning

### History store

- built and integrated into ranking and recording
- still basic
- no approval workflow
- no version tagging
- no confidence decay

### Stability heuristics

- structural byte-encoding volatility detection implemented (`_volatile_indexes`)
- detects: E8/E9 rel32, EB/7x rel8, 0F 8x rel32, RIP-relative MOV/LEA, indirect calls, MOV imm64, MOV imm32 struct stores
- `hardened_pattern` combines empirically changed bytes with structurally predicted volatile bytes
- not yet operand-role-aware at the semantic level (e.g. does not distinguish struct field offsets from other immediates)

### Uniqueness scope

- integrated into ranking and reporting
- strongest inside sampled method memory
- not yet a full module-wide uniqueness pass

### Script template generation

- scaffold generation is implemented
- final detour logic and disable-byte restoration still require manual completion

### Feature discovery quality

- the packet flow is usable now
- heuristic quality still depends on the closeness of the reference hook
- some cases will still need manual reasoning after the packet is produced

## Not Completed

### Metadata and intent systems

- explicit per-hook intent metadata authored in CT schema (currently inferred heuristically)
- constraint-based rejection using authored intent metadata (structural classification exists but requires live disassembly; no CT-side authored constraints yet)
- durable feature metadata layer

### Deeper discovery tools

- field cluster scanner
- call-chain explorer
- resource pattern finder
- behavior probe helper

### Validation and regression

- regression harness with real game fixtures (current tests are structural; no expected-winner fixtures from live games yet)
- richer accepted/rejected history workflow (no approval status, version tagging, or confidence decay)
- module-wide uniqueness fallback (currently method-local only)
- more semantic method-diff layer (currently normalized instruction text, not opcode-category-aware)

### Fully automated feature creation

- complete end-to-end feature creation without human script logic work (scaffold is generated; hook body and original-code restoration still require manual authoring)

## Important Local-State Note

This document describes what is implemented in the local workspace and branch.

Private local-only content should still remain uncommitted publicly.

In particular:

- `AI_Context/CT_Updater_Guidance.md` is local-only
