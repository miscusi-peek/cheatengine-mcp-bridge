# CT Updater Future Improvements

This document captures additional ideas for reducing the amount of work any AI has to do when helping with Cheat Engine table updates.

The current pipeline already does a good job of:

- narrowing search space
- ranking candidates
- previewing patches
- preserving local history

The next improvements are less about generating more candidates and more about reducing ambiguity before an AI ever sees the problem.

## Main Idea

The best future additions are the ones that compress uncertainty.

Instead of giving an AI:

- raw memory
- several plausible candidates
- multiple partial reports

the pipeline should increasingly give it:

- one compact review packet
- a clear semantic summary
- explicit risk and confidence
- fewer decisions to make

## Best Next Additions

### 1. Method-Diff Integration ✅ Done

`method_diff/` is implemented and wired into workflow, postprocess decision artifacts, and feature builder packets. Escalated entries automatically include a normalized instruction diff between old and new candidate windows.

### 2. Patch Preview Scoring ✅ Done

`--preview-only` now includes a `Preview Scoring` section with risk label (`low`/`medium`/`high`), flow bucket, confidence score, and reason codes per fixable entry.

### 3. Constraint-Based Candidate Rejection ✅ Done (heuristic form)

`hook_intent_classifier/` classifies each candidate's instruction window as `write`, `read`, `read_modify_write`, `branch_gate`, `callsite`, `compare`, or `mixed`. The postprocess rescorer computes a majority intent across all candidates and penalizes outliers. When top two candidates disagree, `intent_conflict_with_backup` is added to the decision flags.

Not yet done: authored per-hook intent constraints stored in the CT schema. The current form is fully heuristic.

### 4. Hook Intent Metadata

The updater now infers intent automatically from disassembly. The remaining work here is adding authored intent as a per-hook field in the CT schema so the pipeline can reject candidates that structurally contradict it — not just penalize them probabilistically.

This is the highest remaining value-add because it upgrades the system from "infer intent" to "assert intent."

### 5. Module-Wide Uniqueness Fallback

The current uniqueness check is method-local.

Add:

- method-local uniqueness first
- optional wider module scan for recommended signatures
- rejection of signatures that are unique inside the sampled method but noisy module-wide

Why it helps:

- it prevents globally bad anchors from being accepted just because they are locally unique

### 6. AI Packet Bundling ✅ Done

`bundle/` is implemented and wired into `--write-artifacts`. Each escalated run writes `*.ai_bundle.json` and `*.ai_bundle.md` combining preprocess, postprocess, method diff, and flow summary.

### 7. History Promotion Workflow

`history_store` exists, but it is still basic.

Good follow-up improvements:

- explicit accepted or rejected status
- per-game or per-version tagging
- baseline promotion rules
- previous winner versus current winner comparison
- confidence decay for stale history entries

Why it helps:

- old accepted fixes stop biasing future ranking too strongly when they are no longer relevant

### 8. Regression Harness ✅ Partially Done

`tests/` contains 54 offline unit tests covering lint, stability heuristics, intent rescoring, and template generation. These run without a bridge.

Remaining: real game fixtures — sample CT files with expected winner candidates, expected recommended patterns, and expected patch previews. These cannot be created without live game runs.

### 9. Stronger Pattern Volatility Heuristics ✅ Done

`stability/service.py` now includes `_volatile_indexes()`, a byte-pattern scanner that detects:

- `E8/E9 rel32` call/jmp offsets
- `EB/7x rel8` short branches
- `0F 8x rel32` near Jcc branches
- `[REX] 8B/8D/89 [rip+disp32]` RIP-relative MOV/LEA
- `FF 15 [rip+disp32]` indirect calls
- `[REX.W] B8+r imm64` MOV register immediate
- `[REX] C7 /0 imm32` struct field store

`StabilityReport` now exposes `predicted_volatile_indexes` and `hardened_pattern` — the hardened form wildcards both empirically changed bytes and structurally predicted volatile positions.

### 10. AOB Synthesizer With Explicit Objectives

The signature synthesizer can move from "best available pattern" toward "best optimized pattern."

It should optimize for:

- uniqueness
- stability
- shortness
- readability
- closeness to hook intent

Why it helps:

- the AI has fewer tradeoffs to resolve manually

## Highest-Value Remaining Items

If the goal is specifically "less work for any AI," the highest-value remaining items are:

1. authored hook intent metadata per-hook (converts probabilistic penalty to hard constraint)
2. real game regression fixtures (makes tuning measurable)
3. history management improvements (acceptance status, version tagging, decay)
4. module-wide uniqueness fallback
5. AOB synthesizer with explicit objectives

Items 1–6 from the original list and item 9 are now done.

## Why These Matter

The current pipeline is already strong structurally:

- bytes
- windows
- rankings
- confidence
- previews

The next major improvement is to add more semantics:

- what the hook is supposed to do
- what kind of instruction sequence is acceptable
- what changed semantically between old and new
- how risky the recommended patch is

That is the layer that will make the updater easier for any AI to use, not just for this specific workflow.
