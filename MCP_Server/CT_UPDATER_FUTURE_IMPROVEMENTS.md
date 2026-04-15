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

### 1. Method-Diff Integration

`method_diff` already exists, but it is still mostly a side tool.

Best next step:

- automatically include method-diff output in escalated artifacts
- compare the old known-good window against the top candidate window
- summarize changes such as:
  - same store pattern
  - branch shape changed
  - constant drifted
  - extra guard inserted
  - call site moved

Why it helps:

- AIs review semantic deltas much faster than raw disassembly.

### 2. Patch Preview Scoring

The current preview shows what would change. It could also explain how risky the patch is.

Add:

- patch risk level
- confidence breakdown
- uniqueness verdict
- history alignment verdict
- reasons the patch is considered safe or risky

Why it helps:

- the AI no longer has to infer trustworthiness from multiple reports

### 3. Constraint-Based Candidate Rejection

A lot of bad candidates can be rejected before scoring if the updater knows what kind of hook it is looking for.

Examples:

- this hook must be a write, not a read
- this hook must involve a float op
- this hook must sit after a compare and branch
- this hook must write to memory, not just move between registers

Why it helps:

- the AI spends less time considering impossible matches

### 4. Hook Intent Metadata

The updater currently knows structure better than intent.

A metadata layer per hook could store:

- hook intent: `write`, `read`, `compare`, `branch_patch`, `callsite`
- expected opcode families
- required nearby features
- forbidden nearby features
- notes about why the hook exists

Why it helps:

- preprocess gets better
- postprocess gets better
- previews become clearer
- manual review becomes faster
- history reuse becomes safer

This is one of the highest-value improvements because it adds semantics, not just more scoring.

### 5. Module-Wide Uniqueness Fallback

The current uniqueness check is useful, but it is method-local.

Add:

- method-local uniqueness first
- optional wider module scan for recommended signatures
- rejection of signatures that are unique inside the sampled method but noisy module-wide

Why it helps:

- it prevents globally bad anchors from being accepted just because they are locally unique

### 6. AI Packet Bundling

Right now the pipeline emits multiple useful reports, but a dedicated AI handoff packet would be even better.

The packet should include:

- hook metadata
- original pattern
- best candidate
- backup candidates
- uniqueness result
- stability result
- method-diff summary
- patch preview snippet
- recommended patch
- confidence and risk summary

Why it helps:

- any AI performs better when it gets one compact, complete packet instead of several loosely connected outputs

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

### 8. Regression Harness

This is one of the most important long-term additions.

Build a small offline test harness with:

- sample CT files
- sample known-good outputs
- expected winner candidates
- expected recommended patterns
- expected patch previews

Why it helps:

- pipeline changes can be evaluated against real update scenarios
- tuning becomes measurable instead of guesswork

### 9. Stronger Pattern Volatility Heuristics

The stability analyzer can get smarter by recognizing the kinds of bytes that commonly drift between builds.

Examples:

- displacements
- relative branches
- immediates
- RIP-relative accesses
- struct offsets
- compiler padding

Why it helps:

- wildcarding becomes more principled
- recommended signatures become more durable

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

## Highest-Value Priorities

If the goal is specifically "less work for any AI," the highest-value next items are:

1. hook intent metadata
2. method-diff integration into artifacts
3. constraint-based candidate rejection
4. AI packet bundling
5. regression harness
6. stronger history management

These will usually reduce reasoning load more than adding another scoring heuristic.

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
