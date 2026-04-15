# CT Feature Discovery Guide

This document explains how to use the current feature-building tools to create new Cheat Engine hooks from a nearby reference instead of starting from nothing.

The most important idea is:

- use a known working feature as the anchor
- let the tooling narrow and validate candidates
- only then build the final Auto Assembler script

## What Is Built Today

The current feature-building path is:

1. build a feature packet from a known reference hook
2. inspect ranked candidates, intent labels, and sibling-field hints
3. turn the chosen candidate into an Auto Assembler scaffold

The main tools are:

- `python -m ct_updater.feature_builder`
- `python -m ct_updater.script_template_generator`

Supporting helpers used inside the packet flow:

- `hook_intent_classifier/`
- `sibling_field_finder/`
- `method_diff/`
- `preprocess/`
- `postprocess/`
- `uniqueness/`
- `stability/`

## When To Use This Workflow

This workflow is best when:

- you already have one related hook that works
- the new feature is probably in the same method or system
- you want the tooling to reduce the search space before scripting

Examples:

- you know the `Money` hook and want `Gems`
- you know one health/stat write and want a sibling stat
- you know one inventory/resource path and want another field on the same object

This workflow is weaker when:

- the new feature has no nearby reference at all
- the target logic moved into a totally unrelated subsystem
- the final script behavior is highly custom and not a standard hook scaffold

## Step 1: Choose The Closest Reference Hook

Do not start by asking for the final AOB.

Start by asking:

- which known hook is closest in behavior?
- which known hook likely touches the same structure or method?
- which known hook gives me the smallest search area?

A good reference usually shares one or more of:

- same symbol
- same caller
- same structure base register
- same write pattern
- same branch ladder or compare path

## Step 2: Build A Feature Packet

Use the feature builder against a known CT reference.

Example:

```powershell
python -m ct_updater.feature_builder `
  --ct-file "C:\path\to\Table.CT" `
  --reference "Infinite Item Usage"
```

This writes:

- `<Table>.feature_packet.json`
- `<Table>.feature_packet.md`

You can also choose explicit output paths:

```powershell
python -m ct_updater.feature_builder `
  --ct-file "C:\path\to\Table.CT" `
  --reference "Money" `
  --json-out "C:\work\Money.feature_packet.json" `
  --md-out "C:\work\Money.feature_packet.md"
```

### Useful feature-builder options

- `--reference`
  Hook name or description from the CT.

- `--target-symbol`
  Override the symbol to search when reusing the reference pattern shape against a different method.

- `--target-range`
  Override the scan range.

- `--top`
  Number of ranked candidates to keep.

- `--disasm-count`
  Number of instructions captured per window.

- `--search-multiplier`
  How aggressively to sample nearby windows.

- `--no-mono`
  Skip Mono initialization if already active.

## Step 3: Read The Feature Packet

The feature packet is the main review artifact for building new features.

It includes:

- the original reference hook
- the reference instruction window
- an intent label for that window
- sibling-field candidates near the reference
- ranked candidate windows
- recommended patterns
- candidate-specific scan ranges
- method diff summaries

### What To Look For

When reviewing candidates, prioritize:

- similar instruction shape
- same structure base register
- nearby field offsets
- a good recommended pattern
- a sensible candidate-specific scan range
- stable uniqueness and stability signals

If the best candidate has:

- low confidence
- bad uniqueness
- very different instruction shape
- no obvious relation to the reference

then do not jump straight to scripting.

## Step 4: Use The Packet To Reduce Human Or AI Work

The packet is designed to replace the old manual workflow of:

- find a hook
- dump nearby disassembly
- run two or three side tools
- manually compare candidates
- then guess a script

Instead, the packet should already answer most of:

- which candidate is most likely related?
- what AOB should I start from?
- what scan range should I use?
- does this look like a write, read, compare gate, or mixed path?
- are there sibling field offsets nearby?

That makes AI prompts much smaller and better.

Good AI question:

- "This packet comes from a working Money hook. Candidate 1 and candidate 2 both look related. Which is more likely to be the sibling resource write for Gems?"

Bad AI question:

- "Find me a Gems cheat from the whole binary."

## Step 5: Generate A Script Scaffold

Once you trust a packet candidate, generate a CE Auto Assembler scaffold.

Example:

```powershell
python -m ct_updater.script_template_generator `
  --feature-packet "C:\work\Money.feature_packet.json" `
  --candidate-index 0 `
  --out "C:\work\Money.generated.aa.txt"
```

This uses the selected packet candidate and emits:

- `aobscanregion(...)`
- `alloc(...)`
- labels
- `registersymbol(...)`
- jump scaffold
- disable section scaffold

The generator now prefers the candidate-specific scan range from the packet, not just the original CT range.

You can also generate directly without a packet:

```powershell
python -m ct_updater.script_template_generator `
  --feature-name "MoneyHook" `
  --symbol "GameSymbol:Method" `
  --pattern "41 89 46 18 85 C0" `
  --scan-range 255
```

## Step 6: Finish The Script Logic

The script generator creates the hook scaffold, not the final cheat behavior.

You still need to decide:

- what to overwrite or preserve
- whether to detour, NOP, clamp, or force a value
- what original instructions need to be restored
- what the disable path must undo safely

That part still needs game-specific judgment.

## Practical Example: Money To Another Resource

A strong workflow for "I know Money, now I want another resource" is:

1. build a packet from the known `Money` hook
2. inspect sibling-field candidates and top-ranked windows
3. compare field offsets and instruction shape
4. choose the candidate that looks like the same resource path with a different field or branch
5. generate a scaffold from that candidate
6. write only the game-specific detour logic yourself

This is usually much better than trying to ask an AI to invent the new hook from scratch.

## What Makes A Strong Candidate

A good new-feature candidate usually has:

- a shape similar to the reference window
- the same base register with a different displacement
- the same method or a nearby path in the same routine
- a unique enough signature
- a recommended pattern that is not obviously brittle
- a scan range that makes sense for the found offset

## What This Workflow Does Not Replace

These tools reduce search and validation work, but they do not replace:

- gameplay testing
- script safety review
- enable/disable correctness
- understanding what the code actually does

The tooling helps you trust the hook location.

It does not prove the final cheat semantics for you.
