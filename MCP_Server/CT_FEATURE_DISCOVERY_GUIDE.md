# CT Feature Discovery Guide

This document explains how to use the current updater pipeline and supporting tools to build new Cheat Engine table features, especially when the new feature is not a direct update of an existing hook.

Typical examples:

- you already know the `Money` hook and want to build a `Gems` or `Wood` hook
- you know where one resource is written and want to find a related resource
- you have a hook for one gameplay stat and want to add another nearby stat
- you have a close reference but not an exact AOB or script for the new feature yet

## What The Current Pipeline Is Good At

The current `ct_updater` pipeline is strongest when it helps answer:

- where should the new feature attach?
- which candidate location is most likely correct?
- is the AOB unique enough to trust?
- how should unstable bytes be wildcarded?
- how can the result be packaged so an AI or human can finish the script quickly?

It is weaker at:

- inventing the final Auto Assembler logic from nothing
- proving gameplay semantics with no nearby reference
- rebuilding a feature whose logic has moved far away from known code

So the best way to use the pipeline for new features is:

- use it as a hook-discovery and validation layer
- then use AI or manual scripting to build the final enable/disable script

## Best Mindset

When building a brand new feature, do not start by asking:

- "What is the exact final AOB?"

Start by asking:

- "What known feature is closest in behavior?"
- "What code path probably handles both of them?"
- "What known write/read/check can serve as my reference?"

The closer the reference, the less work any AI has to do.

## Recommended Workflow

### 1. Start From The Closest Known Feature

If you already have one hook that works, use it as your anchor.

Examples:

- known `Money` write -> look for `Gems` write
- known `Health` write -> look for `Mana` or `Stamina` write
- known `XP` add -> look for `Skill XP` or `Crafting XP` add

Good reference features usually share one or more of these:

- same method
- same caller
- same structure
- same transaction logic
- same UI update path

### 2. Identify The Shared Context

Before trying to build a new AOB, ask what the old and new resources probably have in common.

Common relationships:

- same resource manager object
- same inventory array
- same player stats structure
- same function with a different field offset
- same update function with a different opcode path

If `Money` and `Wood` are both resources, there is a good chance:

- they live in the same structure
- they are updated in the same method
- they differ by offset, index, enum, or branch path

That is the kind of relationship the pipeline can help narrow.

### 3. Capture A Reference Window

Once you have a known-good feature:

- disassemble the known hook window
- keep the nearby instruction block
- note what kind of behavior it represents

Important things to note:

- is this a write or a read?
- is this integer or float?
- does it write directly to memory?
- is there a nearby compare and branch?
- is there a nearby call that looks like a notifier, validator, or clamping step?

This gives you a pattern of intent, not just bytes.

### 4. Search For Nearby Related Logic

This is where the pipeline starts helping directly.

Use the known feature to investigate nearby code:

- same method
- nearby methods
- same symbol namespace
- same structure offsets
- similar instruction shape

The goal is to generate candidate windows for the new feature that are "close enough" to the known feature to compare.

### 5. Use The Pipeline To Reduce Candidates

Once you have a likely method or neighborhood, use the tools to narrow the possibilities.

Useful tools:

- `preprocess`
  narrows candidate windows and captures disassembly

- `postprocess`
  ranks candidate windows and suggests a signature

- `uniqueness`
  checks whether the proposed AOB is actually safe to use

- `stability`
  helps choose which bytes should be wildcarded

- `method_diff`
  compares the known feature window against a new candidate window

- `preview`
  helps inspect what would actually change if you convert an existing script

### 6. Ask The Right Type Of Question

When using AI, avoid broad prompts like:

- "Make me a Gems cheat"

That forces the model to solve everything at once.

Instead ask smaller, structured questions:

- "I know this Money write hook. Which nearby candidate looks like the same resource update path for Gems?"
- "Compare these two instruction windows. Which one is a write to a sibling field rather than the same field?"
- "Use this candidate and generate a safe AOB with wildcards."
- "Turn this hook location into an Auto Assembler script that mirrors the Money script structure."

The pipeline makes those questions smaller and more answerable.

## Example: Money To Another Resource

Say you already know how the `Money` code works and want to make another resource code.

A good practical sequence is:

1. Find the known `Money` hook.
2. Capture the nearby disassembly.
3. Determine whether it is:
   - direct write to `[base+offset]`
   - indexed array access
   - resource type switch
   - call into a generic "add resource" routine
4. Identify nearby sibling writes or branches.
5. Use candidate narrowing on those neighboring paths.
6. Compare the known `Money` window to the new candidate with `method_diff`.
7. Use `uniqueness` and `stability` on the proposed new AOB.
8. Generate the final Auto Assembler script from the now-trusted hook point.

In many games, the new resource is not an entirely separate system. It is often:

- the same code path with a different offset
- the same code path with a different enum or index
- the same write pattern on a sibling field

That is exactly where reference-driven discovery works best.

## Heuristics For "Close To It" Features

If you have a nearby reference but not the exact feature, look for these relationships.

### Same Structure, Different Offset

Example:

- `Money` at `[rcx+220]`
- another resource at `[rcx+228]`

Clues:

- same base register
- same write instruction shape
- only the displacement changes

### Same Function, Different Branch

Example:

- branch A updates one resource
- branch B updates another

Clues:

- same compare ladder
- different immediate or enum
- same eventual write form

### Same Caller, Different Callee Path

Example:

- one caller dispatches to multiple resource handlers

Clues:

- same top-level method
- multiple nearby calls with similar surrounding code

### Same Array, Different Index

Example:

- resources are stored in one array
- money is index 0, another resource is index 3

Clues:

- same array base
- same scale/index math
- different constant used in the path

## How To Reduce AI Work

If the goal is to make feature creation easier for any AI, try to provide:

- one known-good hook
- one to three candidate windows
- the likely relationship between them
- the desired intent of the new feature

Good example:

- "This is the working Money hook. I think Gems is either candidate A or B. Both are writes in the same method. Which is more likely a sibling resource write?"

Bad example:

- "Find a new resource cheat from this whole binary."

The smaller and more relational the question is, the better the result.

## What Makes A Candidate Good For A New Feature

A strong candidate for a brand new feature usually has:

- similar instruction shape to the known feature
- similar placement within the same method or system
- a write/read/check pattern consistent with the intended behavior
- a unique enough AOB
- a stable enough byte pattern to survive updates

This is why the updater pipeline still helps even when the feature is new.

It does not have to know the whole feature. It just has to help you trust the hook point.

## Suggested Practical Process

Use this as a repeatable checklist.

1. Start with the nearest known working hook.
2. Write down what that hook is doing semantically.
3. Find nearby sibling code paths.
4. Reduce to a small candidate set.
5. Compare candidate windows against the known hook.
6. Check uniqueness.
7. Check stability.
8. Synthesize a durable AOB.
9. Generate the final script only after the hook point looks trustworthy.
10. Preview the result before treating it as final.

## What The Pipeline Does Not Replace

Even with all the current tools, you still need judgment for:

- choosing the actual cheat behavior
- deciding whether to NOP, overwrite, detour, clamp, or force a value
- handling side effects
- deciding if a script is enable/disable-safe
- validating in-game behavior

The pipeline helps you get to a good hook faster. It does not eliminate the need to understand what the code is supposed to do.

## Bottom Line

The best use of the current pipeline for brand new CT features is:

- use an existing feature as a reference
- use the pipeline to narrow, compare, validate, and stabilize a new hook point
- only then generate the final script

If you are building something close to an existing feature, like turning `Money` knowledge into another resource code, this workflow can reduce a large amount of the search and validation work.
