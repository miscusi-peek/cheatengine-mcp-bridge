# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A three-tier bridge that lets AI agents (via MCP) drive Cheat Engine to inspect and manipulate a running Windows process. See `README.md` for user-facing docs. Current wire/app version: `12.0.0`. After the v12 overhaul the bridge exposes **~180 MCP tools** covering memory, process lifecycle, code injection, symbol management, assembly/compilation, GUI automation, input, cheat tables, and kernel-mode operations.

## Commands

```bash
# Install Python deps (Windows only — uses pywin32)
pip install -r MCP_Server/requirements.txt

# Integration test suite (requires: CE running, ce_mcp_bridge.lua loaded, a process attached)
python MCP_Server/test_mcp.py
```

Loading the Lua side in Cheat Engine: `File → Execute Script → open MCP_Server/ce_mcp_bridge.lua → Execute`. Success log: `[MCP v12.0.0] MCP Server Listening on: CE_MCP_Bridge_v99`. Re-executing the script auto-calls `StopMCPBridge` / `cleanupZombieState` first, so reloading is safe.

There is **no build step** for the bridge itself. `test_mcp.py` is a single end-to-end script that talks to the live Named Pipe; running a "single test" means editing the `all_tests` dict in `test_mcp.py:main` or commenting out sections.

The CT updater has an offline unit-test harness in `ct_updater/tests/`. Run it with:
```bash
python -m unittest discover -s ct_updater/tests -p "test_*.py" -v
```
These tests require no bridge or game connection.

The MCP server is normally spawned by the AI client over stdio, but can be launched directly with `python MCP_Server/mcp_cheatengine.py` for debugging (it blocks waiting for stdio JSON-RPC).

## Architecture

Three processes, two IPC layers:

```
AI client ──(MCP / JSON-RPC over stdio)──▶ mcp_cheatengine.py
                                                  │
                                                  ▼ (length-prefixed JSON-RPC)
                                         \\.\pipe\CE_MCP_Bridge_v99
                                                  │
                                                  ▼
                                          ce_mcp_bridge.lua (inside Cheat Engine)
                                                  │
                                                  ▼ (CE Lua API / DBVM)
                                            Target process memory
```

### Python side — `MCP_Server/mcp_cheatengine.py`

Thin `FastMCP` wrapper. Every `@mcp.tool()` is a one-liner that calls `ce_client.send_command("<method>", {...})` and formats the result. `CEBridgeClient.send_command` writes a 4-byte little-endian length prefix + UTF-8 JSON-RPC body to the Named Pipe, reads the same framing back, caps responses at 16 MB, and auto-reconnects once on pipe failure.

**Windows stdio pitfalls (top of file, before any other imports)** — do not move this block:
- The MCP SDK's `stdio_server` wraps stdio with `TextIOWrapper` without `newline='\n'`, so on Windows it emits `\r\n` and the transport rejects with "invalid trailing data." The file monkey-patches `mcp.server.stdio.stdio_server` **and** `mcp.server.fastmcp.server.stdio_server` (FastMCP captures a reference at import time, so patching only the first module is a silent no-op).
- `sys.stdout` is redirected to `sys.stderr` around third-party imports so stray prints can't corrupt the JSON-RPC stream. Anything diagnostic must go through `debug_log()` (stderr only). A single stray `print()` on stdout will break the protocol.

### Lua side — `MCP_Server/ce_mcp_bridge.lua`

One self-contained script with its own pure-Lua JSON codec, loaded inside Cheat Engine. Key pieces:

- **Worker-thread pipe I/O** (`PipeWorker`): a dedicated thread owns the blocking `pipe.acceptConnection()` / `pipe.readBytes()` calls so the CE GUI never freezes. Every request is handed to the main thread via `thread.synchronize(function() response = executeCommand(payload) end)`. **All CE Lua API calls must run on the main thread** — your `cmd_*` handler is already on it when invoked, so just don't spawn new threads that touch CE APIs directly.
- **Command dispatcher** (`commandHandlers`): a plain table mapping JSON-RPC method name → `cmd_*` function. Several methods have aliases (`read_memory`/`read_bytes`, `find_what_writes_safe` → `cmd_start_dbvm_watch`, etc.).
- **Zombie cleanup** (`cleanupZombieState`): `StartMCPBridge` always calls `StopMCPBridge` first, which tears down any hardware breakpoints, DBVM watches, and scan objects tracked in `serverState`. This is load-bearing — reloading the script while a HW breakpoint is live otherwise leaves orphaned DR slots and can freeze the target. Any new long-lived resource you add should get a cleanup entry here.
- **Universal 32/64-bit handling** (`getArchInfo`, `captureRegisters`, `captureStack`): always branch on `targetIs64Bit()` and use `readPointer()` instead of `readInteger()`/`readQword()` when you mean "pointer-sized." Hardcoding register names or pointer size will silently break on the other architecture.

### Adding a new MCP tool

Two files are the source of truth — there's no codegen, so you must edit both:

1. In `ce_mcp_bridge.lua`: write `local function cmd_foo(params) ... return { success = true, ... } end` and register it in the `commandHandlers` table inside the appropriate unit sub-block (see **Conventions → Section markers** below). The handler name must match the snake_case verb-first convention (`cmd_<name>`).
2. In `mcp_cheatengine.py`: add `@mcp.tool() def foo(...): return format_result(ce_client.send_command("foo", {...}))`.
3. Follow the **Conventions** section below for return shape, address encoding, and naming.
4. Reload the Lua script in CE. The Python server picks up changes automatically via pipe reconnect.

## Environment & safety constraints

- **Windows only.** Named Pipe access via `pywin32`; no plans for cross-platform.
- **Cheat Engine prerequisite**: CE → Settings → Extra → **disable "Query memory region routines"**. With it enabled, memory scans on DBVM-protected pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs. This is documented as a hard requirement in both `README.md` and `AI_Context/AI_Guide_MCP_Server_Implementation.md`; don't weaken the assumption without testing.
- **Pipe name** `\\.\pipe\CE_MCP_Bridge_v99` is hardcoded in both `mcp_cheatengine.py` (as `PIPE_NAME`) and `ce_mcp_bridge.lua` (as `PIPE_NAME`). Keep them in sync if you ever rename it. The `_v99` suffix is the wire-protocol version and is independent of the bridge version (`12.0.0`).
- **Anti-cheat safety** (per `AI_Context/AI_Guide_MCP_Server_Implementation.md`): prefer hardware DR0–DR3 breakpoints over software (`0xCC`) breakpoints, and prefer DBVM watches for truly invisible tracing. The existing `cmd_set_breakpoint` already uses `debug_setBreakpoint` (hardware); keep new debugging tools on that path.
- **Env vars:** `CE_MCP_TIMEOUT` (default 30s) limits per-tool latency; `CE_MCP_ALLOW_SHELL=1` enables `run_command` / `shell_execute` (default: disabled).

## Conventions (v12 overhaul)

### Return shape
- **Success:** `{ success: true, <fields> }`
- **Error:** `{ success: false, error: "<human msg>", error_code: "<UPPER_SNAKE>" }`
- **Error code enum:** `NO_PROCESS`, `INVALID_ADDRESS`, `INVALID_PARAMS`, `CE_API_UNAVAILABLE`, `DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `PERMISSION_DENIED`, `NOT_FOUND`, `OUT_OF_RESOURCES`, `INTERNAL_ERROR`.

### Addresses
Output: always hex string via `toHex()` (e.g. `"0x140001000"`). Input: accept string or integer.

### Naming
Python tool name == Lua dispatcher key == `cmd_<name>` minus prefix. Snake_case, verb-first.

### Section markers for contributions
New handlers are appended with unit markers (e.g. `-- >>> BEGIN UNIT-NN <Title> <<<`) to keep parallel contributions mergeable. New dispatcher entries go inside the `commandHandlers` table in unit sub-blocks.

### Pagination
List-returning commands (scan results, memory regions, modules, threads, disassembly, references, BP hits) support `offset` / `limit` params with a standard `{ total, offset, limit, returned, <key>: [...] }` return shape.

## CT Table Auto-Updater (`MCP_Server/ct_updater/`)

A standalone Python tool that checks whether an existing `.CT` cheat table still works after a game update and auto-patches what it can. Also contains feature-discovery tools for building new hooks. Run from `MCP_Server/`:

```bash
python -m ct_updater "path/to/Game.CT"                        # check + write .updated.CT
python -m ct_updater "path/to/Game.CT" --no-patch             # report only
python -m ct_updater "path/to/Game.CT" --lint                 # pre-flight quality check, no patch
python -m ct_updater "path/to/Game.CT" --preview-only         # show unified diff, no write
python -m ct_updater "path/to/Game.CT" --verbose              # disassembly for broken patterns
python -m ct_updater "path/to/Game.CT" --apply-postprocess-fix   # auto-apply strong postprocess picks
python -m ct_updater "path/to/Game.CT" --write-artifacts      # write per-entry JSON/MD/AI bundle reports
python -m ct_updater "path/to/Game.CT" \
  --history-store ct_history.json --record-history            # track accepted fixes for future runs
```

### Pipeline overview

The updater routes each AOB entry into one of five buckets:

| Bucket | Meaning |
|--------|---------|
| `FAST_PATH_OK` | Pattern still matches — nothing to do |
| `AUTO_FIX` | Safe deterministic repair (range extension or high-confidence byte substitution) |
| `POSTPROCESS_FIX` | Postprocess produced a strong recommendation; patched with `--apply-postprocess-fix` |
| `ESCALATE_POSTPROCESS` | Strong recommendation found but not auto-applied — inspect the decision report |
| `MANUAL_REVIEW` | Confidence too weak; needs human judgment |

Uniqueness is checked before any `AUTO_FIX` is applied — if the pattern matches more than one location in the sampled method memory the fix is blocked and the entry is escalated.

### Module responsibilities

| File / Package | Purpose |
|---|---|
| `bridge.py` | Named pipe client — connects to `CE_MCP_Bridge_v99`, wraps `evaluate_lua`, `read_memory`, `disassemble` |
| `parser.py` | Parses `.CT` XML — extracts `aobscanregion(...)`, `assert(...)`, and pointer entries. Handles bare CE hex (`10C`) vs decimal (`100`). |
| `analyzer.py` | Resolves Mono symbols, reads method memory, scores pattern matches. Returns `OK`, `RANGE_MISS`, `BYTE_CHANGE`, `PARTIAL`, `NOT_FOUND`, `NO_SYMBOL`. |
| `workflow.py` | Decision tree that routes entries through fast-path → preprocess → postprocess → patch/escalate/manual. Classifies each candidate's instruction window with `hook_intent_classifier` for intent consistency scoring. |
| `patcher.py` | Applies fixes to raw `.CT` text; `preview_fixes()` returns a unified diff without writing. |
| `__main__.py` | CLI entry point — orchestrates the pipeline, renders colour report, writes artefacts. |
| `preprocess/` | Samples method memory, scores candidate windows, captures disassembly, builds replacement/wildcard patterns. |
| `postprocess/` | Rescores candidates using 8 signals: byte similarity, confidence, mnemonic shape, structural markers, uniqueness, stability, history alignment, and intent consistency. |
| `uniqueness/` | Counts how many times a candidate pattern appears in sampled memory; classifies as `unique` / `ambiguous` / `unsafe`. |
| `stability/` | Identifies volatile vs stable bytes empirically and via structural heuristics (call offsets, RIP-relative displacements, branch targets, MOV immediates). Produces both empirical and `hardened_pattern` outputs. |
| `history_store/` | Persists accepted fixes to a JSON file; future runs use the stored baseline as a ranking hint. |
| `method_diff/` | Normalized instruction-window diffing; included in escalated decision artifacts. |
| `bundle/` | Combined AI handoff artifact — one JSON/Markdown file per escalated run containing preprocess + decision + flow summary. |
| `preview/` | Preview service; drives `--preview-only` output including risk labels. |
| `lint/` | Pre-flight CT quality checks: zero-wildcard dense patterns, tight scan ranges, duplicate AOBs, unresolvable assert targets. |
| `hook_intent_classifier/` | Classifies an instruction window as `write`, `read`, `read_modify_write`, `branch_gate`, `callsite`, `compare`, or `mixed`. Used by workflow and feature_builder. |
| `feature_builder/` | Reference-driven packet generation for new hooks — runs preprocess + postprocess + method_diff + intent classification + sibling field scan in one call. |
| `sibling_field_finder/` | Discovers nearby struct fields by scanning for same-base-register memory accesses with different offsets. |
| `script_template_generator/` | Generates CE Auto Assembler scaffold (`aobscanregion`, `alloc`, `jmp`, hook body) from a feature packet or direct inputs. |
| `tests/` | Offline unit-test harness (no bridge required). Covers lint, stability heuristics, intent rescoring, and template generation. |

### Auto-fix rules

- **`RANGE_MISS`**: pattern found outside the `aobscanregion` end offset → extends the range. Blocked if uniqueness check finds multiple matches.
- **`BYTE_CHANGE`** (≥85% match, ≥90% for auto-fix without postprocess): a few bytes differ → substitutes the changed bytes and optionally extends range. Blocked if ambiguous.
- **`POSTPROCESS_FIX`** (opt-in): postprocess score ≥ 85% → applies the recommended pattern. Uses the wildcard form when uniqueness is confirmed.
- Everything else requires manual rewrite — the tool flags these with match scores, diff bytes, and optional disassembly.

### Intent consistency scoring

Each candidate's instruction window is classified (`write`, `read`, `branch_gate`, etc.) by `hook_intent_classifier`. The rescorer computes a majority intent across all candidates and penalizes outliers with a 3% weight in the final score. When the top two candidates disagree on intent, `intent_conflict_with_backup` is added to the decision's reason codes to prompt manual review.

### Stability heuristics

`stability/service.py` detects structurally volatile byte positions from raw bytes alone:
- `E8/E9 rel32` — call/jmp relative offsets
- `EB/7x rel8` — short branch offsets
- `0F 8x rel32` — near Jcc offsets
- `[REX] 8B/8D/89 [rip+disp32]` — RIP-relative MOV/LEA displacements
- `FF 15 [rip+disp32]` — indirect call through import table
- `[REX.W] B8+r imm64` — MOV reg, absolute address
- `[REX] C7 /0 imm32` — MOV struct field, immediate

The `hardened_pattern` field wildcards both empirically changed bytes AND structurally volatile positions even if they currently match, producing more durable recommended signatures.

### Key invariants to maintain

- The parser uses `_parse_ce_number()` for all numeric literals — always try hex-with-letter-detection before decimal, since CE auto-assembler uses bare hex (e.g. `10C`) without a `0x` prefix.
- The patcher never modifies the original file; it writes `*.updated.CT` (and backs up any existing `.updated.CT` to `.bak.CT`).
- `bridge.py` must remain compatible with both v11.4.x and v12.x bridges — same pipe name, same `evaluate_lua` method, same `read_memory` response shape (`bytes` list or `data` hex string).
- `workflow.py` checks uniqueness before marking any result `can_auto_fix = True`. Never skip this for new fix paths.
- The postprocess fix threshold (`POSTPROCESS_FIX_THRESHOLD = 0.85`) and high-confidence auto-fix threshold (`HIGH_CONFIDENCE_AUTO_FIX = 0.90`) are defined at the top of `workflow.py` — adjust there, not scattered in caller code.
- The final-score formula weights in `postprocess/rescorer.py` must sum to 1.0. Current weights: byte_score 0.33, confidence 0.19, mnemonic 0.15, structural 0.10, uniqueness 0.10, stability 0.05, history 0.05, intent 0.03.

## Reference material in `AI_Context/`

- `MCP_Bridge_Command_Reference.md` — exhaustive per-command reference with request/response examples. Consult this when working on a specific tool instead of grepping the Lua file.
- `AI_Guide_MCP_Server_Implementation.md` — higher-level architecture and safety notes (v12.0.0).
- `CE_LUA_Documentation.md` — Cheat Engine 7.6 Lua API reference (~229 KB). Offline source of truth when a CE function's behavior is unclear.
- `BATCH_WORKER_BRIEFING.md` — task specifications used during the v12 parallel overhaul. Useful historical context for understanding why sections are structured as they are.
- `plugins/` — Cheat Engine native plugin SDK headers (`cepluginsdk.h/.pas`) and Lua 5.3 headers. **Not used** by the bridge at runtime; it's reference material for CE's C plugin API and unrelated to the Lua script used here.
