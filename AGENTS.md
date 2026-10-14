# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this project is

A three-tier bridge that lets AI agents (via MCP) drive Cheat Engine to inspect and manipulate a running Windows process. See `README.md` for user-facing docs. Current wire/app version: `12.0.0`. After the v12 overhaul the bridge exposes **200+ MCP tools** covering memory, process lifecycle, code injection, symbol management, assembly/compilation, GUI automation, input, cheat tables, and kernel-mode operations.

## Commands

```bash
# Install Python deps (Windows only — uses pywin32)
pip install -r MCP_Server/requirements.txt

# Offline suites (no Cheat Engine needed: real bridge code against a fake CE API, ~30 s)
python tests/run_all.py            # add --real (real-DLL checks) and/or --mutation (do the tests catch breakages?)

# Live smoke test of the newer features (requires CE running with the bridge loaded; spawns and attaches its own throwaway target, restores CE's process afterwards)
python tests/live_smoke.py

# Live end-to-end suite (requires: CE running, ce_mcp_bridge.lua loaded, a process attached)
python MCP_Server/test_mcp.py
```

Loading the Lua side in Cheat Engine: `File -> Execute Script -> open MCP_Server/ce_mcp_bridge.lua -> Execute`. Some CE builds expose this through `Table -> Show Cheat Table Lua Script`; in that case execute `dofile([[C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_mcp_bridge.lua]])` instead of pasting the full bridge. Success log: `[MCP v12.0.0] MCP Server Listening on: CE_MCP_Bridge_v99`. Re-executing the script auto-calls `StopMCPBridge` / `cleanupZombieState` first, so reloading is safe.

There is **no build step and no linter**. Run `python tests/run_all.py` after every change to `ce_mcp_bridge.lua` or `mcp_cheatengine.py`: the offline suites in `tests/` execute the real Lua handlers inside CE's own Lua 5.3 DLL against a fake CE API and exercise the Python client against a fake bridge on a real named pipe (see `tests/README.md`). New behaviour needs a test in the matching suite plus, for Lua logic, a mutant in `tests/mutation_check.py`. A fake CE proves the bridge logic, not CE's real API behaviour. `MCP_Server/test_mcp.py` is the single end-to-end script that talks to the live Named Pipe; running a "single test" means editing the `all_tests` dict in `test_mcp.py:main` or commenting out sections.

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

Thin `FastMCP` wrapper. Every `@mcp.tool()` is a one-liner that calls `ce_client.send_command("<method>", {...})` and formats the result. `CEBridgeClient.send_command` writes a 4-byte little-endian length prefix + UTF-8 JSON-RPC body to the Named Pipe, reads the same framing back, caps responses at 32 MB, and reconnects once on pipe failure. Retry rules matter: read-only methods (see `is_idempotent`) are re-sent after an unknown outcome, but state-changing methods are never re-sent once the request may have reached CE (the error says the outcome is unknown). `connect()` waits up to `CE_MCP_CONNECT_WAIT` for the bridge to re-create its pipe. On timeout `close()` cancels the worker's pending I/O via `CancelIoEx` (ctypes) first; closing the handle while another thread is blocked in `ReadFile` would otherwise hang forever.

**Windows stdio pitfalls (top of file, before any other imports)** — do not move this block:
- The MCP SDK's `stdio_server` wraps stdio with `TextIOWrapper` without `newline='\n'`, so on Windows it emits `\r\n` and the transport rejects with "invalid trailing data." The file monkey-patches `mcp.server.stdio.stdio_server` **and** `mcp.server.fastmcp.server.stdio_server` (FastMCP captures a reference at import time, so patching only the first module is a silent no-op).
- `sys.stdout` is redirected to `sys.stderr` around third-party imports so stray prints can't corrupt the JSON-RPC stream. Anything diagnostic must go through `debug_log()` (stderr only). A single stray `print()` on stdout will break the protocol.

### Capability profiles and tool groups — `MCP_Server/tool_policy.py` (UNIT-29)

`CE_MCP_PROFILE` (readonly < analysis < patch < full, default full, unknown = readonly), `CE_MCP_ALLOW` / `CE_MCP_DENY` and `CE_MCP_TOOLSET` come from the MCP server's environment. `CATALOG` maps every tool and wire method to a `(group, tier)`; **a name that is not in it counts as the top tier**. The gate is `POLICY.check()` at the top of `CEBridgeClient.send_command` (it also inspects the requests inside `batch` and the `kind` of `start_job`, otherwise `batch_commands` would be a bypass); `POLICY.apply(mcp)` then unlists what the profile/toolset hides and `policy_info` explains it. The Lua bridge does not enforce anything. When you add a tool, add it to `CATALOG` (anything that runs code, touches files/clipboard/input or writes kernel memory is `EXEC`; anything that changes the target is at least `WRITE`) - `python tests/test_policy.py` fails until every tool and every Lua dispatcher entry is classified.

### Lua side — `MCP_Server/ce_mcp_bridge.lua`

One self-contained script with its own pure-Lua JSON codec, loaded inside Cheat Engine. Key pieces:

- **Worker-thread pipe I/O** (`PipeWorker`): a dedicated thread owns the blocking `pipe.acceptConnection()` / `pipe.readBytes()` calls so the CE GUI never freezes. Every request is handed to the main thread via `thread.synchronize(function() response = executeCommand(payload) end)`. **All CE Lua API calls must run on the main thread** — your `cmd_*` handler is already on it when invoked, so just don't spawn new threads that touch CE APIs directly.
- **Command dispatcher** (`commandHandlers`): a plain table mapping JSON-RPC method name → `cmd_*` function. Several methods have aliases (`read_memory`/`read_bytes`, `find_what_writes_safe` → `cmd_start_dbvm_watch`, etc.).
- **Zombie cleanup** (`cleanupZombieState`): `StartMCPBridge` always calls `StopMCPBridge` first, which tears down any hardware breakpoints, DBVM watches, and scan objects tracked in `serverState`. This is load-bearing — reloading the script while a HW breakpoint is live otherwise leaves orphaned DR slots and can freeze the target. Any new long-lived resource you add should get a cleanup entry here.
- **Operations unit (UNIT-25)**: `bridge_status` (health/diagnostics), `read_struct` (many typed fields from one read), `batch` (several commands in one main-thread slot; dispatches through `serverState.dispatch`, which is set right after the `commandHandlers` table) and the **async job system**. Jobs (`start_job`/`get_job`/`get_job_result`/`cancel_job`/`list_jobs`) run `scan_all`, `next_scan`, `aob_scan`, `find_references` and `find_call_references` without blocking CE: scans use CE's own async `MemScan` (no `waitTillDone`; `OnScanDone` only raises a flag and the pump timer / `get_job` does the work, because destroying a memscan from inside its own event handler is unsafe; `getProgress()` polling is the fallback) and the Lua-side post-processing of reference searches is time-sliced from a `createTimer` pump. `scan_all`/`next_scan` jobs own the shared scan session, so the blocking `scan_all`/`next_scan`/`get_scan_results` answer `BUSY` while one runs. New long-lived job resources belong in `cleanupZombieState` step 2b.
- **Analysis unit (UNIT-26)**: everything hangs off a single `local U26` table (the chunk is near CE's 200-locals limit, so do not add top-level locals). PE parsing reads headers straight from target memory (`U26.parsePE`): `pe_info`/`pe_imports`/`pe_exports`/`pe_tls_callbacks`, address translation (`va_to_rva`, `rva_to_va`, `rebase_address`) and name exchange with IDA (`export_names`, `export_structures`, `import_names`). The scanning jobs `rtti_scan`, `find_string_refs`, `find_code_caves` run on a shared time-sliced chunk engine (`U26.startStages`; a stage = ranges + `process(job, data, dataBase)` + optional `carry` bytes for patterns that span chunk borders), and `find_pointer_path` chains one value-between memscan per frontier address. Snapshots (`snapshot_region`/`diff_snapshots`) keep raw region copies in `serverState.snapshots` (128 MB / 16 snapshots budget). Register new job kinds in `JOB_STARTERS` and append them to `JOB_KIND_NAMES`.
- **Function boundaries (UNIT-27)**: on x64 `U26.functionAt` resolves the function containing an address from the exception table (`.pdata`, binary-searched in a cached copy of the RUNTIME_FUNCTION array; UNWIND_INFO gives prolog size, frame register, handler and chained parents, so split/cold fragments resolve to their primary function). `find_function_boundaries`, `analyze_function` and `find_string_refs` use it through the global `pdataFunctionBoundaries` / `U26.functionAt` and fall back to the prologue heuristic where there is no entry (leaf functions, x86). Note that those two handlers are defined before `U26` exists, hence the global hook.
- **Struct recovery (UNIT-27)**: `U26.rttiAtVtable` reads the complete object locator in the slot before any vtable (class, bases via `U26.readBases`, `this_offset`), and `recover_struct` walks one or more instances of the same class: pointer-sized slots are classified by what they point at (another RTTI object, text, a vtable, static data), then inline text, doubles, floats, ints, with zero runs merged and the all-zero tail trimmed. The heuristics (`U26.plausibleFloat`/`plausibleDouble`/`looksLikePointer`) are deliberately conservative; extend them together with a case in `tests/test_lua_analysis.py` and a mutant in `tests/mutation_check.py`.
- **Breakpoint control (UNIT-27)**: everything breakpoint-related that is not trivial lives in the `BPX` table (one local; the chunk is near CE's 200-locals limit). `BPX.install` is shared by `set_breakpoint`/`set_data_breakpoint`; `BPX.handle` is the single place a hit is judged (condition, record, `max_hits`, halt). Conditions are `load`ed with a restricted environment and run under a `debug.sethook` instruction budget. `mode="break"` returns a NON-ZERO number (1) from the CE callback without continuing, which is what leaves the thread stopped (measured live: `nil`/`false`/`true`/`0` make CE resume it; `debug_isBroken()` returns a function in CE 7.6, never trust it), recorded in `serverState.halted`; the watchdog (`BPX.watchdog`, driven by the job pump timer) resumes it after `halt_timeout_ms`, and `cleanupZombieState`, `remove_breakpoint`, `clear_all_breakpoints` and `debug_continue` keep that record honest. Never let any code path leave a thread stopped without `serverState.halted` pointing at it.
- **Cross-references (UNIT-28)**: `find_xrefs` is a job on the chunk engine: `U26.xrefModuleStages` builds the scan stages per module and `U26.xrefItem` validates each raw hit in a second, time-sliced phase (`U26.xrefResolveStep`). Raw hits come from byte patterns: `E8`/`E9`/`0F 8x` rel32, short jumps (only the +-128 bytes around the target are examined), modrm bytes with mod=00 rm=101 followed by a displacement (x64 rip-relative; the immediate size is unknown, so four candidate end addresses are tried), exact pointer needles in code and data, and 32-bit RVAs in non-`.pdata` data. The disassembler then decides: `U26.insnStart` decodes **forward** from the enclosing `.pdata` function start (else 96 bytes back) and accepts a rip candidate only if the instruction covering the displacement ends exactly where the candidate says; short jumps must additionally sit on an instruction boundary (`U26.atBoundary`). Do not "widen" backwards over prefix-looking bytes: the 0x40 ending `mov rax,[rax+40h]` looks like a REX prefix to `call [rip+x]` (this misattributed 30% of the hits in `msvcp140.dll`). Build Lua pattern classes with `U26.byteClass`, never by hand: a literal `%` (0x25) or `-` (0x2D) inside a class changes its meaning (the old `find_string_refs` class silently lost modrm 0x25, i.e. `lea r12,[rip+x]`). Validate changes with `python tests/test_lua_xrefs.py --real` (capstone is the independent oracle; `pip install capstone`).
- **Pointer path sets (UNIT-30)**: the two-run comparison. `serverState.path_sets` holds named lists of chains `{module, rva | abs, offsets, runs}` (`U26.ps*` helpers, no new top-level locals). `find_pointer_path(save_as=)` fills one in run 1 (its name is validated before the scans start); `cmd_compare_pointer_paths` re-resolves a set (or inline `chains`) against the address of the same value in the process as it is NOW and returns the chains that land exactly on it with `runs + 1`. Chains are stored module-relative (an absolute base inside a module is converted, module names are compared case-insensitively) because that is what survives ASLR; `module_missing` / `unreadable` / `missed` are counted apart, a miss within `near_delta` bytes is a `near_miss` with `suggested_offsets` (last offset corrected), and `same_process` flags a comparison against the pid of the previous run. Nothing is stored unless `save_as` is given, saving the same name narrows in place, and an empty result never overwrites a set (`U26.psPut` refuses empty sets). Bounds: 16 sets, 5000 chains, 20 history entries, 16 offsets per chain. Run 1's pointers must be re-found by the caller in run 2 (scan, `find_pointer_path`, CE's own pointer scanner): the comparison tests chains, it does not search.
- **Universal 32/64-bit handling** (`getArchInfo`, `captureRegisters`, `captureStack`): always branch on `targetIs64Bit()` and use `readPointer()` instead of `readInteger()`/`readQword()` when you mean "pointer-sized." Hardcoding register names or pointer size will silently break on the other architecture.

### Adding a new MCP tool

Two files are the source of truth — there's no codegen, so you must edit both:

1. In `ce_mcp_bridge.lua`: write `function cmd_foo(params) ... return { success = true, ... } end` and register it in the `commandHandlers` table inside the appropriate unit sub-block (see **Conventions -> Section markers** below). Command handlers are intentionally not top-level locals because Cheat Engine can fail to compile the full bridge once a Lua chunk exceeds 200 local variables. The handler name must match the snake_case verb-first convention (`cmd_<name>`).
2. In `mcp_cheatengine.py`: add `@mcp.tool() def foo(...): return format_result(ce_client.send_command("foo", {...}))`.
3. Follow the **Conventions** section below for return shape, address encoding, and naming. Classify the tool in `MCP_Server/tool_policy.py` (`CATALOG`: group + tier); `tests/test_policy.py` fails until you do.
4. Reload the Lua script in CE. The Python server picks up changes automatically via pipe reconnect.

## Environment & safety constraints

- **Windows only.** Named Pipe access via `pywin32`; no plans for cross-platform.
- **Cheat Engine prerequisite**: CE → Settings → Extra → **disable "Query memory region routines"**. With it enabled, memory scans on DBVM-protected pages trigger `CLOCK_WATCHDOG_TIMEOUT` BSODs. This is documented as a hard requirement in both `README.md` and `AI_Context/AI_Guide_MCP_Server_Implementation.md`; don't weaken the assumption without testing.
- **Pipe name** `\\.\pipe\CE_MCP_Bridge_v99` is hardcoded in both `mcp_cheatengine.py` (as `PIPE_NAME`) and `ce_mcp_bridge.lua` (as `PIPE_NAME`). Keep them in sync if you ever rename it. The `_v99` suffix is the wire-protocol version and is independent of the bridge version (`12.0.0`).
- **Codex config:** use TOML, not JSON. Add `[mcp_servers.cheatengine]`, `command = "python"`, and `args = ['C:\path\to\MCP_Server\mcp_cheatengine.py']`. Use TOML single-quoted strings for Windows paths so backslashes are literal, then restart Codex and verify with the `ping` tool.
- **Anti-cheat safety** (per `AI_Context/AI_Guide_MCP_Server_Implementation.md`): prefer hardware DR0–DR3 breakpoints over software (`0xCC`) breakpoints, and prefer DBVM watches for truly invisible tracing. The existing `cmd_set_breakpoint` already uses `debug_setBreakpoint` (hardware); keep new debugging tools on that path.
- **Env vars:** `CE_MCP_TIMEOUT` (default 30s) limits per-tool latency (keep it below the MCP host's own tool timeout); `CE_MCP_CONNECT_WAIT` (default 2s) is how long to retry a busy/re-created pipe; `CE_MCP_ALLOW_SHELL=1` enables `run_command` / `shell_execute` (default: disabled). `CE_MCP_PROFILE`, `CE_MCP_ALLOW`, `CE_MCP_DENY` and `CE_MCP_TOOLSET` restrict and shrink the tool set (see the policy section above).

## Conventions (v12 overhaul)

### Return shape
- **Success:** `{ success: true, <fields> }`
- **Error:** `{ success: false, error: "<human msg>", error_code: "<UPPER_SNAKE>" }`
- **Error code enum:** `NO_PROCESS`, `INVALID_ADDRESS`, `INVALID_PARAMS`, `CE_API_UNAVAILABLE`, `DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `PERMISSION_DENIED`, `NOT_FOUND`, `OUT_OF_RESOURCES`, `BUSY`, `INTERNAL_ERROR`.

### Addresses
Output: always hex string via `toHex()` (e.g. `"0x140001000"`). Input: accept string or integer.

### Naming
Python tool name == Lua dispatcher key == `cmd_<name>` minus prefix. Snake_case, verb-first.

### Section markers for contributions
New handlers are appended with unit markers (e.g. `-- >>> BEGIN UNIT-NN <Title> <<<`) to keep parallel contributions mergeable. New dispatcher entries go inside the `commandHandlers` table in unit sub-blocks.

### Pagination
List-returning commands (scan results, memory regions, modules, threads, disassembly, references, BP hits) support `offset` / `limit` params with a standard `{ total, offset, limit, returned, <key>: [...] }` return shape.

## Reference material in `AI_Context/`

- `MCP_Bridge_Command_Reference.md` — exhaustive per-command reference with request/response examples. Consult this when working on a specific tool instead of grepping the Lua file.
- `AI_Guide_MCP_Server_Implementation.md` — higher-level architecture and safety notes (v12.0.0).
- `CE_LUA_Documentation.md` — Cheat Engine 7.6 Lua API reference (~229 KB). Offline source of truth when a CE function's behavior is unclear.
- `BATCH_WORKER_BRIEFING.md` — task specifications used during the v12 parallel overhaul. Useful historical context for understanding why sections are structured as they are.
- `plugins/` — Cheat Engine native plugin SDK headers (`cepluginsdk.h/.pas`) and Lua 5.3 headers. **Not used** by the bridge at runtime; it's reference material for CE's C plugin API and unrelated to the Lua script used here.
