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

There is **no build step, no linter, and no unit-test harness**. `test_mcp.py` is a single end-to-end script that talks to the live Named Pipe; running a "single test" means editing the `all_tests` dict in `test_mcp.py:main` or commenting out sections.

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

## Reference material in `AI_Context/`

- `MCP_Bridge_Command_Reference.md` — exhaustive per-command reference with request/response examples. Consult this when working on a specific tool instead of grepping the Lua file.
- `AI_Guide_MCP_Server_Implementation.md` — higher-level architecture and safety notes (v12.0.0).
- `CE_LUA_Documentation.md` — Cheat Engine 7.6 Lua API reference (~229 KB). Offline source of truth when a CE function's behavior is unclear.
- `BATCH_WORKER_BRIEFING.md` — task specifications used during the v12 parallel overhaul. Useful historical context for understanding why sections are structured as they are.
- `plugins/` — Cheat Engine native plugin SDK headers (`cepluginsdk.h/.pas`) and Lua 5.3 headers. **Not used** by the bridge at runtime; it's reference material for CE's C plugin API and unrelated to the Lua script used here.
