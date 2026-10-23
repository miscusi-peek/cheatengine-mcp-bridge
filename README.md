[Demo](https://github.com/user-attachments/assets/a184a006-f569-4b55-858a-ed80a7139035)

# Cheat Engine MCP Bridge

**Let multibillion $ AI datacenters analyze the program memory for you.**

Create mods, trainers, security audits, game bots, accelerate RE, or do anything else with any program and game in a fraction of a time.

[![Version](https://img.shields.io/badge/version-12.0.0-blue.svg)](#) [![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)

> [!NOTE]
> Thanks everyone for the stars, much appreciated! <3
> 
> Specially a big thank you to all the contributors!!
> 
> [@libangli218](https://github.com/libangli218), [@lauralex](https://github.com/lauralex), [@iamtyroon](https://github.com/iamtyroon), [@HachiroSan](https://github.com/HachiroSan), [@Attacktive](https://github.com/Attacktive)

---

## The Problem

You're staring at gigabytes of memory. Millions of addresses. Thousands of functions. Finding *that one pointer*, *that one structure* takes **days or weeks** of manual work.

**What if you could just ask?**

> *"Find the packet decryptor hook."*  
> *"Find the OPcode of character coordinates."*  
> *"Find the OPcode of health values."*  
> *"Find the unique AOB pattern to make my trainer reliable after game updates."*

**That's exactly what this does.**

_- Stop clicking through hex dumps and start having conversations with the memory._

---

## What You Get:

| Before (Manual) | After (AI Agent + MCP) |
|-----------------|---------------------|
| Day 1: Find packet address | Minute 1: "Find RX packet decryption hook" |
| Day 2: Trace what writes to it | Minute 3: "Generate unique AOB signature to make it update persistent" |
| Day 3: Find RX hook | Minute 6: "Find movement OPcodes" |
| Day 4: Document structure | Minute 10: "Create python interpreter of hex to plain text" |
| Day 5: Game updates, start over | **Done.** |

**Your AI can now:**
- Read any memory instantly (integers, floats, strings, pointers)
- Follow pointer chains: `[[base+0x10]+0x20]+0x8` → resolved in ms
- Auto-analyze structures with field types and values
- Identify C++ objects via RTTI: *"This is a CPlayer object"*
- Disassemble and analyze functions
- Debug invisibly with hardware breakpoints + Ring -1 hypervisor
- And much more!

---

## How It Works
```mermaid
flowchart TD
    AI[AI Agent: Claude/Cursor/Copilot]
    
    AI -->|MCP Protocol - JSON-RPC over stdio| MCP
    
    MCP[mcp_cheatengine.py - Python MCP Server]
    
    MCP <-->|Named Pipe - Async| PIPE
    
    PIPE["\\.\\pipe\\CE_MCP_Bridge_v99"]
    
    PIPE <--> CE
    
    subgraph CE[Cheat Engine - DBVM Mode]
        subgraph LUA[ce_mcp_bridge.lua]
            WORKER[Worker Thread - Blocking I/O]
            MAIN[Main Thread - GUI + CE API]
            WORKER <-->|Sync| MAIN
        end
    end
    
    MAIN -->|Memory Access| TARGET[Target .exe]
```
---

## Installation

```bash
pip install -r MCP_Server/requirements.txt
```
Or manually:
```bash
pip install mcp pywin32
```

> [!NOTE]
> Native pipe mode is **Windows only** because it uses Named Pipes (`pywin32`). Use TCP relay transport when the MCP server runs outside the Windows environment that hosts Cheat Engine and cannot open the named pipe directly.

---

## Quick Start

### 1. Load Bridge in Cheat Engine
1. Enable DBVM in Cheat Engine if you plan to use DBVM tools.
2. Open Cheat Engine's Lua Engine or script executor.
   - Preferred: `File` -> `Execute Script` -> open `MCP_Server/ce_mcp_bridge.lua` -> `Execute`.
   - If your Cheat Engine build does not show `File` -> `Execute Script`, use `Table` -> `Show Cheat Table Lua Script`, paste the `dofile(...)` line below, and execute it:

```lua
dofile([[C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_mcp_bridge.lua]])
```

Look for: `[MCP v12.0.0] MCP Server Listening on: CE_MCP_Bridge_v99`

### 2. Configure MCP Client
Add to your MCP configuration (e.g., `mcp_config.json`):
```json
{
  "servers": {
    "cheatengine": {
      "command": "python",
      "args": ["C:/path/to/MCP_Server/mcp_cheatengine.py"]
    }
  }
}
```
Restart the IDE to load the MCP server config.

For Codex, add a TOML server block to `~/.codex/config.toml`:

```toml
[mcp_servers.cheatengine]
command = "python"
args = ['C:\path\to\cheatengine-mcp-bridge\MCP_Server\mcp_cheatengine.py']
```

Use single quotes for the Windows path so TOML treats backslashes literally.

#### TCP relay transport

The TCP relay lets `mcp_cheatengine.py` talk to Cheat Engine through a TCP socket instead of opening the Windows named pipe itself. Cheat Engine and the Lua bridge still run on Windows, while the MCP server can run anywhere that can reach the relay: another Windows process, a VM, a container, a Linux host, or a remote machine. This can also be used with WSL without changing the Lua bridge.

1. On Windows, load `MCP_Server/ce_mcp_bridge.lua` in Cheat Engine as usual.
2. On Windows, start the relay:

```powershell
python C:\path\to\cheatengine-mcp-bridge\MCP_Server\ce_tcp_relay.py --host 127.0.0.1 --port 9876
```

3. In the environment where the MCP server will run, install the MCP dependency without `pywin32`, then run/configure the MCP server with TCP transport:

```bash
python3 -m pip install -r MCP_Server/requirements-tcp.txt
```

```bash
CE_MCP_TRANSPORT=tcp \
CE_MCP_HOST=127.0.0.1 \
CE_MCP_PORT=9876 \
python3 /path/to/cheatengine-mcp-bridge/MCP_Server/mcp_cheatengine.py
```

For MCP client configs that support environment variables:

```json
{
  "servers": {
    "cheatengine": {
      "command": "python3",
      "args": ["/path/to/cheatengine-mcp-bridge/MCP_Server/mcp_cheatengine.py"],
      "env": {
        "CE_MCP_TRANSPORT": "tcp",
        "CE_MCP_HOST": "127.0.0.1",
        "CE_MCP_PORT": "9876"
      }
    }
  }
}
```

Set `--host` on the relay and `CE_MCP_HOST` on the MCP server to addresses that match your network setup. Keep the relay bound to trusted interfaces only, because anyone who can reach it can control the Cheat Engine bridge.

### 3. Verify Connection
Use the `ping` tool to verify connectivity:
```json
{"success": true, "version": "12.0.0", "message": "CE MCP Bridge Active"}
```

### 4. Start Asking Questions
```
"What process is attached?"
"Read 16 bytes at the base address"
"Disassemble the entry point"
```

---

## 200+ MCP Tools Available

### Memory
| Tool | Description |
|------|-------------|
| `read_memory`, `read_integer`, `read_string` | Read any data type |
| `read_pointer_chain` | Follow `[[base+0x10]+0x20]` paths |
| `scan_all`, `aob_scan` | Find values and byte patterns |

### Analysis
| Tool | Description |
|------|-------------|
| `disassemble`, `analyze_function` | Code analysis |
| `dissect_structure` | Auto-detect fields and types |
| `get_rtti_classname` | Identify C++ object types |
| `find_references`, `find_call_references` | Cross-references |

### Debugging
| Tool | Description |
|------|-------------|
| `set_breakpoint`, `set_data_breakpoint` | Hardware breakpoints with conditions (`RAX==5`, `u32(RDX+8)==0x1234`), `max_hits`, validation, and a `mode="break"` that stops the thread for inspection |
| `get_halted_state`, `debug_continue` | Inspect a thread stopped by a break-mode breakpoint (fresh registers, instruction, stack, captured memory), then run / step it. A watchdog resumes it by itself, so a lost client cannot freeze the game |
| `start_dbvm_watch` | Ring -1 invisible tracing |

### Process Lifecycle
| Tool | Description |
|------|-------------|
| `open_process`, `get_process_list` | Attach to or enumerate running processes |
| `create_process` | Launch a new process under CE's control |
| `pause_process`, `unpause_process` | Suspend / resume target execution |

### Memory Allocation
| Tool | Description |
|------|-------------|
| `allocate_memory`, `free_memory` | Reserve and release memory in the target |
| `set_memory_protection`, `full_access` | Adjust page protection flags |

### Code Injection
| Tool | Description |
|------|-------------|
| `inject_dll` | Load a DLL into the target process |
| `execute_code`, `execute_method` | Run shellcode or CE Lua methods remotely |

### Symbol Management
| Tool | Description |
|------|-------------|
| `register_symbol`, `get_symbol_info` | Create and query named symbols |
| `enable_windows_symbols` | Enable PDB symbol resolution |

### Assembly / Compilation
| Tool | Description |
|------|-------------|
| `assemble_instruction` | Assemble a single x86/x64 instruction to bytes |
| `compile_c_code` | Compile C source into injected shellcode |
| `generate_api_hook_script` | Generate a CE auto-assembler API hook template |

### Window / GUI Automation
| Tool | Description |
|------|-------------|
| `find_window` | Locate a window by title or class |
| `send_window_message` | Post `WM_*` messages to a target window |

### Input Automation
| Tool | Description |
|------|-------------|
| `get_pixel` | Sample a pixel color at screen coordinates |
| `is_key_pressed`, `do_key_press` | Query and simulate keyboard input |

### Cheat Table
| Tool | Description |
|------|-------------|
| `load_table`, `save_table` | Load / save `.CT` cheat table files |
| `get_address_list` | Enumerate entries in the active cheat table |

### Kernel Mode (DBK / DBVM)
| Tool | Description |
|------|-------------|
| `dbk_get_cr3` | Read the CR3 register for the target process |
| `read_process_memory_cr3` | Read physical memory via CR3 bypass |

And many more at `AI_Context/MCP_Bridge_Command_Reference.md`

---

### Operations & Async Jobs
| Tool | Description |
|------|-------------|
| `bridge_status` | One-call health report (bridge version, uptime, attached process, DBK/DBVM, breakpoint/job counts, request stats, warnings). Still answers when CE is unreachable and says why. |
| `read_struct` | Read many typed fields (`u32`, `f32`, `ptr`, `cstring`, `wstring`, ...) with a single memory read |
| `batch_commands` | Run up to 100 commands in one round trip |
| `start_job`, `get_job`, `get_job_result`, `wait_for_job`, `cancel_job`, `list_jobs` | Run long scans (`scan_all`, `next_scan`, `aob_scan`, `find_references`, `find_call_references`) in the background with progress, without freezing CE or hitting the client timeout |

`read_memory` now takes `format` (`hex` default, `base64`, `array`, `both`); `hex` roughly halves the output of the old default.

### Analysis, PE & IDA Exchange
| Tool | Description |
|------|-------------|
| `pe_info`, `pe_imports`, `pe_exports`, `pe_tls_callbacks` | Parse a loaded module's PE headers from memory: sections (rwx), imports with the live IAT values (spot hooks), exports with forwarders, TLS callbacks |
| `rtti_scan_module` | Every MSVC RTTI class in a module: vtable address/RVA, virtual function count, base-class chain (x64 and x86) |
| `pe_functions` | Exact x64 function boundaries from `.pdata` (also used by `find_function_boundaries`, `analyze_function` and string refs): unwind info, exception handler, split-fragment resolution |
| `recover_struct` | Class layout from live instance(s) of a polymorphic MSVC class: RTTI name/bases, virtual functions with exact sizes, inferred fields (typed pointers, text, floats, doubles, ints), C declaration and an optional CE structure |
| `find_string_refs` | Code (`lea reg,[rip+x]`, absolute operands) and data that reference a string, with the function each reference is in |
| `find_xrefs` | Everything that references an address or a range ("who calls this", "who touches this variable"): calls and jumps (rel32 and short), x64 rip-relative operands classified as read / write / lea / call, absolute pointers in code and data, jump-table RVAs. Hits are validated with the disassembler and grouped by calling function |
| `find_code_caves` | Runs of `0xCC`/`0x00`/`0x90` padding for patches and hooks |
| `find_pointer_path` | Reverse pointer search: static `[[module+rva]+o1]+o2` chains that reach a heap address, verified by re-resolving. Holders that lie close together share one memory scan, so deep searches need far fewer full-process scans. `save_as` keeps the chains in a named set for the two-run comparison |
| `compare_pointer_paths`, `list_pointer_sets`, `get_pointer_set`, `drop_pointer_set` | **Two-run pointer path comparison**: after the target restarts and you have found the same value again, `compare_pointer_paths(target=<new address>, name=<set>)` re-resolves every stored chain from its `module+RVA` base and keeps the ones that still land on it (`save_as` narrows the set; a chain with `runs=3` survived three restarts). Chains that miss by a small distance come back as `near_misses` with a corrected last offset, and a comparison inside the same process instance is flagged. Sets are saved to a file, so they survive target restarts, reloads of the script and CE restarts |
| `list_patches`, `undo_patch` | **Patch journal**: every write made through `write_memory`, `write_integer`, `write_string`, `copy_memory` and `auto_assemble` is recorded with the bytes it replaced (the write's reply carries its `patch_id`). `undo_patch(id)` puts them back (a script patch runs its `[DISABLE]` section), `undo_patch(all=true)` unwinds everything newest first. An undo is refused when the bytes changed since the patch unless `force=true`. The journal is saved to a file: after a reload of the bridge, byte patches can still be undone while the same process is attached (script patches cannot). `drop_patches` forgets entries |
| `snapshot_region`, `diff_snapshots`, `list_snapshots`, `delete_snapshot` | Save memory copies and diff them (`C`hanged / `U`nchanged pattern per pair) for unknown-value hunting without scans |
| `va_to_rva`, `rva_to_va`, `rebase_address` | Translate between runtime addresses, module+RVA and IDA addresses |
| `export_names`, `export_structures`, `import_names` | Send CE symbols, RTTI vtables and structure definitions to IDA (JSON, an IDAPython script, C declarations) and bring IDA names back as CE symbols |

The long-running ones (`rtti_scan_module`, `find_string_refs`, `find_xrefs`, `find_code_caves`, `find_pointer_path`) run as background jobs: they wait up to `wait_seconds` and otherwise return a `job_id` for `wait_for_job` / `get_job_result`.

## Critical Configuration

### BSOD Prevention
> [!CAUTION]
> **You MUST disable:** Cheat Engine → Settings → Extra → **"Query memory region routines"**
> 
> Enabled: Causes `CLOCK_WATCHDOG_TIMEOUT` BSODs due to conflicts with DBVM/Anti-Cheat when scanning protected pages.

---

## Troubleshooting

### Cheat Engine says "too many local variables"

Load the bridge from disk with `dofile(...)` instead of pasting the full script into a cheat table script. The bridge also declares command handlers as global functions intentionally; this avoids Cheat Engine's Lua chunk limit of 200 local variables when the complete bridge is compiled at once.

### MCP client cannot connect

Check these in order:

1. Cheat Engine is open and shows `MCP Server Listening on: CE_MCP_Bridge_v99`.
2. The MCP client was restarted after adding the server config.
3. The configured `mcp_cheatengine.py` path exists.
4. `pip install -r MCP_Server/requirements.txt` has installed both `mcp` and `pywin32`.
5. Run the MCP `bridge_status` tool: it works even when CE is unreachable and reports whether the pipe is missing (CE not running / bridge not loaded) or busy (another MCP client holds it).
6. Run the MCP `ping` tool. A successful connection returns `success: true` and the bridge version. `process_id: 0` is normal until Cheat Engine is attached to a target process.

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CE_MCP_TIMEOUT` | `30` | Timeout (seconds) for each MCP tool call. Keep it below your MCP host's own tool timeout. |
| `CE_MCP_CONNECT_WAIT` | `2` | Seconds to keep retrying when the pipe is busy or being re-created after a disconnect. |
| `CE_MCP_ALLOW_SHELL` | *unset* | Set to `1` to enable `run_command` / `shell_execute` tools. **Arbitrary code execution risk** — leave unset by default. |
| `CE_MCP_PROFILE` | `full` | What the AI client may **do**: `readonly` (observe), `analysis` (+ breakpoints, symbols, attach), `patch` (+ write memory), `full` (+ Lua, AutoAssembler, injection, shell, files, input). See below. |
| `CE_MCP_STATE_DIR` | *see text* | Read by the **Lua bridge** (set it in Cheat Engine's environment, or as a Lua global before loading the script): folder for the saved pointer sets and patch journal. Default: the folder of `ce_mcp_bridge.lua` when loaded with `dofile`, else `%LOCALAPPDATA%`, else the temp folder; `off` disables saving. |
| `CE_MCP_TOOLSET` | *all* | Which tools are **listed** (shrinks the tool schema the model reads): groups and presets, e.g. `reverse` or `core,memory,analysis`. |
| `CE_MCP_ALLOW` / `CE_MCP_DENY` | *unset* | Comma separated tool names: lift one tool above the profile / remove one below it (deny wins). |

### Safety profiles and tool groups

`CE_MCP_ALLOW_SHELL` only ever covered two tools. `evaluate_lua`, `auto_assemble` (scripts can contain `{$lua}`), `execute_code*`, `inject_dll`, `load_table`, `delete_file`, input automation and kernel writes reach the same power, so a prompt-injected client could always have used one of them. `CE_MCP_PROFILE` closes that: every call passes one gate in the MCP server (including the methods hidden inside `batch_commands` and `start_job`), and tools above the profile are not even listed. An unknown profile value fails closed (`readonly`). Set it in the MCP server's environment, e.g. in the client's MCP config:

```json
"cheatengine": { "command": "python", "args": ["C:\\path\\to\\mcp_cheatengine.py"], "env": { "CE_MCP_PROFILE": "analysis", "CE_MCP_TOOLSET": "reverse" } }
```

| Profile | Adds | Typical use |
|---------|------|-------------|
| `readonly` | reading memory, process/module info, scans, disassembly, PE/RTTI/xref analysis, snapshots | reverse engineering with an AI you do not fully trust |
| `analysis` | breakpoints, DBVM watches, symbols, structures, attaching, host introspection | live debugging without changing the target |
| `patch` | write memory/registers/protection, allocations | applying a patch you have reviewed |
| `full` | Lua, AutoAssembler, code execution, injection, shell, files, clipboard, input automation, kernel writes | the previous behaviour (default) |

Tool groups: `core` (always), `memory`, `scan`, `analysis`, `symbols`, `structures`, `table`, `debug`, `asm`, `exec`, `system`, `gui`, `kernel`; presets `minimal` (core, memory, scan), `reverse` (+ analysis, symbols, structures, debug) and `all`. A toolset only changes what is listed: with all 207 tools the schema is about 100 KB of text, `reverse` about 68 KB and `minimal` about 27 KB. The `policy_info` tool tells a client what is active and why a tool is missing.

---

## Example Workflows

**Finding a value:**
```
You: "Scan for gold: 15000"  →  AI finds 47 results
You: "Gold changed to 15100"  →  AI filters to 3 addresses
You: "What writes to the first one?"  →  AI sets hardware BP
You: "Disassemble that function"  →  Full AddGold logic revealed
```

**Understanding a structure:**
```
You: "What's at [[game.exe+0x1234]+0x10]?"
AI: "RTTI: CPlayerInventory"
AI: "0x00=vtable, 0x08=itemCount(int), 0x10=itemArray(ptr)..."
```

---

## Project Structure

```
CLAUDE.md                               # Claude Code agent guidance (this repo)
README.md                               # User-facing documentation

MCP_Server/
├── mcp_cheatengine.py                  # Python MCP Server (FastMCP)
├── ce_mcp_bridge.lua                   # Cheat Engine Lua Bridge
└── test_mcp.py                         # Live end-to-end test (needs Cheat Engine running)

tests/
├── run_all.py                          # Runs every offline suite (no Cheat Engine needed)
├── test_lua_*.py                       # Lua bridge: codec/replies, jobs, PE/RTTI/analysis
├── test_client_*.py                    # Python MCP client against a fake bridge pipe
├── mutation_check.py                   # Proves the suites catch deliberate breakages
├── lua_harness.py, testkit.py          # Shared helpers
└── README.md

AI_Context/
├── BATCH_WORKER_BRIEFING.md            # Parallel-worker task specifications (v12 overhaul)
├── MCP_Bridge_Command_Reference.md     # MCP Commands reference
├── CE_LUA_Documentation.md             # Full CheatEngine 7.6 official documentation
└── AI_Guide_MCP_Server_Implementation.md  # Full technical documentation for AI agent
```

---

## Testing

### Offline suites (no Cheat Engine needed)
```bash
python tests/run_all.py
```
Runs the real bridge code against a fake Cheat Engine API plus the Python client against a fake bridge pipe (about 30 seconds). Add `--real` to also validate the PE/RTTI parsing against real system DLLs and `--mutation` to check that the suites catch deliberate breakages. Details in [`tests/README.md`](tests/README.md).

### Live end-to-end test (Cheat Engine running, bridge loaded, a process attached)
```bash
python MCP_Server/test_mcp.py
```

Expected output:
```
✅ Memory Reading: 6/6 tests passed
✅ Process Info: 4/4 tests passed  
✅ Code Analysis: 8/8 tests passed
✅ Breakpoints: 4/4 tests passed
✅ DBVM Functions: 3/3 tests passed
✅ Utility Commands: 11/11 tests passed
⏭️ Skipped: 1 test (generate_signature)
────────────────────────────────────
Total: 36/37 PASSED (100% success)
```

---

## The Bottom Line

You no longer need to be an expert. Just ask the right questions.

⚠️ EDUCATIONAL DISCLAIMER

This code is for educational and research purposes only. It's created to show the capabilities of the Model Context Protocol (MCP) and LLM-based debugging. I do not condone the use of these tools for malicious hacking, cheating in multiplayer games, or violating Terms of Service. This is a demonstration of software engineering automation.
