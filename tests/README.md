# Offline test suites

These tests need **no Cheat Engine process**. They run the real bridge code against a fake CE API, so they are
fast (about 30 s in total) and safe to run on every change. The live end-to-end script is still
[`MCP_Server/test_mcp.py`](../MCP_Server/test_mcp.py) (needs CE running, the bridge loaded and a process attached).

```bash
python tests/run_all.py              # all suites
python tests/run_all.py -v           # + full output of each suite
python tests/run_all.py --real       # + validate PE/RTTI parsing against real system DLLs
python tests/run_all.py --mutation   # + check the suites catch deliberate breakages
python tests/test_lua_jobs.py        # a single suite (exit code 0 = all passed)
```

## Requirements
- Windows, `pip install -r MCP_Server/requirements.txt` (`mcp`, `pywin32`).
- Cheat Engine's `lua53-64.dll` (found in the usual install folders, or set `CE_LUA_DLL`). The bridge is written for
  CE's Lua 5.3, so the tests deliberately use that exact runtime. Without it the Lua suites are *skipped*, not failed
  (`run_all.py --strict` turns skips into failures).

## Suites
| File | What it covers |
|------|----------------|
| `test_lua_robustness.py` | JSON codec (`\u` escapes, int64 numbers, invalid UTF-8), `executeCommand` never throwing, breakpoint-hit recording and the callback that must always resume the target |
| `test_lua_jobs.py` | `read_memory` formats, `read_struct`, `batch`, `bridge_status`, and the async job system (scan jobs, poll fallback, cancel, caps, cleanup) |
| `test_lua_analysis.py` | PE imports/exports/TLS, RVA/IDA translation, RTTI, string refs, code caves, pointer paths, snapshots, `export_names`/`import_names`/`export_structures`, on synthetic x64 **and** x86 images |
| `test_lua_xrefs.py` | `find_xrefs`: calls/jumps (rel32, rel8, across chunk borders), rip-relative operands and their read/write classification, absolute pointers, RVAs and the `.pdata` exclusion, ranges, module selection, limits, on synthetic x64 and x86 images with a fake instruction decoder |
| `test_lua_pathsets.py` | UNIT-30: `find_pointer_path(save_as=)`, `compare_pointer_paths` across simulated restarts (memory wiped, modules moved, pid changed): survivors and run counts, narrowing, near misses and their corrected offsets, same-process flag, null pointers / missing modules, inline chains (normalisation, duplicates, bad input), paging, the 16-set and 20-entry bounds, x86 wrap-around |
| `test_lua_patches.py` | UNIT-31 patch journal: every write tool recorded with the exact bytes it replaced (sizes per type, wide strings, copy destinations, auto_assemble scripts), failed writes not recorded, undo / conflicts / force / verify, stacked patches unwound newest first, other-process and unreadable/oversized entries, batch, bounds |
| (state files) | `test_lua_pathsets.py` and `test_lua_patches.py` also run several bridge instances one after another on a temporary state folder: sets and journal come back after a reload, damaged/edited files, the `.tmp` fallback, `off`, an unwritable folder, pid reuse, compaction. The fake CE defaults to `CE_MCP_STATE_DIR=off`, so no suite writes to your real state folder |
| `test_lua_load.py` | The WHOLE bridge file executed in a fake CE (not extracted pieces): executing it twice must stop the first instance, and the real pipe worker/dispatcher answers every registered method with a proper reply (never a bare `true`; process-less calls say `NO_PROCESS`). Catches what piecewise tests cannot: helpers shadowing each other, load-time errors, reload behaviour |
| `test_client_retry.py` | The Python client against a fake bridge on a real named pipe: no double execution of state-changing commands, reconnect backoff, timeouts that must not hang, bad UTF-8, RPC errors |
| `test_client_jobs.py` | UNIT-25 MCP tools: parameter forwarding, `wait_for_job`, `batch_commands` retry policy |
| `test_policy.py` | Capability profiles and tool groups: every tool and Lua dispatcher entry is classified, profile tiers nest, allow/deny, nothing smuggled through `batch` or `start_job`, and the real server module in subprocesses with different `CE_MCP_*` environments (only denied calls are sent, so a live bridge is never reached) |
| `test_client_analysis.py` | UNIT-26 MCP tools: parameter cleaning, job wrappers (`wait_seconds` / `timed_out`), tool registration and schemas |

`test_lua_analysis.py --real` goes further than the synthetic images: it parses `user32.dll` and `msvcp140.dll` as
loaded in the test process and cross-checks them with Windows itself: every export against `GetProcAddress`, every
resolved import against `GetProcAddress` of the imported function, section flags against `VirtualQuery`, and the RTTI
scan against the known `std::` exception classes. (Some `user32` exports are redirected by Windows' app-compat shims;
those are skipped because `GetProcAddress` no longer returns the module's own export.)

`test_lua_xrefs.py --real` checks `find_xrefs` against an independent oracle (`pip install capstone`): capstone
linear-sweeps the code of `msvcp140.dll` and `user32.dll` function by function and lists every direct branch and
rip-relative operand with the address it reaches. The bridge job then runs on the same bytes (capstone also answers
its `disassemble` / `getInstructionSize` calls, as CE's disassembler would, through `run_lua(callbacks=...)`) for the
most-referenced and some rarely-referenced targets plus one 64-byte range, and the two sets of instruction addresses
must be identical. Without capstone this part is skipped.

Shared fake CE API for the suites that run synthetic PE images: `fake_ce.py` (`STUBS`, `HELPERS`).

## Live smoke test (needs a running Cheat Engine)
`python tests/live_smoke.py [--only SECTION] [-v]` checks the things only a real CE can confirm. It spawns its own
throwaway target (`live_target.py`), attaches CE to it, runs about 60 checks through the real MCP tool layer and
re-attaches whatever CE had open before. Sections: connection, attach, memory, scan jobs, pe analysis (incl. RTTI and
`recover_struct` on a real `msvcp140.dll`), xrefs (hits verified by reading the bytes back from the live process),
snapshots, breakpoints (max_hits, conditions, data breakpoints, break mode: the target's counter must really stand still,
the watchdog and `clear_all_breakpoints` must resume it) and bridge health. It exits with code 77 (skipped) when the pipe
does not exist. It is not part of `run_all.py`.

What it found when first run (all fixed, each now covered offline as well):
- every UNIT-25..28 tool answered `true` in CE: three different `requireProcess` helpers had shadowed each other
  (`test_lua_robustness.py` lint + `test_lua_load.py`);
- re-executing the script left the old bridge instance serving the pipe next to the new one (`test_lua_load.py`);
- break mode did not stop the thread: a breakpoint callback must return a NON-ZERO number to leave the thread stopped
  (`nil`, `false`, `true`, `0` all make CE resume it) - the fake debugger now models this.

CE quirks worth knowing: `debug_isBroken()` returns a function value instead of a boolean in CE 7.6 (the bridge never
trusts it), and the debugger interface for the first breakpoint comes from CE's own settings - the VEH debugger (2)
crashed the throwaway Python target, so the smoke test starts interface 1 (`debug_process(1)`) explicitly.

## Mutation check
`mutation_check.py` applies one small plausible bug at a time to a copy of `ce_mcp_bridge.lua` and requires the
matching suite to fail. It exists because "all tests pass" says nothing if the tests cannot fail. If you change the
bridge code and an anchor disappears the mutant is reported `STALE`; update its text in `mutation_check.py`.
One mutant is a documented survivor (a defensive x86 sanity check that cannot change any observable result).

## Writing tests
- Suites print lines starting with `PASS` / `FAIL`; `testkit` counts them and `finish()` turns the totals into the
  exit code (a run with zero passes, any `FAIL`, or any `LUA ERROR` / `COMPILE FAIL` line is a failure).
- Lua suites extract the real functions from `ce_mcp_bridge.lua` (see `lua_harness.func_end` / `between`) and run
  them in a fresh state with fake CE globals (`createMemScan`, `readBytes`, `enumModules`, ...). When you add a
  command, extend the matching suite *and* add a mutant for its most important branch.
- A passing fake-CE test proves the bridge logic, not that CE behaves as the fake does. Behaviour that depends on
  the real CE API (memscan events, hardware breakpoints, DBVM) still needs `MCP_Server/test_mcp.py` or manual checks.
