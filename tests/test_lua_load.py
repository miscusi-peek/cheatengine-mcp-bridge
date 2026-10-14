"""Offline checks that run the WHOLE bridge file (not extracted pieces) inside a fake Cheat Engine.

The other Lua suites extract functions from ce_mcp_bridge.lua and run them in isolation. That cannot see problems that
only exist when the file runs as one chunk: a later `local function` shadowing an earlier one (every UNIT-25..28 tool
once answered `true` in a real CE because of that), top-level code that fails at load time, or what happens when the
script is executed a second time (File -> Execute Script / dofile again).

What this does
  * reload:   executes the file twice in one Lua state; the second execution must shut the first instance down
              (it used to leave both worker threads serving the pipe).
  * dispatch: executes it once with createThread running the REAL PipeWorker against a fake pipe that feeds one request
              per registered method (params {}), with a process attached and again with none. Every reply must be a
              proper JSON-RPC reply whose result is an object (never a bare `true`), and the tools of UNITs 25-28 must
              neither crash on empty params nor ignore a missing process.

Usage: python tests/test_lua_load.py [path/to/ce_mcp_bridge.lua]
"""
import json
import re

from lua_harness import run_lua, load, arg_path, finish, compile_check, BRIDGE_LUA

path = arg_path(1, BRIDGE_LUA)
src = load(path)
compile_check(src)

# method names from the dispatcher table
block = src[src.index("local commandHandlers = {"):src.index("serverState.dispatch = commandHandlers")]
methods = sorted(set(re.findall(r"^\s+([A-Za-z0-9_]+)\s*=\s*cmd_[A-Za-z0-9_]+", block, re.M)))
print("registered methods:", len(methods))

# never fed to the real handlers even with empty params: anything that touches files, processes or the machine
SKIP = {"run_command", "shell_execute", "delete_file", "write_region_to_file", "create_process", "inject_dll", "inject_dotnet_dll",
        "execute_code", "execute_code_ex", "execute_code_local", "execute_code_local_ex", "evaluate_lua", "load_table", "save_table",
        "speak_text", "play_sound", "beep", "show_message", "input_query", "show_selection_list", "set_mouse_pos", "do_key_press",
        "key_down", "key_up", "send_window_message", "write_clipboard", "pause_process", "unpause_process", "debug_process"}
# the tools added by the UNIT-25..28 work: they must degrade to a clean error on empty params, never crash
OWN = {"bridge_status", "read_struct", "batch", "start_job", "get_job", "get_job_result", "cancel_job", "list_jobs", "pe_info", "pe_imports",
       "pe_exports", "pe_tls_callbacks", "va_to_rva", "rva_to_va", "rebase_address", "export_names", "export_structures", "import_names",
       "snapshot_region", "list_snapshots", "delete_snapshot", "diff_snapshots", "pe_functions", "recover_struct", "get_halted_state",
       "set_breakpoint", "set_data_breakpoint", "remove_breakpoint", "list_breakpoints", "get_breakpoint_hits", "clear_all_breakpoints"}
# of those, the ones that need an attached process and must say so
NEEDS_PROCESS = {"read_struct", "pe_info", "pe_imports", "pe_exports", "pe_tls_callbacks", "pe_functions", "recover_struct", "snapshot_region",
                 "set_breakpoint", "set_data_breakpoint"}

FAKE = r'''
local _unique = 0
setmetatable(_G, { __index = function(g, name)          -- CE constants (vtByte, soExactValue, co_run, ...) get distinct values
  if type(name) == "string" and (name:match("^vt%%u") or name:match("^so%%u") or name:match("^rt%%u") or name:match("^fsm%%u") or name:match("^co_")) then
    _unique = _unique + 1; rawset(g, name, _unique); return _unique
  end
end })
PID = %(pid)d
local queue = {}
RESPONSES = {}
THREADS = {}
RUN_THREADS = %(run)s
function getOpenedProcessID() return PID end
function targetIs64Bit() return true end
function sleep() end
function getCEVersion() return 7.6 end
function readBytes() return nil end
function readPointer() return nil end
function readInteger() return nil end
function dbk_initialized() return false end
function dbvm_initialized() return false end
function debug_isDebugging() return false end
function enumModules() return {} end
function getSettings() return { Value = {} } end
function createTimer() return { Enabled = false, Interval = 0, destroy = function() end } end
function getAddressSafe(s) if type(s) == "number" then return s end return tonumber(s) end

local current
function createThread(fn)
  local th = { Terminated = false }
  function th.terminate() th.Terminated = true end
  function th.synchronize(f) return f() end
  THREADS[#THREADS + 1] = th
  if RUN_THREADS then current = th; fn(th) end
  return th
end
function createPipe()
  local pipe = { Connected = false }
  local payload
  function pipe.acceptConnection()
    if #queue == 0 then current.Terminated = true else pipe.Connected = true end
  end
  function pipe.readBytes(n)
    if #queue == 0 then pipe.Connected = false; return nil end
    payload = table.remove(queue, 1)
    local len = #payload
    return { len %% 256, (len // 256) %% 256, (len // 65536) %% 256, (len // 16777216) %% 256 }
  end
  function pipe.readString(n) return payload end
  function pipe.writeBytes() end
  function pipe.writeString(s) RESPONSES[#RESPONSES + 1] = s end
  function pipe.destroy() pipe.Connected = false end
  return pipe
end
function FEED(method, params) queue[#queue + 1] = '{"jsonrpc":"2.0","method":"' .. method .. '","params":' .. params .. ',"id":"' .. method .. '"}' end
'''

BRIDGE = "local bridge_chunk, load_err = load(BRIDGE_SOURCE, '=bridge')\nassert(bridge_chunk, load_err)\n"


def lua_long(s):
    level = 0
    while ("]" + "=" * level + "]") in s:
        level += 1
    return "[" + "=" * level + "[" + s + "]" + "=" * level + "]"


# ---------------------------------------------------------------- reload
prog = FAKE % {"pid": 4242, "run": "false"} + "\nBRIDGE_SOURCE = " + lua_long(src) + "\n" + BRIDGE + r'''
local out = {}
bridge_chunk()
out[#out + 1] = "threads after first execution: " .. #THREADS
local stop1 = StopMCPBridge
bridge_chunk()
out[#out + 1] = "threads after second execution: " .. #THREADS
out[#out + 1] = "first terminated: " .. tostring(THREADS[1].Terminated)
out[#out + 1] = "second terminated: " .. tostring(THREADS[2].Terminated)
out[#out + 1] = "stop function replaced: " .. tostring(StopMCPBridge ~= stop1)
bridge_chunk()
out[#out + 1] = "third: first=" .. tostring(THREADS[1].Terminated) .. " second=" .. tostring(THREADS[2].Terminated) .. " third=" .. tostring(THREADS[3].Terminated)
StopMCPBridge()
out[#out + 1] = "after StopMCPBridge: third=" .. tostring(THREADS[3].Terminated)
return table.concat(out, "\n")
'''
ok, msg = run_lua(prog, "reload")
print("-- reload"); print(msg)
lines = {l.split(": ", 1)[0]: l.split(": ", 1)[1] for l in msg.splitlines() if ": " in l}
print(("PASS  " if ok else "FAIL  ") + "the whole bridge file executes (twice) in a fake CE without errors")
print(("PASS  " if lines.get("threads after first execution") == "1" else "FAIL  ") + "one worker thread per execution (first)")
print(("PASS  " if lines.get("threads after second execution") == "2" else "FAIL  ") + "one worker thread per execution (second)")
print(("PASS  " if lines.get("first terminated") == "true" else "FAIL  ") + "executing the script again shuts the previous instance down")
print(("PASS  " if lines.get("second terminated") == "false" else "FAIL  ") + "the new instance keeps running")
print(("PASS  " if lines.get("stop function replaced") == "true" else "FAIL  ") + "the global StopMCPBridge now belongs to the new instance")
print(("PASS  " if "first=true second=true third=false" in msg else "FAIL  ") + "a third execution stops the second, and only that one is left running")
print(("PASS  " if lines.get("after StopMCPBridge") == "third=true" else "FAIL  ") + "StopMCPBridge stops the current instance")


# ---------------------------------------------------------------- dispatch
def dispatch(pid, names):
    feed = "\n".join("FEED(%s, '{}')" % json.dumps(n) for n in names)
    code = FAKE % {"pid": pid, "run": "true"} + "\nBRIDGE_SOURCE = " + lua_long(src) + "\n" + BRIDGE + feed + "\nbridge_chunk()\nreturn table.concat(RESPONSES, '\\n')\n"
    ok, text = run_lua(code, "dispatch-%d" % pid, ascii_only=False)
    replies = {}
    if ok:
        for line in text.split("\n"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            replies[r.get("id")] = r
    return ok, replies, text


names = [n for n in methods if n not in SKIP]
ok, with_proc, text = dispatch(4242, names)
print("-- dispatch with a process attached (%d methods)" % len(names))
print(("PASS  " if ok else "FAIL  ") + "the real PipeWorker/executeCommand path handles every request" + ("" if ok else "  " + text[:300]))
print(("PASS  " if len(with_proc) == len(names) else "FAIL  ") + "every request got a reply (%d of %d)" % (len(with_proc), len(names)))
nonobj = {n: r.get("result") for n, r in with_proc.items() if "result" in r and not isinstance(r["result"], dict)}
print(("PASS  " if not nonobj else "FAIL  ") + "every result is a JSON object (never a bare true/number)%s" % ("" if not nonobj else "  " + str(dict(list(nonobj.items())[:5]))))
crash = sorted(n for n in OWN if n in with_proc and with_proc[n].get("error", {}).get("code") == -32603)
print(("PASS  " if not crash else "FAIL  ") + "UNIT-25..28 tools answer empty params with a clean error, not an internal error%s" % ("" if not crash else "  " + str(crash)))
missing = sorted(n for n in OWN if n in methods and n not in with_proc)
print(("PASS  " if not missing else "FAIL  ") + "all UNIT-25..28 tools are registered and answered%s" % ("" if not missing else "  " + str(missing)))
other_crash = sorted(n for n, r in with_proc.items() if n not in OWN and r.get("error", {}).get("code") == -32603)
print("      older handlers that raise instead of rejecting empty params (informational): %d %s" % (len(other_crash), other_crash))
for n in ("read_struct", "pe_info"):
    r = with_proc.get(n, {}).get("result", {})
    print(("PASS  " if r.get("success") is False and r.get("error_code") in ("INVALID_PARAMS", "INVALID_ADDRESS", "NO_PROCESS") else "FAIL  ") + "%s with a process but no parameters is a proper error reply: %s" % (n, str(r)[:120]))

ok, no_proc, text = dispatch(0, sorted(NEEDS_PROCESS))
print("-- dispatch without a process")
for n in sorted(NEEDS_PROCESS):
    r = no_proc.get(n, {}).get("result", {})
    print(("PASS  " if isinstance(r, dict) and r.get("error_code") == "NO_PROCESS" else "FAIL  ") + "%s without a process: NO_PROCESS%s" % (n, "" if isinstance(r, dict) and r.get("error_code") == "NO_PROCESS" else "  " + str(r)[:120]))

finish()
