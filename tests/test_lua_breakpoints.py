"""Offline checks of the breakpoint upgrades (UNIT-27): conditions, max_hits, break-and-inspect with its watchdog,
data-breakpoint validation, and the guarantee that a hit callback can never leave the target halted by accident.

A fake debugger simulates hardware breakpoint hits (FIRE), debug_continueFromBreakpoint, debug_isBroken and queue().
Usage: python tests/test_lua_breakpoints.py [path/to/ce_mcp_bridge.lua]
"""
import sys

from lua_harness import run_lua, load, func_end, arg_path, finish, compile_check, BRIDGE_LUA

t = load(arg_path(1, BRIDGE_LUA))
compile_check(t)

prefix = t[:t.index("-- Shared helper: scan for MZ PE headers")]
region = t[t.index("local function clearGhostBpSlot(addr)"):func_end(t, "function cmd_get_halted_state(params)")[1]]
dbg_i, dbg_j = func_end(t, "local function requireDebugger()")
dbg = t[dbg_i:dbg_j]
i, j = func_end(t, "function cmd_debug_continue(params)")
dbg += t[i:j]

STUBS = r'''
PROCESS_PID = 99
TARGET64 = true
function getOpenedProcessID() return PROCESS_PID end
function targetIs64Bit() return TARGET64 end
function getAddressSafe(s) if type(s) == "number" then return s end return tonumber(s) end
co_run, co_stepinto, co_stepover = 1, 2, 3
bptExecute, bptWrite, bptAccess, bpmDebugRegister = 10, 11, 12, 20

PAGES = {}
function poke(addr, str)
  local pos = 1
  while pos <= #str do
    local idx, off = (addr + pos - 1) // 4096, (addr + pos - 1) % 4096
    local page = PAGES[idx] or string.rep("\0", 4096)
    local n = math.min(4096 - off, #str - pos + 1)
    PAGES[idx] = page:sub(1, off) .. str:sub(pos, pos + n - 1) .. page:sub(off + n + 1)
    pos = pos + n
  end
end
function readBytes(addr, size, asTable)
  local parts, pos = {}, 0
  while pos < size do
    local idx, off = (addr + pos) // 4096, (addr + pos) % 4096
    local page = PAGES[idx]
    if not page then return nil end
    local n = math.min(4096 - off, size - pos)
    parts[#parts + 1] = page:sub(off + 1, off + n)
    pos = pos + n
  end
  local s = table.concat(parts)
  local t = { string.byte(s, 1, #s) }
  if not asTable then return table.unpack(t) end
  return t
end
function readQword(a) local b = readBytes(a, 8, true); if not b then return nil end return (string.unpack("<I8", string.char(table.unpack(b)))) end
function readInteger(a) local b = readBytes(a, 4, true); if not b then return nil end return (string.unpack("<I4", string.char(table.unpack(b)))) end
function disassemble(a) return "insn@" .. string.format("%X", a) end

-- fake debugger ---------------------------------------------------------------
BPS, CONTINUES, REMOVED, QUEUED = {}, {}, {}, {}
BROKEN, SET_FAIL, CONTEXT_RAX = false, false, nil
function debug_setBreakpoint(addr, size, trigger, method, cb)
  if SET_FAIL then error("debugger not attached") end
  BPS[addr] = { size = size, trigger = trigger, cb = cb }
end
function debug_removeBreakpoint(addr) BPS[addr] = nil; REMOVED[#REMOVED + 1] = addr end
function debug_continueFromBreakpoint(m) CONTINUES[#CONTINUES + 1] = m; BROKEN = false end
function debug_isBroken() return BROKEN end
function debug_isDebugging() return true end
function debug_getContext() if CONTEXT_RAX then RAX = CONTEXT_RAX end end
function queue(f) QUEUED[#QUEUED + 1] = f end
function FLUSH() local q = QUEUED; QUEUED = {}; for _, f in ipairs(q) do f() end end
-- simulate a hardware breakpoint hit: returns the callback's return value and how many continues it issued
function FIRE(addr, regs)
  for k, v in pairs(regs or {}) do _G[k] = v end
  BROKEN = true
  local before = #CONTINUES
  local bp = BPS[addr]
  if not bp then error(string.format('no breakpoint armed at 0x%X', addr), 2) end
  local ret = bp.cb()
  -- measured in a real CE: unless the callback returns a non-zero number, CE resumes the thread by itself
  if BROKEN and not (type(ret) == "number" and ret ~= 0) then BROKEN = false end
  return ret, #CONTINUES - before
end
'''

TESTS = r'''
local results = {}
local function eq(name, got, want)
  local ok = (got == want)
  results[#results + 1] = (ok and "PASS  " or "FAIL  ") .. name .. (ok and "" or ("  got=" .. tostring(got) .. " want=" .. tostring(want)))
end
local function reset() cmd_clear_all_breakpoints({}); serverState.breakpoint_hits = {}; BPS = {}; CONTINUES = {}; REMOVED = {}; QUEUED = {}; BROKEN = false end
local function listed(id) for _, b in ipairs(cmd_list_breakpoints({}).breakpoints) do if b.id == id then return b end end end
local function hitsOf(id) return cmd_get_breakpoint_hits({ id = id, clear = false }).hits end
local function wait(sec) local t0 = os.clock(); while os.clock() - t0 < sec do end end

-- ===================== plain log mode keeps working =====================
local r = cmd_set_breakpoint({ address = 0x1000, id = "a" })
eq("set_breakpoint ok", r.success and r.mode == "log" and r.slot == 1 and r.method == "hardware_debug_register" and r.id == "a", true)
local ret, cont = FIRE(0x1000, { RAX = 5, RIP = 0x1000, RSP = 0x7000 })
eq("log mode resumes the thread and returns 1", ret == 1 and cont == 1, true)
eq("hit recorded with registers", hitsOf("a")[1].registers.RAX, "0x00000005")
eq("collision gets a suffix", cmd_set_breakpoint({ address = 0x1100, id = "a" }).id, "a_2")
reset()
PROCESS_PID = 0
eq("no process -> NO_PROCESS", cmd_set_breakpoint({ address = 0x1000 }).error_code, "NO_PROCESS")
PROCESS_PID = 99
eq("bad address", cmd_set_breakpoint({ address = "zzz" }).error_code, "INVALID_ADDRESS")

-- ===================== conditions =====================
cmd_set_breakpoint({ address = 0x2000, id = "c", condition = "RAX == 5" })
ret, cont = FIRE(0x2000, { RAX = 4 })
eq("false condition: no hit, thread still resumed", #hitsOf("c") == 0 and cont == 1 and ret == 1, true)
FIRE(0x2000, { RAX = 5 })
eq("true condition records", #hitsOf("c"), 1)
local b = listed("c")
eq("list shows seen/filtered/total", b.seen_hits == 2 and b.filtered_hits == 1 and b.total_hits == 1 and b.condition == "RAX == 5", true)

poke(0x8008, string.pack("<I4", 0x1234)); poke(0x5000, string.pack("<I8", 0x5000))
cmd_set_breakpoint({ address = 0x3000, id = "m", condition = "u32(RDX + 8) == 0x1234 and ptr(RCX) == 0x5000 and U32 == nil" })
FIRE(0x3000, { RDX = 0x8000, RCX = 0x5000 })
FIRE(0x3000, { RDX = 0x9000, RCX = 0x5000 })           -- unreadable memory: u32 returns nil -> comparison false
eq("memory readers in conditions (nil for unreadable memory)", #hitsOf("m"), 1)
cmd_set_breakpoint({ address = 0x3100, id = "h", condition = "hits() < 2" })
for _ = 1, 4 do FIRE(0x3100, {}) end
eq("hits() counts matched hits", #hitsOf("h"), 2)
cmd_set_breakpoint({ address = 0x3200, id = "lc", condition = "rax == 7" })
FIRE(0x3200, { RAX = 7 })
eq("register names are case-insensitive", #hitsOf("lc"), 1)
reset()                                                  -- only 4 hardware debug registers

local before = #cmd_list_breakpoints({}).breakpoints
r = cmd_set_breakpoint({ address = 0x4000, id = "bad", condition = "RAX ==" })
eq("syntax error -> INVALID_PARAMS", r.error_code == "INVALID_PARAMS" and r.error:find("Invalid condition", 1, true) ~= nil, true)
eq("...and nothing was registered or armed", #cmd_list_breakpoints({}).breakpoints == before and BPS[0x4000] == nil, true)
cmd_set_breakpoint({ address = 0x4100, id = "sb", condition = "os == nil and io == nil and load == nil and _G == nil and require == nil" })
FIRE(0x4100, {})
eq("sandbox: no os/io/load/_G/require inside conditions", #hitsOf("sb"), 1)
cmd_set_breakpoint({ address = 0x4200, id = "esc", condition = "os.execute('echo pwned')" })
FIRE(0x4200, {})
eq("a condition that errors still records the hit, flagged", #hitsOf("esc") == 1 and hitsOf("esc")[1].condition_error ~= nil, true)
cmd_set_breakpoint({ address = 0x4300, id = "loop", condition = "(function() while true do end end)()" })
local t0 = os.clock()
FIRE(0x4300, {})
eq("infinite loop is cut off by the instruction budget", os.clock() - t0 < 5 and hitsOf("loop")[1].condition_error:find("instruction budget", 1, true) ~= nil, true)
for _ = 1, 5 do FIRE(0x4300, {}) end
eq("a condition that keeps failing is switched off", listed("loop").condition_disabled, true)
cmd_set_breakpoint({ address = 0x4400, id = "ok", condition = "RAX == 1" })
eq("long conditions are refused", cmd_set_breakpoint({ address = 0x4500, condition = string.rep("1", 600) }).error_code, "INVALID_PARAMS")
reset()

-- ===================== max_hits =====================
cmd_set_breakpoint({ address = 0x5000, id = "mh", max_hits = 3 })
for _ = 1, 3 do FIRE(0x5000, {}) end
b = listed("mh")
eq("max_hits reached: completed, detach deferred to the main loop", b.state == "completed" and #QUEUED == 1 and BPS[0x5000] ~= nil, true)
ret, cont = FIRE(0x5000, {})
eq("hits after completion are not recorded but the thread runs", #hitsOf("mh") == 3 and cont == 1 and listed("mh").seen_hits == 4, true)
FLUSH()
eq("deferred detach removed the breakpoint and freed the slot", BPS[0x5000] == nil and listed("mh").slot == nil, true)
for i = 1, 4 do eq("slot " .. i .. " free again", cmd_set_breakpoint({ address = 0x5100 + i * 16 }).success, true) end
eq("the 5th breakpoint has no debug register left", cmd_set_breakpoint({ address = 0x5200 }).error_code, "OUT_OF_RESOURCES")
reset()
local savedQueue = queue
queue = nil
cmd_set_breakpoint({ address = 0x5300, id = "nq", max_hits = 1 })
FIRE(0x5300, {})
eq("without queue() the detach is immediate", BPS[0x5300] == nil, true)
queue = savedQueue
eq("max_hits must be positive", cmd_set_breakpoint({ address = 0x5400, max_hits = 0 }).error_code, "INVALID_PARAMS")
reset()

-- ===================== break-and-inspect =====================
poke(0x8010, string.char(0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0))
r = cmd_set_breakpoint({ address = 0x6000, id = "b", mode = "break", halt_timeout_ms = 150, inspect = { { expr = "RDX + 0x10", size = 8 } } })
eq("break mode armed", r.success and r.mode == "break" and r.halt_timeout_ms == 150, true)
ret, cont = FIRE(0x6000, { RAX = 1, RDX = 0x8000, RIP = 0x6000, RSP = 0x7000 })
eq("break mode leaves the thread stopped (non-zero return, no continue)", ret == 1 and cont == 0 and BROKEN == true, true)
eq("halted state recorded with the inspected memory", serverState.halted.id == "b" and serverState.halted.memory[1].hex == "DE AD BE EF 00 00 00 00", true)
eq("list shows the halted state", listed("b").state, "halted")
CONTEXT_RAX = 999
local s = cmd_get_halted_state({})
eq("get_halted_state: halted, fresh registers, instruction", s.halted and s.registers.RAX == "0x000003E7" and s.instruction == "insn@6000", true)
eq("get_halted_state: watchdog countdown + the hit", s.auto_resume_in_seconds > 0 and s.auto_resume_in_seconds <= 0.15 and s.hit ~= nil, true)
eq("get_halted_state: inspected memory", s.memory[1].address, "0x00008010")
ret, cont = FIRE(0x6000, {})
CONTEXT_RAX = nil
eq("a second break hit while halted just resumes", ret == 1 and cont == 1, true)
BROKEN = true
r = cmd_debug_continue({ method = "run" })
eq("debug_continue run resumes and clears the halted state", r.success and serverState.halted == nil and CONTINUES[#CONTINUES] == co_run, true)
s = cmd_get_halted_state({})
eq("afterwards: not halted, last_halt explains", s.halted == false and s.last_halt.reason == "resumed", true)

FIRE(0x6000, { RAX = 2, RDX = 0x8000, RIP = 0x6000, RSP = 0x7000 })
r = cmd_debug_continue({ method = "step_into" })
eq("step_into keeps the thread under bridge control", r.success and serverState.halted ~= nil and serverState.halted.stepping and serverState.halted.steps == 1, true)
s = cmd_get_halted_state({})
eq("while the step is in flight it still reports halted+stepping", s.halted and s.stepping and s.steps == 1, true)
BROKEN = true
s = cmd_get_halted_state({})
eq("after the step landed", s.halted and s.stepping and s.halted_seconds >= 0, true)
cmd_debug_continue({ method = "run" })

FIRE(0x6000, { RAX = 3, RDX = 0x8000 })
BROKEN = false                                           -- the user pressed Run in Cheat Engine
s = cmd_get_halted_state({})
eq("resumed outside the bridge is noticed", s.halted == false and s.note ~= nil and serverState.halted == nil, true)

FIRE(0x6000, { RAX = 4, RDX = 0x8000 })
wait(0.2)
local continuesBefore = #CONTINUES
eq("watchdog reports no halted thread left", BPX.watchdog(), false)
eq("watchdog resumed the thread after the timeout", #CONTINUES == continuesBefore + 1 and serverState.halted == nil and serverState.last_halt.reason == "timeout", true)
eq("auto_resumed is counted", listed("b").auto_resumed, 1)

FIRE(0x6000, { RDX = 0x8000 })
eq("while the deadline is in the future the watchdog stays out of the way", BPX.watchdog() == true and serverState.halted ~= nil, true)
s = cmd_get_halted_state({ extend_ms = 5000 })
eq("extend_ms postpones the watchdog", s.auto_resume_in_seconds > 1, true)
cmd_remove_breakpoint({ id = "b" })
eq("removing the breakpoint resumes a thread halted on it", serverState.halted == nil and serverState.last_halt.reason == "breakpoint removed", true)

cmd_set_breakpoint({ address = 0x6100, id = "b2", mode = "break" })
FIRE(0x6100, {})
cmd_clear_all_breakpoints({})
eq("clear_all resumes a halted thread", serverState.halted == nil and serverState.last_halt.reason == "all breakpoints cleared", true)
cmd_set_breakpoint({ address = 0x6200, id = "b3", mode = "break" })
FIRE(0x6200, {})
continuesBefore = #CONTINUES
cleanupZombieState()
eq("reloading the bridge resumes a halted thread", #CONTINUES == continuesBefore + 1 and serverState.halted == nil, true)
reset()
eq("inspect needs mode break", cmd_set_breakpoint({ address = 0x6300, inspect = { { expr = "RAX" } } }).error_code, "INVALID_PARAMS")
eq("inspect expressions are validated", cmd_set_breakpoint({ address = 0x6300, mode = "break", inspect = { { expr = "RAX +" } } }).error_code, "INVALID_PARAMS")
eq("mode is validated", cmd_set_breakpoint({ address = 0x6300, mode = "pause" }).error_code, "INVALID_PARAMS")
eq("get_halted_state when nothing is halted", cmd_get_halted_state({}).halted, false)

-- ===================== data breakpoints =====================
eq("size must be 1/2/4/8", cmd_set_data_breakpoint({ address = 0x9000, size = 3 }).error_code, "INVALID_PARAMS")
r = cmd_set_data_breakpoint({ address = 0x9001, size = 4 })
eq("alignment is enforced", r.error_code == "INVALID_PARAMS" and r.error:find("aligned", 1, true) ~= nil, true)
eq("access_type is validated", cmd_set_data_breakpoint({ address = 0x9000, access_type = "x" }).error_code, "INVALID_PARAMS")
r = cmd_set_data_breakpoint({ address = 0x9008, size = 8, access_type = "w" })
eq("8-byte aligned write watch", r.success and r.size == 8 and BPS[0x9008].trigger == bptWrite and BPS[0x9008].size == 8, true)
r = cmd_set_data_breakpoint({ address = 0x9010, size = 2, access_type = "rw" })
eq("rw uses the access trigger", BPS[0x9010].trigger, bptAccess)
reset()

poke(0x9100, string.pack("<I4", 5))
cmd_set_data_breakpoint({ address = 0x9100, id = "d", size = 4, access_type = "w" })
poke(0x9100, string.pack("<I4", 6))
FIRE(0x9100, { RIP = 0x7777 })
local h = hitsOf("d")[1]
eq("data hit: value, previous value, changed flag, size", h.value == 6 and h.previous_value == 5 and h.value_changed == true and h.size == 4, true)
FIRE(0x9100, { RIP = 0x7777 })
eq("same-value write: value_changed false", hitsOf("d")[2].value_changed, false)
eq("data hit has the instruction", h.instruction, "insn@7777")

poke(0x9200, string.pack("<I4", 1))
r = cmd_set_data_breakpoint({ address = 0x9200, id = "dr", size = 4, access_type = "r" })
eq("read watch explains its limits", r.note ~= nil and BPS[0x9200].trigger == bptAccess, true)
FIRE(0x9200, {})
poke(0x9200, string.pack("<I4", 2))
FIRE(0x9200, {})                                          -- the value changed: that was a write
FIRE(0x9200, {})
eq("read watch drops hits where the value changed", #hitsOf("dr") == 2 and listed("dr").filtered_hits == 1, true)

poke(0x9300, string.char(0xAB))
cmd_set_data_breakpoint({ address = 0x9300, id = "d1", size = 1, access_type = "w" })
FIRE(0x9300, {})
eq("1-byte watch reads 1 byte", hitsOf("d1")[1].value, 0xAB)
reset()

-- ===================== failures roll back =====================
SET_FAIL = true
r = cmd_set_breakpoint({ address = 0xA000, id = "f" })
SET_FAIL = false
eq("debug_setBreakpoint failure is reported", r.success == false and r.error_code == "INTERNAL_ERROR" and r.error:find("debugger not attached", 1, true) ~= nil, true)
eq("...and leaves no state behind", listed("f") == nil and serverState.hw_bp_slots[1] == nil and serverState.breakpoint_hits["f"] == nil, true)
eq("the slot is usable afterwards", cmd_set_breakpoint({ address = 0xA000, id = "f" }).slot, 1)

-- a hit callback that throws must still resume the target
local cb = safeBpCallback(function() error("boom") end)
local before2 = #CONTINUES
eq("throwing callback body still resumes", cb() == 1 and #CONTINUES == before2 + 1, true)

return table.concat(results, "\n")
'''

program = STUBS + "\n" + prefix + "\n" + region + "\n" + dbg + "\n" + TESTS
ok, msg = run_lua(program, "bp_test")
print(msg)
print("LUA EXEC", "OK" if ok else "ERROR")
finish()
