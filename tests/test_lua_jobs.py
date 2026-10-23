"""Offline checks of UNIT-25: read_memory formats, read_struct, batch, bridge_status and the async job system.

Runs the real handlers against a fake CE API (memscan, foundlist, timer, memory) inside CE's Lua 5.3.
Usage: python tests/test_lua_jobs.py [path/to/ce_mcp_bridge.lua]
"""
import sys

from lua_harness import run_lua, load, func_end, arg_path, finish, compile_check, BRIDGE_LUA


t = load(arg_path(1, BRIDGE_LUA))

compile_check(t)

prefix = t[:t.index("-- Shared helper: scan for MZ PE headers")]
i, j = func_end(t, "function cmd_read_memory(params)")
read_block = t[t.index("-- Byte-table helpers shared by read_memory"):j]
i, _ = func_end(t, "function cmd_scan_all(params)")
_, j = func_end(t, "function cmd_next_scan(params)")
scan_block = t[t.index("local USER_MODE_MAX"):j]
i, j = func_end(t, "function cmd_get_scan_results(params)")
results_block = t[i:j]
unit = t[t.index("-- >>> BEGIN UNIT-25 Operations"):t.index("-- >>> END UNIT-25 <<<")]

STUBS = r'''
local _unique = 0
setmetatable(_G, { __index = function(g, name)
  if type(name) == "string" and (name:match("^so%u") or name:match("^vt%u") or name:match("^rt%u") or name:match("^fsm%u")) then
    _unique = _unique + 1; rawset(g, name, _unique); return _unique
  end
end })

PROCESS_PID = 1234
function getOpenedProcessID() return PROCESS_PID end
function targetIs64Bit() return true end
function getAddressSafe(s) if type(s) == "number" then return s end return tonumber(s) end
function getCEVersion() return 7.6 end
function dbk_initialized() return false end
function dbvm_initialized() return true end
function debug_isDebugging() return false end
function getSettings() return { Value = {} } end
function cmd_get_process_info() return { success = true, pid = 1234, name = "game.exe", is_64bit = true } end

-- fake memory: MEM[addr] = byte
MEM = {}
function readBytes(addr, size, asTable)
  local t = {}
  for i = 0, size - 1 do
    local b = MEM[addr + i]
    if b == nil then return nil end
    t[#t + 1] = b
  end
  return t
end
function readInteger(addr) return REL and REL[addr] end
function disassemble(addr)
  local t0 = os.clock(); while os.clock() - t0 < (DIS_COST or 0) do end
  return "insn@" .. string.format("%X", addr)
end

SCANS = {}
FAKE_RESULTS = {}
function createMemScan()
  local ms = { destroyed = false, progress = { TotalAddressesToScan = 0, CurrentlyScanned = 0, ResultsFound = 0 } }
  SCANS[#SCANS + 1] = ms
  local function begin(...) ms.args = { ... }; ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 10, ResultsFound = 0 } end
  function ms.firstScan(...) begin(...) end
  function ms.nextScan(...) begin(...) end
  function ms.getProgress() return ms.progress end
  function ms.destroy() ms.destroyed = true end
  function ms.complete(results, fire)
    ms.results = results or FAKE_RESULTS
    ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 100, ResultsFound = #ms.results }
    if fire ~= false and ms.OnScanDone then ms.OnScanDone(ms) end
  end
  function ms.waitTillDone() ms.complete(ms.results, true) end
  return ms
end
function createFoundList(ms)
  local fl = { destroyed = false }
  function fl.initialize() end
  function fl.getCount() return #(ms.results or {}) end
  function fl.getAddress(i) return ms.results[i + 1] end
  function fl.destroy() fl.destroyed = true end
  return fl
end
TIMERS = {}
function createTimer(owner, enabled)
  local tm = { Enabled = enabled or false, Interval = 0 }
  function tm.destroy() tm.destroyed = true end
  TIMERS[#TIMERS + 1] = tm
  return tm
end
'''

TESTS = r'''
local results = {}
local function eq(name, got, want)
  local ok = (got == want)
  results[#results + 1] = (ok and "PASS  " or "FAIL  ") .. name .. (ok and "" or ("  got=" .. tostring(got) .. " want=" .. tostring(want)))
end
local function put(addr, bytes) for i, b in ipairs(bytes) do MEM[addr + i - 1] = b end end
local function lastScan() return SCANS[#SCANS] end

serverState.dispatch = {}

-- ===================== read_memory formats =====================
put(0x1000, { 72, 101, 108, 108, 111 })   -- "Hello"
local r = cmd_read_memory({ address = 0x1000, size = 5 })
eq("read_memory default keeps legacy data+bytes", r.data == "48 65 6C 6C 6F" and #r.bytes == 5, true)
r = cmd_read_memory({ address = 0x1000, size = 5, format = "hex" })
eq("format=hex has data, no bytes", r.data == "48 65 6C 6C 6F" and r.bytes == nil and r.format == "hex", true)
r = cmd_read_memory({ address = 0x1000, size = 5, format = "base64" })
eq("format=base64", r.base64, "SGVsbG8=")
eq("format=base64 has no data/bytes", r.data == nil and r.bytes == nil, true)
r = cmd_read_memory({ address = 0x1000, size = 4, format = "base64" })
eq("base64 padding (4 bytes)", r.base64, "SGVsbA==")
r = cmd_read_memory({ address = 0x1000, size = 3, format = "base64" })
eq("base64 no padding (3 bytes)", r.base64, "SGVs")
r = cmd_read_memory({ address = 0x1000, size = 5, format = "array" })
eq("format=array has bytes only", r.data == nil and #r.bytes == 5, true)
r = cmd_read_memory({ address = 0x1000, size = 5, format = "nope" })
eq("bad format -> INVALID_PARAMS", r.error_code, "INVALID_PARAMS")
r = cmd_read_memory({ address = 0x9999, size = 5 })
eq("unreadable -> failure", r.success, false)
-- big read round-trips through base64 (chunking of table.unpack)
for i = 0, 9999 do MEM[0x20000 + i] = i % 251 end
r = cmd_read_memory({ address = 0x20000, size = 10000, format = "base64" })
eq("10k base64 length", #r.base64, math.ceil(10000 / 3) * 4)

-- ===================== read_struct =====================
local base = 0x5000
put(base + 0,  { 0xEF, 0xBE, 0xAD, 0xDE })                       -- u32 0xDEADBEEF
put(base + 4,  string.byte(string.pack("<f", 1.5), 1, 4) and { string.byte(string.pack("<f", 1.5), 1, 4) })
put(base + 8,  { string.byte(string.pack("<I8", 0x7FF612345678), 1, 8) })   -- ptr
put(base + 16, { 1 })                                             -- bool
put(base + 17, { 104, 105, 0, 0, 0, 0, 0, 0 })                    -- cstring "hi"
put(base + 25, { string.byte(string.pack("<I2I2I2I2", 72, 0xE9, 0x20AC, 0), 1, 8) })  -- wstring "H\xe9\xe2\x82\xac"
put(base + 33, { string.byte(string.pack("<i2", -2), 1, 2) })     -- i16
put(base + 35, { 255, 255, 255, 255, 255, 255, 255, 255 })        -- u64 max
r = cmd_read_struct({ address = base, fields = {
  { name = "id",   type = "dword" },
  { name = "hp",   type = "float" },
  { name = "next", type = "pointer" },
  { name = "alive", type = "bool" },
  { name = "tag",  type = "cstring", size = 8 },
  { name = "wide", type = "wstring", size = 4 },
  { name = "delta", type = "i16" },
  { name = "big",  type = "u64" },
} })
eq("read_struct success", r.success, true)
local f = {}
for _, e in ipairs(r.fields or {}) do f[e.name] = e end
eq("u32 value", f.id.value, 0xDEADBEEF)
eq("u32 hex", f.id.hex, "0xDEADBEEF")
eq("float value", f.hp.value, 1.5)
eq("ptr value (hex string)", f.next.value, "0x7FF612345678")
eq("bool", f.alive.value, true)
eq("cstring stops at NUL", f.tag.value, "hi")
eq("wstring -> UTF-8", f.wide.value, "H\xC3\xA9\xE2\x82\xAC")
eq("i16 negative", f.delta.value, -2)
eq("u64 max -> hex string", f.big.value, "0xFFFFFFFFFFFFFFFF")
eq("auto-advancing offsets", f.next.offset, 8)
eq("span reported", r.span, 43)
r = cmd_read_struct({ address = base, fields = { { name = "x", type = "u32", offset = 0 }, { name = "y", type = "u16", offset = 0x40 } } })
eq("partially unreadable span: readable field still returned", r.fields[1].value, 0xDEADBEEF)
eq("partially unreadable span: bad field flagged", r.fields[2].error ~= nil, true)
r = cmd_read_struct({ address = base, fields = { { name = "x", type = "wat" } } })
eq("unknown type -> INVALID_PARAMS", r.error_code, "INVALID_PARAMS")
r = cmd_read_struct({ address = base, fields = {} })
eq("empty fields -> INVALID_PARAMS", r.error_code, "INVALID_PARAMS")
r = cmd_read_struct({ address = base, fields = { { name = "x", type = "bytes", size = 4, offset = 0 } } })
eq("bytes field", r.fields[1].value, "EF BE AD DE")
PROCESS_PID = 0
r = cmd_read_struct({ address = base, fields = { { type = "u8" } } })
eq("no process -> NO_PROCESS", r.error_code, "NO_PROCESS")
PROCESS_PID = 1234

-- ===================== batch =====================
serverState.dispatch = {
  ok = function(p) return { success = true, v = p.x } end,
  bad = function() return { success = false, error = "nope", error_code = "NOT_FOUND" } end,
  boom = function() error("kaboom") end,
  nilret = function() return nil end,
  batch = cmd_batch,
}
r = cmd_batch({ requests = { { method = "ok", params = { x = 1 } }, { method = "bad" }, { method = "boom" }, { method = "nilret" }, { method = "missing" }, { method = "batch", params = {} } } })
eq("batch executes all", r.executed, 6)
eq("batch ok result", r.results[1].v, 1)
eq("batch counts failures", r.failed, 4)
eq("handler error contained", r.results[3].error_code, "INTERNAL_ERROR")
eq("nil result normalised", r.results[4].success, true)
eq("unknown method", r.results[5].error_code, "NOT_FOUND")
eq("nested batch rejected", r.results[6].error_code, "INVALID_PARAMS")
r = cmd_batch({ requests = { { method = "ok" }, { method = "bad" }, { method = "ok" } }, stop_on_error = true })
eq("stop_on_error stops", r.executed, 2)
eq("empty batch rejected", cmd_batch({ requests = {} }).error_code, "INVALID_PARAMS")
local many = {}
for i = 1, 101 do many[i] = { method = "ok" } end
eq("oversize batch rejected", cmd_batch({ requests = many }).error_code, "INVALID_PARAMS")

-- ===================== jobs: scan_all via OnScanDone =====================
FAKE_RESULTS = { "1000", "2000", "3000" }
r = cmd_start_job({ kind = "bogus" })
eq("unknown job kind", r.error_code, "INVALID_PARAMS")
PROCESS_PID = 0
eq("job needs a process", cmd_start_job({ kind = "scan_all", params = { value = "5" } }).error_code, "NO_PROCESS")
PROCESS_PID = 1234
r = cmd_start_job({ kind = "scan_all", params = { value = "5", type = "dword" } })
eq("scan_all job starts", r.success and r.state == "running", true)
local jid = r.job_id
local ms1 = lastScan()
eq("job scan_all did not block (no waitTillDone result yet)", ms1.results, nil)
eq("scan_job_id claimed", serverState.scan_job_id, jid)
eq("timer pump started", TIMERS[1] and TIMERS[1].Enabled, true)
eq("sync scan_all refused while job runs", cmd_scan_all({ value = "1" }).error_code, "BUSY")
eq("sync next_scan refused", cmd_next_scan({ value = "1" }).error_code, "BUSY")
eq("get_scan_results refused", cmd_get_scan_results({}).error_code, "BUSY")
eq("second scan job refused", cmd_start_job({ kind = "scan_all", params = { value = "1" } }).error_code, "BUSY")
r = cmd_get_job({ job_id = jid })
eq("get_job reports progress", r.state == "running" and r.progress.current == 10 and r.progress.total == 100 and r.progress.percent == 10.0, true)
eq("get_job_result while running -> BUSY", cmd_get_job_result({ job_id = jid }).error_code, "BUSY")
ms1.complete()      -- CE fires OnScanDone
r = cmd_get_job({ job_id = jid })
eq("job done after OnScanDone", r.state, "done")
eq("scan_job_id released", serverState.scan_job_id, nil)
eq("job result count", cmd_get_job_result({ job_id = jid }).count, 3)
eq("scan session installed", serverState.scan_memscan == ms1 and serverState.scan_foundlist ~= nil, true)
local okr, rr = pcall(cmd_get_scan_results, {})
eq("sync results no longer BUSY", (not okr) or rr.error_code ~= "BUSY", true)

-- ===================== jobs: completion by polling (OnScanDone never fires) =====================
r = cmd_start_job({ kind = "next_scan", params = { value = "6" } })
eq("next_scan job starts", r.success, true)
local jid2 = r.job_id
ms1.complete({ "1000" }, false)   -- progress complete, callback lost
r = cmd_get_job({ job_id = jid2 })
eq("poll-based completion (progress complete)", r.state, "done")
eq("next_scan count", cmd_get_job_result({ job_id = jid2 }).count, 1)
eq("shared session survives job", serverState.scan_memscan == ms1 and not ms1.destroyed, true)

-- ===================== jobs: cancel =====================
r = cmd_start_job({ kind = "next_scan", params = { value = "7" } })
local jid3 = r.job_id
r = cmd_cancel_job({ job_id = jid3 })
eq("cancel next_scan", r.state, "cancelled")
eq("cancel next_scan discards session", serverState.scan_memscan == nil and ms1.destroyed, true)
eq("scan_job_id cleared by cancel", serverState.scan_job_id, nil)
eq("note explains discard", r.note ~= nil, true)
eq("get_job shows cancelled", cmd_get_job({ job_id = jid3 }).state, "cancelled")
eq("cancel finished job is a no-op", cmd_cancel_job({ job_id = jid3 }).success, true)
eq("next_scan job without session fails", cmd_start_job({ kind = "next_scan", params = { value = "1" } }).success, false)
eq("failed start leaves no job behind", cmd_get_job({ job_id = "job_999" }).error_code, "NOT_FOUND")

r = cmd_start_job({ kind = "scan_all", params = { value = "5" } })
local jid4 = r.job_id
local msPriv = lastScan()
cmd_cancel_job({ job_id = jid4 })
eq("cancel scan_all destroys private memscan", msPriv.destroyed, true)

-- ===================== jobs: aob_scan =====================
FAKE_RESULTS = { "140001000", "140002000", "140003000", "140004000" }
r = cmd_start_job({ kind = "aob_scan", params = { pattern = "48 8B ?? 05", limit = 2 } })
local jid5 = r.job_id
local msA = lastScan()
eq("aob uses byte-array memscan", msA.args[2] ~= nil and msA.args[4] == "48 8B ?? 05", true)
eq("aob does not claim scan session", serverState.scan_job_id, nil)
msA.complete()
r = cmd_get_job_result({ job_id = jid5 })
eq("aob total_matches", r.total_matches, 4)
eq("aob honours limit", r.returned, 2)
eq("aob address format", r.addresses[1].address, "0x140001000")
eq("aob temp memscan freed", msA.destroyed, true)
eq("aob without pattern", cmd_start_job({ kind = "aob_scan", params = {} }).error_code, "INVALID_PARAMS")

-- ===================== jobs: find_references (time-sliced) =====================
local refs = {}
for i = 1, 60 do refs[i] = string.format("%X", 0x140000000 + i * 16) end
DIS_COST = 0.002
r = cmd_start_job({ kind = "find_references", params = { address = 0x7FF612345678 } })
local jid6 = r.job_id
local msR = lastScan()
eq("find_references pattern is little-endian 8 bytes", msR.args[4], "78 56 34 12 F6 7F 00 00")
msR.complete(refs)
local timer = TIMERS[1]
local ticks = 0
while cmd_get_job({ job_id = jid6 }).state == "running" and ticks < 100 do
  timer.OnTimer(); ticks = ticks + 1
end
DIS_COST = 0
r = cmd_get_job({ job_id = jid6 })
eq("find_references finishes", r.state, "done")
eq("processing was split across several ticks", ticks > 1, true)
r = cmd_get_job_result({ job_id = jid6, offset = 10, limit = 5 })
eq("result total", r.total, 60)
eq("pagination returned", r.returned, 5)
eq("pagination offset", r.references[1].address, string.format("0x%X", 0x140000000 + 11 * 16))
eq("result has target/arch", r.target == "0x7FF612345678" and r.arch == "x64", true)
eq("memscan + foundlist released", msR.destroyed, true)

-- ===================== jobs: find_call_references =====================
local func = 0x140005000
local c1, c2, c3 = 0x140001000, 0x140002000, 0x140003000
REL = { [c1 + 1] = func - (c1 + 5), [c2 + 1] = 0x1234, [c3 + 1] = (func - (c3 + 5)) & 0xFFFFFFFF }
r = cmd_start_job({ kind = "find_call_references", params = { address = func } })
local jid7 = r.job_id
local msC = lastScan()
eq("call scan pattern", msC.args[4], "E8 ?? ?? ?? ??")
msC.complete({ string.format("%X", c1), string.format("%X", c2), string.format("%X", c3) })
for _ = 1, 5 do TIMERS[1].OnTimer() end   -- tick 1 advances scanning->processing, later ticks process
r = cmd_get_job_result({ job_id = jid7 })
eq("callers found (incl. negative rel32 wrap)", r.total, 2)
eq("callers shape", r.callers[1].caller_address, string.format("0x%X", c1))

-- ===================== jobs: limits, listing, cleanup =====================
for i = 1, 4 do cmd_start_job({ kind = "aob_scan", params = { pattern = "90" } }) end
eq("running-job cap", cmd_start_job({ kind = "aob_scan", params = { pattern = "90" } }).error_code, "OUT_OF_RESOURCES")
local listed = cmd_list_jobs({})
eq("list_jobs sorted by creation", listed.jobs[1].job_id, "job_1")
local st = cmd_bridge_status({})
eq("bridge_status success", st.success, true)
eq("bridge_status counts running jobs", st.state.jobs_running, 4)
eq("bridge_status reports process", st.process.attached and st.process.pid, 1234)
eq("bridge_status drivers", st.drivers.dbvm_loaded == true and st.drivers.dbk_loaded == false, true)
eq("bridge_status warns about unreadable qmr setting", st.query_memory_region_routines == "unknown" and #st.warnings >= 1, true)
eq("bridge_status ce_version", st.ce_version, 7.6)

local running = {}
for _, s in ipairs(SCANS) do if not s.destroyed then running[#running + 1] = s end end
local timerBefore = serverState.job_timer
local ok = pcall(cleanupZombieState)
eq("cleanupZombieState tolerates running jobs", ok, true)
eq("cleanup clears jobs", next(serverState.jobs), nil)
eq("cleanup destroys timer", timerBefore.destroyed == true and serverState.job_timer == nil, true)
local allFreed = true
for _, s in ipairs(running) do if not s.destroyed then allFreed = false end end
eq("cleanup destroys every live memscan exactly via job/session", allFreed, true)

-- pruning keeps the job table bounded
serverState.jobs = {}
serverState.job_next_id = 1
for i = 1, 30 do
  local rr = cmd_start_job({ kind = "aob_scan", params = { pattern = "90" } })
  lastScan().complete({})
end
local n = 0
for _ in pairs(serverState.jobs) do n = n + 1 end
eq("finished jobs pruned to 20(+1 newest)", n <= 21, true)

return table.concat(results, "\n")
'''

program = STUBS + "\n" + prefix + "\n" + read_block + "\n" + scan_block + "\n" + results_block + "\n" + 'local BPX = { watchdog = function() return false end }\n' + unit + "\n" + TESTS
ok, msg = run_lua(program, "ops_test")
print(msg)
print("LUA EXEC", "OK" if ok else "ERROR")
finish()
