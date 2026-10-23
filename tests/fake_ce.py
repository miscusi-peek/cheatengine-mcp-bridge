"""Fake Cheat Engine API shared by the offline Lua suites that run synthetic PE images.

STUBS   - Lua: process/module/memory stubs (page-granular memory via PAGE()/poke()), fake memscan, timers, structures.
HELPERS - Lua: PASS/FAIL recording (eq) and runJob(kind, params), which drives a job to completion through the pump.
"""

STUBS = r'''
local _unique = 0
setmetatable(_G, { __index = function(g, name)
  if type(name) == "string" and (name:match("^so%u") or name:match("^vt%u") or name:match("^rt%u") or name:match("^fsm%u")) then
    _unique = _unique + 1; rawset(g, name, _unique); return _unique
  end
end })

CE_MCP_STATE_DIR = CE_MCP_STATE_DIR or "off"    -- no state files unless a test asks for them (UNIT-30/31 persistence)
PROCESS_PID = 4242
TARGET64 = true
function getOpenedProcessID() return PROCESS_PID end
function targetIs64Bit() return TARGET64 end
MODULES = {}
function enumModules() return MODULES end
function getAddressSafe(s)
  if type(s) == "number" then return s end
  if type(s) ~= "string" then return nil end
  local n = tonumber(s); if n then return math.tointeger(n) or n end
  local function modbase(nm) for _, m in ipairs(MODULES) do if m.Name:lower() == nm:lower() then return m.Address end end end
  local name, off = s:match("^([%w_%.%-]+)%+(.+)$")
  if name then
    local b = modbase(name); local o = tonumber(off) or tonumber("0x" .. off)
    if b and o then return b + o end
  end
  return modbase(s)
end
function getCEVersion() return 7.6 end
function dbk_initialized() return false end
function dbvm_initialized() return false end
function debug_isDebugging() return false end
function getSettings() return { Value = {} } end

-- page-granular fake memory
PAGES = {}
function PAGE(addr, hex)
  PAGES[addr // 4096] = (hex:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
end
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
  local parts = {}
  local pos = 0
  while pos < size do
    local idx, off = (addr + pos) // 4096, (addr + pos) % 4096
    local page = PAGES[idx]
    if not page then return nil end
    local n = math.min(4096 - off, size - pos)
    parts[#parts + 1] = page:sub(off + 1, off + n)
    pos = pos + n
  end
  local s = table.concat(parts)
  local t = {}
  for i = 1, #s, 4096 do
    local chunk = { string.byte(s, i, math.min(i + 4095, #s)) }
    for k = 1, #chunk do t[#t + 1] = chunk[k] end
  end
  if not asTable then return table.unpack(t) end
  return t
end
function readPointer(addr)
  local b = readBytes(addr, TARGET64 and 8 or 4, true)
  if not b then return nil end
  local s = string.char(table.unpack(b))
  return (string.unpack(TARGET64 and "<I8" or "<I4", s))
end
function readInteger(addr)
  local b = readBytes(addr, 4, true); if not b then return nil end
  return (string.unpack("<I4", string.char(table.unpack(b))))
end
function disassemble(addr) return "insn@" .. string.format("%X", addr) end
function getInstructionSize(addr) local b = readBytes(addr, 1, false); return b == 0xE8 and 5 or 1 end

-- fake memscan / foundlist / timer
SCANS = {}
PTR_MODEL = nil
function createMemScan()
  local ms = { destroyed = false, progress = { TotalAddressesToScan = 0, CurrentlyScanned = 0, ResultsFound = 0 } }
  SCANS[#SCANS + 1] = ms
  function ms.firstScan(...)
    ms.args = { ... }
    ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 10, ResultsFound = 0 }
    if PTR_MODEL and ms.args[1] == soValueBetween then
      local lo, hi = tonumber(ms.args[4]), tonumber(ms.args[5])
      local res = {}
      for loc, val in pairs(PTR_MODEL) do if val >= lo and val <= hi then res[#res + 1] = string.format("%X", loc) end end
      table.sort(res)
      ms.planned = res
    end
  end
  function ms.getProgress() return ms.progress end
  function ms.destroy() ms.destroyed = true end
  function ms.complete(results)
    ms.results = results or {}
    ms.completed = true
    ms.progress = { TotalAddressesToScan = 100, CurrentlyScanned = 100, ResultsFound = #ms.results }
    if ms.OnScanDone then ms.OnScanDone(ms) end
  end
  function ms.waitTillDone() ms.complete(ms.results) end
  return ms
end
function createFoundList(ms)
  local fl = {}
  function fl.initialize() end
  function fl.getCount() return #(ms.results or {}) end
  function fl.getAddress(i) return ms.results[i + 1] end
  function fl.destroy() end
  return fl
end
function createTimer() local tm = { Enabled = false, Interval = 0 }; function tm.destroy() end; return tm end

SYMS = {}
function enumRegisteredSymbols() return SYMS end
REGISTERED = {}
function registerSymbol(name, addr, dns) REGISTERED[name] = addr end

CREATED = {}
function createStructure(name)
  local st = { Name = name, elements = {}, Count = 0 }
  function st.addToGlobalStructureList() end
  function st.addElement() local el = {}; st.elements[#st.elements + 1] = el; st.Count = #st.elements; return el end
  CREATED[#CREATED + 1] = st
  return st
end

STRUCTS = {}
function getStructureCount() return #STRUCTS end
function getStructure(i) return STRUCTS[i + 1] end
'''

HELPERS = r'''
local results = {}
local function eq(name, got, want)
  local ok = (got == want)
  results[#results + 1] = (ok and "PASS  " or "FAIL  ") .. name .. (ok and "" or ("  got=" .. tostring(got) .. " want=" .. tostring(want)))
end
local function completePending()
  for _, ms in ipairs(SCANS) do
    if not ms.completed and not ms.destroyed and ms.planned then ms.complete(ms.planned) end
  end
end
local function runJob(kind, params)
  local r = cmd_start_job({ kind = kind, params = params })
  if not r.success then return r end
  local id = r.job_id
  for _ = 1, 20000 do
    local st = cmd_get_job({ job_id = id })
    if st.state ~= "running" then
      if st.state == "done" then
        local res = cmd_get_job_result({ job_id = id, limit = 1000 })
        res.job = st
        return res
      end
      return st
    end
    completePending()
    if serverState.job_timer then serverState.job_timer.OnTimer() end
  end
  return { success = false, error = "job did not finish" }
end
local function hexes(list, key) local o = {} for i, v in ipairs(list) do o[i] = v[key] end return o end
local function join(t) return table.concat(t, ",") end
'''
