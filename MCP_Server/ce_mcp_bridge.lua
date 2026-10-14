-- ============================================================================
-- CHEATENGINE MCP BRIDGE v12.0.0
-- ============================================================================

-- Reload safety. serverState (and everything else below) is local to one execution of this script, and the global
-- StopMCPBridge captures it. If this execution only called its own StopMCPBridge it would stop nothing: the worker
-- thread of the PREVIOUS execution would keep serving the same pipe next to the new one, and each client connection
-- would randomly reach either. At this point the global still holds the previous execution's StopMCPBridge, so ask it
-- to shut its instance down before this chunk redefines anything.
if type(StopMCPBridge) == "function" then
    local okPrev, errPrev = pcall(StopMCPBridge)
    if not okPrev then print("[MCP] could not stop the previous bridge instance: " .. tostring(errPrev)) end
end

local PIPE_NAME = "CE_MCP_Bridge_v99"
local VERSION = "12.0.0"

-- Global State
local serverState = {
    running = false,
    timer = nil,
    pipe = nil,
    connected = false,
    scan_memscan = nil,
    scan_foundlist = nil,
    scan_is_unknown_first = false,   -- last scan_all was an "unknown initial value" first scan
    breakpoints = {},
    breakpoint_hits = {},
    hw_bp_slots = {},      -- Hardware breakpoint slots (max 4)
    active_watches = {},   -- DBVM watch IDs for hypervisor-level tracing
    started_at = os.time(),
    stats = { requests = 0, errors = 0 },   -- updated by executeCommand, reported by bridge_status
    jobs = {},             -- async jobs (UNIT-25)
    job_next_id = 1
}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

local function toHex(num)
    if not num then return "nil" end
    if num >= 0 and num <= 0xFFFFFFFF then
        return string.format("0x%08X", num)
    else
        return string.format("0x%X", num)
    end
end

local function toHexLow32(num)
    if not num then return nil end
    return num & 0xFFFFFFFF
end

local function log(msg)
    print("[MCP v" .. VERSION .. "] " .. msg)
end

-- Universal 32/64-bit architecture helper
-- Returns pointer size, whether target is 64-bit, and current stack/instruction pointers
local function getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
        is64bit = is64,
        ptrSize = ptrSize,
        stackPtr = stackPtr,
        instPtr = instPtr
    }
end

-- Universal register capture - works for both 32-bit and 64-bit targets
local function captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and toHex(RAX) or nil,
            RBX = RBX and toHex(RBX) or nil,
            RCX = RCX and toHex(RCX) or nil,
            RDX = RDX and toHex(RDX) or nil,
            RSI = RSI and toHex(RSI) or nil,
            RDI = RDI and toHex(RDI) or nil,
            RBP = RBP and toHex(RBP) or nil,
            RSP = RSP and toHex(RSP) or nil,
            RIP = RIP and toHex(RIP) or nil,
            R8 = R8 and toHex(R8) or nil,
            R9 = R9 and toHex(R9) or nil,
            R10 = R10 and toHex(R10) or nil,
            R11 = R11 and toHex(R11) or nil,
            R12 = R12 and toHex(R12) or nil,
            R13 = R13 and toHex(R13) or nil,
            R14 = R14 and toHex(R14) or nil,
            R15 = R15 and toHex(R15) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x64"
        }
    else
        return {
            EAX = EAX and toHex(EAX) or nil,
            EBX = EBX and toHex(EBX) or nil,
            ECX = ECX and toHex(ECX) or nil,
            EDX = EDX and toHex(EDX) or nil,
            ESI = ESI and toHex(ESI) or nil,
            EDI = EDI and toHex(EDI) or nil,
            EBP = EBP and toHex(EBP) or nil,
            ESP = ESP and toHex(ESP) or nil,
            EIP = EIP and toHex(EIP) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x86"
        }
    end
end

-- Universal stack capture - reads stack with correct pointer size
local function captureStack(depth)
    local arch = getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    if not stackPtr then return stack end
    
    for i = 0, depth - 1 do
        local val
        if arch.is64bit then
            val = readQword(stackPtr + i * arch.ptrSize)
        else
            val = readInteger(stackPtr + i * arch.ptrSize)
        end
        if val then stack[i] = toHex(val) end
    end
    return stack
end

-- Pagination helper: parse offset/limit params and slice a table.
-- Returns: limit, offset, page_table, total
-- Usage: local limit, offset, page, total = paginate(params, allItems, 100)
local function paginate(params, items, defaultLimit)
    local limit = math.max(1, math.min(params.limit or params.max or defaultLimit or 100, 10000))
    local offset = math.max(0, params.offset or 0)
    local total = #items
    local page = {}
    for i = offset + 1, math.min(offset + limit, total) do
        page[#page + 1] = items[i]
    end
    return limit, offset, page, total
end

-- Map a human-readable scan_option to a CE scan constant.
-- Returns nil for unrecognized options so callers can report INVALID_PARAMS instead of silently falling back to an exact scan.
-- Global (not local) so handlers defined earlier in the chunk can call it and so it doesn't consume one of Lua's 200 local slots.
function resolveScanOption(opt)
    local o = tostring(opt or "exact"):lower()
    if o == "exact"             then return soExactValue
    elseif o == "unknown"       then return soUnknownValue
    elseif o == "between"       then return soValueBetween
    elseif o == "bigger"        then return soBiggerThan
    elseif o == "smaller"       then return soSmallerThan
    elseif o == "increased"     then return soIncreasedValue
    elseif o == "increased_by"  then return soIncreasedValueBy
    elseif o == "decreased"     then return soDecreasedValue
    elseif o == "decreased_by"  then return soDecreasedValueBy
    elseif o == "changed"       then return soChanged
    elseif o == "unchanged"     then return soUnchanged
    else return nil
    end
end

SCAN_OPTION_NAMES = "exact, unknown, between, bigger, smaller, increased, increased_by, decreased, decreased_by, changed, unchanged"

-- NOTE: "unknown initial value" (soUnknownValue) first scans store candidates
-- per-region (fs_advanced / REGION file header). TFoundList.getCount() returns 0
-- in that mode and the addresses are NOT individually enumerable (GetAddressOnly
-- returns nothing), so the authoritative count is the total scanned addresses —
-- every scanned address is a potential match. UNKNOWN_SCAN_NOTE is attached by the
-- result readers so clients don't mistake the empty result list for a failed scan.
UNKNOWN_SCAN_NOTE = "Unknown initial value scan: candidates are stored per-region and are not individually enumerable. Run a next_scan to narrow them down."
function resolveScanResultCount(ms, fallbackCount)
    local p = ms.getProgress()
    if p and p.TotalAddressesToScan then
        return p.TotalAddressesToScan
    end
    return fallbackCount
end

-- CE's firstScan/nextScan take two inputs; soValueBetween (and the *_by options) need BOTH of them.
-- Passing the bounds as a single "0,1" string with input2 = nil makes CE scan for garbage and return 0 hits.
-- Returns: input1, input2, errorMessage
--   "between" accepts either an explicit value2, or a single value holding both bounds separated by "," or ".." (e.g. "0,1" / "0..1").
--   "-" is deliberately not a separator because it collides with negative numbers.
function resolveScanInputs(scanOpt, value, value2)
    -- Options that compare against the previous scan take no input at all.
    if scanOpt == soUnknownValue or scanOpt == soChanged or scanOpt == soUnchanged
       or scanOpt == soIncreasedValue or scanOpt == soDecreasedValue then
        return nil, nil, nil
    end

    if scanOpt == soValueBetween then
        local lo, hi
        if value2 ~= nil and tostring(value2) ~= "" then
            lo, hi = value, value2
        else
            local s = tostring(value or "")
            lo, hi = s:match("^%s*(.-)%s*,%s*(.-)%s*$")
            if not lo then lo, hi = s:match("^%s*(.-)%s*%.%.%s*(.-)%s*$") end
        end
        if lo == nil or hi == nil or tostring(lo) == "" or tostring(hi) == "" then
            return nil, nil, "'between' needs two bounds: pass value2, or value as \"min,max\" (e.g. \"0,1\")"
        end
        return tostring(lo), tostring(hi), nil
    end

    if value == nil or tostring(value) == "" then
        return nil, nil, "This scan option requires a value"
    end
    return tostring(value), nil, nil
end

-- ============================================================================
-- SHARED HELPERS (Unit 5 refactor — used by multiple cmd_* handlers)
-- ============================================================================
-- >>> BEGIN UNIT-05 Shared helpers <<<

local function parseAddress(input)
    -- Accepts string hex ("0x140001000"), symbol ("game.exe+1000"), or integer.
    -- Returns (address, error) — address nil if invalid.
    if type(input) == "number" then return input, nil end
    if type(input) ~= "string" then return nil, "address must be string or number" end
    local addr = getAddressSafe(input)
    if not addr or addr == 0 then return nil, "Invalid address: " .. tostring(input) end
    return addr, nil
end

local function requireProcess()
    -- Returns nil if a process is attached; returns an error table otherwise.
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return nil
end

local function findModulesViaMZScan(maxCount)
    -- Shared MZ-header AOB scan used by cmd_get_process_info and cmd_enum_modules.
    -- Returns an array of { name, address, size, source } tables.
    maxCount = maxCount or 50
    local moduleList = {}
    local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, maxCount) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then
                local peOffset = readInteger(addr + 0x3C)
                local moduleSize = 0
                local realName = nil

                if peOffset and peOffset > 0 and peOffset < 0x1000 then
                    -- Get Size of Image
                    local sizeOfImage = readInteger(addr + peOffset + 0x50)
                    if sizeOfImage then moduleSize = sizeOfImage end

                    -- TRY TO READ INTERNAL NAME FROM EXPORT DIRECTORY
                    -- PE Header + 0x78 is the Data Directory for Exports (32-bit)
                    local exportRVA = readInteger(addr + peOffset + 0x78)
                    if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                        -- Export Directory + 0x0C is the Name RVA
                        local nameRVA = readInteger(addr + exportRVA + 0x0C)
                        if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                            local name = readString(addr + nameRVA, 64)
                            if name and #name > 0 and #name < 60 then
                                realName = name
                            end
                        end
                    end
                end

                -- Determine module name
                local modName
                if realName then
                    modName = realName
                elseif i == 0 then
                    -- First module is likely main exe - use process name or L2.exe
                    modName = (process ~= "" and process) or "L2.exe"
                else
                    modName = "Module_" .. string.format("%X", addr)
                end

                table.insert(moduleList, {
                    name = modName,
                    address = toHex(addr),
                    size = moduleSize,
                    source = realName and "export_directory" or "aob_fallback"
                })
            end
        end
        mzScan.destroy()
    end
    return moduleList
end

local function findFunctionPrologue(addr, maxSearch)
    -- Searches backward from addr for a function prologue (x86: "55 8B EC" / x64: "55 48 89 E5" / "48 83 EC xx").
    -- Returns (prologueAddress, prologueType) or (nil, nil).
    maxSearch = maxSearch or 4096
    local is64 = targetIs64Bit()
    local funcStart = nil
    local prologueType = nil
    for offset = 0, maxSearch do
        local checkAddr = addr - offset
        local b1 = readBytes(checkAddr, 1, false)
        local b2 = readBytes(checkAddr + 1, 1, false)
        local b3 = readBytes(checkAddr + 2, 1, false)
        local b4 = readBytes(checkAddr + 3, 1, false)

        -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
        if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x86_standard"
            break
        end

        -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
        if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
            funcStart = checkAddr
            prologueType = "x64_standard"
            break
        end

        -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx) - common in leaf functions
        if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x64_leaf"
            break
        end
    end
    return funcStart, prologueType
end

-- >>> END UNIT-05 <<<

-- ============================================================================
-- CLEANUP & SAFETY ROUTINES (CRITICAL FOR ROBUSTNESS)
-- ============================================================================
-- Prevents "zombie" breakpoints and DBVM watches when script is reloaded

local function cleanupZombieState()
    log("Cleaning up zombie resources...")
    local cleaned = { breakpoints = 0, dbvm_watches = 0, scans = 0 }
    
    -- 0. A thread halted by a break-and-inspect breakpoint must not stay stopped when the bridge goes away
    if serverState.halted then
        pcall(debug_continueFromBreakpoint, co_run)
        serverState.halted = nil
    end

    -- 1. Remove all Hardware Breakpoints managed by us
    if serverState.breakpoints then
        for id, bp in pairs(serverState.breakpoints) do
            if bp.address then
                local ok = pcall(function() debug_removeBreakpoint(bp.address) end)
                if ok then cleaned.breakpoints = cleaned.breakpoints + 1 end
            end
        end
    end
    
    -- 2. Stop all DBVM Watches
    if serverState.active_watches then
        for key, watch in pairs(serverState.active_watches) do
            if watch.id then
                local ok = pcall(function() dbvm_watch_disable(watch.id) end)
                if ok then cleaned.dbvm_watches = cleaned.dbvm_watches + 1 end
            end
        end
    end

    -- 2b. Async jobs (UNIT-25): stop the pump, free private memscans/foundlists.
    -- Must run before step 3: a running next_scan job shares serverState.scan_memscan,
    -- which step 3 destroys (never destroy it twice).
    if serverState.jobs then
        for _, job in pairs(serverState.jobs) do
            if job._fl then pcall(function() job._fl.destroy() end) end
            if job._ms and job._ms ~= serverState.scan_memscan then
                pcall(function() job._ms.destroy() end)
            end
        end
    end
    if serverState.job_timer then
        pcall(function() serverState.job_timer.destroy() end)
        serverState.job_timer = nil
    end
    serverState.jobs = {}
    serverState.scan_job_id = nil

    -- 3. Cleanup Scan memory objects
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
        cleaned.scans = cleaned.scans + 1
    end
    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end
    serverState.scan_is_unknown_first = false

    -- 4. Cleanup persistent scans (Unit 15)
    if serverState.persistent_scans then
        for name, entry in pairs(serverState.persistent_scans) do
            if entry then
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                pcall(function() entry.ms.destroy() end)
                cleaned.scans = cleaned.scans + 1
            end
        end
    end

    -- Reset all tracking tables
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    serverState.active_watches = {}

    -- 4. Release any mapped memory MDL handles (Unit-21)
    if mappedMemoryMDL then
        for key, mdl in pairs(mappedMemoryMDL) do
            pcall(function() unmapMemory(getAddressSafe(key) or 0, mdl) end)
        end
        -- mappedMemoryMDL is module-level, reassign to clear it
        for k in pairs(mappedMemoryMDL) do mappedMemoryMDL[k] = nil end
    end

    serverState.persistent_scans = {}
    
    if cleaned.breakpoints > 0 or cleaned.dbvm_watches > 0 or cleaned.scans > 0 then
        log(string.format("Cleaned: %d breakpoints, %d DBVM watches, %d scans",
            cleaned.breakpoints, cleaned.dbvm_watches, cleaned.scans))
    end

    -- Extension point (reserved for additive units 7-23):
    -- If you add new long-lived resources to serverState (persistent scans,
    -- custom symbols, injected code caves, etc.), register their cleanup here
    -- so script reload doesn't leak them.

    return cleaned
end

-- ============================================================================
-- JSON LIBRARY (Pure Lua - Complete Implementation)
-- ============================================================================
local json = {}
local encode

local escape_char_map = { [ "\\" ] = "\\", [ "\"" ] = "\"", [ "\b" ] = "b", [ "\f" ] = "f", [ "\n" ] = "n", [ "\r" ] = "r", [ "\t" ] = "t" }
local escape_char_map_inv = { [ "/" ] = "/" }
for k, v in pairs(escape_char_map) do escape_char_map_inv[v] = k end
local function escape_char(c) return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte())) end
local function encode_nil(val) return "null" end
local function encode_table(val, stack)
  local res, stack = {}, stack or {}
  if stack[val] then error("circular reference") end
  stack[val] = true
  if rawget(val, 1) ~= nil or next(val) == nil then
    for i, v in ipairs(val) do table.insert(res, encode(v, stack)) end
    stack[val] = nil
    return "[" .. table.concat(res, ",") .. "]"
  else
    for k, v in pairs(val) do
      if type(k) ~= "string" then k = tostring(k) end
      table.insert(res, encode(k, stack) .. ":" .. encode(v, stack))
    end
    stack[val] = nil
    return "{" .. table.concat(res, ",") .. "}"
  end
end
-- Replace invalid UTF-8 bytes with U+FFFD so the Python side can always decode the reply.
local function sanitize_utf8(s)
  if utf8.len(s) then return s end
  local out, i = {}, 1
  while i <= #s do
    local ok, bad = utf8.len(s, i)
    if ok then out[#out + 1] = s:sub(i); break end
    if bad > i then out[#out + 1] = s:sub(i, bad - 1) end
    out[#out + 1] = "\xEF\xBF\xBD"
    i = bad + 1
  end
  return table.concat(out)
end
local function encode_string(val) return '"' .. sanitize_utf8(val):gsub('[%z\1-\31\\"]', escape_char) .. '"' end
local function encode_number(val)
  if math.type(val) == "integer" then return string.format("%d", val) end
  if val ~= val or val <= -math.huge or val >= math.huge then return "null" end
  local s = string.format("%.14g", val)
  if tonumber(s) ~= val then s = string.format("%.17g", val) end
  return s
end
local type_func_map = { ["nil"] = encode_nil, ["table"] = encode_table, ["string"] = encode_string, ["number"] = encode_number, ["boolean"] = tostring, ["function"] = function() return "null" end, ["userdata"] = function() return "null" end }
encode = function(val, stack) local t = type(val) local f = type_func_map[t] if f then return f(val, stack) end error("unexpected type '" .. t .. "'") end
json.encode = encode

local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
local decode
local json_simple_escapes = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', b = '\b', f = '\f', n = '\n', r = '\r', t = '\t' }
local function decode_string(str, pos)
  local startpos = pos + 1
  local endpos = pos
  while true do
    endpos = str:find('["\\]', endpos + 1)
    if not endpos then return nil, "expected closing quote" end
    if str:sub(endpos, endpos) == '"' then break end
    endpos = endpos + 1
  end
  local raw = str:sub(startpos, endpos - 1)
  if not raw:find("\\", 1, true) then return raw, endpos + 1 end
  -- Single left-to-right pass so "\\u0041" (escaped backslash + text) is not
  -- mistaken for a unicode escape, and \uXXXX (incl. surrogate pairs) becomes UTF-8.
  local out, i, n = {}, 1, #raw
  while i <= n do
    local j = raw:find("\\", i, true)
    if not j then out[#out + 1] = raw:sub(i); break end
    if j > i then out[#out + 1] = raw:sub(i, j - 1) end
    local c = raw:sub(j + 1, j + 1)
    if c == "u" then
      local hex = raw:match("^%x%x%x%x", j + 2)
      if not hex then
        out[#out + 1] = "\\u"; i = j + 2
      else
        local cp, adv = tonumber(hex, 16), j + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          local lo = raw:match("^\\u(%x%x%x%x)", adv)
          local lcp = lo and tonumber(lo, 16)
          if lcp and lcp >= 0xDC00 and lcp <= 0xDFFF then
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lcp - 0xDC00)
            adv = adv + 6
          else
            cp = 0xFFFD
          end
        elseif cp >= 0xDC00 and cp <= 0xDFFF then
          cp = 0xFFFD
        end
        out[#out + 1] = utf8.char(cp); i = adv
      end
    else
      out[#out + 1] = json_simple_escapes[c] or ("\\" .. c)
      i = j + 2
    end
  end
  return table.concat(out), endpos + 1
end
local function decode_number(str, pos)
  local numstr = str:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
  local val = tonumber(numstr)
  if not val then return nil, "invalid number" end
  return val, pos + #numstr
end
local function decode_literal(str, pos)
  local word = str:match("^%a+", pos)
  if word == "true" then return true, pos + 4 end
  if word == "false" then return false, pos + 5 end
  if word == "null" then return nil, pos + 4 end
  return nil, "invalid literal"
end
local function decode_array(str, pos)
  pos = pos + 1
  local arr, n = {}, 0
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "]" then return arr, pos + 1 end
  while true do
        local val
        val, pos = decode(str, pos)
        n = n + 1
        arr[n] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "]" then return arr, pos + 1 end
    if c ~= "," then return nil, "expected ']' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local function decode_object(str, pos)
  pos = pos + 1
  local obj = {}
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "}" then return obj, pos + 1 end
  while true do
        local key
        key, pos = decode_string(str, pos)
        if not key then return nil, "expected string key" end
    pos = decode_scanwhite(str, pos)
    if str:sub(pos, pos) ~= ":" then return nil, "expected ':'" end
    pos = decode_scanwhite(str, pos + 1)
        local val
        val, pos = decode(str, pos)
        obj[key] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "}" then return obj, pos + 1 end
    if c ~= "," then return nil, "expected '}' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local char_func_map = { ['"'] = decode_string, ["{"] = decode_object, ["["] = decode_array }
setmetatable(char_func_map, { __index = function(t, c) if c:match("%d") or c == "-" then return decode_number end return decode_literal end })
decode = function(str, pos)
  pos = pos or 1
  pos = decode_scanwhite(str, pos)
  local c = str:sub(pos, pos)
  return char_func_map[c](str, pos)
end
json.decode = decode

-- ============================================================================
-- COMMAND HANDLERS - PROCESS & MODULES
-- ============================================================================

-- Shared helper: scan for MZ PE headers via AOB and read module names from export directories.
-- Returns a list of {name, address, size, is_64bit, path, source} entries (up to maxCount).
-- Names are only taken from real PE export directories; otherwise the entry is named "Module_<HEX>".
local function aobScanPEModules(maxCount)
    maxCount = maxCount or 50
    local found = {}
    local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
    if not mzScan or mzScan.Count == 0 then return found end
    for i = 0, math.min(mzScan.Count - 1, maxCount - 1) do
        local addr = tonumber(mzScan.getString(i), 16)
        if addr then
            local peOffset = readInteger(addr + 0x3C)
            local moduleSize = 0
            local realName = nil
            if peOffset and peOffset > 0 and peOffset < 0x1000 then
                local sizeOfImage = readInteger(addr + peOffset + 0x50)
                if sizeOfImage then moduleSize = sizeOfImage end
                local exportRVA = readInteger(addr + peOffset + 0x78)
                if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                    local nameRVA = readInteger(addr + exportRVA + 0x0C)
                    if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                        local name = readString(addr + nameRVA, 64)
                        if name and #name > 0 and #name < 60 then
                            realName = name
                        end
                    end
                end
            end
            table.insert(found, {
                name    = realName or ("Module_" .. string.format("%X", addr)),
                address = toHex(addr),
                size    = moduleSize,
                is_64bit = false,
                path    = "",
                source  = realName and "export_directory" or "aob_fallback",
                real_name = realName  -- kept for callers that need to know if it's verified
            })
        end
    end
    mzScan.destroy()
    return found
end

function cmd_get_process_info(params)
    -- FORCE REFRESH: Tell CE to try and reload symbols using current DBVM rights
    pcall(reinitializeSymbolhandler)
    
    local pid = getOpenedProcessID()
    if pid and pid > 0 then
        -- Get modules using the same logic as enum_modules (with AOB fallback)
        local modules = enumModules(pid)
        if not modules or #modules == 0 then
            modules = enumModules()
        end
        
        -- Build module list
        local moduleList = {}
        local mainModuleName = nil
        local usedAobFallback = false
        
        if modules and #modules > 0 then
            for i = 1, math.min(#modules, 50) do
                local m = modules[i]
                if m then
                    table.insert(moduleList, {
                        name = m.Name or "???",
                        address = toHex(m.Address or 0),
                        size = m.Size or 0
                    })
                    if i == 1 then mainModuleName = m.Name end
                end
            end
        end
        
        -- If still no modules, try AOB fallback for PE headers with export-directory name reading
        if #moduleList == 0 then
            usedAobFallback = true
            moduleList = findModulesViaMZScan(50)
            if #moduleList > 0 then mainModuleName = moduleList[1].name end
            local aobModules = aobScanPEModules(50)
            for idx, m in ipairs(aobModules) do
                table.insert(moduleList, {
                    name    = m.name,
                    address = m.address,
                    size    = m.size,
                    source  = m.source
                })
                -- Only use as main module name if backed by a real export-directory entry
                if idx == 1 and m.real_name then mainModuleName = m.real_name end
            end
        end

        -- If neither enumModules nor the AOB fallback produced any modules, report failure honestly
        if #moduleList == 0 then
            return {
                success = false,
                error = "Process attached but cannot enumerate modules (likely anti-cheat interference). Try enum_modules directly, or attach to a different process.",
                error_code = "CE_API_UNAVAILABLE",
                process_id = pid
            }
        end

        -- Use the best available module-derived process name
        local name = mainModuleName or (moduleList[1] and moduleList[1].name) or "UnknownProcess"

        return {
            success = true,
            process_id = pid,
            process_name = name,
            module_count = #moduleList,
            modules = moduleList,
            used_aob_fallback = usedAobFallback
        }
    end
    return { success = false, error = "No process attached" }
end

function cmd_enum_modules(params)
    local pid = getOpenedProcessID()
    local modules = enumModules(pid)  -- Try with PID first
    
    -- If that fails, try without PID
    if not modules or #modules == 0 then
        modules = enumModules()
    end
    
    local result = {}
    if modules and #modules > 0 then
        for i, m in ipairs(modules) do
            if m then
                table.insert(result, {
                    name = m.Name or "???",
                    address = toHex(m.Address or 0),
                    size = m.Size or 0,
                    is_64bit = m.Is64Bit or false,
                    path = m.PathToFile or ""
                })
            end
        end
    end
    
    -- Fallback: If no modules found, try to find them via MZ header scan with export-directory name reading
    if #result == 0 then
        local fallback = findModulesViaMZScan(50)
        for _, m in ipairs(fallback) do
            table.insert(result, {
                name = m.name,
                address = m.address,
                size = m.size,
                is_64bit = false,
                path = "",
                source = m.source
            })
        end

        local aobModules = aobScanPEModules(50)
        for _, m in ipairs(aobModules) do
            table.insert(result, {
                name     = m.name,
                address  = m.address,
                size     = m.size,
                is_64bit = m.is_64bit,
                path     = m.path,
                source   = m.source
            })
        end
    end

    -- If both enumModules and the AOB fallback failed to produce any modules, report failure honestly
    if #result == 0 and (pid or 0) > 0 then
        return {
            success = false,
            error = "Process attached but cannot enumerate modules (likely anti-cheat interference). Try enum_modules directly, or attach to a different process.",
            error_code = "CE_API_UNAVAILABLE",
            process_id = pid
        }
    end
    
    local fallback_used = #result > 0 and result[1] and result[1].source ~= nil
    local limit, offset, page, total = paginate(params, result, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, modules = page, fallback_used = fallback_used }
end

function cmd_get_symbol_address(params)
    local symbol = params.symbol or params.name
    if not symbol then return { success = false, error = "No symbol name" } end
    
    local addr = getAddressSafe(symbol)
    if addr then
        return { success = true, symbol = symbol, address = toHex(addr), value = addr }
    end
    return { success = false, error = "Symbol not found: " .. symbol }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY READ
-- ============================================================================

-- Byte-table helpers shared by read_memory / read_struct / jobs.
local function bytesToString(bytes, first, last)
    first = first or 1
    last = last or #bytes
    local parts = {}
    for i = first, last, 4096 do
        parts[#parts + 1] = string.char(table.unpack(bytes, i, math.min(i + 4095, last)))
    end
    return table.concat(parts)
end

local B64_CHARS = {}
do
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for i = 1, 64 do B64_CHARS[i - 1] = alphabet:sub(i, i) end
end

local function base64Encode(s)
    local out = {}
    for i = 1, #s, 3 do
        local a, b, c = s:byte(i, i + 2)
        local n = (a << 16) | ((b or 0) << 8) | (c or 0)
        out[#out + 1] = B64_CHARS[(n >> 18) & 63] .. B64_CHARS[(n >> 12) & 63]
            .. (b and B64_CHARS[(n >> 6) & 63] or "=") .. (c and B64_CHARS[n & 63] or "=")
    end
    return table.concat(out)
end

-- format: "both" (default, legacy: hex string + integer array), "hex" (string only),
-- "base64", "array" (integer array only). Large reads are 2-3x smaller with "hex"/"base64".
function cmd_read_memory(params)
    local addr = params.address
    local size = math.max(1, math.min(params.size or 256, 1048576))  -- 1 MB max
    local fmt = params.format or "both"
    if fmt ~= "both" and fmt ~= "hex" and fmt ~= "base64" and fmt ~= "array" then
        return { success = false, error = "Unknown format '" .. tostring(fmt) .. "'. Valid: hex, base64, array, both", error_code = "INVALID_PARAMS" }
    end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local bytes = readBytes(addr, size, true)
    if not bytes then return { success = false, error = "Failed to read at " .. toHex(addr) } end

    local result = { success = true, address = toHex(addr), size = #bytes }
    if fmt == "both" or fmt == "hex" then
        local hex = {}
        for i, b in ipairs(bytes) do hex[i] = string.format("%02X", b) end
        result.data = table.concat(hex, " ")
    end
    if fmt == "base64" then
        result.base64 = base64Encode(bytesToString(bytes))
    end
    if fmt == "both" or fmt == "array" then
        result.bytes = bytes
    end
    if fmt ~= "both" then result.format = fmt end
    return result
end

function cmd_read_integer(params)
    local addr = params.address
    local itype = params.type or "dword"
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local val
    if itype == "byte" then
        local b = readBytes(addr, 1, true)
        if b and #b > 0 then val = b[1] end
    elseif itype == "word" then val = readSmallInteger(addr)
    elseif itype == "dword" then val = readInteger(addr)
    elseif itype == "qword" then val = readQword(addr)
    elseif itype == "float" then val = readFloat(addr)
    elseif itype == "double" then val = readDouble(addr)
    else return { success = false, error = "Unknown type: " .. tostring(itype) } end
    
    if val == nil then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    return { success = true, address = toHex(addr), value = val, type = itype, hex = toHex(val) }
end

function cmd_read_string(params)
    local addr = params.address
    local maxlen = params.max_length or 256
    local wide = params.wide or false
    -- encoding: "ascii" | "utf8" | "utf16le" | "raw" (default "utf8")
    -- Backward compat: wide=true maps to utf16le unless encoding is explicitly set
    local encoding = params.encoding or (wide and "utf16le" or "utf8")

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local parts = {}
    local rawLen = 0

    if encoding == "utf16le" then
        local str = readString(addr, maxlen, true)
        rawLen = str and #str or 0
        if str then
            for i = 1, #str do
                local byte = str:byte(i)
                if byte >= 32 and byte < 127 then
                    parts[#parts + 1] = str:sub(i, i)
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = str:sub(i, i)
                else
                    parts[#parts + 1] = string.format("\\x%02X", byte)
                end
            end
        end
    elseif encoding == "raw" then
        local bytes = readBytes(addr, maxlen, true)
        rawLen = bytes and #bytes or 0
        if bytes then
            for i, b in ipairs(bytes) do parts[i] = string.format("%02X", b) end
        end
        return { success = true, address = toHex(addr), value = table.concat(parts, " "), encoding = encoding, wide = false, length = rawLen, raw_length = rawLen }
    elseif encoding == "ascii" then
        local str = readString(addr, maxlen, false)
        rawLen = str and #str or 0
        if str then
            for i = 1, #str do
                local byte = str:byte(i)
                if byte >= 32 and byte < 127 then
                    parts[#parts + 1] = str:sub(i, i)
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = " "
                else
                    parts[#parts + 1] = string.format("\\x%02X", byte)
                end
            end
        end
    else
        -- utf8 (default): preserve valid UTF-8 multi-byte sequences; strip C0 controls
        local str = readString(addr, maxlen, false)
        rawLen = str and #str or 0
        if str then
            local i = 1
            while i <= #str do
                local byte = str:byte(i)
                if byte >= 0x80 then
                    local seqLen
                    if byte >= 0xF0 then seqLen = 4
                    elseif byte >= 0xE0 then seqLen = 3
                    elseif byte >= 0xC0 then seqLen = 2
                    else seqLen = 1 end  -- 0x80-0xBF: orphan continuation byte
                    if seqLen > 1 and i + seqLen - 1 <= #str then
                        local valid = true
                        for j = i + 1, i + seqLen - 1 do
                            local cb = str:byte(j)
                            if cb < 0x80 or cb > 0xBF then valid = false; break end
                        end
                        if valid then
                            parts[#parts + 1] = str:sub(i, i + seqLen - 1)
                            i = i + seqLen
                        else
                            parts[#parts + 1] = string.format("\\x%02X", byte)
                            i = i + 1
                        end
                    else
                        parts[#parts + 1] = string.format("\\x%02X", byte)
                        i = i + 1
                    end
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = str:sub(i, i)
                    i = i + 1
                elseif byte >= 0x20 and byte < 0x80 then
                    parts[#parts + 1] = str:sub(i, i)
                    i = i + 1
                else
                    i = i + 1  -- strip C0 control bytes
                end
            end
        end
    end

    local sanitized = table.concat(parts)
    return { success = true, address = toHex(addr), value = sanitized, encoding = encoding, wide = (encoding == "utf16le"), length = rawLen, raw_length = #sanitized }
end

function cmd_read_pointer(params)
    local base = params.base or params.address
    local offsets = params.offsets or {}
    
    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local path = { toHex(base) }
    
    for i, offset in ipairs(offsets) do
        -- Use readPointer for 32/64-bit compatibility (readInteger on 32-bit, readQword on 64-bit)
        local ptr = readPointer(currentAddr)
        if not ptr then
            return { success = false, error = "Failed to read pointer at " .. toHex(currentAddr), path = path }
        end
        currentAddr = ptr + offset
        table.insert(path, toHex(currentAddr))
    end
    
    -- Read final value using readPointer for 32/64-bit compatibility
    local finalValue = readPointer(currentAddr)
    return { 
        success = true, 
        base = toHex(base), 
        final_address = toHex(currentAddr), 
        value = finalValue, 
        path = path 
    }
end

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

function cmd_aob_scan(params)
    local pattern = params.pattern
    local protection = params.protection or "+X"
    local limit = params.limit or 100
    
    if not pattern then return { success = false, error = "No pattern provided" } end
    
    local results = AOBScan(pattern, protection)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addrStr = results.getString(i)
        local addr = tonumber(addrStr, 16)
        table.insert(addresses, { 
            address = "0x" .. addrStr, 
            value = addr 
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, pattern = pattern, addresses = addresses }
end

local USER_MODE_MAX = 0x7FFFFFFFFFFFFFFF

-- An async scan job owns the shared memscan until it finishes.
local function scanBusyError()
    if serverState.scan_job_id then
        return { success = false, error = "Scan job " .. serverState.scan_job_id .. " is still running; poll get_job or cancel_job first.", error_code = "BUSY" }
    end
    return nil
end

-- Validates scan_all parameters. Shared by cmd_scan_all and the scan_all job so both
-- behave identically. Returns args table, or nil + error reply.
local function prepareFirstScan(params)
    local scanOpt = resolveScanOption(params.scan_option or "exact")
    if not scanOpt then
        return nil, { success = false, error = "Unknown scan_option '" .. tostring(params.scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt ~= soExactValue and scanOpt ~= soUnknownValue and scanOpt ~= soValueBetween
       and scanOpt ~= soBiggerThan and scanOpt ~= soSmallerThan then
        return nil, { success = false, error = "scan_option '" .. tostring(params.scan_option) .. "' is only valid for next_scan. First scan supports: exact, unknown, between, bigger, smaller", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, params.value, params.value2)
    if inputErr then
        return nil, { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local vtype = params.type or "dword"
    local varType = vtDword
    if vtype == "byte" then varType = vtByte
    elseif vtype == "word" then varType = vtWord
    elseif vtype == "qword" then varType = vtQword
    elseif vtype == "float" then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString end

    return { scanOpt = scanOpt, varType = varType, input1 = input1, input2 = input2,
             protect = params.protection or "+W-C" }
end

-- Makes a finished first-scan memscan the active scan session; returns the result count.
local function commitFirstScan(ms, scanOpt)
    local fl = createFoundList(ms)
    fl.initialize()
    local count = fl.getCount()

    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
    end

    serverState.scan_memscan = ms
    serverState.scan_foundlist = fl
    serverState.scan_is_unknown_first = (scanOpt == soUnknownValue)

    -- unknown-initial-value scans report 0 via the foundlist; see resolveScanResultCount()
    if scanOpt == soUnknownValue then
        count = resolveScanResultCount(ms, count)
    end
    return count
end

function cmd_scan_all(params)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareFirstScan(params)
    if err then return err end

    local ms = createMemScan()

    -- Use specific protection flags if provided (defaults to +W-C from Python)
    -- CRITICAL: Limit scan to User Mode space (0x7FFFFFFFFFFFFFFF) to prevent BSODs in Kernel/Guard regions
    ms.firstScan(args.scanOpt, args.varType, rtRounded, args.input1, args.input2, 0, USER_MODE_MAX, args.protect, fsmNotAligned, "1", false, false, false, false)
    ms.waitTillDone()

    return { success = true, count = commitFirstScan(ms, args.scanOpt) }
end

function cmd_get_scan_results(params)
    local busy = scanBusyError()
    if busy then return busy end
    -- limit: preferred param; max: backward-compat alias
    local limit = params.limit or params.max or 100
    limit = math.max(1, math.min(limit, 10000))
    local offset = math.max(0, params.offset or 0)

    if not serverState.scan_foundlist then
        return { success = false, error = "No scan results. Run scan_all first." }
    end

    local fl = serverState.scan_foundlist
    local total = fl.getCount()
    local results = {}

    -- NOTE: unknown-initial-value scans are not individually enumerable via the
    -- foundlist (see resolveScanResultCount()); report the scanned-address total
    -- and signal it so an empty result list isn't mistaken for a scan failure.
    if serverState.scan_is_unknown_first then
        local ms = serverState.scan_memscan
        if ms then
            total = resolveScanResultCount(ms, total)
        end
        return {
            success = true,
            total = total,
            offset = offset,
            limit = limit,
            returned = 0,
            results = results,
            enumerable = false,
            unknown_initial_value = true,
            note = UNKNOWN_SCAN_NOTE
        }
    end

    local endIdx = math.min(offset + limit, total) - 1

    for i = offset, endIdx do
        -- IMPORTANT: Ensure address has 0x prefix for consistency with all other commands
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0x") and not addrStr:match("^0X") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value = fl.getValue(i)
        })
    end

    return { success = true, total = total, offset = offset, limit = limit, returned = #results, results = results }
end

-- ============================================================================
-- COMMAND HANDLERS - NEXT SCAN & WRITE MEMORY (Added by MCP Enhancement)
-- ============================================================================

-- Validates next_scan parameters (shared with the next_scan job).
local function prepareNextScan(params)
    -- scan_option is the v12 name; scan_type is kept as a backward-compat alias
    local scanType = params.scan_option or params.scan_type or "exact"

    if not serverState.scan_memscan then
        return nil, { success = false, error = "No previous scan. Run scan_all first." }
    end

    local scanOpt = resolveScanOption(scanType)
    if not scanOpt then
        return nil, { success = false, error = "Unknown scan_option '" .. tostring(scanType) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt == soUnknownValue then
        return nil, { success = false, error = "scan_option 'unknown' is only valid for scan_all", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, params.value, params.value2)
    if inputErr then
        return nil, { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    return { ms = serverState.scan_memscan, scanOpt = scanOpt, input1 = input1, input2 = input2 }
end

-- Replaces the foundlist with the results of the finished next scan; returns the count.
local function commitNextScan(ms)
    if serverState.scan_foundlist then
        serverState.scan_foundlist.destroy()
    end
    local fl = createFoundList(ms)
    fl.initialize()
    serverState.scan_foundlist = fl
    serverState.scan_is_unknown_first = false
    return fl.getCount()
end

function cmd_next_scan(params)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareNextScan(params)
    if err then return err end

    args.ms.nextScan(args.scanOpt, rtRounded, args.input1, args.input2, false, false, false, false, false)
    args.ms.waitTillDone()

    return { success = true, count = commitNextScan(args.ms) }
end

function cmd_write_integer(params)
    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    if vtype == "byte" then
        if type(value) ~= "number" or value < 0 or value > 0xFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "word" or vtype == "2bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "dword" or vtype == "4bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFFFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    end

    local ok, err
    if vtype == "byte" then
        ok, err = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, err = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, err = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, err = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, err = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, err = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype) }
    end

    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end

    return { success = true, address = toHex(addr), value = value, type = vtype }
end

function cmd_write_memory(params)
    local addr = params.address
    local bytes = params.bytes
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if not bytes or #bytes == 0 then return { success = false, error = "No bytes provided" } end
    
    local ok, err = pcall(writeBytes, addr, bytes)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), bytes_written = #bytes }
end

function cmd_write_string(params)
    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if not str then return { success = false, error = "No string provided" } end
    
    local ok, err = pcall(writeString, addr, str, wide)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), length = #str, wide = wide }
end


-- ============================================================================
-- COMMAND HANDLERS - DISASSEMBLY & ANALYSIS
-- ============================================================================

function cmd_disassemble(params)
    local addr = params.address
    local count = params.count or 20
    local count = math.max(1, math.min(params.count or 20, 1000))

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local allInstructions = {}
    local currentAddr = addr

    for i = 1, count do
        local ok, disasm = pcall(disassemble, currentAddr)
        if not ok or not disasm then break end

        local instSize = getInstructionSize(currentAddr) or 1
        local instBytes = readBytes(currentAddr, instSize, true) or {}
        local bytesHex = {}
        for _, b in ipairs(instBytes) do table.insert(bytesHex, string.format("%02X", b)) end

        table.insert(allInstructions, {
            address = toHex(currentAddr),
            offset = currentAddr - addr,
            size = instSize,
            bytes = table.concat(bytesHex, " "),
            instruction = disasm
        })

        currentAddr = currentAddr + instSize
    end

    local limit, offset, page, total = paginate(params, allInstructions, 100)
    return { success = true, start_address = toHex(addr), total = total, offset = offset, limit = limit, returned = #page, instructions = page }
end

function cmd_get_instruction_info(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local ok, disasm = pcall(disassemble, addr)
    if not ok or not disasm then
        return { success = false, error = "Failed to disassemble at " .. toHex(addr) }
    end
    local size = getInstructionSize(addr)
    local bytes = readBytes(addr, size or 1, true) or {}
    local bytesHex = {}
    for _, b in ipairs(bytes) do table.insert(bytesHex, string.format("%02X", b)) end
    
    local prevAddr = getPreviousOpcode(addr)
    
    return {
        success = true,
        address = toHex(addr),
        instruction = disasm,
        size = size,
        bytes = table.concat(bytesHex, " "),
        previous_instruction = prevAddr and toHex(prevAddr) or nil
    }
end

function cmd_find_function_boundaries(params)
    local addr = params.address
    local maxSearch = params.max_search or 4096

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()

    -- x64 modules: the exception table gives the exact start and end (see pdataFunctionBoundaries)
    if type(pdataFunctionBoundaries) == "function" then
        local okPd, pd = pcall(pdataFunctionBoundaries, addr)
        if okPd and pd then
            return {
                success = true, found = true, query_address = toHex(addr),
                function_start = toHex(pd.start), function_end = toHex(pd.finish - 1), function_size = pd.finish - pd.start,
                method = "pdata", exact = true, fragment = pd.fragment or nil,
                exception_handler = pd.handler_rva and toHex(pd.module.base + pd.handler_rva) or nil,
                module = pd.module.name, expression = pd.module.name .. "+" .. string.format("0x%X", pd.start - pd.module.base),
                arch = "x64"
            }
        end
    end

    local funcStart, prologueType = findFunctionPrologue(addr, maxSearch)

    -- Search forwards for return instruction
    local funcEnd = nil
    if funcStart then
        for offset = 0, maxSearch do
            local b = readBytes(funcStart + offset, 1, false)
            if b == 0xC3 or b == 0xC2 then
                funcEnd = funcStart + offset
                break
            end
        end
    end

    local found = funcStart ~= nil

    return {
        success = true,
        found = found,
        query_address = toHex(addr),
        function_start = funcStart and toHex(funcStart) or nil,
        function_end = funcEnd and toHex(funcEnd) or nil,
        function_size = (funcStart and funcEnd) and (funcEnd - funcStart + 1) or nil,
        prologue_type = prologueType,
        method = "heuristic",
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

function cmd_analyze_function(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()

    local pd
    if type(pdataFunctionBoundaries) == "function" then
        local okPd, res = pcall(pdataFunctionBoundaries, addr)
        if okPd then pd = res end
    end
    local funcStart, prologueType
    if pd then
        funcStart, prologueType = pd.start, "pdata"
    else
        funcStart, prologueType = findFunctionPrologue(addr, 4096)
    end

    if not funcStart then 
        return { 
            success = false, 
            error = "Could not find function start",
            arch = is64 and "x64" or "x86",
            query_address = toHex(addr)
        } 
    end
    
    -- Analyze calls within function
    local calls = {}
    local funcEnd = nil
    local currentAddr = funcStart
    
    local limitAddr = pd and pd.finish or (funcStart + 0x2000)
    while currentAddr < limitAddr do
        local instSize = getInstructionSize(currentAddr)
        if not instSize or instSize == 0 then break end
        
        local b1 = readBytes(currentAddr, 1, false)
        if (b1 == 0xC3 or b1 == 0xC2) and not pd then
            funcEnd = currentAddr
            break
        end
        
        -- Detect CALL instructions
        -- E8 xx xx xx xx = relative CALL (most common)
        if b1 == 0xE8 then
            local relOffset = readInteger(currentAddr + 1)
            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    target = toHex(currentAddr + 5 + relOffset),
                    type = "relative"
                })
            end
        end
        
        -- FF /2 = indirect CALL (CALL r/m32 or CALL r/m64)
        if b1 == 0xFF then
            local b2 = readBytes(currentAddr + 1, 1, false)
            if b2 and (b2 >= 0x10 and b2 <= 0x1F) then  -- ModR/M for /2
                local disasm = disassemble(currentAddr)
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    instruction = disasm,
                    type = "indirect"
                })
            end
        end
        
        currentAddr = currentAddr + instSize
    end
    
    if pd then funcEnd = pd.finish - 1 end

    return {
        success = true,
        function_start = toHex(funcStart),
        function_end = funcEnd and toHex(funcEnd) or nil,
        prologue_type = prologueType,
        method = pd and "pdata" or "heuristic",
        exact = pd and true or nil,
        arch = is64 and "x64" or "x86",
        call_count = #calls,
        calls = calls
    }
end

-- ============================================================================
-- COMMAND HANDLERS - REFERENCE FINDING
-- ============================================================================

function cmd_find_references(params)
    local targetAddr = params.address

    if type(targetAddr) == "string" then targetAddr = getAddressSafe(targetAddr) end
    if not targetAddr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()
    local pattern

    -- Convert address to AOB pattern (little-endian)
    if is64 and targetAddr > 0xFFFFFFFF then
        -- 64-bit address: 8 bytes little-endian
        local bytes = {}
        local tempAddr = targetAddr
        for i = 1, 8 do
            bytes[i] = tempAddr % 256
            tempAddr = math.floor(tempAddr / 256)
        end
        pattern = string.format("%02X %02X %02X %02X %02X %02X %02X %02X",
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
    else
        -- 32-bit address: 4 bytes little-endian
        local b1 = targetAddr % 256
        local b2 = math.floor(targetAddr / 256) % 256
        local b3 = math.floor(targetAddr / 65536) % 256
        local b4 = math.floor(targetAddr / 16777216) % 256
        pattern = string.format("%02X %02X %02X %02X", b1, b2, b3, b4)
    end

    local scanResults = AOBScan(pattern, "+X")
    if not scanResults then
        local limit, offset, page, total = paginate(params, {}, 50)
        return { success = true, target = toHex(targetAddr), total = total, offset = offset, limit = limit, returned = 0, references = {}, arch = is64 and "x64" or "x86" }
    end

    local allRefs = {}
    for i = 0, scanResults.Count - 1 do
        local refAddr = tonumber(scanResults.getString(i), 16)
        local disasm = disassemble(refAddr) or "???"
        allRefs[#allRefs + 1] = { address = toHex(refAddr), instruction = disasm }
    end
    scanResults.destroy()

    local limit, offset, page, total = paginate(params, allRefs, 50)
    return { success = true, target = toHex(targetAddr), total = total, offset = offset, limit = limit, returned = #page, references = page, arch = is64 and "x64" or "x86" }
end

function cmd_find_call_references(params)
    local funcAddr = params.address or params.function_address

    if type(funcAddr) == "string" then funcAddr = getAddressSafe(funcAddr) end
    if not funcAddr then return { success = false, error = "Invalid function address" } end

    -- Collect ALL matching callers to get accurate total for pagination
    local allCallers = {}
    local scanResults = AOBScan("E8 ?? ?? ?? ??", "+X")

    if scanResults then
        for i = 0, scanResults.Count - 1 do
            local callAddr = tonumber(scanResults.getString(i), 16)
            local relOffset = readInteger(callAddr + 1)

            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                local target = callAddr + 5 + relOffset

                if target == funcAddr then
                    allCallers[#allCallers + 1] = {
                        caller_address = toHex(callAddr),
                        instruction = disassemble(callAddr) or "???"
                    }
                end
            end
        end
        scanResults.destroy()
    end

    local limit, offset, page, total = paginate(params, allCallers, 100)
    return { success = true, function_address = toHex(funcAddr), total = total, offset = offset, limit = limit, returned = #page, callers = page }
end

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

-- Clears any hw_bp_slots entry (and its tracking tables) whose address matches
-- addr, so the slot is available for re-use without leaking the old entry.
local function clearGhostBpSlot(addr)
    for i = 1, 4 do
        if serverState.hw_bp_slots[i] and serverState.hw_bp_slots[i].address == addr then
            local oldId = serverState.hw_bp_slots[i].id
            serverState.hw_bp_slots[i] = nil
            if oldId then
                serverState.breakpoints[oldId] = nil
                serverState.breakpoint_hits[oldId] = nil
            end
        end
    end
end

-- Max buffered hits per breakpoint. When full, the oldest quarter is dropped
-- (amortised O(1)); bp.total_hits keeps the cumulative count.
local MAX_HITS_PER_BP = 2000

-- Appends a hit to a breakpoint's buffer. The bucket is looked up on every hit
-- because get_breakpoint_hits/clear_all/remove_breakpoint replace or drop it.
local function recordBpHit(bpId, hitData)
    local bucket = serverState.breakpoint_hits[bpId]
    if not bucket then return end
    local bp = serverState.breakpoints[bpId]
    if bp then bp.total_hits = (bp.total_hits or 0) + 1 end
    local n = #bucket
    if n >= MAX_HITS_PER_BP then
        local drop = MAX_HITS_PER_BP // 4
        table.move(bucket, drop + 1, n, 1)
        for i = n, n - drop + 1, -1 do bucket[i] = nil end
        if bp then bp.dropped_hits = (bp.dropped_hits or 0) + drop end
        n = n - drop
    end
    bucket[n + 1] = hitData
end

-- Hit callbacks MUST reach debug_continueFromBreakpoint, otherwise the target
-- thread stays halted. Run the body under pcall and always continue - except for
-- a break-and-inspect hit, where the body returns "halt" and the thread is left stopped.
-- What CE does with the callback's return value (measured in a live CE, see tests/live_smoke.py): nil, false, true and
-- 0 all make CE resume the thread by itself; a NON-ZERO number (1, 2) means "the script took care of it" and CE leaves
-- the thread stopped. So both paths return 1: the normal one after continuing explicitly, the halt one without.
local function safeBpCallback(body)
    return function()
        local ok, result = pcall(body)
        if not ok then log("Breakpoint callback error: " .. tostring(result)) end
        if ok and result == "halt" then return 1 end
        debug_continueFromBreakpoint(co_run)
        return 1
    end
end

-- Breakpoint control lives in one table: this chunk is close to CE's 200-locals limit.
--   condition  : sandboxed expression over the registers (RAX, ...), memory readers (u32(addr), ptr(addr), f32(addr) ...)
--                and hits()/seen(); runs under an instruction budget so it can never hang the target
--   max_hits   : detach after N matching hits
--   mode=break : leave the thread stopped (break-and-inspect); a watchdog resumes it after halt_timeout_ms
local BPX = { HALT_DEFAULT_MS = 10000, HALT_MAX_MS = 300000, HALT_HARD_LIMIT_S = 600,
              CONDITION_INSTRUCTION_LIMIT = 200000, MAX_CONDITION_ERRORS = 5, MAX_INSPECT = 8 }

BPX.REGISTER_NAMES = {}
for _, n in ipairs({ "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                     "EFLAGS", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP" }) do
    BPX.REGISTER_NAMES[n] = true
end

function BPX.readNum(addr, size, fmt)
    local ok, bytes = pcall(readBytes, addr, size, true)
    if not ok or not bytes or #bytes ~= size then return nil end
    return (string.unpack(fmt, string.char(table.unpack(bytes))))
end

function BPX.readValue(addr, size)
    return BPX.readNum(addr, size, ({ [1] = "<I1", [2] = "<I2", [4] = "<I4", [8] = "<I8" })[size])
end

-- The only globals a condition can see: registers (CE publishes them while the thread is stopped), memory readers
-- that return nil for unreadable memory, and a few math helpers.
function BPX.makeEnv(bp)
    local env = {}
    for name, spec in pairs({ u8 = { 1, "<I1" }, u16 = { 2, "<I2" }, u32 = { 4, "<I4" }, u64 = { 8, "<I8" },
                              i8 = { 1, "<i1" }, i16 = { 2, "<i2" }, i32 = { 4, "<i4" }, i64 = { 8, "<i8" },
                              f32 = { 4, "<f" }, f64 = { 8, "<d" } }) do
        env[name] = function(a)
            if math.type(a) ~= "integer" then return nil end
            return BPX.readNum(a, spec[1], spec[2])
        end
    end
    env.ptr = targetIs64Bit() and env.u64 or env.u32
    env.hits = function() return bp.total_hits or 0 end
    env.seen = function() return bp.seen_hits or 0 end
    env.abs, env.min, env.max, env.floor = math.abs, math.min, math.max, math.floor
    return setmetatable(env, { __index = function(_, k)
        if type(k) == "string" then
            local up = k:upper()
            if BPX.REGISTER_NAMES[up] then return _G[up] end
        end
    end })
end

function BPX.compile(expr, bp)
    if type(expr) ~= "string" or expr == "" then return nil, "empty expression" end
    if #expr > 500 then return nil, "expression is longer than 500 characters" end
    local fn, err = load("return (" .. expr .. ")", "=expr", "t", BPX.makeEnv(bp))
    if not fn then return nil, tostring(err) end
    return fn
end

-- Run a compiled expression under an instruction budget (a `while true do end` inside it would otherwise hang the target).
function BPX.run(fn)
    local hookable = type(debug) == "table" and type(debug.sethook) == "function"
    if hookable then
        debug.sethook(function() error("expression exceeded its instruction budget", 2) end, "", BPX.CONDITION_INSTRUCTION_LIMIT)
    end
    local ok, res = pcall(fn)
    if hookable then debug.sethook() end
    return ok, res
end

-- Should this hit be recorded?  Returns pass, conditionError. A failing condition records the hit (flagged) so the
-- failure is visible, and is switched off after MAX_CONDITION_ERRORS failures.
function BPX.test(bp)
    if not bp.condition_fn then return true end
    local ok, res = BPX.run(bp.condition_fn)
    if not ok then
        bp.condition_errors = (bp.condition_errors or 0) + 1
        bp.last_condition_error = tostring(res)
        if bp.condition_errors >= BPX.MAX_CONDITION_ERRORS then
            bp.condition_fn, bp.condition_disabled = nil, true
        end
        return true, tostring(res)
    end
    return (res ~= nil and res ~= false and res ~= 0), nil
end

function BPX.detach(bpId)
    local bp = serverState.breakpoints[bpId]
    if not bp or bp.detached then return end
    pcall(function() debug_removeBreakpoint(bp.address) end)
    if bp.slot then
        serverState.hw_bp_slots[bp.slot] = nil
        bp.slot = nil
    end
    bp.detached = true
end

-- Detaching from inside the breakpoint's own callback is risky, so defer it to the main loop when CE offers queue().
function BPX.scheduleDetach(bpId)
    if type(queue) == "function" and pcall(queue, function() BPX.detach(bpId) end) then return end
    BPX.detach(bpId)
end

function BPX.readInspect(bp)
    local out = {}
    for i, spec in ipairs(bp.inspect or {}) do
        local ok, addr = BPX.run(spec.fn)
        local entry = { expr = spec.expr, size = spec.size }
        if ok and math.type(addr) == "integer" then
            entry.address = toHex(addr)
            local okR, bytes = pcall(readBytes, addr, spec.size, true)
            if okR and bytes then
                local hex = {}
                for k, b in ipairs(bytes) do hex[k] = string.format("%02X", b) end
                entry.hex = table.concat(hex, " ")
            else
                entry.error = "unreadable"
            end
        else
            entry.error = "expression failed: " .. tostring(addr)
        end
        out[i] = entry
    end
    return out
end

-- ---- break-and-inspect --------------------------------------------------------------------------------
function BPX.halt(bpId, bp, hit)
    local now = os.clock()
    local arch = getArchInfo()
    serverState.halted = {
        id = bpId, since = now, timeout_ms = bp.halt_timeout_ms, deadline = now + bp.halt_timeout_ms / 1000,
        hard_deadline = now + BPX.HALT_HARD_LIMIT_S, steps = 0, hit = hit,
        registers = captureRegisters(), stack = captureStack(16), memory = BPX.readInspect(bp),
        instruction = arch.instPtr and disassemble(arch.instPtr) or nil,
    }
    if BPX.ensurePump then BPX.ensurePump() end      -- the pump timer hosts the watchdog
end

function BPX.resume(reason)
    local h = serverState.halted
    if not h then return nil end
    pcall(debug_continueFromBreakpoint, co_run)
    serverState.halted = nil
    serverState.last_halt = { breakpoint = h.id, reason = reason, halted_seconds = os.clock() - h.since, steps = h.steps }
    return h
end

-- Called from the pump timer. Resumes a halted thread whose client went away; returns true while one is still halted.
function BPX.watchdog()
    local h = serverState.halted
    if not h then return false end
    local now = os.clock()
    if now >= h.deadline or now >= h.hard_deadline then
        BPX.resume(now >= h.hard_deadline and "hard limit reached" or "timeout")
        local bp = serverState.breakpoints[h.id]
        if bp then bp.auto_resumed = (bp.auto_resumed or 0) + 1 end
        return false
    end
    return true
end

-- One hit: condition -> record -> max_hits -> optionally halt. Returns "halt" to leave the thread stopped.
function BPX.handle(bpId, buildHit)
    local bp = serverState.breakpoints[bpId]
    if not bp then return nil end                          -- removed while the hit was in flight
    bp.seen_hits = (bp.seen_hits or 0) + 1
    if bp.completed then return nil end                    -- max_hits reached, waiting for the deferred detach
    local pass, condErr = BPX.test(bp)
    if not pass then
        bp.filtered_hits = (bp.filtered_hits or 0) + 1
        return nil
    end
    local hit = buildHit(bp)
    if hit == nil then
        bp.filtered_hits = (bp.filtered_hits or 0) + 1
        return nil
    end
    if condErr then hit.condition_error = condErr end
    recordBpHit(bpId, hit)
    if bp.max_hits and (bp.total_hits or 0) >= bp.max_hits then
        bp.completed = true
        BPX.scheduleDetach(bpId)
    end
    if bp.mode == "break" and not serverState.halted then
        BPX.halt(bpId, bp, hit)
        return "halt"
    end
    return nil
end

function BPX.invalid(msg)
    return { success = false, error = msg, error_code = "INVALID_PARAMS" }
end

-- Shared by set_breakpoint (kind "execute") and set_data_breakpoint (kind "data").
function BPX.install(kind, params)
    local perr = requireProcess()
    if perr then return perr end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local mode = params.mode or "log"
    if mode ~= "log" and mode ~= "break" then return BPX.invalid("mode must be 'log' or 'break'") end
    local maxHits
    if params.max_hits ~= nil then
        maxHits = math.tointeger(tonumber(params.max_hits))
        if not maxHits or maxHits < 1 then return BPX.invalid("max_hits must be a positive integer") end
    end
    local haltMs = math.max(100, math.min(tonumber(params.halt_timeout_ms) or BPX.HALT_DEFAULT_MS, BPX.HALT_MAX_MS))

    local size, accessType, trigger = 1, nil, bptExecute
    if kind == "data" then
        accessType = params.access_type or "w"
        if accessType ~= "r" and accessType ~= "w" and accessType ~= "rw" then return BPX.invalid("access_type must be 'r', 'w' or 'rw'") end
        size = math.tointeger(tonumber(params.size or 4)) or 0
        if size ~= 1 and size ~= 2 and size ~= 4 and size ~= 8 then return BPX.invalid("size must be 1, 2, 4 or 8") end
        if addr % size ~= 0 then
            return BPX.invalid(string.format("a %d-byte hardware data breakpoint must be %d-byte aligned; %s is not", size, size, toHex(addr)))
        end
        trigger = (accessType == "w") and bptWrite or bptAccess     -- x86 debug registers cannot watch reads only
    end

    local bpId = params.id or tostring(addr)
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    local bp = { address = addr, type = (kind == "data") and "data" or "execute", mode = mode, max_hits = maxHits,
                 halt_timeout_ms = haltMs, size = size, access_type = accessType, created = os.time() }
    if params.condition ~= nil and params.condition ~= "" then
        local fn, err = BPX.compile(params.condition, bp)
        if not fn then return BPX.invalid("Invalid condition: " .. tostring(err)) end
        bp.condition, bp.condition_fn = params.condition, fn
    end
    if params.inspect ~= nil then
        if mode ~= "break" then return BPX.invalid("inspect only applies to mode 'break'") end
        if type(params.inspect) ~= "table" or #params.inspect > BPX.MAX_INSPECT then
            return BPX.invalid("inspect must be a list of at most " .. BPX.MAX_INSPECT .. " {expr, size} entries")
        end
        bp.inspect = {}
        for i, spec in ipairs(params.inspect) do
            local fn, err = BPX.compile(type(spec) == "table" and spec.expr or nil, bp)
            if not fn then return BPX.invalid("inspect[" .. i .. "]: " .. tostring(err)) end
            bp.inspect[i] = { expr = spec.expr, fn = fn, size = math.max(1, math.min(math.tointeger(tonumber(spec.size)) or 16, 256)) }
        end
    end

    clearGhostBpSlot(addr)

    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end
    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)", error_code = "OUT_OF_RESOURCES" }
    end

    if kind == "execute" then
        -- Remove existing breakpoint at this address
        pcall(function() debug_removeBreakpoint(addr) end)
    else
        bp.last_value = BPX.readValue(addr, size)       -- baseline for value_changed / read filtering
    end

    bp.slot = slot
    serverState.breakpoint_hits[bpId] = {}
    serverState.breakpoints[bpId] = bp
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }

    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16

    local function buildExecuteHit(b)
        local hit = { id = bpId, address = toHex(addr), timestamp = os.time(), breakpoint_type = "hardware_execute" }
        if captureRegs then hit.registers = captureRegisters() end
        if captureStackFlag then hit.stack = captureStack(stackDepth) end
        return hit
    end

    local function buildDataHit(b)
        local arch = getArchInfo()
        local value = BPX.readValue(addr, size)
        local prev = b.last_value
        b.last_value = value
        -- 'r' can only be approximated (the CPU reports reads and writes): a changed value means that was a write
        if accessType == "r" and prev ~= nil and value ~= prev then return nil end
        local changed                                   -- not `x and y or nil`: that turns false into nil
        if prev ~= nil and value ~= nil then changed = (value ~= prev) end
        local instPtr = arch.instPtr
        return {
            id = bpId, type = "data_" .. accessType, address = toHex(addr), size = size, timestamp = os.time(),
            breakpoint_type = "hardware_data", value = value, previous_value = prev,
            value_changed = changed,
            registers = captureRegisters(), instruction = instPtr and disassemble(instPtr) or "???",
            arch = arch.is64bit and "x64" or "x86",
        }
    end

    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    local build = (kind == "data") and buildDataHit or buildExecuteHit
    local ok, err = pcall(debug_setBreakpoint, addr, size, trigger, bpmDebugRegister,
                          safeBpCallback(function() return BPX.handle(bpId, build) end))
    if not ok then
        serverState.breakpoints[bpId] = nil
        serverState.breakpoint_hits[bpId] = nil
        serverState.hw_bp_slots[slot] = nil
        return { success = false, error = "debug_setBreakpoint failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end

    local out = { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register", mode = mode,
                  condition = bp.condition, max_hits = maxHits }
    if mode == "break" then out.halt_timeout_ms = haltMs end
    if kind == "data" then
        out.access_type, out.size = accessType, size
        if accessType == "r" then
            out.note = "x86 debug registers cannot watch reads only: this watches read+write and drops hits where the value changed (a write). A write of the identical value looks like a read."
        end
    end
    return out
end

function cmd_set_breakpoint(params)
    return BPX.install("execute", params)
end

function cmd_set_data_breakpoint(params)
    return BPX.install("data", params)
end

function cmd_remove_breakpoint(params)
    local bpId = params.id

    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        if serverState.halted and serverState.halted.id == bpId then BPX.resume("breakpoint removed") end
        if not bp.detached then
            pcall(function() debug_removeBreakpoint(bp.address) end)
        end

        if bp.slot then
            serverState.hw_bp_slots[bp.slot] = nil
        end

        serverState.breakpoints[bpId] = nil
        return { success = true, id = bpId }
    end

    return { success = false, error = "Breakpoint not found: " .. tostring(bpId) }
end

function cmd_get_breakpoint_hits(params)
    local bpId = params.id
    local clear = params.clear ~= false

    local hits
    if bpId then
        hits = serverState.breakpoint_hits[bpId] or {}
        if clear then serverState.breakpoint_hits[bpId] = {} end
    else
        hits = {}
        for id, hitsForBp in pairs(serverState.breakpoint_hits) do
            for _, hit in ipairs(hitsForBp) do
                hits[#hits + 1] = hit
            end
        end
        if clear then
            for id in pairs(serverState.breakpoint_hits) do
                serverState.breakpoint_hits[id] = {}
            end
        end
    end

    local limit, offset, page, total = paginate(params, hits, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, hits = page }
end

function cmd_list_breakpoints(params)
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        local state = "active"
        if bp.completed then state = "completed" end
        if serverState.halted and serverState.halted.id == id then state = "halted" end
        table.insert(list, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot,
            state = state,
            mode = bp.mode or "log",
            hit_count = #(serverState.breakpoint_hits[id] or {}),
            total_hits = bp.total_hits or 0,
            dropped_hits = bp.dropped_hits or 0,
            seen_hits = bp.seen_hits or 0,
            filtered_hits = bp.filtered_hits or 0,
            condition = bp.condition,
            condition_errors = bp.condition_errors,
            condition_disabled = bp.condition_disabled,
            max_hits = bp.max_hits,
            size = bp.size,
            access_type = bp.access_type,
            auto_resumed = bp.auto_resumed,
        })
    end
    return { success = true, count = #list, breakpoints = list }
end

function cmd_clear_all_breakpoints(params)
    local count = 0
    if serverState.halted then BPX.resume("all breakpoints cleared") end
    for id, bp in pairs(serverState.breakpoints) do
        if not bp.detached then
            pcall(function() debug_removeBreakpoint(bp.address) end)
        end
        count = count + 1
    end
    serverState.breakpoints = {}
    for id in pairs(serverState.breakpoint_hits) do
        serverState.breakpoint_hits[id] = {}
    end
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- State of a thread stopped by a mode="break" breakpoint (or by stepping from one): fresh registers, the instruction,
-- stack, the memory the breakpoint asked to inspect and the time left before the watchdog resumes it.
-- Resume with debug_continue (run / step_into / step_over). `extend_ms` postpones the watchdog.
function cmd_get_halted_state(params)
    local h = serverState.halted
    if not h then
        return { success = true, halted = false, last_halt = serverState.last_halt }
    end
    local now = os.clock()
    local okB, broken = pcall(debug_isBroken)
    local grace = h.stepping and (now - (h.step_started or 0)) < 2
    if okB and not broken and not grace then
        serverState.halted = nil
        serverState.last_halt = { breakpoint = h.id, reason = "resumed outside the bridge", halted_seconds = now - h.since, steps = h.steps }
        return { success = true, halted = false, note = "The thread was resumed outside the bridge (Cheat Engine's UI?).", last_halt = serverState.last_halt }
    end
    if params.extend_ms then
        local ms = math.max(0, math.min(tonumber(params.extend_ms) or 0, BPX.HALT_MAX_MS))
        h.deadline = math.min(now + ms / 1000, h.hard_deadline)
    end
    pcall(debug_getContext, true)             -- the register globals are only valid after a refresh
    local arch = getArchInfo()
    local depth = math.max(1, math.min(tonumber(params.stack_depth) or 16, 256))
    return {
        success = true, halted = true, breakpoint = h.id, stepping = h.stepping or false, steps = h.steps,
        halted_seconds = now - h.since, auto_resume_in_seconds = math.max(0, h.deadline - now),
        registers = captureRegisters(), instruction = arch.instPtr and disassemble(arch.instPtr) or nil,
        stack = captureStack(depth), memory = h.memory, hit = (not h.stepping) and h.hit or nil,
    }
end


-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end
    
    local fn, err = load(code, "mcp_evaluate_lua", "t")
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end
    
    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end
    
    return { success = true, result = tostring(result) }
end

-- >>> BEGIN UNIT-22 Threading Sync <<<
-- ============================================================================
-- COMMAND HANDLERS - THREADING & SYNCHRONIZATION
-- These operate on CE's Lua scripting host, NOT the target process.
-- No process guard is needed or appropriate here.
-- ============================================================================

local _unit22_thread_counter = 0

function cmd_create_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process.
    -- It carries the same risk as evaluate_lua. Only use with trusted code.
    local code = params.code
    local arg  = params.arg or ""
    if not code then return { success = false, error = "No code provided" } end

    local ok, err = pcall(function()
        createThread(function(thread, a)
            local f, ferr = loadstring(code)
            if not f then error("Compile error: " .. tostring(ferr)) end
            return f(thread, a)
        end, arg)
    end)

    if not ok then
        return { success = false, error = "createThread failed: " .. tostring(err) }
    end
    _unit22_thread_counter = _unit22_thread_counter + 1
    return { success = true, thread_id = _unit22_thread_counter }
end

function cmd_get_global_variable(params)
    local name = params.name
    if not name then return { success = false, error = "No variable name provided" } end

    local ok, value = pcall(getGlobalVariable, name)
    if not ok then
        return { success = false, error = "getGlobalVariable failed: " .. tostring(value) }
    end
    return { success = true, value = tostring(value) }
end

function cmd_set_global_variable(params)
    local name  = params.name
    local value = params.value
    if not name  then return { success = false, error = "No variable name provided"  } end
    if value == nil then return { success = false, error = "No value provided" } end

    local ok, err = pcall(setGlobalVariable, name, value)
    if not ok then
        return { success = false, error = "setGlobalVariable failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_queue_to_main_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    -- on the main thread. It carries the same risk as evaluate_lua.
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end

    local ok, err = pcall(function()
        queue(function()
            local f, ferr = loadstring(code)
            if not f then error("Compile error: " .. tostring(ferr)) end
            f()
        end)
    end)

    if not ok then
        return { success = false, error = "queue failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_check_synchronize(params)
    local ok, err = pcall(checkSynchronize)
    if not ok then
        return { success = false, error = "checkSynchronize failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_in_main_thread(params)
    local ok, result = pcall(inMainThread)
    if not ok then
        return { success = false, error = "inMainThread failed: " .. tostring(result) }
    end
    return { success = true, is_main_thread = result == true }
end

-- >>> END UNIT-22 <<<

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

function cmd_get_memory_regions(params)
    local regions = {}
    local maxRegions = params.max or 100
    local pageSize = 0x1000  -- 4KB pages
    
    -- Sample memory at common base addresses to find valid regions
    local sampleAddresses = {
        0x00010000, 0x00400000, 0x10000000, 0x20000000, 0x30000000,
        0x40000000, 0x50000000, 0x60000000, 0x70000000
    }
    
    -- Also add addresses from modules we found via AOB scan
    local mzScan = AOBScan("4D 5A 90 00 03 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, 20) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then table.insert(sampleAddresses, addr) end
        end
        mzScan.destroy()
    end
    
    -- Check each sample address for memory protection
    for _, baseAddr in ipairs(sampleAddresses) do
        if #regions >= maxRegions then break end
        
        local ok, prot = pcall(getMemoryProtection, baseAddr)
        if ok and prot then
            -- Found a valid memory page
            local protStr = ""
            if prot.r then protStr = protStr .. "R" end
            if prot.w then protStr = protStr .. "W" end
            if prot.x then protStr = protStr .. "X" end
            
            -- Try to find region size by scanning forward
            local regionSize = pageSize
            for offset = pageSize, 0x1000000, pageSize do
                local ok2, prot2 = pcall(getMemoryProtection, baseAddr + offset)
                if not ok2 or not prot2 or 
                   prot2.r ~= prot.r or prot2.w ~= prot.w or prot2.x ~= prot.x then
                    break
                end
                regionSize = offset + pageSize
            end
            
            table.insert(regions, {
                base = toHex(baseAddr),
                size = regionSize,
                protection = protStr,
                readable = prot.r or false,
                writable = prot.w or false,
                executable = prot.x or false
            })
        end
    end
    
    return { success = true, count = #regions, regions = regions }
end

-- ============================================================================
-- COMMAND HANDLERS - UTILITY
-- ============================================================================

function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

function cmd_search_string(params)
    local searchStr = params.string or params.pattern
    local wide = params.wide or false
    local limit = params.limit or 100
    
    if not searchStr then return { success = false, error = "No search string" } end
    
    -- Convert string to AOB pattern
    local pattern = ""
    for i = 1, #searchStr do
        if i > 1 then pattern = pattern .. " " end
        pattern = pattern .. string.format("%02X", searchStr:byte(i))
        if wide then pattern = pattern .. " 00" end
    end
    
    local results = AOBScan(pattern)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addr = tonumber(results.getString(i), 16)
        local preview = readString(addr, 50, wide) or ""
        table.insert(addresses, {
            address = "0x" .. results.getString(i),
            preview = preview
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, addresses = addresses }
end

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
function cmd_dissect_structure(params)
    local address = params.address
    local size = params.size or 256
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure" }
    end
    
    -- Use the Structure class autoGuess method
    pcall(function() struct:autoGuess(address, 0, size) end)
    
    local elements = {}
    local count = struct.Count or 0
    
    for i = 0, count - 1 do
        local elem = struct.Element[i]
        if elem then
            local val = nil
            -- Try to get current value
            pcall(function() val = elem:getValue(address) end)
            
            table.insert(elements, {
                offset = elem.Offset,
                hex_offset = string.format("+0x%X", elem.Offset),
                name = elem.Name or "",
                vartype = elem.Vartype,
                bytesize = elem.Bytesize,
                current_value = val
            })
        end
    end
    
    -- Cleanup - don't add to global list
    pcall(function() struct:removeFromGlobalStructureList() end)
    
    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
function cmd_get_thread_list(params)
    local list = createStringlist()
    getThreadlist(list)

    local allThreads = {}
    for i = 0, list.Count - 1 do
        local idHex = list[i]
        allThreads[#allThreads + 1] = { id_hex = idHex, id_int = tonumber(idHex, 16) }
    end
    list.destroy()

    local limit, offset, page, total = paginate(params, allThreads, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, threads = page }
end

-- AutoAssemble: Execute an AutoAssembler script
function cmd_auto_assemble(params)
    local script = params.script or params.code
    local disable = params.disable or false
    
    if not script then return { success = false, error = "No script provided" } end
    
    local success, disableInfo = autoAssemble(script)
    
    if success then
        local result = {
            success = true,
            executed = true
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo)
        }
    end
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
function cmd_enum_memory_regions_full(params)
    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed" }
    end

    local allRegions = {}
    for i, r in ipairs(regions) do
        local prot = r.Protect or 0
        local state = r.State or 0
        local protStr
        if     prot == 0x10 then protStr = "X"
        elseif prot == 0x20 then protStr = "RX"
        elseif prot == 0x40 then protStr = "RWX"
        elseif prot == 0x80 then protStr = "WX"
        elseif prot == 0x02 then protStr = "R"
        elseif prot == 0x04 then protStr = "RW"
        elseif prot == 0x08 then protStr = "W"
        else                     protStr = string.format("0x%X", prot)
        end

        allRegions[#allRegions + 1] = {
            base             = toHex(r.BaseAddress or 0),
            allocation_base  = toHex(r.AllocationBase or 0),
            size             = r.RegionSize or 0,
            state            = state,
            protect          = prot,
            protect_string   = protStr,
            type             = r.Type or 0,
            is_committed     = state == 0x1000,
            is_reserved      = state == 0x2000,
            is_free          = state == 0x10000
        }
    end

    local limit, offset, page, total = paginate(params, allRegions, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, regions = page }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
function cmd_read_pointer_chain(params)
    local offsets = params.offsets or {}
    local r = resolveChain(params.base, offsets)
    if not r.ok then
        return { success = false, error = r.error, partial_chain = r.chain, failed_at_address = r.failed_at }
    end
    return {
        success = true,
        base = r.base,
        offsets = offsets,
        final_address = r.final_address_hex,
        final_value = r.final_value,
        chain = r.chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
function cmd_get_rtti_classname(params)
    local address = params.address
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local className = getRTTIClassName(address)
    
    if className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
function cmd_get_address_info(params)
    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
function cmd_checksum_memory(params)
    local address = params.address
    local size = params.size or 256
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local ok, hash = pcall(md5memory, address, size)
    
    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash)
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
function cmd_generate_signature(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)
    
    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature)
        }
    end
    
    if not signature or signature == "" then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature - pattern not unique enough"
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

-- ============================================================================
-- DBVM HYPERVISOR TOOLS (Safe Dynamic Tracing - Ring -1)
-- ============================================================================
-- These tools use DBVM (Debuggable Virtual Machine) for hypervisor-level tracing.
-- They are 100% invisible to anti-cheat: no game memory modification, no debug registers.
-- DBVM works at the hypervisor level, beneath the OS, making it undetectable.
-- ============================================================================

-- Get Physical Address: Converts virtual address to physical RAM address
-- Required for DBVM operations which work on physical memory
function cmd_get_physical_address(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- Check if DBK (kernel driver) is available
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    
    if not ok then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings."
        }
    end
    
    if not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page may not be present in RAM."
        }
    end
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        physical_int = phys
    }
end

-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
function cmd_start_dbvm_watch(params)
    local addr = params.address
    local mode = params.mode or "w"  -- "w" = write, "r" = read, "rw" = both, "x" = execute
    local maxEntries = params.max_entries or 1000  -- Internal buffer size
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- 0. Safety Checks
    if not dbk_initialized() then
        return { success = false, error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode" }
    end
    
    if not dbvm_initialized() then
        -- Try to initialize if possible
        pcall(dbvm_initialize)
        if not dbvm_initialized() then
            return { success = false, error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM" }
        end
    end

    -- 1. Get Physical Address (DBVM works on physical RAM)
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    if not ok or not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page might be paged out or invalid."
        }
    end
    
    -- 2. Check if already watching this address
    local watchKey = toHex(addr)
    if serverState.active_watches[watchKey] then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Already watching this address. Call stop_dbvm_watch first."
        }
    end
    
    -- 3. Configure watch options
    -- Bit 0: Log multiple times (1 = yes)
    -- Bit 1: Ignore size / log whole page (2)
    -- Bit 2: Log FPU registers (4)
    -- Bit 3: Log Stack (8)
    local options = 1 + 2 + 8  -- Multiple logging + whole page + stack context
    
    -- 4. Start the appropriate watch based on mode
    local watch_id
    local okWatch, result
    
    log(string.format("Starting DBVM watch on Phys: 0x%X (Mode: %s)", phys, mode))

    if mode == "x" then
        if not dbvm_watch_executes then
            return { success = false, error = "dbvm_watch_executes function missing from CE Lua engine" }
        end
        okWatch, result = pcall(dbvm_watch_executes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    elseif mode == "r" or mode == "rw" then
        okWatch, result = pcall(dbvm_watch_reads, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    else  -- default: write
        okWatch, result = pcall(dbvm_watch_writes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    end
    
    if not okWatch then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch CRASHED/FAILED: " .. tostring(result)
        }
    end
    
    if not watch_id then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch returned nil (check CE console for details)"
        }
    end
    
    -- 5. Store watch for later retrieval
    serverState.active_watches[watchKey] = {
        id = watch_id,
        physical = phys,
        mode = mode,
        start_time = os.time()
    }
    
    return {
        success = true,
        status = "monitoring",
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        watch_id = watch_id,
        mode = mode,
        note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end"
    }
end

-- Poll DBVM Watch: Retrieve logged accesses WITHOUT stopping the watch
-- This is CRITICAL for continuous packet monitoring - logs can be polled repeatedly
function cmd_poll_dbvm_watch(params)
    local addr = params.address
    local clear = (params.clear ~= false)  -- nil→true, false→false, true→true
    local max_results = params.max_results or 1000
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address. Call start_dbvm_watch first."
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}
    
    -- Retrieve log entries (DBVM accumulates these automatically)
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    
    if okLog and log then
        local count = math.min(#log, max_results)
        for i = 1, count do
            local entry = log[i]
            -- For packet capture, we need the stack pointer to read [ESP+4]
            -- ESP/RSP contains the stack pointer at time of execution
            local hitData = {
                hit_number = i,
                -- 32-bit game uses ESP, 64-bit uses RSP
                ESP = entry.RSP and toHexLow32(entry.RSP) or nil,
                RSP = entry.RSP and toHex(entry.RSP) or nil,
                EIP = entry.RIP and toHexLow32(entry.RIP) or nil,
                RIP = entry.RIP and toHex(entry.RIP) or nil,
                -- Include key registers that might hold packet buffer
                EAX = entry.RAX and toHexLow32(entry.RAX) or nil,
                ECX = entry.RCX and toHexLow32(entry.RCX) or nil,
                EDX = entry.RDX and toHexLow32(entry.RDX) or nil,
                EBX = entry.RBX and toHexLow32(entry.RBX) or nil,
                ESI = entry.RSI and toHexLow32(entry.RSI) or nil,
                EDI = entry.RDI and toHexLow32(entry.RDI) or nil,
            }
            table.insert(results, hitData)
        end
    end

    if clear then
        pcall(dbvm_watch_clearlog, watch_id)
    end

    local uptime = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        status = "active",
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        uptime_seconds = uptime,
        hit_count = #results,
        hits = results,
        note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end."
    }
end

-- Stop DBVM Watch: Retrieve logged accesses and disable monitoring
-- Returns all instructions that touched the monitored memory
function cmd_stop_dbvm_watch(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address"
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}
    
    -- 1. Retrieve the log of all memory accesses
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    
    if okLog and log then
        -- Parse each log entry (contains CPU context at time of access)
        for i, entry in ipairs(log) do
            local hitData = {
                hit_number = i,
                instruction_address = entry.RIP and toHex(entry.RIP) or nil,
                instruction = entry.RIP and (pcall(disassemble, entry.RIP) and disassemble(entry.RIP) or "???") or "???",
                -- CPU registers at time of access
                registers = {
                    RAX = entry.RAX and toHex(entry.RAX) or nil,
                    RBX = entry.RBX and toHex(entry.RBX) or nil,
                    RCX = entry.RCX and toHex(entry.RCX) or nil,
                    RDX = entry.RDX and toHex(entry.RDX) or nil,
                    RSI = entry.RSI and toHex(entry.RSI) or nil,
                    RDI = entry.RDI and toHex(entry.RDI) or nil,
                    RBP = entry.RBP and toHex(entry.RBP) or nil,
                    RSP = entry.RSP and toHex(entry.RSP) or nil,
                    RIP = entry.RIP and toHex(entry.RIP) or nil
                }
            }
            table.insert(results, hitData)
        end
    end
    
    -- 2. Disable the watch
    pcall(dbvm_watch_disable, watch_id)
    
    -- 3. Clean up
    serverState.active_watches[watchKey] = nil
    
    local duration = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        hit_count = #results,
        duration_seconds = duration,
        hits = results,
        note = #results > 0 and "Found instructions that accessed the memory" or "No accesses detected during monitoring"
    }
end

-- >>> BEGIN UNIT-23 Debug Multimedia <<<

local progressStateMap = {
    none          = tbpsNone,
    normal        = tbpsNormal,
    paused        = tbpsPaused,
    error         = tbpsError,
    indeterminate = tbpsIndeterminate,
}

function cmd_output_debug_string(params)
    local message = params.message
    if type(message) ~= "string" then
        return { success = false, error = "message must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(outputDebugString, message)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_speak_text(params)
    local text = params.text
    if type(text) ~= "string" then
        return { success = false, error = "text must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err
    if params.english_only then
        ok, err = pcall(speakEnglish, text)
    else
        ok, err = pcall(speak, text)
    end
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_play_sound(params)
    if type(params.filename) ~= "string" or params.filename:find("%.%.") then
        return { success = false, error = "Invalid filename", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(playSound, params.filename)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_beep(params)
    local ok, err = pcall(beep)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_set_progress_state(params)
    local tbState = progressStateMap[params.state]
    if not tbState then
        return { success = false, error = "state must be one of: none, normal, paused, error, indeterminate", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressState, tbState)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_set_progress_value(params)
    local current = params.current
    local max = params.max
    if type(current) ~= "number" or type(max) ~= "number" then
        return { success = false, error = "current and max must be numbers", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressValue, current, max)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

-- >>> END UNIT-23 <<<

-- >>> BEGIN UNIT-21 Kernel DBVM <<<
-- ============================================================================
-- COMMAND HANDLERS - KERNEL MODE / DBVM EXTENSIONS (Unit 21)
-- Requires DBK kernel driver and/or DBVM hypervisor to be loaded.
-- ============================================================================

-- MDL handles for active mapMemory() calls, keyed by mapped-address hex string.
-- mapMemory() returns (address, mdl); unmapMemory() needs the mdl to release it.
-- Cleared by cleanupZombieState() on bridge stop/restart.
local mappedMemoryMDL = {}

local function dbkNotLoadedError()
    return {
        success = false,
        error = "Kernel driver (DBK) or hypervisor (DBVM) not loaded",
        error_code = "DBK_NOT_LOADED"
    }
end

function cmd_dbk_get_cr0(params)
    local ok, result = pcall(dbk_getCR0)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr0 = toHex(result) }
end

function cmd_dbk_get_cr3(params)
    local ok, result = pcall(dbk_getCR3)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr3 = toHex(result) }
end

function cmd_dbk_get_cr4(params)
    local ok, result = pcall(dbk_getCR4)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr4 = toHex(result) }
end

function cmd_read_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local size     = tonumber(params.size)

    if not cr3_str or not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters cr3, address and size are required" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value" }
    end

    local ok, byteTable = pcall(readProcessMemoryCR3, cr3, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not byteTable then
        return { success = false, error = "Read failed — page may be paged out or invalid" }
    end

    return { success = true, bytes = byteTable, size = #byteTable }
end

function cmd_write_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local bytes    = params.bytes

    if not cr3_str or not addr_str or not bytes or type(bytes) ~= "table" then
        return { success = false, error = "Parameters cr3, address and bytes (list) are required" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value" }
    end

    local ok = pcall(writeProcessMemoryCR3, cr3, addr, bytes)
    if not ok then return dbkNotLoadedError() end

    return { success = true, bytes_written = #bytes }
end

function cmd_map_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local addr_str = params.address
    local size     = tonumber(params.size)

    if not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters address and size are required" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid address value" }
    end

    local ok, mappedAddr, mdl = pcall(mapMemory, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not mappedAddr then
        return { success = false, error = "mapMemory failed — address may be invalid or DBK not loaded" }
    end

    local key = toHex(mappedAddr)
    mappedMemoryMDL[key] = mdl  -- retain MDL so unmap_memory can release it

    return { success = true, mapped_address = key }
end

function cmd_unmap_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local addr_str = params.mapped_address
    if not addr_str then
        return { success = false, error = "Parameter mapped_address is required" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid mapped_address value" }
    end

    local key = toHex(addr)
    local ok  = pcall(unmapMemory, addr, mappedMemoryMDL[key])
    if not ok then return dbkNotLoadedError() end

    mappedMemoryMDL[key] = nil

    return { success = true }
end

function cmd_dbk_writes_ignore_write_protection(params)
    local enable = params.enable
    if type(enable) ~= "boolean" then
        return { success = false, error = "Parameter enable (boolean) is required" }
    end

    local ok = pcall(dbk_writesIgnoreWriteProtection, enable)
    if not ok then return dbkNotLoadedError() end

    return { success = true }
end

function cmd_get_physical_address_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str = params.cr3
    local va_str  = params.virtual_address

    if not cr3_str or not va_str then
        return { success = false, error = "Parameters cr3 and virtual_address are required" }
    end

    local cr3 = type(cr3_str) == "string" and getAddressSafe(cr3_str) or cr3_str
    local va  = type(va_str)  == "string" and getAddressSafe(va_str)  or va_str
    if not cr3 or not va then
        return { success = false, error = "Invalid cr3 or virtual_address value" }
    end

    local ok, phys = pcall(getPhysicalAddressCR3, cr3, va)
    if not ok then return dbkNotLoadedError() end
    if not phys then
        return { success = false, error = "Address not paged — virtual address may not be mapped in this CR3" }
    end

    return { success = true, physical_address = toHex(phys) }
end

-- >>> END UNIT-21 <<<
-- >>> BEGIN UNIT-20a File IO Clipboard <<<
-- ============================================================================
-- UNIT-20a: Safe File I/O and Clipboard Tools
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f == "" then return nil, "Invalid filename" end
    if f:find("%.%.") then return nil, "Path traversal not allowed" end
    return f, nil
end

function cmd_file_exists(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(fileExists, f)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, exists = result == true }
end

function cmd_delete_file(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(deleteFile, f)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true }
end

local function listPathEntries(path, ceFn, resultKey)
    local f, err = sanitizeFilename(path)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(ceFn, f)
    if not ok then return { success = false, error = tostring(result) } end
    local entries = {}
    if type(result) == "table" then
        for _, v in ipairs(result) do table.insert(entries, v) end
    end
    return { success = true, count = #entries, [resultKey] = entries }
end

function cmd_get_file_list(params)
    return listPathEntries(params.path, getFileList, "files")
end

function cmd_get_directory_list(params)
    return listPathEntries(params.path, getDirectoryList, "directories")
end

function cmd_get_temp_folder(params)
    local ok, result = pcall(getTempFolder)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, path = tostring(result) }
end

function cmd_get_file_version(params)
    local f, err = sanitizeFilename(params.filename)
    if not f then return { success = false, error = err } end
    -- getFileVersion returns two values; wrap in a closure so pcall captures both
    local ok, errOrRaw, verTable = pcall(function() return getFileVersion(f) end)
    if not ok then return { success = false, error = tostring(errOrRaw) } end
    if type(verTable) ~= "table" then
        return { success = false, error = "getFileVersion did not return a version table" }
    end
    local major   = verTable.major   or 0
    local minor   = verTable.minor   or 0
    local release = verTable.release or 0
    local build   = verTable.build   or 0
    return {
        success = true,
        major = major,
        minor = minor,
        release = release,
        build = build,
        version_string = string.format("%d.%d.%d.%d", major, minor, release, build)
    }
end

function cmd_read_clipboard(params)
    local ok, result = pcall(readFromClipboard)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, text = tostring(result or "") }
end

function cmd_write_clipboard(params)
    local text = params.text
    if type(text) ~= "string" then return { success = false, error = "text must be a string" } end
    local ok, err = pcall(writeToClipboard, text)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

-- >>> END UNIT-20a <<<

-- ============================================================================
-- UNIT-20b: Shell Execution Handlers
-- NOTE: Security gate (CE_MCP_ALLOW_SHELL env var check) is enforced on the
--       Python side, before this Lua code is ever reached.
-- ============================================================================

-- run_command: Wraps CE's runCommand(exepath, parameters, pathtoexecutein)
-- Returns output string and exit code. SECURITY: arbitrary code execution.
function cmd_run_command(params)
    local command = params.command
    local args = params.args or ""

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    local ok, output, exitCode = pcall(runCommand, command, args)

    if not ok then
        return { success = false, error = "runCommand failed: " .. tostring(output) }
    end

    return {
        success = true,
        output = tostring(output or ""),
        exit_code = tonumber(exitCode) or 0
    }
end

-- shell_execute: Wraps CE's shellExecute(command, parameters, folder, showcommand)
-- SECURITY: arbitrary code execution via Windows ShellExecute.
function cmd_shell_execute(params)
    local command = params.command
    local args = params.args or ""
    local verb = string.lower(params.verb or "open")
    local workingDir = params.working_dir or ""
    local showCommand = params.showcommand

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    -- CE's shellExecute wrapper does not expose an explicit "verb" argument.
    -- Keep compatibility explicit to avoid silent behavior differences.
    if verb ~= "open" then
        return { success = false, error = "Unsupported verb for shell_execute: " .. tostring(verb), error_code = "INVALID_PARAMS" }
    end

    if showCommand ~= nil and type(showCommand) ~= "number" then
        return { success = false, error = "showcommand must be a number when provided", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(shellExecute, command, args, workingDir ~= "" and workingDir or nil, showCommand)

    if not ok then
        return { success = false, error = "shellExecute failed: " .. tostring(err) }
    end

    return { success = true }
end

-- >>> END UNIT-20b <<<

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

-- >>> BEGIN UNIT-19 Structure Management <<<

serverState.structures = serverState.structures or {}
serverState.structure_next_id = serverState.structure_next_id or 1

local vartypeMap = {
    byte      = vtByte,
    word      = vtWord,
    dword     = vtDword,
    qword     = vtQword,
    float     = vtSingle,
    single    = vtSingle,
    double    = vtDouble,
    string    = vtString,
    aob       = vtByteArray,
    bytearray = vtByteArray,
    pointer   = vtPointer,
}

-- Constant reverse map; hoisted so it is not reallocated on every call.
local vtypeNames = {
    [vtByte]      = "byte",
    [vtWord]      = "word",
    [vtDword]     = "dword",
    [vtQword]     = "qword",
    [vtSingle]    = "float",
    [vtDouble]    = "double",
    [vtString]    = "string",
    [vtByteArray] = "aob",
    [vtPointer]   = "pointer",
}

local function vtypeToString(vt)
    return vtypeNames[vt] or tostring(vt)
end

-- Hoisted so it is not re-created on every export call.
local function xmlEscape(s)
    s = tostring(s)
    s = s:gsub("&", "&amp;")
    s = s:gsub("<", "&lt;")
    s = s:gsub(">", "&gt;")
    s = s:gsub('"', "&quot;")
    s = s:gsub("'", "&apos;")
    return s
end

-- Returns structure object on success, or nil + error-result table on failure.
local function resolveStructure(params)
    local sid = params.structure_id
    if not sid then
        return nil, { success = false, error = "structure_id is required", error_code = "INVALID_PARAMS" }
    end
    local structure = serverState.structures[sid]
    if not structure then
        return nil, { success = false, error = "Unknown structure_id: " .. tostring(sid), error_code = "NOT_FOUND" }
    end
    return structure, nil
end

-- Reads element properties via pcall-guarded property access.
local function readElementProps(el)
    local name, offset, vt, size
    pcall(function() name   = el.Name    end)
    pcall(function() offset = el.Offset  end)
    pcall(function() vt     = el.Vartype end)
    pcall(function() size   = el.Bytesize end)
    return name or "", offset or 0, vt, size or 0
end

function cmd_create_structure(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, structure = pcall(createStructure, name)
    if not ok or not structure then
        return { success = false, error = "createStructure failed: " .. tostring(structure), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function() structure.addToGlobalStructureList() end)
    if not ok2 then
        return { success = false, error = "addToGlobalStructureList failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local id = serverState.structure_next_id
    serverState.structure_next_id = serverState.structure_next_id + 1
    serverState.structures[id] = structure

    return { success = true, structure_id = id }
end

function cmd_get_structure_by_name(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, count = pcall(getStructureCount)
    if not ok then
        return { success = false, error = "getStructureCount failed: " .. tostring(count), error_code = "CE_API_UNAVAILABLE" }
    end

    for i = 0, count - 1 do
        local ok2, s = pcall(getStructure, i)
        if ok2 and s then
            local ok3, sname = pcall(function() return s.Name end)
            if ok3 and sname == name then
                local sid = nil
                for id, stored in pairs(serverState.structures) do
                    local ok4, sn = pcall(function() return stored.Name end)
                    if ok4 and sn == name then sid = id; break end
                end
                if not sid then
                    sid = serverState.structure_next_id
                    serverState.structure_next_id = serverState.structure_next_id + 1
                    serverState.structures[sid] = s
                end
                local ok5, sz  = pcall(function() return s.Size end)
                local ok6, cnt = pcall(function() return s.Count end)
                return {
                    success       = true,
                    structure_id  = sid,
                    name          = name,
                    element_count = ok6 and cnt or 0,
                    size          = ok5 and sz  or 0,
                }
            end
        end
    end

    return { success = false, error = "Structure not found: " .. name, error_code = "NOT_FOUND" }
end

function cmd_add_element_to_structure(params)
    local ename  = params.name
    local offset = params.offset
    local etype  = params.type

    local structure, err = resolveStructure(params)
    if not structure then return err end

    if not ename or offset == nil or not etype then
        return { success = false, error = "name, offset, type are required", error_code = "INVALID_PARAMS" }
    end

    local vt = vartypeMap[string.lower(tostring(etype))]
    if not vt then
        return { success = false, error = "Unknown type: " .. tostring(etype), error_code = "INVALID_PARAMS" }
    end

    local ok, element = pcall(function() return structure.addElement() end)
    if not ok or not element then
        return { success = false, error = "addElement failed: " .. tostring(element), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function()
        element.Name    = ename
        element.Offset  = offset
        element.Vartype = vt
    end)
    if not ok2 then
        return { success = false, error = "Setting element properties failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok3, cnt = pcall(function() return structure.Count end)
    local idx = (ok3 and cnt) and (cnt - 1) or nil

    return { success = true, element_index = idx }
end

function cmd_get_structure_elements(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, cnt = pcall(function() return structure.Count end)
    if not ok then
        return { success = false, error = "Failed to read structure count: " .. tostring(cnt), error_code = "CE_API_UNAVAILABLE" }
    end

    local elements = {}
    for i = 0, cnt - 1 do
        local ok2, el = pcall(function() return structure.getElement(i) end)
        if ok2 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            elements[#elements + 1] = {
                name   = elName,
                offset = elOffset,
                type   = vtypeToString(elVt),
                size   = elSize,
            }
        end
    end

    return { success = true, structure_id = params.structure_id, elements = elements }
end

function cmd_export_structure_to_xml(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, sname = pcall(function() return structure.Name end)
    if not ok then sname = "Unknown" end
    local ok2, sz  = pcall(function() return structure.Size end)
    if not ok2 then sz = 0 end
    local ok3, cnt = pcall(function() return structure.Count end)
    if not ok3 then cnt = 0 end

    local lines = {}
    lines[#lines + 1] = '<?xml version="1.0" encoding="utf-8"?>'
    lines[#lines + 1] = string.format('<Structure Name="%s" Size="%d">', xmlEscape(sname), sz)

    for i = 0, cnt - 1 do
        local ok4, el = pcall(function() return structure.getElement(i) end)
        if ok4 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            lines[#lines + 1] = string.format(
                '  <Element Name="%s" Offset="%d" Type="%s" Size="%d"/>',
                xmlEscape(elName), elOffset, xmlEscape(vtypeToString(elVt)), elSize
            )
        end
    end

    lines[#lines + 1] = '</Structure>'

    return { success = true, xml = table.concat(lines, "\n") }
end

function cmd_delete_structure(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    pcall(function() structure.removeFromGlobalStructureList() end)
    pcall(function() structure.destroy() end)

    serverState.structures[params.structure_id] = nil
    return { success = true }
end
-- >>> BEGIN UNIT-18 Cheat Table Records <<<

local UNIT18_TYPE_MAP = {
    byte      = "vtByte",
    word      = "vtWord",
    dword     = "vtDword",
    qword     = "vtQword",
    float     = "vtSingle",
    single    = "vtSingle",
    double    = "vtDouble",
    string    = "vtString",
    bytearray = "vtByteArray",
    aob       = "vtByteArray",
}

-- Returns (al, nil) on success or (nil, error-response-table) on failure.
local function unit18_get_al()
    local ok, al = pcall(getAddressList)
    if not ok or not al then
        return nil, { success = false, error = "Cannot get AddressList", error_code = "CE_API_UNAVAILABLE" }
    end
    return al, nil
end

-- Returns (rec, nil) on success or (nil, error-response-table) when not found.
local function unit18_get_rec_by_id(al, id)
    local ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
    if not ok or not rec then
        return nil, { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end
    return rec, nil
end

-- Validates a table-file path: non-empty string, no directory traversal.
local function unit18_check_filename(filename)
    if type(filename) ~= "string" or filename == "" then
        return { success = false, error = "filename required", error_code = "INVALID_PARAMS" }
    end
    if filename:find("%.%.") then
        return { success = false, error = "Path traversal not allowed", error_code = "INVALID_PARAMS" }
    end
end

local function unit18_rec_to_table(rec)
    if not rec then return nil end

    local function prop(name)
        local ok, v = pcall(function() return rec[name] end)
        return ok and v or nil
    end

    local offsetCount = prop("OffsetCount") or 0
    local offsets = {}
    for i = 0, offsetCount - 1 do
        local ok, off = pcall(function() return rec.Offset[i] end)
        table.insert(offsets, ok and off or nil)
    end

    return {
        id          = prop("ID"),
        description = prop("Description") or "",
        address     = prop("Address")     or "",
        type        = prop("VarType")     or "",
        value       = prop("Value")       or "",
        offsets     = offsets,
        enabled     = prop("Active")      or false,
    }
end

function cmd_load_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(loadTable, filename, params.merge or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_save_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(saveTable, filename, params.protect or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_get_address_list(params)
    local offset = params.offset or 0
    local limit  = params.limit  or 100

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, count = pcall(function() return al.Count end)
    if not okC then count = 0 end

    local records = {}
    local returned = 0
    for i = offset, math.min(offset + limit - 1, count - 1) do
        local okR, rec = pcall(function() return al[i] end)
        if okR and rec then
            table.insert(records, unit18_rec_to_table(rec))
            returned = returned + 1
        end
    end

    return {
        success  = true,
        total    = count,
        offset   = offset,
        limit    = limit,
        returned = returned,
        records  = records,
    }
end

function cmd_get_memory_record(params)
    local id   = params.id
    local desc = params.description

    if id == nil and desc == nil then
        return { success = false, error = "id or description required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec
    if id ~= nil then
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
        if not ok then rec = nil end
    else
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByDescription(desc) end)
        if not ok then rec = nil end
    end

    if not rec then
        return { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end

    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_create_memory_record(params)
    local description = params.description
    local address     = params.address
    local typeStr     = string.lower(params.type or "dword")

    if type(description) ~= "string" or description == "" then
        return { success = false, error = "description required", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" or address == "" then
        return { success = false, error = "address required", error_code = "INVALID_PARAMS" }
    end

    local vtName = UNIT18_TYPE_MAP[typeStr]
    if not vtName then
        return { success = false, error = "Unknown type: " .. typeStr, error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, rec = pcall(function() return al:createMemoryRecord() end)
    if not okC or not rec then
        return { success = false, error = tostring(rec), error_code = "INTERNAL_ERROR" }
    end

    -- Helper: set a property, rolling back the record on failure.
    local function set_prop(name, val)
        local ok = pcall(function() rec[name] = val end)
        if not ok then
            pcall(function() rec:delete() end)
            return { success = false, error = "Failed to set " .. name, error_code = "INTERNAL_ERROR" }
        end
    end

    local perr = set_prop("Description", description)
    if perr then return perr end

    perr = set_prop("Address", address)
    if perr then return perr end

    -- VarType accepts the string constant name; fall back to the global numeric value.
    if not pcall(function() rec.VarType = vtName end) then
        pcall(function() rec.VarType = _G[vtName] end)
    end

    local okId, recId = pcall(function() return rec.ID end)
    if not okId then recId = nil end

    return { success = true, id = recId, record = unit18_rec_to_table(rec) }
end

function cmd_delete_memory_record(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec:delete() end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_get_memory_record_value(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, value = pcall(function() return rec.Value end)
    if not ok then
        return { success = false, error = tostring(value), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, value = tostring(value or "") }
end

function cmd_set_memory_record_value(params)
    local id    = params.id
    local value = params.value
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    if value == nil then
        return { success = false, error = "value required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec.Value = tostring(value) end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

-- >>> END UNIT-19 <<<

-- >>> END UNIT-18 <<<

-- >>> BEGIN UNIT-17 Input Automation <<<
-- ============================================================================
-- COMMAND HANDLERS - INPUT AUTOMATION (mouse, keyboard, screen)
-- These APIs operate system-wide and require NO attached process.
-- ============================================================================

-- Shared helpers (local to this section)
local function parse_xy(params)
    if params.x == nil then return nil, nil, "Missing parameter: x" end
    if params.y == nil then return nil, nil, "Missing parameter: y" end
    local x, y = tonumber(params.x), tonumber(params.y)
    if x == nil or y == nil then return nil, nil, "Parameters x and y must be numbers" end
    return x, y, nil
end

local function parse_vk(params)
    if params.vk == nil then return nil, "Missing parameter: vk (Windows virtual-key code, e.g. 0x41 for 'A')" end
    local vk = tonumber(params.vk)
    if vk == nil then return nil, "Parameter vk must be a number" end
    return vk, nil
end

-- Execute a no-return CE key API (keyDown / keyUp / doKeyPress) and return {success}.
local function run_key_action(fn, vk, fn_name)
    local ok, err = pcall(fn, vk)
    if not ok then return { success = false, error = fn_name .. " failed: " .. tostring(err) } end
    return { success = true }
end

function cmd_get_pixel(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, rgb = pcall(getPixel, x, y)
    if not ok then return { success = false, error = "getPixel failed: " .. tostring(rgb) } end
    -- Windows COLORREF format: 0x00BBGGRR
    local r = rgb % 256
    local g = math.floor(rgb / 256) % 256
    local b = math.floor(rgb / 65536) % 256
    return { success = true, r = r, g = g, b = b, rgb = rgb }
end

function cmd_get_mouse_pos(params)
    local ok, x, y = pcall(getMousePos)
    if not ok then return { success = false, error = "getMousePos failed: " .. tostring(x) } end
    return { success = true, x = x, y = y }
end

function cmd_set_mouse_pos(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, e = pcall(setMousePos, x, y)
    if not ok then return { success = false, error = "setMousePos failed: " .. tostring(e) } end
    return { success = true }
end

function cmd_is_key_pressed(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end

    local ok, pressed = pcall(isKeyPressed, vk)
    if not ok then return { success = false, error = "isKeyPressed failed: " .. tostring(pressed) } end
    return { success = true, pressed = pressed == true }
end

function cmd_key_down(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyDown, vk, "keyDown")
end

function cmd_key_up(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyUp, vk, "keyUp")
end

function cmd_do_key_press(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(doKeyPress, vk, "doKeyPress")
end

function cmd_get_screen_info(params)
    local ok_w, width  = pcall(getScreenWidth)
    local ok_h, height = pcall(getScreenHeight)
    local ok_d, dpi    = pcall(getScreenDPI)

    if not ok_w then return { success = false, error = "getScreenWidth failed: " .. tostring(width) } end
    if not ok_h then return { success = false, error = "getScreenHeight failed: " .. tostring(height) } end
    if not ok_d then return { success = false, error = "getScreenDPI failed: " .. tostring(dpi) } end

    return { success = true, width = width, height = height, dpi = dpi }
end

-- >>> END UNIT-17 <<<

-- >>> BEGIN UNIT-16 Window GUI <<<
-- ============================================================================
-- WINDOW / GUI COMMAND HANDLERS
-- No process guard required: these APIs are system-wide window operations.
-- ============================================================================

-- Shared helper: parse a hex window-handle string into a number.
-- Returns the number, or nil if the string is missing/invalid.
local function parseHandle(hexStr)
    return tonumber(hexStr, 16)
end

function cmd_find_window(params)
    local title      = params.title
    local class_name = params.class_name

    if not title and not class_name then
        return { success = false, error = "At least one of title or class_name must be provided" }
    end

    local ok, handle = pcall(function()
        return findWindow(class_name, title)
    end)

    if not ok then
        return { success = false, error = tostring(handle) }
    end

    if not handle or handle == 0 then
        return { success = false, error_code = "NOT_FOUND" }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_get_window_caption(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, caption = pcall(function()
        return getWindowCaption(handle)
    end)

    if not ok then
        return { success = false, error = tostring(caption) }
    end

    return { success = true, caption = caption or "" }
end

function cmd_get_window_class_name(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, cls = pcall(function()
        return getWindowClassName(handle)
    end)

    if not ok then
        return { success = false, error = tostring(cls) }
    end

    return { success = true, class_name = cls or "" }
end

function cmd_get_window_process_id(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, pid = pcall(function()
        return getWindowProcessID(handle)
    end)

    if not ok then
        return { success = false, error = tostring(pid) }
    end

    return { success = true, process_id = pid }
end

function cmd_send_window_message(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local msg    = params.msg    or 0
    local wparam = params.wparam or 0
    local lparam = params.lparam or 0

    local ok, result = pcall(function()
        return sendMessage(handle, msg, wparam, lparam)
    end)

    if not ok then
        return { success = false, error = tostring(result) }
    end

    return { success = true, result = result or 0 }
end

-- Modal dialog — blocks the CE main thread until the user clicks OK.
function cmd_show_message(params)
    local message = params.message
    if not message then
        return { success = false, error = "message is required" }
    end

    local ok, err = pcall(function()
        showMessage(message)
    end)

    if not ok then
        return { success = false, error = tostring(err) }
    end

    return { success = true }
end

-- Modal dialog — blocks until the user submits or cancels.
function cmd_input_query(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local default = params.default or ""

    local ok, value = pcall(function()
        return inputQuery(caption, prompt, default)
    end)

    if not ok then
        return { success = false, error = tostring(value) }
    end

    -- inputQuery returns nil on cancel (CE contract)
    if value == nil then
        return { success = true, value = "", cancelled = true }
    end

    return { success = true, value = value, cancelled = false }
end

-- Modal dialog — blocks until the user selects an item or cancels.
function cmd_show_selection_list(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local options = params.options

    if type(options) ~= "table" then
        return { success = false, error = "options must be a list of strings" }
    end

    local sl = createStringlist()
    for _, v in ipairs(options) do
        sl.add(tostring(v))
    end

    local ok, idx, selected = pcall(function()
        return showSelectionList(caption, prompt, sl)
    end)

    sl.destroy()

    if not ok then
        return { success = false, error = tostring(idx) }
    end

    if idx == nil or idx < 0 then
        return { success = true, selected_index = -1, selected_value = "", cancelled = true }
    end

    return {
        success        = true,
        selected_index = idx,
        selected_value = selected or "",
        cancelled      = false
    }
end

-- >>> END UNIT-16 <<<

-- >>> BEGIN UNIT-15 Advanced Scanning <<<
-- ============================================================================
-- UNIT 15: Advanced Scanning (module-scoped, unique, persistent)
-- ============================================================================

-- Persistent scan state (Unit 15)
serverState.persistent_scans = serverState.persistent_scans or {}

-- Helper: NO_PROCESS guard used by all Unit-15 commands
local function requireProcessPair()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

-- Helper: map human-readable var-type string to CE constant
local function resolveVarType(vtype)
    local t = (vtype or "dword"):lower()
    if t == "byte"   then return vtByte
    elseif t == "word"   then return vtWord
    elseif t == "dword"  then return vtDword
    elseif t == "qword"  then return vtQword
    elseif t == "float"  then return vtSingle
    elseif t == "double" then return vtDouble
    elseif t == "string" then return vtString
    else return vtDword
    end
end

-- resolveScanOption / resolveScanInputs live in the HELPER FUNCTIONS section at the top of this file (global, so every cmd_* handler shares one mapping).

function cmd_aob_scan_unique(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local pattern    = params.pattern
    local protection = params.protection or "+X"

    if not pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end

    -- AOBScan lets us count matches; AOBScanUnique returns first-found (non-deterministic on multiple hits)
    local results
    local scanOk, scanMsg = pcall(function()
        results = AOBScan(pattern, protection)
    end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
    end

    local count = results and results.Count or 0
    if count ~= 1 then
        if results then pcall(function() results.destroy() end) end
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    local addrStr = results.getString(0)
    local addr    = tonumber(addrStr, 16)
    pcall(function() results.destroy() end)

    return {
        success = true,
        address = "0x" .. (addrStr or "0"),
        value   = addr
    }
end

function cmd_aob_scan_module(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local pattern     = params.pattern
    local module_name = params.module_name
    local protection  = params.protection or "+X"

    if not pattern     then return { success = false, error = "No pattern provided",     error_code = "INVALID_PARAMS" } end
    if not module_name then return { success = false, error = "No module_name provided", error_code = "INVALID_PARAMS" } end

    local modBase, modSize
    local modBaseOk = pcall(function() modBase = getAddress(module_name) end)
    if not modBaseOk or not modBase or modBase == 0 then
        return { success = false, error = "Module not found: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modSizeOk = pcall(function() modSize = getModuleSize(module_name) end)
    if not modSizeOk or not modSize or modSize == 0 then
        return { success = false, error = "Cannot get module size for: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modEnd = modBase + modSize

    local results
    local scanOk, scanMsg = pcall(function() results = AOBScan(pattern, protection) end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
    end

    local addresses = {}
    if results and results.Count > 0 then
        for i = 0, results.Count - 1 do
            local addrStr = results.getString(i)
            local addr    = tonumber(addrStr, 16)
            if addr and addr >= modBase and addr < modEnd then
                table.insert(addresses, "0x" .. addrStr)
            end
        end
    end
    if results then pcall(function() results.destroy() end) end

    return {
        success     = true,
        count       = #addresses,
        module_name = module_name,
        pattern     = pattern,
        addresses   = addresses
    }
end

function cmd_aob_scan_module_unique(params)
    -- requireProcess() is also called inside cmd_aob_scan_module; early-exit here gives a cleaner error path
    local ok, err = requireProcessPair()
    if not ok then return err end

    local r = cmd_aob_scan_module(params)
    if not r.success then return r end

    local count = r.count or 0
    if count ~= 1 then
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times in module (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    return {
        success = true,
        address = r.addresses[1],
        module_name = params.module_name
    }
end

function cmd_pointer_rescan(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local value               = params.value
    local previous_results_file = params.previous_results_file

    if not value then
        return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" }
    end

    local rescanOk, rescanMsg = pcall(function()
        if previous_results_file then
            pointerRescan(value, previous_results_file)
        else
            pointerRescan(value)
        end
    end)

    if not rescanOk then
        return {
            success    = false,
            error      = "pointerRescan failed: " .. tostring(rescanMsg),
            error_code = "SCAN_ERROR",
            note       = "A prior pointer scan must exist in CE before calling pointer_rescan"
        }
    end

    return { success = true, result_count = -1, note = "Pointer rescan complete. Check CE Pointer Scanner window for results." }
end

function cmd_create_persistent_scan(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local name = params.name
    if not name or name == "" then
        return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" }
    end

    local existing = serverState.persistent_scans[name]
    if existing then
        if existing.fl then pcall(function() existing.fl.destroy() end) end
        pcall(function() existing.ms.destroy() end)
        serverState.persistent_scans[name] = nil
    end

    local ms
    local msOk, msMsg = pcall(function() ms = createMemScan() end)
    if not msOk or not ms then
        return { success = false, error = "createMemScan failed: " .. tostring(msMsg), error_code = "SCAN_ERROR" }
    end

    serverState.persistent_scans[name] = {
        ms            = ms,
        fl            = nil,
        has_scan      = false,
        unknown_first = false
    }

    return { success = true, scan_name = name }
end

function cmd_persistent_scan_first_scan(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local name        = params.name
    local value       = params.value
    local vtype       = params.type or "dword"
    local scan_option = params.scan_option or "exact"

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found. Call create_persistent_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms      = entry.ms
    local varType = resolveVarType(vtype)
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error = "Unknown scan_option '" .. tostring(scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt ~= soExactValue and scanOpt ~= soUnknownValue and scanOpt ~= soValueBetween
       and scanOpt ~= soBiggerThan and scanOpt ~= soSmallerThan then
        return { success = false, error = "scan_option '" .. tostring(scan_option) .. "' is only valid for next_scan. First scan supports: exact, unknown, between, bigger, smaller", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, value, params.value2)
    if inputErr then
        return { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local fsOk, fsMsg = pcall(function()
        ms.firstScan(scanOpt, varType, rtRounded, input1, input2,
                     0, 0x7FFFFFFFFFFFFFFF, "+W-C", fsmNotAligned, "1",
                     false, false, false, false)
        ms.waitTillDone()
    end)
    if not fsOk then
        return { success = false, error = "firstScan failed: " .. tostring(fsMsg), error_code = "SCAN_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "SCAN_ERROR" }
    end

    entry.fl            = fl
    entry.has_scan      = true
    entry.unknown_first = (scanOpt == soUnknownValue)

    local count = fl.getCount()
    -- unknown-initial-value scans report 0 via the foundlist; see resolveScanResultCount()
    if scanOpt == soUnknownValue then
        count = resolveScanResultCount(ms, count)
    end

    return { success = true, scan_name = name, count = count }
end

function cmd_persistent_scan_next_scan(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local name        = params.name
    local value       = params.value
    local scan_option = params.scan_option or "exact"

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.has_scan then
        return { success = false, error = "No first scan done for '" .. name .. "'. Call persistent_scan_first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms      = entry.ms
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error = "Unknown scan_option '" .. tostring(scan_option) .. "'. Valid: " .. SCAN_OPTION_NAMES, error_code = "INVALID_PARAMS" }
    end
    if scanOpt == soUnknownValue then
        return { success = false, error = "scan_option 'unknown' is only valid for first_scan", error_code = "INVALID_PARAMS" }
    end

    local input1, input2, inputErr = resolveScanInputs(scanOpt, value, params.value2)
    if inputErr then
        return { success = false, error = inputErr, error_code = "INVALID_PARAMS" }
    end

    local nsOk, nsMsg = pcall(function()
        ms.nextScan(scanOpt, rtRounded, input1, input2, false, false, false, false, false)
        ms.waitTillDone()
    end)
    if not nsOk then
        return { success = false, error = "nextScan failed: " .. tostring(nsMsg), error_code = "SCAN_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "SCAN_ERROR" }
    end

    entry.fl = fl
    entry.unknown_first = false

    return { success = true, scan_name = name, count = fl.getCount() }
end

function cmd_persistent_scan_get_results(params)
    local name   = params.name
    local offset = params.offset or 0
    local limit  = params.limit  or 100

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.fl then
        return { success = false, error = "No results for '" .. name .. "'. Run first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local fl      = entry.fl
    local total   = fl.getCount()
    local results = {}

    -- NOTE: unknown-initial-value scans are not individually enumerable via the
    -- foundlist (see resolveScanResultCount()); report the scanned-address total
    -- and signal it so an empty result list isn't mistaken for a scan failure.
    if entry.unknown_first then
        total = resolveScanResultCount(entry.ms, total)
        return {
            success              = true,
            scan_name            = name,
            total                = total,
            offset               = offset,
            limit                = limit,
            returned             = 0,
            results              = results,
            enumerable           = false,
            unknown_initial_value = true,
            note = UNKNOWN_SCAN_NOTE
        }
    end

    local stop = math.min(offset + limit - 1, total - 1)
    for i = offset, stop do
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0[xX]") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value   = fl.getValue(i)
        })
    end

    return {
        success   = true,
        scan_name = name,
        total     = total,
        offset    = offset,
        limit     = limit,
        results   = results
    }
end

function cmd_persistent_scan_destroy(params)
    local name = params.name
    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    pcall(function() entry.ms.destroy() end)
    serverState.persistent_scans[name] = nil

    return { success = true, scan_name = name, destroyed = true }
end

-- >>> END UNIT-15 <<<

-- >>> BEGIN UNIT-14 Memory Operations <<<
-- ============================================================================
-- COMMAND HANDLERS - MEMORY OPERATIONS (Unit 14)
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f:find("%.%.") then return nil, "Invalid filename" end
    return f, nil
end

function cmd_copy_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local src = params.source
    local size = params.size
    local dest = params.dest  -- may be nil
    local method = params.method or 0

    if not src then return { success = false, error = "Missing source address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    if type(src) == "string" then src = getAddressSafe(src) end
    if not src then return { success = false, error = "Invalid source address" } end

    local destAddr = nil
    if dest ~= nil then
        if type(dest) == "string" then destAddr = getAddressSafe(dest)
        else destAddr = dest end
        if not destAddr then return { success = false, error = "Invalid dest address" } end
    end

    local ok, result = pcall(copyMemory, src, size, destAddr, method)
    if not ok or not result then
        return { success = false, error = "copyMemory failed: " .. tostring(result) }
    end

    return { success = true, dest_address = toHex(result), size = size }
end

function cmd_compare_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local addr1 = params.addr1
    local addr2 = params.addr2
    local size = params.size
    local method = params.method or 0

    if not addr1 then return { success = false, error = "Missing addr1" } end
    if not addr2 then return { success = false, error = "Missing addr2" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    if type(addr1) == "string" then addr1 = getAddressSafe(addr1) end
    if type(addr2) == "string" then addr2 = getAddressSafe(addr2) end
    if not addr1 then return { success = false, error = "Invalid addr1" } end
    if not addr2 then return { success = false, error = "Invalid addr2" } end

    local ok, r1, r2 = pcall(compareMemory, addr1, addr2, size, method)
    if not ok then
        return { success = false, error = "compareMemory failed: " .. tostring(r1) }
    end

    if r1 == true then
        return { success = true, equal = true, first_diff = -1 }
    else
        return { success = true, equal = false, first_diff = r2 or -1 }
    end
end

function cmd_write_region_to_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local addr = params.address
    local size = params.size
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    if not addr then return { success = false, error = "Missing address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local ok, bytes_written = pcall(writeRegionToFile, sanitized, addr, size)
    if not ok then
        return { success = false, error = "writeRegionToFile failed: " .. tostring(bytes_written) }
    end

    return { success = true, bytes_written = bytes_written or 0, filename = sanitized }
end

function cmd_read_region_from_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local filename = params.filename
    local destination = params.destination

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    if not destination then return { success = false, error = "Missing destination address" } end

    if type(destination) == "string" then destination = getAddressSafe(destination) end
    if not destination then return { success = false, error = "Invalid destination address" } end

    local ok, bytes_read = pcall(readRegionFromFile, sanitized, destination)
    if not ok then
        return { success = false, error = "readRegionFromFile failed: " .. tostring(bytes_read) }
    end

    return { success = true, bytes_read = bytes_read or 0 }
end

function cmd_md5_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local addr = params.address
    local size = params.size

    if not addr then return { success = false, error = "Missing address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local ok, result = pcall(md5memory, addr, size)
    if not ok or not result then
        return { success = false, error = "md5memory failed: " .. tostring(result) }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_md5_file(params)
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    local ok, result = pcall(md5file, sanitized)
    if not ok or not result then
        return { success = false, error = "md5file failed: " .. tostring(result) }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_create_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local size = params.size
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    local ok, handle = pcall(createSection, size)
    if not ok or not handle then
        return { success = false, error = "createSection failed: " .. tostring(handle) }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_map_view_of_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local handle = params.handle
    local address = params.address  -- optional preferred base

    if not handle then return { success = false, error = "Missing handle" } end

    if type(handle) == "string" then handle = tonumber(handle, 16) end
    if not handle then return { success = false, error = "Invalid handle" } end

    local prefAddr = nil
    if address ~= nil then
        if type(address) == "string" then prefAddr = getAddressSafe(address)
        else prefAddr = address end
        if not prefAddr then return { success = false, error = "Invalid address" } end
    end

    local ok, mapped
    if prefAddr then
        ok, mapped = pcall(mapViewOfSection, handle, prefAddr)
    else
        ok, mapped = pcall(mapViewOfSection, handle)
    end

    if not ok or not mapped then
        return { success = false, error = "mapViewOfSection failed: " .. tostring(mapped) }
    end

    return { success = true, mapped_address = toHex(mapped) }
end

-- >>> END UNIT-14 <<<

-- >>> BEGIN UNIT-13 Assembly & Compilation <<<
-- ============================================================================
-- ASSEMBLY & COMPILATION TOOLS (Unit 13)
-- ============================================================================

-- Helper: check process is attached (for tools that need a target process address)
-- >>> BEGIN UNIT-12 Symbol Management <<<
function cmd_register_symbol(params)
    local name = params.name
    local address = params.address
    local do_not_save = params.do_not_save
    if do_not_save == nil then do_not_save = false end
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" and type(address) ~= "number" then
        return { success = false, error = "Parameter 'address' must be a string or integer", error_code = "INVALID_PARAMS" }
    end
    local resolvedAddr = address
    if type(address) == "string" then
        resolvedAddr = getAddressSafe(address)
    end
    if not resolvedAddr or resolvedAddr == 0 then
        return { success = false, error = "Invalid address: " .. tostring(address), error_code = "INVALID_ADDRESS" }
    end
    local ok, err = pcall(registerSymbol, name, resolvedAddr, do_not_save)
    if not ok then
        return { success = false, error = "registerSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, name = name, address = toHex(resolvedAddr) }
end

function cmd_unregister_symbol(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(unregisterSymbol, name)
    if not ok then
        return { success = false, error = "unregisterSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enum_registered_symbols(params)
    local ok, result = pcall(enumRegisteredSymbols)
    if not ok then
        return { success = false, error = "enumRegisteredSymbols failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    local symbols = {}
    if result and type(result) == "table" then
        for i = 1, #result do
            local sym = result[i]
            if sym then
                local addrVal = sym.address or 0
                local modName = sym.module or sym.modulename or ""
                table.insert(symbols, {
                    name    = sym.symbolname or sym.name or "",
                    address = toHex(addrVal),
                    module  = tostring(modName)
                })
            end
        end
    end
    return { success = true, count = #symbols, symbols = symbols }
end

function cmd_delete_all_registered_symbols(params)
    -- Count before deleting (CE returns no count from deleteAllRegisteredSymbols)
    local countOk, symResult = pcall(enumRegisteredSymbols)
    local deletedCount = 0
    if countOk and symResult and type(symResult) == "table" then
        deletedCount = #symResult
    end
    local ok, err = pcall(deleteAllRegisteredSymbols)
    if not ok then
        return { success = false, error = "deleteAllRegisteredSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, deleted_count = deletedCount }
end

function cmd_enable_windows_symbols(params)
    local ok, err = pcall(enableWindowsSymbols)
    if not ok then
        return { success = false, error = "enableWindowsSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enable_kernel_symbols(params)
    local ok, err = pcall(enableKernelSymbols)
    if not ok then
        local errMsg = tostring(err)
        if errMsg:lower():find("dbk") or errMsg:lower():find("kernel") or errMsg:lower():find("driver") then
            return { success = false, error = "Kernel driver not loaded", error_code = "DBK_NOT_LOADED" }
        end
        return { success = false, error = "enableKernelSymbols failed: " .. errMsg, error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_get_symbol_info(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, info = pcall(getSymbolInfo, name)
    if not ok then
        return { success = false, error = "getSymbolInfo failed: " .. tostring(info), error_code = "INTERNAL_ERROR" }
    end
    if not info then
        return { success = false, error = "Symbol not found: " .. name, error_code = "NOT_FOUND" }
    end
    local addrVal = info.address or 0
    local modName = info.modulename or info.module or ""
    return {
        success = true,
        name    = info.searchkey or info.name or name,
        address = toHex(addrVal),
        module  = tostring(modName),
        size    = info.size or 0
    }
end

function cmd_get_module_size(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local module_name = params.module_name
    if type(module_name) ~= "string" or module_name == "" then
        return { success = false, error = "Parameter 'module_name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, sz = pcall(getModuleSize, module_name)
    if not ok then
        return { success = false, error = "getModuleSize failed: " .. tostring(sz), error_code = "INTERNAL_ERROR" }
    end
    if not sz then
        return { success = false, error = "Module not found: " .. module_name, error_code = "NOT_FOUND" }
    end
    return { success = true, size = sz }
end

function cmd_load_new_symbols(params)
    local ok, err = pcall(loadNewSymbols)
    if not ok then
        return { success = false, error = "loadNewSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_reinitialize_symbol_handler(params)
    local ok, err = pcall(reinitializeSymbolhandler)
    if not ok then
        return { success = false, error = "reinitializeSymbolhandler failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end
-- >>> END UNIT-12 <<<
-- >>> BEGIN UNIT-11 Context + ThreadBPs <<<
-- ============================================================================
-- UNIT-11: DEBUG CONTEXT INSPECTION + PER-THREAD BREAKPOINTS
-- ============================================================================

local function u11_guard()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

function cmd_assemble_instruction(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local line = params.line
    local address = params.address
    local preference = params.preference or 0
    local skipRangeCheck = params.skip_range_check or false

    if not line or line == "" then
        return { success = false, error = "No instruction line provided" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address) }
    end

    -- assemble() accepts nil address; it skips relative-offset resolution in that case
    local asmOk, result = pcall(assemble, line, address, preference, skipRangeCheck)

    if not asmOk then
        return { success = false, error = "assemble() raised error: " .. tostring(result) }
    end

    if not result then
        return { success = false, error = "assemble() returned nil (invalid instruction or address)" }
    end

    local bytes = {}
    for i = 1, #result do bytes[i] = result[i] end

    return { success = true, bytes = bytes, size = #bytes }
end

function cmd_auto_assemble_check(params)
    local script = params.script
    local enable = params.enable
    if enable == nil then enable = true end
    local targetSelf = params.target_self or false

    if not script or script == "" then
        return { success = false, error = "No script provided" }
    end

    local checkOk, valid, errMsg = pcall(autoAssembleCheck, script, enable, targetSelf)

    if not checkOk then
        return { success = false, valid = false, errors = { tostring(valid) } }
    end

    if valid then
        return { success = true, valid = true, errors = {} }
    end

    local errors = {}
    if errMsg then table.insert(errors, tostring(errMsg)) end
    return { success = true, valid = false, errors = errors }
end

function cmd_compile_c_code(params)
    -- No NO_PROCESS guard: pure compilation without an address doesn't require a target process
    local source = params.source
    local address = params.address
    local targetSelf = params.target_self or false
    local kernelMode = params.kernelmode or false

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compile) ~= "function" then
        return { success = false, error = "TCC compiler not available", error_code = "CE_API_UNAVAILABLE" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address) }
    end

    local compOk, symbols, errMsg = pcall(compile, source, address, targetSelf, kernelMode, false)

    if not compOk then
        return { success = false, symbols = {}, errors = { tostring(symbols) } }
    end

    if not symbols then
        local errors = {}
        if errMsg then table.insert(errors, tostring(errMsg)) end
        return { success = false, symbols = {}, errors = errors }
    end

    local symResult = {}
    for name, addr in pairs(symbols) do
        symResult[tostring(name)] = toHex(addr)
    end

    return { success = true, symbols = symResult, errors = {} }
end

function cmd_compile_cs_code(params)
    local source = params.source
    local references = params.references or {}
    local coreAssembly = params.core_assembly

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compileCS) ~= "function" then
        return { success = false, error = ".NET runtime or compileCS not available", error_code = "CE_API_UNAVAILABLE" }
    end

    -- compileCS(text, references, coreAssembly OPTIONAL) — pass coreAssembly only when provided
    local csOk, result = pcall(compileCS, source, references, coreAssembly)

    if not csOk then
        return { success = false, assembly_handle = nil, error = tostring(result) }
    end

    if not result then
        return { success = false, assembly_handle = nil, error = "compileCS returned nil" }
    end

    return { success = true, assembly_handle = tostring(result) }
end

function cmd_generate_api_hook_script(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local address = params.address
    local targetAddress = params.target_address
    local codeToExecute = params.code_to_execute or ""

    if not address then return { success = false, error = "No address provided" } end
    if not targetAddress then return { success = false, error = "No target_address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if type(targetAddress) == "string" then targetAddress = getAddressSafe(targetAddress) end

    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end
    if not targetAddress then return { success = false, error = "Invalid target_address: " .. tostring(params.target_address) } end

    -- CE signature: generateAPIHookScript(address, addresstojumpto, addresstogetnewcalladdress OPT, ext OPT, targetself OPT)
    -- code_to_execute maps to ext (4th param); 3rd param (new-call-address) is unused here
    local ext = codeToExecute ~= "" and codeToExecute or nil
    local genOk, result = pcall(generateAPIHookScript, address, targetAddress, nil, ext)

    if not genOk then
        return { success = false, error = "generateAPIHookScript failed: " .. tostring(result) }
    end

    if not result then
        return { success = false, error = "generateAPIHookScript returned nil" }
    end

    return { success = true, script = tostring(result) }
end

function cmd_generate_code_injection_script(params)
    local ok, err = requireProcessPair()
    if not ok then return err end

    local address = params.address
    if not address then return { success = false, error = "No address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end

    -- generateCodeInjectionScript(script: TStrings, address, farjmp) mutates TStrings in-place
    local sl = createStringlist()
    local genOk, genErr = pcall(generateCodeInjectionScript, sl, address)

    if not genOk then
        sl.destroy()
        return { success = false, error = "generateCodeInjectionScript failed: " .. tostring(genErr) }
    end

    local script = sl.Text
    sl.destroy()

    if not script or script == "" then
        return { success = false, error = "generateCodeInjectionScript produced empty script" }
    end

    return { success = true, script = script }
end

-- >>> END UNIT-13 <<<

-- All settable register names shared between get and set handlers
local U11_REG_NAMES = {
    "RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP",
    "R8","R9","R10","R11","R12","R13","R14","R15",
    "EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP",
    "EFLAGS"
}

function cmd_debug_get_context(params)
    local extraRegs = params.extra_regs == true

    local ok, err = u11_guard()
    if not ok then return err end

    local callOk, callErr = pcall(debug_getContext, extraRegs)
    if not callOk then
        return { success = false, error = "debug_getContext failed: " .. tostring(callErr), error_code = "CE_API_ERROR" }
    end

    -- captureRegisters() reads the same CE globals that debug_getContext just populated
    local regs = captureRegisters()
    local arch  = regs.arch
    regs.arch   = nil  -- arch is returned at top level, not inside registers

    local result = { success = true, arch = arch, registers = regs }

    if extraRegs then
        local extra = {}
        local is64  = arch == "x64"
        -- XMM0-15 (0-7 on 32-bit): each pointer is a CE-local address of 16 raw bytes
        local maxXmm = is64 and 15 or 7
        for i = 0, maxXmm do
            local xmmOk, xmmPtr = pcall(debug_getXMMPointer, i)
            if xmmOk and xmmPtr then
                local rawBytes = readBytes(xmmPtr, 16, true)
                if rawBytes then
                    local parts = {}
                    for _, b in ipairs(rawBytes) do
                        parts[#parts + 1] = string.format("%02X", b)
                    end
                    extra["xmm" .. i] = table.concat(parts)
                end
            end
        end
        -- FP0-FP7 are globals populated by debug_getContext(true)
        local fpVars = { FP0, FP1, FP2, FP3, FP4, FP5, FP6, FP7 }
        for i, v in ipairs(fpVars) do
            if v ~= nil then extra["fp" .. (i - 1)] = tostring(v) end
        end
        result.extra = extra
    end

    return result
end

function cmd_debug_set_context(params)
    local registers = params.registers
    if type(registers) ~= "table" then
        return { success = false, error = "registers must be an object/dict", error_code = "INVALID_PARAMS" }
    end

    local ok, err = u11_guard()
    if not ok then return err end

    for _, name in ipairs(U11_REG_NAMES) do
        local val = registers[name]
        if val ~= nil then
            local numVal
            if type(val) == "string" then
                numVal = tonumber(val, 16) or tonumber(val)
            elseif type(val) == "number" then
                numVal = val
            end
            if numVal then _G[name] = numVal end
        end
    end

    local setOk, setErr = pcall(debug_setContext)
    if not setOk then
        return { success = false, error = "debug_setContext failed: " .. tostring(setErr), error_code = "CE_API_ERROR" }
    end

    return { success = true }
end

function cmd_debug_get_xmm_pointer(params)
    local xmmNr = params.xmm_nr or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local ptrOk, ptr = pcall(debug_getXMMPointer, xmmNr)
    if not ptrOk then
        return { success = false, error = "debug_getXMMPointer failed: " .. tostring(ptr), error_code = "CE_API_ERROR" }
    end

    return { success = true, xmm_nr = xmmNr, pointer = toHex(ptr) }
end

function cmd_debug_set_last_branch_recording(params)
    local enable = params.enable == true

    local ok, err = u11_guard()
    if not ok then return err end

    -- LBR only works under kernel-mode debugger (interface == 3)
    local iface = debug_getCurrentDebuggerInterface and debug_getCurrentDebuggerInterface() or nil
    if iface ~= 3 then
        return {
            success            = false,
            error              = "LBR requires kernel debugger",
            error_code         = "CE_API_UNAVAILABLE",
            debugger_interface = iface
        }
    end

    local lbrOk, lbrErr = pcall(debug_setLastBranchRecording, enable)
    if not lbrOk then
        return { success = false, error = "debug_setLastBranchRecording failed: " .. tostring(lbrErr), error_code = "CE_API_ERROR" }
    end

    return { success = true, enabled = enable }
end

function cmd_debug_get_last_branch_record(params)
    local index = params.index or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local recOk, record = pcall(debug_getLastBranchRecord, index)
    if not recOk then
        return { success = false, error = "debug_getLastBranchRecord failed: " .. tostring(record), error_code = "CE_API_ERROR" }
    end

    if type(record) ~= "table" then
        return { success = false, error = "Unexpected return from debug_getLastBranchRecord: " .. tostring(record), error_code = "CE_API_ERROR" }
    end

    return {
        success = true,
        index   = index,
        from    = record.from and toHex(record.from) or nil,
        to      = record.to   and toHex(record.to)   or nil,
    }
end

function cmd_debug_set_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address
    local size     = params.size    or 1
    local trigger  = params.trigger or "execute"

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    local bpTrigger
    if trigger == "write" then
        bpTrigger = bptWrite
    elseif trigger == "read" or trigger == "access" then
        bpTrigger = bptAccess
    else
        bpTrigger = bptExecute
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoint_hits[bpHandle] = {}

    local setOk, setErr = pcall(debug_setBreakpointForThread, threadId, addr, size, bpTrigger, bpmDebugRegister, function()
        table.insert(serverState.breakpoint_hits[bpHandle], {
            handle    = bpHandle,
            thread_id = threadId,
            address   = toHex(addr),
            timestamp = os.time(),
            registers = captureRegisters(),
        })
        debug_continueFromBreakpoint(co_run)
        return 1
    end)

    if not setOk then
        serverState.breakpoint_hits[bpHandle] = nil
        return { success = false, error = "debug_setBreakpointForThread failed: " .. tostring(setErr), error_code = "CE_API_ERROR" }
    end

    serverState.breakpoints[bpHandle] = { address = addr, type = "thread_bp", thread_id = threadId }

    return {
        success   = true,
        bp_handle = bpHandle,
        thread_id = threadId,
        address   = toHex(addr),
        trigger   = trigger,
        size      = size,
    }
end

function cmd_debug_remove_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    -- CE has no dedicated per-thread remove; debug_removeBreakpoint by address is the supported path
    local remOk, remErr = pcall(debug_removeBreakpoint, addr)
    if not remOk then
        return { success = false, error = "debug_removeBreakpoint failed: " .. tostring(remErr), error_code = "CE_API_ERROR" }
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoints[bpHandle]     = nil
    serverState.breakpoint_hits[bpHandle] = nil

    return { success = true, thread_id = threadId, address = toHex(addr) }
end

-- >>> END UNIT-11 <<<
-- >>> BEGIN UNIT-10 Debugger Control <<<
-- ============================================================================
-- COMMAND HANDLERS - DEBUGGER CONTROL (Unit 10)
-- ============================================================================
-- Wraps CE's native debugger control APIs: debugProcess, debug_isDebugging,
-- debug_getCurrentDebuggerInterface, debug_breakThread,
-- debug_continueFromBreakpoint, detachIfPossible, pause, unpause.
--
-- pause() and unpause() are confirmed CE global functions (celua.txt lines 441-442).
-- co_run, co_stepinto, co_stepover are CE global constants used by
-- debug_continueFromBreakpoint (celua.txt line 822).

-- Maps debugProcess interface int to a readable name.
-- Input domain: 0=default, 1=Windows(native), 2=VEH, 3=Kernel(DBK), 4=DBVM
local DEBUGGER_INTERFACE_INPUT_NAME = {
    [0] = "default",
    [1] = "windows_native",
    [2] = "veh",
    [3] = "kernel_dbk",
    [4] = "dbvm",
}

-- Maps debug_getCurrentDebuggerInterface() output to a readable name.
-- CE docs: 1=windows, 2=VEH, 3=Kernel, 4=mac_native, 5=gdb, nil=none
local DEBUGGER_INTERFACE_CURRENT_NAME = {
    [1] = "windows_native",
    [2] = "veh",
    [3] = "kernel",
    [4] = "mac_native",
    [5] = "gdb",
}

function cmd_debug_process(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end
    local iface = params.interface or 0
    if type(iface) ~= "number" then iface = tonumber(iface) or 0 end
    local ok, err = pcall(debugProcess, iface)
    if not ok then
        return { success = false, error = tostring(err) }
    end
    return {
        success = true,
        interface_used = iface,
        interface_name = DEBUGGER_INTERFACE_INPUT_NAME[iface] or "unknown",
    }
end

function cmd_debug_is_debugging(params)
    local ok, result = pcall(debug_isDebugging)
    if not ok then
        return { success = false, error = tostring(result) }
    end
    return { success = true, is_debugging = result == true }
end

function cmd_debug_get_current_debugger_interface(params)
    local ok, iface = pcall(debug_getCurrentDebuggerInterface)
    if not ok then
        return { success = false, error = tostring(iface) }
    end
    local ifaceName = iface ~= nil
        and (DEBUGGER_INTERFACE_CURRENT_NAME[iface] or ("unknown_" .. tostring(iface)))
        or "none"
    return {
        success = true,
        interface = iface,
        interface_name = ifaceName,
    }
end

-- Returns nil when the debugger is active, or an error table when it is not.
local function requireDebugger()
    local ok, isDbg = pcall(debug_isDebugging)
    if not ok or not isDbg then
        return { success = false, error = "Debugger is not attached" }
    end
end

-- Calls fn() with no args, guarded by a NO_PROCESS check. Returns {success}.
local function callWithProcessGuard(fn)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end
    local ok, err = pcall(fn)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_debug_break_thread(params)
    local guard = requireDebugger()
    if guard then return guard end
    local tid = params.thread_id
    if type(tid) ~= "number" then tid = tonumber(tid) end
    if not tid then
        return { success = false, error = "Missing required param: thread_id" }
    end
    local ok, err = pcall(debug_breakThread, tid)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_debug_continue(params)
    local guard = requireDebugger()
    if guard then return guard end
    local method = params.method or "run"
    -- Map string to CE constant. co_run, co_stepinto, co_stepover are CE globals.
    local ceMethod
    if method == "run" then
        ceMethod = co_run
    elseif method == "step_into" then
        ceMethod = co_stepinto
    elseif method == "step_over" then
        ceMethod = co_stepover
    else
        return { success = false, error = "Unknown method: " .. tostring(method) .. ". Valid: run, step_into, step_over" }
    end
    local ok, err = pcall(debug_continueFromBreakpoint, ceMethod)
    if not ok then return { success = false, error = tostring(err) } end
    local h = serverState.halted
    if h then
        if method == "run" then
            serverState.halted = nil
            serverState.last_halt = { breakpoint = h.id, reason = "resumed", halted_seconds = os.clock() - h.since, steps = h.steps }
        else    -- stepping: the thread is still "ours"; the watchdog window restarts
            h.stepping, h.step_started, h.steps = true, os.clock(), (h.steps or 0) + 1
            h.deadline = math.min(os.clock() + h.timeout_ms / 1000, h.hard_deadline)
        end
    end
    return { success = true }
end

function cmd_debug_detach(params)
    local ok, result = pcall(detachIfPossible)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, detached = result == true }
end

function cmd_pause_process(params)   return callWithProcessGuard(pause)   end
function cmd_unpause_process(params) return callWithProcessGuard(unpause) end

-- >>> END UNIT-10 <<<
-- >>> BEGIN UNIT-09 Code Injection <<<
-- ============================================================================
-- COMMAND HANDLERS - CODE INJECTION & EXECUTION
-- ============================================================================

-- Lua 5.1 compat: 'unpack' moved to 'table.unpack' in Lua 5.2+
local unpack = unpack or table.unpack

local function requireProcessBool()
    local pid = getOpenedProcessID()
    return pid and pid > 0
end

function cmd_inject_dll(params)
    if not requireProcessBool() then return { success = false, error = "No process attached" } end
    local filepath = params.filepath
    if not filepath then return { success = false, error = "No filepath provided" } end
    local skip = params.skip_symbol_reload or false

    local ok, result = pcall(injectDLL, filepath, skip)
    if not ok then
        return { success = false, error = "injectDLL failed: " .. tostring(result) }
    end
    return { success = result == true }
end

function cmd_inject_dotnet_dll(params)
    if not requireProcessBool() then return { success = false, error = "No process attached" } end
    local dllpath    = params.filepath
    local className  = params.class_name
    local methodName = params.method_name
    local param      = params.param or ""
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end

    if not dllpath    then return { success = false, error = "No filepath provided" } end
    if not className  then return { success = false, error = "No class_name provided" } end
    if not methodName then return { success = false, error = "No method_name provided" } end

    local ok, result = pcall(injectDotNetDLL, dllpath, className, methodName, param, timeout)
    if not ok then
        return { success = false, error = "injectDotNetDLL failed: " .. tostring(result) }
    end
    return { success = true, result = result }
end

function cmd_execute_code(params)
    if not requireProcessBool() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local param   = params.param   or 0
    local timeout = params.timeout
    if timeout == nil then timeout = -1 end

    local ok, retval = pcall(executeCode, addr, param, timeout)
    if not ok then
        return { success = false, error = "executeCode failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_code_ex(params)
    if not requireProcessBool() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeCodeEx, callMethod, timeout, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeEx failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_method(params)
    if not requireProcessBool() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local instance = params.instance
    if type(instance) == "string" then instance = getAddressSafe(instance) end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeMethod, callMethod, timeout, addr, instance, unpack(args))
    if not ok then
        return { success = false, error = "executeMethod failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local param = params.param or 0

    local ok, retval = pcall(executeCodeLocal, addr, param)
    if not ok then
        return { success = false, error = "executeCodeLocal failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local_ex(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local callMethod = params.call_method or 0
    local args = params.args or {}

    local ok, retval = pcall(executeCodeLocalEx, callMethod, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeLocalEx failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- >>> END UNIT-09 <<<
-- >>> BEGIN UNIT-08 Memory Allocation <<<

-- Windows PAGE_* protection constants used by allocateMemory
local PROT_CONSTANTS = {
    r   = 0x02,  -- PAGE_READONLY
    rw  = 0x04,  -- PAGE_READWRITE
    rx  = 0x20,  -- PAGE_EXECUTE_READ
    rwx = 0x40,  -- PAGE_EXECUTE_READWRITE
}

-- Reconstruct a PAGE_* name string from r/w/x booleans
local function protectionName(r, w, x)
    if x and w and r then return "PAGE_EXECUTE_READWRITE" end
    if x and r        then return "PAGE_EXECUTE_READ"      end
    if w and r        then return "PAGE_READWRITE"         end
    if r              then return "PAGE_READONLY"          end
    if x              then return "PAGE_EXECUTE"           end
    if w              then return "PAGE_WRITECOPY"         end
    return "PAGE_NOACCESS"
end

function cmd_allocate_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local baseAddr = params.base_address
    if type(baseAddr) == "string" then baseAddr = getAddressSafe(baseAddr) end

    local protStr = params.protection or "rwx"
    local protConst = PROT_CONSTANTS[protStr]
    if not protConst then
        return { success = false, error = "Invalid protection string; use r, rw, rx, or rwx", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateMemory, size, baseAddr, protConst)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

function cmd_free_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size or 0

    local ok, err = pcall(deAlloc, addr, size)
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_allocate_shared_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local name = params.name
    if not name or name == "" then
        return { success = false, error = "Invalid name parameter", error_code = "INVALID_PARAMS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateSharedMemory, name, size)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Shared memory allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

function cmd_get_memory_protection(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local ok, prot = pcall(getMemoryProtection, addr)
    if not ok or not prot then
        return { success = false, error = tostring(prot), error_code = "INTERNAL_ERROR" }
    end

    local r = prot.r == true
    local w = prot.w == true
    local x = prot.x == true

    return {
        success = true,
        read    = r,
        write   = w,
        execute = x,
        raw     = protectionName(r, w, x)
    }
end

function cmd_set_memory_protection(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local r = params.read  ~= false
    local w = params.write ~= false
    local x = params.execute ~= false

    local ok, err = pcall(setMemoryProtection, addr, size, { r = r, w = w, x = x })
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_full_access(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(fullAccess, addr, size)
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_allocate_kernel_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    if not dbk_initialized() then
        return { success = false, error = "Kernel driver (DBK) not loaded", error_code = "DBK_NOT_LOADED" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateKernelMemory, size)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Kernel allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

-- >>> END UNIT-08 <<<
-- >>> BEGIN UNIT-07 Process Lifecycle <<<

function cmd_open_process(params)
    local target = params.process_id_or_name
    if not target then return { success = false, error = "Missing process_id_or_name" } end

    local numeric = tonumber(target)
    local ok, err = pcall(openProcess, numeric or target)
    if not ok then return { success = false, error = tostring(err) } end

    local ok2, pid = pcall(getOpenedProcessID)
    if not ok2 or not pid or pid == 0 then
        return { success = false, error = "Process not found or could not be opened" }
    end

    local name = (process ~= "" and process) or tostring(target)
    return { success = true, process_id = pid, process_name = name }
end

function cmd_get_process_list(params)
    local ok, list = pcall(getProcesslist)
    if not ok then return { success = false, error = tostring(list) } end

    local processes = {}
    if list then
        for k, v in pairs(list) do
            local pid, name
            if type(k) == "number" and type(v) == "string" then
                pid = k
                name = v
            elseif type(v) == "string" then
                local hex_pid, pname = v:match("^(%x+)-(.+)$")
                if hex_pid then
                    pid = tonumber(hex_pid, 16)
                    name = pname
                end
            end
            if pid and name then
                table.insert(processes, { pid = pid, name = name })
            end
        end
    end

    return { success = true, count = #processes, processes = processes }
end

function cmd_get_processid_from_name(params)
    local name = params.name
    if not name then return { success = false, error = "Missing name" } end

    local ok, pid = pcall(getProcessIDFromProcessName, name)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "Process not found", error_code = "NOT_FOUND" }
    end

    return { success = true, process_id = pid }
end

function cmd_get_foreground_process(params)
    local ok, pid = pcall(getForegroundProcess)
    if not ok then return { success = false, error = tostring(pid) } end

    local hwnd = 0
    local ok2, wh = pcall(getForegroundWindow)
    if ok2 and wh then hwnd = wh end

    return { success = true, process_id = pid or 0, window_handle = toHex(hwnd) }
end

function cmd_create_process(params)
    local path = params.path
    if not path then return { success = false, error = "Missing path" } end
    local args = params.args or ""
    local debug_flag = params.debug or false
    local break_on_entry = params.break_on_entry or false

    local ok, err = pcall(createProcess, path, args, debug_flag, break_on_entry)
    if not ok then return { success = false, error = tostring(err) } end

    local ok2, pid = pcall(getOpenedProcessID)
    local result_pid = (ok2 and pid) or 0

    return { success = true, process_id = result_pid }
end

function cmd_get_opened_process_id(params)
    local ok, pid = pcall(getOpenedProcessID)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return { success = true, process_id = pid }
end

function cmd_get_opened_process_handle(params)
    local ok, handle = pcall(getOpenedProcessHandle)
    if not ok then return { success = false, error = tostring(handle) } end
    return { success = true, handle = toHex(handle or 0) }
end

-- >>> END UNIT-07 <<<

-- >>> BEGIN UNIT-24 Pointer Analysis <<<

-- Bidirectional 32<->64-bit general-purpose register name aliases (uppercase keys).
-- Global (not local) to avoid the >200-local chunk compile limit.
POINTER_REG_ALIASES = {
    RAX="EAX", EAX="RAX", RBX="EBX", EBX="RBX", RCX="ECX", ECX="RCX",
    RDX="EDX", EDX="RDX", RSI="ESI", ESI="RSI", RDI="EDI", EDI="RDI",
    RBP="EBP", EBP="RBP", RSP="ESP", ESP="RSP", RIP="EIP", EIP="RIP",
    R8="R8D", R8D="R8", R9="R9D", R9D="R9", R10="R10D", R10D="R10",
    R11="R11D", R11D="R11", R12="R12D", R12D="R12", R13="R13D", R13D="R13",
    R14="R14D", R14D="R14", R15="R15D", R15D="R15",
}

function isPointerRegister(name)
    return name ~= nil and POINTER_REG_ALIASES[name:upper()] ~= nil
end

-- Parse a signed hex displacement string like "+1A" or "-08" -> integer.
function parseHexDisp(s)
    local sign, hex = s:match("^([%+%-])(%x+)$")
    if not hex then return nil end
    local v = tonumber(hex, 16)
    if sign == "-" then return -v end
    return v
end

-- Parse the first [...] memory operand of an instruction string.
-- Returns a table { form, base, index, scale, disp } or (nil, errmsg).
-- Displacements are hex (CE disassembly convention).
function parseMemoryOperand(instruction)
    if type(instruction) ~= "string" then
        return nil, "instruction must be a string"
    end
    local raw = instruction:match("%[([^%]]+)%]")
    if not raw then
        return nil, "no memory operand found in: " .. instruction
    end
    -- Normalize: drop spaces, lowercase, strip segment override (e.g. ds:).
    local op = raw:gsub("%s+", ""):lower():gsub("^[cdsefg]s:", "")

    local b, i, s, d

    -- [base+index*scale+disp] / [base+index*scale-disp]
    b, i, s, d = op:match("^(%w+)%+(%w+)%*(%d+)([%+%-]%x+)$")
    if b then
        return { form="indexed", base=b, index=i, scale=tonumber(s), disp=parseHexDisp(d) }
    end
    -- [base+index*scale]
    b, i, s = op:match("^(%w+)%+(%w+)%*(%d+)$")
    if b then
        return { form="indexed", base=b, index=i, scale=tonumber(s), disp=0 }
    end
    -- [base+disp] / [base-disp]  (base must be a register)
    b, d = op:match("^(%w+)([%+%-]%x+)$")
    if b and isPointerRegister(b) then
        local form = (b=="rip" or b=="eip") and "rip_relative" or "register_indirect"
        return { form=form, base=b, index=nil, scale=nil, disp=parseHexDisp(d) }
    end
    -- [base]  (register)
    b = op:match("^(%w+)$")
    if b and isPointerRegister(b) then
        return { form="register_indirect", base=b, index=nil, scale=nil, disp=0 }
    end
    -- [disp]  (absolute / direct address; all hex digits)
    local abs = op:match("^(%x+)$")
    if abs then
        return { form="absolute", base=nil, index=nil, scale=nil, disp=tonumber(abs, 16) }
    end

    return nil, "unrecognized memory operand: " .. raw
end

-- Coerce a hex-string ("0x..."), decimal string, or number to a number.
function toNumberAny(v)
    if type(v) == "number" then return v end
    if type(v) == "string" then return tonumber(v) or tonumber(v, 16) end
    return nil
end

-- Look up a register value from a hit snapshot, trying the 32/64-bit alias.
function resolveRegisterValue(registers, regName)
    local up = regName:upper()
    local v = registers[up]
    if v == nil then
        local alias = POINTER_REG_ALIASES[up]
        if alias then v = registers[alias] end
    end
    return toNumberAny(v)
end

-- Format a signed displacement as "+0xN" / "-0xN".
function formatHexDisp(disp)
    if disp == nil then return nil end
    if disp < 0 then return string.format("-0x%X", -disp) end
    return string.format("+0x%X", disp)
end

-- Turn one captured memory access into pointer-walk-back facts. Pure: no CE API calls.
function cmd_analyze_pointer_access(params)
    local instruction = params.instruction
    local registers = params.registers
    if type(instruction) ~= "string" then
        return { success=false, error="instruction (string) is required", error_code="INVALID_PARAMS" }
    end
    if type(registers) ~= "table" then
        return { success=false, error="registers (object) is required", error_code="INVALID_PARAMS" }
    end

    local op, err = parseMemoryOperand(instruction)
    if not op then
        return { success=false, error=err, error_code="INVALID_PARAMS" }
    end

    local warnings = {}
    local result = {
        success = true,
        access_type = op.form,
        base_register = op.base and op.base:upper() or nil,
        index_register = op.index and op.index:upper() or nil,
        scale = op.scale,
        displacement = op.disp,
        hex_displacement = formatHexDisp(op.disp),
        struct_base = nil,
        accessed_address = nil,
        next_scan_value = nil,
        is_static = (op.form == "rip_relative" or op.form == "absolute"),
        has_dynamic_index = (op.form == "indexed"),
        warnings = warnings,
    }
    if params.is_64bit ~= nil then
        result.scan_type = params.is_64bit and "qword" or "dword"
    end

    -- Static roots terminate the chain; nothing to scan for.
    if op.form == "absolute" then
        result.accessed_address = toHex(op.disp)
        result.note = "Absolute/global address. Chain root: map with get_address_info."
        return result
    end
    if op.form == "rip_relative" then
        if params.accessed_address ~= nil then
            result.accessed_address = toHex(toNumberAny(params.accessed_address) or 0)
        else
            table.insert(warnings, "rip_relative: accessed_address not provided and cannot be computed without instruction length")
        end
        result.note = "RIP-relative/global. Chain root: map with get_address_info."
        return result
    end

    -- register_indirect / indexed: climb one level.
    local baseVal = resolveRegisterValue(registers, op.base)
    if baseVal == nil then
        return { success=false, error="register value not provided: " .. result.base_register, error_code="INVALID_PARAMS" }
    end
    result.struct_base = toHex(baseVal)
    result.next_scan_value = toHex(baseVal)

    local accessed = baseVal + (op.disp or 0)
    if op.form == "indexed" then
        local idxVal = resolveRegisterValue(registers, op.index)
        if idxVal ~= nil then
            accessed = baseVal + idxVal * (op.scale or 1) + (op.disp or 0)
        else
            accessed = nil
            table.insert(warnings, "index register value not provided; accessed_address not computed")
        end
        table.insert(warnings, "indexed access: this level's offset (index*scale+disp) is index-dependent")
    end
    if accessed ~= nil then
        result.accessed_address = toHex(accessed)
    end

    if params.accessed_address ~= nil and accessed ~= nil then
        local given = toNumberAny(params.accessed_address)
        if given ~= nil and given ~= accessed then
            table.insert(warnings, "computed accessed_address differs from provided value; register state may lag the access")
        end
    end

    result.note = "Scan for a pointer equal to next_scan_value to find the holder one level up. Repeat until struct_base lands in a static module (check with get_address_info)."
    return result
end

-- Resolve a pointer chain (CE convention: deref, then add offset). Uses CE's
-- readPointer / getAddressSafe. Returns a table: ok + (final_address number,
-- final_address_hex, final_value, chain) or (error, chain, failed_at).
function resolveChain(base, offsets)
    local baseNum = base
    if type(baseNum) == "string" then baseNum = getAddressSafe(baseNum) end
    if not baseNum then
        return { ok=false, error="Invalid base address" }
    end
    local cur = baseNum
    local chain = { { step=0, address=toHex(cur), description="base" } }
    for i, offset in ipairs(offsets or {}) do
        local ptr = readPointer(cur)
        if not ptr then
            return { ok=false, error="Failed to read pointer at step " .. i, chain=chain, failed_at=toHex(cur) }
        end
        cur = ptr + offset
        table.insert(chain, {
            step=i, address=toHex(cur), offset=offset,
            hex_offset=string.format("+0x%X", offset), pointer_value=toHex(ptr),
        })
    end
    local finalValue = nil
    pcall(function() finalValue = readPointer(cur) end)
    return { ok=true, base=toHex(baseNum), final_address=cur, final_address_hex=toHex(cur), final_value=finalValue, chain=chain }
end

-- Resolve many candidate chains; report which land on target (matches only by default).
function cmd_validate_pointer_chains(params)
    local chains = params.chains
    if type(chains) ~= "table" then
        return { success=false, error="chains (array) is required", error_code="INVALID_PARAMS" }
    end
    if #chains > 5000 then
        return { success=false, error="Too many chains (max 5000); page the input.", error_code="INVALID_PARAMS" }
    end
    local target = params.target
    if type(target) == "string" then target = getAddressSafe(target) end
    if not target then
        return { success=false, error="Invalid target address", error_code="INVALID_ADDRESS" }
    end
    local includeMisses = params.include_misses == true

    local matched, unreadable = 0, 0
    local matches = {}
    local misses = includeMisses and {} or nil

    for _, c in ipairs(chains) do
        local offs = c.offsets or {}
        local r = resolveChain(c.base, offs)
        if not r.ok then
            unreadable = unreadable + 1
            if includeMisses then
                table.insert(misses, { base=c.base, offsets=offs, error=r.error })
            end
        elseif r.final_address == target then
            matched = matched + 1
            table.insert(matches, { base=r.base, offsets=offs, final_address=r.final_address_hex, final_value=r.final_value })
        elseif includeMisses then
            table.insert(misses, { base=r.base, offsets=offs, final_address=r.final_address_hex, final_value=r.final_value })
        end
    end

    local out = {
        success = true,
        target = toHex(target),
        total = #chains,
        matched = matched,
        unreadable = unreadable,
        matches = matches,
    }
    if includeMisses then out.misses = misses end
    return out
end

-- >>> END UNIT-24 <<<

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

-- >>> BEGIN UNIT-25 Operations: bridge_status, read_struct, batch, async jobs <<<

local function countKeys(tbl)
    local n = 0
    for _ in pairs(tbl or {}) do n = n + 1 end
    return n
end

-- ---------------------------------------------------------------------------
-- bridge_status: one-call health/diagnostics report
-- ---------------------------------------------------------------------------
function cmd_bridge_status(params)
    local warnings = {}
    local info = {
        success = true,
        version = VERSION,
        pipe = PIPE_NAME,
        uptime_seconds = os.time() - (serverState.started_at or os.time()),
        client_connected = serverState.connected and true or false,
        tools_registered = countKeys(serverState.dispatch),
    }

    local okVer, ceVer = pcall(getCEVersion)
    if okVer then info.ce_version = ceVer end

    local okProc, pinfo = pcall(cmd_get_process_info, {})
    local proc = { attached = false }
    if okProc and type(pinfo) == "table" and pinfo.success then
        proc = {}
        for k, v in pairs(pinfo) do if k ~= "success" then proc[k] = v end end
        proc.attached = true
    else
        warnings[#warnings + 1] = "No process attached to Cheat Engine; memory tools will return NO_PROCESS."
    end
    info.process = proc

    local drivers = {}
    local okK, dbk = pcall(dbk_initialized)
    if okK then drivers.dbk_loaded = dbk and true or false end
    local okD, dbvm = pcall(dbvm_initialized)
    if okD then drivers.dbvm_loaded = dbvm and true or false end
    local okG, dbg = pcall(debug_isDebugging)
    if okG then drivers.debugger_attached = dbg and true or false end
    info.drivers = drivers

    local slotsUsed = 0
    for i = 1, 4 do if serverState.hw_bp_slots[i] then slotsUsed = slotsUsed + 1 end end
    local running, tracked = 0, 0
    for _, job in pairs(serverState.jobs or {}) do
        tracked = tracked + 1
        if job.state == "running" then running = running + 1 end
    end
    info.state = {
        breakpoints = countKeys(serverState.breakpoints),
        hw_slots_used = slotsUsed,
        hw_slots_total = 4,
        dbvm_watches = countKeys(serverState.active_watches),
        persistent_scans = countKeys(serverState.persistent_scans),
        scan_session_active = serverState.scan_memscan ~= nil,
        structures = countKeys(serverState.structures),
        jobs_running = running,
        jobs_tracked = tracked,
        scan_job = serverState.scan_job_id,
    }
    info.stats = serverState.stats

    -- CE exposes no documented getter for the "Query memory region routines" checkbox, so this
    -- is a best-effort probe of the settings registry. "unknown" means "could not be read".
    local qmr = "unknown"
    local okS, settings = pcall(getSettings)
    if okS and settings then
        for _, key in ipairs({ "Use DBK QueryMemoryRegion", "Use dbk QueryMemoryRegion", "UseDBKQueryMemoryRegion", "Query memory region routines" }) do
            local okV, v = pcall(function() return settings.Value[key] end)
            if okV and v ~= nil and v ~= "" then
                qmr = (v == true or v == 1 or tostring(v):lower() == "true" or tostring(v) == "1") and "enabled" or "disabled"
                info.query_memory_region_setting_key = key
                break
            end
        end
    end
    info.query_memory_region_routines = qmr
    if qmr == "enabled" then
        warnings[#warnings + 1] = "'Query memory region routines' is ENABLED (Settings > Extra). Scans on DBVM-protected pages can trigger CLOCK_WATCHDOG_TIMEOUT BSODs; disable it."
    elseif qmr == "unknown" and (drivers.dbk_loaded or drivers.dbvm_loaded) then
        warnings[#warnings + 1] = "DBK/DBVM is loaded and the 'Query memory region routines' setting could not be read; confirm it is disabled (Settings > Extra) before scanning."
    end
    if running > 0 then
        warnings[#warnings + 1] = tostring(running) .. " async job(s) running."
    end
    info.warnings = warnings
    return info
end

-- ---------------------------------------------------------------------------
-- read_struct: several typed fields from one memory read
-- ---------------------------------------------------------------------------
local STRUCT_INT = {
    i8  = { fmt = "<i1", size = 1 }, u8  = { fmt = "<I1", size = 1 },
    i16 = { fmt = "<i2", size = 2 }, u16 = { fmt = "<I2", size = 2 },
    i32 = { fmt = "<i4", size = 4 }, u32 = { fmt = "<I4", size = 4 },
    i64 = { fmt = "<i8", size = 8 }, u64 = { fmt = "<I8", size = 8 },
    f32 = { fmt = "<f",  size = 4, float = true }, f64 = { fmt = "<d", size = 8, float = true },
}
local STRUCT_ALIASES = {
    byte = "u8", word = "u16", dword = "u32", qword = "u64", float = "f32", single = "f32",
    double = "f64", int = "i32", uint = "u32", short = "i16", ushort = "u16",
    int8 = "i8", uint8 = "u8", int16 = "i16", uint16 = "u16", int32 = "i32", uint32 = "u32",
    int64 = "i64", uint64 = "u64", pointer = "ptr", boolean = "bool", string = "cstring", utf16 = "wstring",
}
local STRUCT_TYPE_NAMES = "i8,u8,i16,u16,i32,u32,i64,u64,f32,f64,ptr,bool,bytes,cstring,wstring"
local STRUCT_MAX_FIELDS, STRUCT_MAX_SPAN = 512, 65536

local function clampInt(v, lo, hi)
    v = math.floor(tonumber(v) or lo)
    return math.max(lo, math.min(hi, v))
end

local function utf16leToUtf8(s)
    local out, i = {}, 1
    while i + 1 <= #s do
        local cu = string.unpack("<I2", s, i)
        i = i + 2
        if cu == 0 then break end
        if cu >= 0xD800 and cu <= 0xDBFF and i + 1 <= #s then
            local lo = string.unpack("<I2", s, i)
            if lo >= 0xDC00 and lo <= 0xDFFF then
                cu = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00)
                i = i + 2
            else
                cu = 0xFFFD
            end
        elseif cu >= 0xD800 and cu <= 0xDFFF then
            cu = 0xFFFD
        end
        out[#out + 1] = utf8.char(cu)
    end
    return table.concat(out)
end

local function normalizeStructFields(fields, is64)
    local out, nextOffset = {}, 0
    for i, f in ipairs(fields) do
        if type(f) ~= "table" then
            return nil, { success = false, error = "fields[" .. i .. "] must be an object", error_code = "INVALID_PARAMS" }
        end
        local ftype = tostring(f.type or ""):lower()
        ftype = STRUCT_ALIASES[ftype] or ftype
        local size
        if STRUCT_INT[ftype] then size = STRUCT_INT[ftype].size
        elseif ftype == "ptr" then size = is64 and 8 or 4
        elseif ftype == "bool" then size = 1
        elseif ftype == "bytes" then size = clampInt(f.size or f.length or 16, 1, 4096)
        elseif ftype == "cstring" then size = clampInt(f.size or f.length or 64, 1, 4096)
        elseif ftype == "wstring" then size = 2 * clampInt(f.size or f.length or 32, 1, 2048)  -- size = characters
        else
            return nil, { success = false, error = "fields[" .. i .. "]: unknown type '" .. tostring(f.type) .. "'. Valid: " .. STRUCT_TYPE_NAMES, error_code = "INVALID_PARAMS" }
        end
        local offset = f.offset
        if offset == nil then offset = nextOffset else offset = tonumber(offset) end
        if not offset or offset < 0 then
            return nil, { success = false, error = "fields[" .. i .. "]: invalid offset", error_code = "INVALID_PARAMS" }
        end
        offset = math.floor(offset)
        out[#out + 1] = { name = f.name and tostring(f.name) or ("field" .. i), type = ftype, offset = offset, size = size }
        nextOffset = offset + size
    end
    return out
end

local function fillStructEntry(entry, f, buf, pos, is64)
    local spec = STRUCT_INT[f.type]
    if spec then
        local v = string.unpack(spec.fmt, buf, pos)
        if f.type == "u64" and v < 0 then
            entry.value = toHex(v)                       -- above 2^63: hex string, JSON numbers are signed
        else
            entry.value = v
            if not spec.float and spec.size >= 4 then entry.hex = toHex(v) end
        end
    elseif f.type == "ptr" then
        entry.value = toHex(string.unpack(is64 and "<I8" or "<I4", buf, pos))
    elseif f.type == "bool" then
        entry.value = string.unpack("<I1", buf, pos) ~= 0
    elseif f.type == "bytes" then
        local parts = {}
        for i = 0, f.size - 1 do parts[#parts + 1] = string.format("%02X", buf:byte(pos + i)) end
        entry.value = table.concat(parts, " ")
    elseif f.type == "cstring" then
        local s = buf:sub(pos, pos + f.size - 1)
        local nul = s:find("\0", 1, true)
        entry.value = nul and s:sub(1, nul - 1) or s
    elseif f.type == "wstring" then
        entry.value = utf16leToUtf8(buf:sub(pos, pos + f.size - 1))
    end
end

function cmd_read_struct(params)
    local perr = requireProcess()
    if perr then return perr end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local fields = params.fields
    if type(fields) ~= "table" or #fields == 0 then
        return { success = false, error = "fields must be a non-empty array of {name, type, offset?, size?}", error_code = "INVALID_PARAMS" }
    end
    if #fields > STRUCT_MAX_FIELDS then
        return { success = false, error = "At most " .. STRUCT_MAX_FIELDS .. " fields per call", error_code = "INVALID_PARAMS" }
    end

    local is64 = targetIs64Bit()
    local specs, serr = normalizeStructFields(fields, is64)
    if serr then return serr end

    local spanStart, spanEnd = math.huge, 0
    for _, f in ipairs(specs) do
        spanStart = math.min(spanStart, f.offset)
        spanEnd = math.max(spanEnd, f.offset + f.size)
    end
    local span = spanEnd - spanStart
    if span > STRUCT_MAX_SPAN then
        return { success = false, error = "Field span of " .. span .. " bytes exceeds the " .. STRUCT_MAX_SPAN .. " byte limit", error_code = "INVALID_PARAMS" }
    end

    local whole
    local bytes = readBytes(addr + spanStart, span, true)
    if bytes then whole = bytesToString(bytes) end

    local entries = {}
    for i, f in ipairs(specs) do
        local entry = { name = f.name, type = f.type, offset = f.offset }
        local buf, pos
        if whole then
            buf, pos = whole, f.offset - spanStart + 1
        else
            -- the span as a whole was unreadable: try each field on its own
            local fb = readBytes(addr + f.offset, f.size, true)
            if fb then buf, pos = bytesToString(fb), 1 end
        end
        if not buf then
            entry.error = "unreadable at " .. toHex(addr + f.offset)
        else
            local ok, err = pcall(fillStructEntry, entry, f, buf, pos, is64)
            if not ok then entry.error = tostring(err) end
        end
        entries[i] = entry
    end

    return { success = true, address = toHex(addr), span = span, arch = is64 and "x64" or "x86", fields = entries }
end

-- ---------------------------------------------------------------------------
-- batch: several commands in one round trip (single main-thread slot)
-- ---------------------------------------------------------------------------
local BATCH_MAX = 100

function cmd_batch(params)
    local reqs = params.requests
    if type(reqs) ~= "table" or #reqs == 0 then
        return { success = false, error = "requests must be a non-empty array of {method, params}", error_code = "INVALID_PARAMS" }
    end
    if #reqs > BATCH_MAX then
        return { success = false, error = "At most " .. BATCH_MAX .. " requests per batch", error_code = "INVALID_PARAMS" }
    end

    local stopOnError = params.stop_on_error == true
    local results, failed = {}, 0
    for i, req in ipairs(reqs) do
        local method = type(req) == "table" and req.method or nil
        local handler = method and serverState.dispatch[method]
        local result
        if method == "batch" then
            result = { success = false, error = "batch calls cannot be nested", error_code = "INVALID_PARAMS" }
        elseif not handler then
            result = { success = false, error = "Method not found: " .. tostring(method), error_code = "NOT_FOUND" }
        else
            local ok, r = pcall(handler, type(req.params) == "table" and req.params or {})
            if ok then
                result = r
                if result == nil then result = { success = true } end
            else
                result = { success = false, error = "Internal error: " .. tostring(r), error_code = "INTERNAL_ERROR" }
            end
        end
        results[i] = result
        if type(result) == "table" and result.success == false then
            failed = failed + 1
            if stopOnError then break end
        end
    end
    return { success = true, requested = #reqs, executed = #results, failed = failed, results = results }
end

-- ---------------------------------------------------------------------------
-- Async jobs: long scans without freezing CE or hitting the client timeout.
--   scan_all / next_scan / aob_scan : native CE memscan, started without waitTillDone
--   find_references / find_call_references : memscan, then post-processed in
--     time-sliced chunks from a CE timer so the GUI stays responsive
-- ---------------------------------------------------------------------------
local MAX_RUNNING_JOBS = 4
local MAX_TRACKED_FINISHED_JOBS = 20
local JOB_TICK_INTERVAL_MS = 15
local JOB_TICK_BUDGET_S = 0.02
local jobFinish, jobAdvance, ensurePump

local function jobReleaseResources(job)
    if job._fl then pcall(function() job._fl.destroy() end); job._fl = nil end
    if job._ms and job._temp then pcall(function() job._ms.destroy() end) end
    job._ms = nil
end

jobFinish = function(job, state, fields)
    job.state = state
    job.phase = state
    job.finished = os.time()
    if fields then for k, v in pairs(fields) do job[k] = v end end
    jobReleaseResources(job)
    job._step, job._after_scan = nil, nil
    if serverState.scan_job_id == job.id then serverState.scan_job_id = nil end
end

local function jobFail(job, message, code)
    jobFinish(job, "failed", { error = message, error_code = code or "INTERNAL_ERROR" })
end

local function jobProgress(job)
    local cur, total, found = 0, 0, nil
    if job.state == "running" and job.phase == "scanning" and job._ms then
        local ok, p = pcall(function() return job._ms.getProgress() end)
        if ok and type(p) == "table" then
            cur, total, found = p.CurrentlyScanned or 0, p.TotalAddressesToScan or 0, p.ResultsFound
        end
    elseif job.progress then
        cur, total = job.progress.current or 0, job.progress.total or 0
    end
    return { current = cur, total = total, percent = total > 0 and math.floor(cur / total * 1000) / 10 or nil, results_found = found }
end

-- Moves a job out of the scanning phase once its memscan has finished. Called from
-- OnScanDone, from the pump timer and from get_job, so it must be idempotent.
jobAdvance = function(job)
    if job.state ~= "running" or job.phase ~= "scanning" or job._advancing then return end
    local ms = job._ms
    local done = job._scan_done
    if not done and ms then
        local ok, p = pcall(function() return ms.getProgress() end)
        if ok and type(p) == "table" and (p.TotalAddressesToScan or 0) > 0
           and (p.CurrentlyScanned or 0) >= p.TotalAddressesToScan then
            -- the scan loop has covered everything; let the worker threads wind down
            job._advancing = true
            pcall(function() ms.waitTillDone() end)
            job._advancing = false
            done = true
        end
    end
    if not done or not job._after_scan then return end
    job._advancing = true
    local ok, err = pcall(job._after_scan, job)
    job._advancing = false
    if not ok and job.state == "running" then
        jobFail(job, "Post-scan processing failed: " .. tostring(err))
    end
end

local function jobPump()
    local deadline = os.clock() + JOB_TICK_BUDGET_S
    local active = BPX.watchdog()    -- also keeps the timer alive while a thread is halted
    for _, job in pairs(serverState.jobs) do
        if job.state == "running" then
            active = true
            if job.phase == "scanning" then
                jobAdvance(job)
            elseif job.phase == "processing" and job._step and os.clock() < deadline then
                local ok, err = pcall(job._step, job, deadline)
                if not ok then jobFail(job, "Job step failed: " .. tostring(err)) end
            end
        end
    end
    if not active and serverState.job_timer then serverState.job_timer.Enabled = false end
end

ensurePump = function()
    if not serverState.job_timer then
        local timer = createTimer(nil, false)
        timer.Interval = JOB_TICK_INTERVAL_MS
        timer.OnTimer = function()
            local ok, err = pcall(jobPump)
            if not ok then log("Job pump error: " .. tostring(err)) end
        end
        serverState.job_timer = timer
    end
    serverState.job_timer.Enabled = true
end
BPX.ensurePump = ensurePump      -- the break-and-inspect watchdog runs from the same timer

local function pruneJobs()
    local finished = {}
    for _, job in pairs(serverState.jobs) do
        if job.state ~= "running" then finished[#finished + 1] = job end
    end
    if #finished <= MAX_TRACKED_FINISHED_JOBS then return end
    table.sort(finished, function(a, b) return a.seq < b.seq end)
    for i = 1, #finished - MAX_TRACKED_FINISHED_JOBS do
        serverState.jobs[finished[i].id] = nil
    end
end

local function addressToAobPattern(addr, is64)
    local raw
    if is64 and addr > 0xFFFFFFFF then raw = string.pack("<I8", addr) else raw = string.pack("<I4", addr & 0xFFFFFFFF) end
    local parts = {}
    for i = 1, #raw do parts[i] = string.format("%02X", raw:byte(i)) end
    return table.concat(parts, " ")
end

-- The handler only raises a flag: advancing a job can destroy its memscan, and destroying a memscan
-- from inside its own event handler is unsafe. The pump timer (or get_job) does the actual work.
local function onScanDone(job)
    return function() job._scan_done = true end
end

-- Private (temporary) AOB memscan used by aob_scan / find_references / find_call_references.
local function startAobMemscan(job, pattern, protection)
    local ms = createMemScan()
    job._ms, job._temp = ms, true
    job.phase = "scanning"
    ms.OnScanDone = onScanDone(job)
    ms.firstScan(soExactValue, vtByteArray, rtRounded, pattern, "", 0, USER_MODE_MAX, protection, fsmNotAligned, "1", true, false, false, false)
end

local JOB_STARTERS = {}

JOB_STARTERS.scan_all = function(job, p)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareFirstScan(p)
    if err then return err end

    local ms = createMemScan()
    job._ms = ms               -- not temporary: becomes the scan session when it finishes
    job.phase = "scanning"
    serverState.scan_job_id = job.id
    ms.OnScanDone = onScanDone(job)
    job._after_scan = function(j)
        local count = commitFirstScan(ms, args.scanOpt)
        pcall(function() ms.OnScanDone = nil end)
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = { fields = { count = count } } })
    end
    ms.firstScan(args.scanOpt, args.varType, rtRounded, args.input1, args.input2, 0, USER_MODE_MAX, args.protect, fsmNotAligned, "1", false, false, false, false)
end

JOB_STARTERS.next_scan = function(job, p)
    local busy = scanBusyError()
    if busy then return busy end
    local args, err = prepareNextScan(p)
    if err then return err end

    local ms = args.ms
    job._ms = ms
    job._shared_ms = true      -- the active scan session; never destroyed as a job resource
    job.phase = "scanning"
    serverState.scan_job_id = job.id
    ms.OnScanDone = onScanDone(job)
    job._after_scan = function(j)
        local count = commitNextScan(ms)
        pcall(function() ms.OnScanDone = nil end)
        j._ms = nil
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = { fields = { count = count } } })
    end
    ms.nextScan(args.scanOpt, rtRounded, args.input1, args.input2, false, false, false, false, false)
end

JOB_STARTERS.aob_scan = function(job, p)
    if not p.pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end
    local limit = clampInt(p.limit or 100, 1, 10000)
    job._after_scan = function(j)
        local fl = createFoundList(j._ms)
        fl.initialize()
        j._fl = fl
        local total = fl.getCount()
        local addrs = {}
        for i = 0, math.min(total, limit) - 1 do
            local s = fl.getAddress(i)
            addrs[#addrs + 1] = { address = "0x" .. s, value = tonumber(s, 16) }
        end
        j.progress = { current = 1, total = 1 }
        jobFinish(j, "done", { result = {
            fields = { pattern = p.pattern, total_matches = total, count = #addrs },
            list_key = "addresses", items = addrs } })
    end
    startAobMemscan(job, p.pattern, p.protection or "+X")
end

-- Phase 2 of find_references / find_call_references: walk the memscan hits in
-- time slices (disassemble / readInteger per hit is what makes the blocking version slow).
local function beginProcessing(job, stepFn)
    local fl = createFoundList(job._ms)
    fl.initialize()
    job._fl = fl
    job._n, job._i, job._items = fl.getCount(), 0, {}
    job.progress = { current = 0, total = job._n }
    job.phase = "processing"
    job._step = stepFn
    ensurePump()
end

local function finishList(job, listKey, fields)
    job.progress = { current = job._n, total = job._n }
    jobFinish(job, "done", { result = { fields = fields, list_key = listKey, items = job._items } })
    return true
end

JOB_STARTERS.find_references = function(job, p)
    local target = p.address
    if type(target) == "string" then target = getAddressSafe(target) end
    if not target then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end
    local is64 = targetIs64Bit()
    local arch = is64 and "x64" or "x86"

    job._after_scan = function(j)
        beginProcessing(j, function(jb, deadline)
            local fl = jb._fl
            while jb._i < jb._n do
                local addr = tonumber(fl.getAddress(jb._i), 16)
                jb._i = jb._i + 1
                if addr then
                    jb._items[#jb._items + 1] = { address = toHex(addr), instruction = disassemble(addr) or "???" }
                end
                if os.clock() >= deadline then jb.progress.current = jb._i; return false end
            end
            return finishList(jb, "references", { target = toHex(target), arch = arch })
        end)
    end
    startAobMemscan(job, addressToAobPattern(target, is64), "+X")
end

JOB_STARTERS.find_call_references = function(job, p)
    local funcAddr = p.address or p.function_address
    if type(funcAddr) == "string" then funcAddr = getAddressSafe(funcAddr) end
    if not funcAddr then return { success = false, error = "Invalid function address", error_code = "INVALID_ADDRESS" } end

    job._after_scan = function(j)
        beginProcessing(j, function(jb, deadline)
            local fl = jb._fl
            while jb._i < jb._n do
                local callAddr = tonumber(fl.getAddress(jb._i), 16)
                jb._i = jb._i + 1
                local rel = callAddr and readInteger(callAddr + 1)
                if rel then
                    if rel > 0x7FFFFFFF then rel = rel - 0x100000000 end
                    if callAddr + 5 + rel == funcAddr then
                        jb._items[#jb._items + 1] = { caller_address = toHex(callAddr), instruction = disassemble(callAddr) or "???" }
                    end
                end
                if os.clock() >= deadline then jb.progress.current = jb._i; return false end
            end
            return finishList(jb, "callers", { function_address = toHex(funcAddr) })
        end)
    end
    startAobMemscan(job, "E8 ?? ?? ?? ??", "+X")
end

local JOB_KIND_NAMES = "scan_all, next_scan, aob_scan, find_references, find_call_references"

local function jobSummary(job)
    local s = {
        job_id = job.id, kind = job.kind, state = job.state, phase = job.phase,
        elapsed_seconds = (job.finished or os.time()) - job.created,
        progress = jobProgress(job),
    }
    if job.state == "failed" then s.error, s.error_code = job.error, job.error_code end
    if job.note then s.note = job.note end
    if job.state == "done" and job.result then
        s.result_ready = true
        s.result_summary = job.result.fields
        if job.result.items then s.result_items = #job.result.items end
    end
    return s
end

local function jobNotFound(id)
    return { success = false, error = "No such job: " .. tostring(id), error_code = "NOT_FOUND" }
end

function cmd_start_job(params)
    local kind = params.kind
    local starter = JOB_STARTERS[kind]
    if not starter then
        return { success = false, error = "Unknown job kind '" .. tostring(kind) .. "'. Valid: " .. JOB_KIND_NAMES, error_code = "INVALID_PARAMS" }
    end
    local p = params.params
    if p ~= nil and type(p) ~= "table" then
        return { success = false, error = "params must be an object", error_code = "INVALID_PARAMS" }
    end
    p = p or {}
    local perr = requireProcess()
    if perr then return perr end

    local running = 0
    for _, job in pairs(serverState.jobs) do
        if job.state == "running" then running = running + 1 end
    end
    if running >= MAX_RUNNING_JOBS then
        return { success = false, error = "Too many running jobs (" .. running .. "); wait for one to finish or cancel_job", error_code = "OUT_OF_RESOURCES" }
    end

    pruneJobs()
    local seq = serverState.job_next_id
    serverState.job_next_id = seq + 1
    local job = { id = "job_" .. seq, seq = seq, kind = kind, state = "running", phase = "starting",
                  created = os.time(), progress = { current = 0, total = 0 } }
    serverState.jobs[job.id] = job

    local function abort()
        if job._ms and not job._shared_ms then pcall(function() job._ms.destroy() end) end
        if job._shared_ms and job._ms then pcall(function() job._ms.OnScanDone = nil end) end
        job._ms = nil
        if serverState.scan_job_id == job.id then serverState.scan_job_id = nil end
        serverState.jobs[job.id] = nil
    end

    local ok, err = pcall(starter, job, p)
    if not ok then
        abort()
        return { success = false, error = "Failed to start job: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    if err then          -- starter returned an error reply
        abort()
        return err
    end
    ensurePump()
    return { success = true, job_id = job.id, kind = kind, state = job.state }
end

function cmd_get_job(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    jobAdvance(job)
    local s = jobSummary(job)
    s.success = true
    return s
end

function cmd_get_job_result(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    jobAdvance(job)
    if job.state ~= "done" or not job.result then
        return { success = false, error = "Job " .. job.id .. " is " .. job.state .. "; no result available",
                 error_code = job.state == "running" and "BUSY" or "NOT_FOUND", state = job.state, error_detail = job.error }
    end
    local out = { success = true, job_id = job.id, kind = job.kind }
    for k, v in pairs(job.result.fields or {}) do out[k] = v end
    if job.result.list_key then
        local limit, offset, page, total = paginate(params, job.result.items, 100)
        out.total, out.offset, out.limit, out.returned = total, offset, limit, #page
        out[job.result.list_key] = page
    end
    return out
end

function cmd_cancel_job(params)
    local job = serverState.jobs[params.job_id]
    if not job then return jobNotFound(params.job_id) end
    if job.state ~= "running" then
        return { success = true, job_id = job.id, state = job.state, note = "Job was not running" }
    end

    local note
    if job.phase == "scanning" and job._ms then
        -- CE has no "stop scan" call; destroying the memscan terminates its scanner threads.
        if job._shared_ms then
            -- next_scan runs on the shared scan session; a half-finished session is unusable.
            if serverState.scan_foundlist then pcall(function() serverState.scan_foundlist.destroy() end); serverState.scan_foundlist = nil end
            pcall(function() job._ms.destroy() end)
            serverState.scan_memscan = nil
            note = "The active scan session was discarded; run scan_all again."
        else
            pcall(function() job._ms.destroy() end)
        end
        job._ms = nil
    end
    jobFinish(job, "cancelled", { note = note })
    return { success = true, job_id = job.id, state = job.state, note = note }
end

function cmd_list_jobs(params)
    local list = {}
    for _, job in pairs(serverState.jobs) do list[#list + 1] = job end
    table.sort(list, function(a, b) return a.seq < b.seq end)
    local out = {}
    for i, job in ipairs(list) do out[i] = jobSummary(job) end
    return { success = true, count = #out, jobs = out }
end

-- >>> END UNIT-25 <<<

-- >>> BEGIN UNIT-26 Analysis: PE/modules, address translation, RTTI, string refs, code caves, pointer paths, snapshots <<<

local U26 = { CHUNK = 0x10000, SNAP_MAX_TOTAL = 128 * 1024 * 1024, SNAP_MAX_ONE = 64 * 1024 * 1024, SNAP_MAX_COUNT = 16 }
serverState.snapshots = {}
serverState.snapshot_bytes = 0
serverState.snapshot_seq = 0
serverState.rtti_cache = {}      -- lower(module name) -> RTTI items from the last rtti_scan job

function U26.err(msg, code)
    return { success = false, error = msg, error_code = code or "INVALID_PARAMS" }
end

function U26.addr(v)
    if type(v) == "number" then return v end
    if type(v) == "string" and v ~= "" then return getAddressSafe(v) end
    return nil
end

function U26.hex(n) return string.format("0x%X", n) end

-- ---------------------------------------------------------------------------
-- memory helpers (all reads go through readBytes so they behave like CE's own)
-- ---------------------------------------------------------------------------
function U26.rd(addr, n)
    local b = readBytes(addr, n, true)
    if not b then return nil end
    return bytesToString(b)
end

function U26.u32(a) local s = U26.rd(a, 4); if s then return (string.unpack("<I4", s)) end end
function U26.u64(a) local s = U26.rd(a, 8); if s then return (string.unpack("<I8", s)) end end
function U26.ptr(a, is64) if is64 then return U26.u64(a) end return U26.u32(a) end

-- NUL-terminated string (<= max bytes). Returns text, terminated?
function U26.cstr(addr, max)
    max = max or 256
    local out, got = {}, 0
    while got < max do
        local n = math.min(64, max - got)
        local s = U26.rd(addr + got, n)
        if not s then
            n = 1
            s = U26.rd(addr + got, 1)     -- near an unmapped page: step byte by byte
            if not s then break end
        end
        local nul = s:find("\0", 1, true)
        if nul then
            out[#out + 1] = s:sub(1, nul - 1)
            return table.concat(out), true
        end
        out[#out + 1] = s
        got = got + #s
    end
    return table.concat(out), false
end

-- ---------------------------------------------------------------------------
-- modules and PE headers
-- ---------------------------------------------------------------------------
function U26.listModules()
    local list = {}
    local ok, mods = pcall(enumModules, getOpenedProcessID())
    if not ok or type(mods) ~= "table" or #mods == 0 then ok, mods = pcall(enumModules) end
    if ok and type(mods) == "table" then
        for _, m in ipairs(mods) do
            if m and m.Address then
                list[#list + 1] = { name = m.Name or "???", base = m.Address, size = m.Size or 0, is64 = m.Is64Bit }
            end
        end
    end
    return list
end

function U26.moduleFor(mods, addr)
    for _, m in ipairs(mods) do
        if addr >= m.base and addr < m.base + m.size then return m end
    end
    return nil
end

-- spec: nil/"" = main module (first), module name (exact, then substring), or an address inside a module.
-- Returns module, nil, allModules   or   nil, errorReply
function U26.findModule(spec)
    local mods = U26.listModules()
    if #mods == 0 then return nil, U26.err("No modules found (is a process attached?)", "NO_PROCESS") end
    if spec == nil or spec == "" then return mods[1], nil, mods end
    if type(spec) == "string" then
        local l = spec:lower()
        for _, m in ipairs(mods) do if m.name:lower() == l then return m, nil, mods end end
        for _, m in ipairs(mods) do if m.name:lower():find(l, 1, true) then return m, nil, mods end end
    end
    local a = U26.addr(spec)
    if a then
        local m = U26.moduleFor(mods, a)
        if m then return m, nil, mods end
    end
    return nil, U26.err("Module not found: " .. tostring(spec), "NOT_FOUND")
end

U26.DIR_NAMES = { [0] = "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
                  "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr_runtime", "reserved" }
U26.MACHINES = { [0x8664] = "x64", [0x14C] = "x86", [0xAA64] = "arm64", [0x1C4] = "arm" }

function U26.parsePE(base)
    local s = U26.rd(base, 0x1000) or U26.rd(base, 0x400)
    if not s or #s < 0x40 or s:sub(1, 2) ~= "MZ" then
        return nil, "No valid MZ header at " .. U26.hex(base)
    end
    local nt = string.unpack("<I4", s, 0x3D)
    if nt < 0x40 or nt + 0x108 > #s then
        local bigger = nt >= 0x40 and nt < 0x10000 and U26.rd(base, nt + 0x1000)
        if not bigger then return nil, "PE header lies outside the readable header page" end
        s = bigger
    end
    if s:sub(nt + 1, nt + 4) ~= "PE\0\0" then return nil, "Missing PE signature" end

    local pe = { base = base }
    local machine, nsec, stamp = string.unpack("<I2I2I4", s, nt + 5)
    local optSize, fileChars = string.unpack("<I2I2", s, nt + 21)
    local opt = nt + 24
    local magic = string.unpack("<I2", s, opt + 1)
    if magic ~= 0x20B and magic ~= 0x10B then return nil, "Unknown optional header magic " .. U26.hex(magic) end
    local is64 = (magic == 0x20B)
    pe.is64, pe.ptrSize = is64, is64 and 8 or 4
    pe.machine = machine
    pe.machine_name = U26.MACHINES[machine] or U26.hex(machine)
    pe.timestamp, pe.characteristics = stamp, fileChars
    pe.entry_rva = string.unpack("<I4", s, opt + 17)
    pe.preferred_base = is64 and string.unpack("<I8", s, opt + 25) or string.unpack("<I4", s, opt + 29)
    pe.section_alignment = string.unpack("<I4", s, opt + 33)
    pe.size_of_image, pe.size_of_headers = string.unpack("<I4I4", s, opt + 57)
    pe.subsystem, pe.dll_characteristics = string.unpack("<I2I2", s, opt + 69)
    local nDirs = string.unpack("<I4", s, opt + (is64 and 109 or 93))
    local dirOff = opt + (is64 and 112 or 96)
    pe.dirs = {}
    for i = 0, math.min(nDirs, 16) - 1 do
        local rva, size = string.unpack("<I4I4", s, dirOff + i * 8 + 1)
        pe.dirs[i] = { rva = rva, size = size }
    end

    local secOff = opt + optSize
    if secOff + nsec * 40 > #s then
        local bigger = U26.rd(base, secOff + nsec * 40)
        if not bigger then return nil, "Section table is unreadable" end
        s = bigger
    end
    pe.sections = {}
    for i = 0, math.min(nsec, 96) - 1 do
        local o = secOff + i * 40
        local name = s:sub(o + 1, o + 8):gsub("\0.*$", "")
        local vsize, vaddr, rawSize, rawPtr = string.unpack("<I4I4I4I4", s, o + 9)
        local chars = string.unpack("<I4", s, o + 37)
        local flags = ((chars & 0x40000000) ~= 0 and "r" or "-") .. ((chars & 0x80000000) ~= 0 and "w" or "-") .. ((chars & 0x20000000) ~= 0 and "x" or "-")
        pe.sections[#pe.sections + 1] = {
            name = name, rva = vaddr, vsize = vsize, raw_size = rawSize, raw_ptr = rawPtr,
            characteristics = chars, flags = flags,
            exec = (chars & 0x20000000) ~= 0, discardable = (chars & 0x02000000) ~= 0,
        }
    end
    return pe
end

function U26.sectionFor(pe, rva)
    for _, sec in ipairs(pe.sections) do
        if rva >= sec.rva and rva < sec.rva + math.max(sec.vsize, sec.raw_size) then return sec end
    end
    return nil
end

function U26.peFor(params)
    local perr = requireProcess()
    if perr then return nil, nil, nil, perr end
    local mod, merr, mods = U26.findModule(params.module)
    if not mod then return nil, nil, nil, merr end
    local pe, e = U26.parsePE(mod.base)
    if not pe then return nil, nil, nil, U26.err(e, "INTERNAL_ERROR") end
    return mod, pe, mods
end

function cmd_pe_info(params)
    local mod, pe, _, err = U26.peFor(params)
    if not mod then return err end
    local sections, dirs = {}, {}
    for i, sec in ipairs(pe.sections) do
        sections[i] = { name = sec.name, rva = sec.rva, rva_hex = U26.hex(sec.rva), virtual_size = sec.vsize, raw_size = sec.raw_size,
                        flags = sec.flags, characteristics = U26.hex(sec.characteristics), address = U26.hex(mod.base + sec.rva) }
    end
    for i = 0, 15 do
        local d = pe.dirs[i]
        if d and d.rva ~= 0 then dirs[#dirs + 1] = { name = U26.DIR_NAMES[i], index = i, rva = d.rva, rva_hex = U26.hex(d.rva), size = d.size } end
    end
    return {
        success = true, module = mod.name, base = U26.hex(mod.base), arch = pe.machine_name, is_64bit = pe.is64,
        entry_point_rva = pe.entry_rva, entry_point = U26.hex(mod.base + pe.entry_rva),
        preferred_image_base = U26.hex(pe.preferred_base), relocated = (pe.preferred_base ~= mod.base),
        size_of_image = pe.size_of_image, size_of_headers = pe.size_of_headers, subsystem = pe.subsystem,
        dll_characteristics = U26.hex(pe.dll_characteristics), timestamp = pe.timestamp,
        sections = sections, data_directories = dirs,
    }
end

function cmd_pe_imports(params)
    local mod, pe, mods, err = U26.peFor(params)
    if not mod then return err end
    local P = pe.ptrSize
    local dir = pe.dirs[1]
    local dllFilter = (type(params.dll) == "string" and params.dll ~= "") and params.dll:lower() or nil
    local entries, dlls = {}, {}
    if dir and dir.rva ~= 0 then
        local descBase = mod.base + dir.rva
        for di = 0, 4095 do
            local desc = U26.rd(descBase + di * 20, 20)
            if not desc then break end
            local oft, _, _, nameRva, ft = string.unpack("<I4I4I4I4I4", desc)
            if oft == 0 and nameRva == 0 and ft == 0 then break end
            local dllName = U26.cstr(mod.base + nameRva, 260) or "?"
            if not dllFilter or dllName:lower():find(dllFilter, 1, true) then
                local src = (oft ~= 0) and oft or ft
                local count = 0
                for idx = 0, 65535 do
                    local thunk = U26.ptr(mod.base + src + idx * P, pe.is64)
                    if not thunk or thunk == 0 then break end
                    entries[#entries + 1] = { dll = dllName, thunk = thunk, iat_rva = ft + idx * P }
                    count = count + 1
                end
                dlls[#dlls + 1] = { name = dllName, count = count }
            end
        end
    end

    local limit, offset, page, total = paginate(params, entries, 100)
    local ordBit = 1 << (P * 8 - 1)
    local out = {}
    for i, e in ipairs(page) do
        local item = { dll = e.dll, iat_rva = e.iat_rva, iat_address = U26.hex(mod.base + e.iat_rva) }
        if (e.thunk & ordBit) ~= 0 then
            item.ordinal = e.thunk & 0xFFFF
        else
            local hint = U26.rd(mod.base + e.thunk, 2)
            if hint then item.hint = (string.unpack("<I2", hint)) end
            item.name = U26.cstr(mod.base + e.thunk + 2, 256)
        end
        local resolved = U26.ptr(mod.base + e.iat_rva, pe.is64)
        if resolved then
            item.resolved = U26.hex(resolved)
            local rm = U26.moduleFor(mods, resolved)
            if rm then item.resolved_module = rm.name end
        end
        out[i] = item
    end
    return { success = true, module = mod.name, total = total, offset = offset, limit = limit, returned = #out, dlls = dlls, imports = out }
end

function cmd_pe_exports(params)
    local mod, pe, _, err = U26.peFor(params)
    if not mod then return err end
    local dir = pe.dirs[0]
    local entries = {}
    local dllName
    if dir and dir.rva ~= 0 then
        local ed = U26.rd(mod.base + dir.rva, 40)
        if not ed then return U26.err("Export directory is unreadable", "INTERNAL_ERROR") end
        local _, _, _, _, nameRva, ordBase, nFuncs, nNames, funcsRva, namesRva, ordsRva = string.unpack("<I4I4I2I2I4I4I4I4I4I4I4", ed)
        dllName = U26.cstr(mod.base + nameRva, 260)
        nFuncs, nNames = math.min(nFuncs, 65536), math.min(nNames, 65536)
        local funcsRaw = nFuncs > 0 and U26.rd(mod.base + funcsRva, nFuncs * 4) or ""
        local namesRaw = nNames > 0 and U26.rd(mod.base + namesRva, nNames * 4) or ""
        local ordsRaw = nNames > 0 and U26.rd(mod.base + ordsRva, nNames * 2) or ""
        if not funcsRaw or not namesRaw or not ordsRaw then return U26.err("Export tables are unreadable", "INTERNAL_ERROR") end
        local named = {}
        local function isForwarder(rva) return rva >= dir.rva and rva < dir.rva + dir.size end
        for i = 0, nNames - 1 do
            local nRva = string.unpack("<I4", namesRaw, i * 4 + 1)
            local ord = string.unpack("<I2", ordsRaw, i * 2 + 1)
            local fRva = ord < nFuncs and string.unpack("<I4", funcsRaw, ord * 4 + 1) or 0
            named[ord] = true
            local e = { name = U26.cstr(mod.base + nRva, 512), ordinal = ordBase + ord, rva = fRva }
            if fRva ~= 0 and isForwarder(fRva) then e.forwarder = U26.cstr(mod.base + fRva, 512) end
            entries[#entries + 1] = e
        end
        for ord = 0, nFuncs - 1 do
            if not named[ord] then
                local fRva = string.unpack("<I4", funcsRaw, ord * 4 + 1)
                if fRva ~= 0 then
                    local e = { ordinal = ordBase + ord, rva = fRva }
                    if isForwarder(fRva) then e.forwarder = U26.cstr(mod.base + fRva, 512) end
                    entries[#entries + 1] = e
                end
            end
        end
    end
    local filter = (type(params.name_contains) == "string" and params.name_contains ~= "") and params.name_contains:lower() or nil
    if filter then
        local kept = {}
        for _, e in ipairs(entries) do
            if e.name and e.name:lower():find(filter, 1, true) then kept[#kept + 1] = e end
        end
        entries = kept
    end
    local limit, offset, page, total = paginate(params, entries, 100)
    for _, e in ipairs(page) do
        e.rva_hex = U26.hex(e.rva)
        e.address = U26.hex(mod.base + e.rva)
    end
    return { success = true, module = mod.name, export_name = dllName, total = total, offset = offset, limit = limit, returned = #page, exports = page }
end

function cmd_pe_tls_callbacks(params)
    local mod, pe, mods, err = U26.peFor(params)
    if not mod then return err end
    local dir = pe.dirs[9]
    if not dir or dir.rva == 0 then
        return { success = true, module = mod.name, has_tls = false, callbacks = {} }
    end
    local P = pe.ptrSize
    local td = U26.rd(mod.base + dir.rva, P == 8 and 40 or 24)
    if not td then return U26.err("TLS directory is unreadable", "INTERNAL_ERROR") end
    local startRaw, endRaw, indexAddr, cbArray, zeroFill, chars
    if pe.is64 then
        startRaw, endRaw, indexAddr, cbArray, zeroFill, chars = string.unpack("<I8I8I8I8I4I4", td)
    else
        startRaw, endRaw, indexAddr, cbArray, zeroFill, chars = string.unpack("<I4I4I4I4I4I4", td)
    end
    local callbacks = {}
    if cbArray ~= 0 then
        for i = 0, 63 do
            local va = U26.ptr(cbArray + i * P, pe.is64)
            if not va or va == 0 then break end
            local c = { address = U26.hex(va), rva = va - mod.base, rva_hex = U26.hex(va - mod.base) }
            local sec = U26.sectionFor(pe, va - mod.base)
            if sec then c.section = sec.name end
            local m = U26.moduleFor(mods, va)
            if m then c.module = m.name end
            callbacks[#callbacks + 1] = c
        end
    end
    return {
        success = true, module = mod.name, has_tls = true, callback_count = #callbacks, callbacks = callbacks,
        raw_data_start = U26.hex(startRaw), raw_data_end = U26.hex(endRaw), index_address = U26.hex(indexAddr),
        callbacks_array = U26.hex(cbArray), size_of_zero_fill = zeroFill, characteristics = chars,
    }
end

-- ---------------------------------------------------------------------------
-- address translation (CE <-> IDA / any rebased image)
-- ---------------------------------------------------------------------------
function U26.baseOf(spec)
    if type(spec) == "number" then return spec end
    if type(spec) == "string" and spec ~= "" then
        local n = tonumber(spec)
        if n then return math.tointeger(n) or n end
        local m = U26.findModule(spec)
        if m then return m.base end
    end
    return nil
end

function U26.toList(single, many)
    if type(many) == "table" then return many, true end
    return { single }, false
end

function cmd_va_to_rva(params)
    local perr = requireProcess()
    if perr then return perr end
    local list, multi = U26.toList(params.address, params.addresses)
    local mods = U26.listModules()
    local peCache = {}
    local results = {}
    for i, raw in ipairs(list) do
        local a = U26.addr(raw)
        if not a then
            results[i] = { input = tostring(raw), found = false, error = "invalid address" }
        else
            local m = U26.moduleFor(mods, a)
            if not m then
                results[i] = { address = U26.hex(a), found = false }
            else
                local rva = a - m.base
                local r = { address = U26.hex(a), found = true, module = m.name, base = U26.hex(m.base), rva = rva, rva_hex = U26.hex(rva),
                            expression = m.name .. "+" .. U26.hex(rva) }
                if params.ida_image_base then
                    local ib = U26.baseOf(params.ida_image_base)
                    if ib then r.ida_address = U26.hex(ib + rva) end
                end
                if params.include_section ~= false then
                    peCache[m.base] = peCache[m.base] or { U26.parsePE(m.base) }
                    local pe = peCache[m.base][1]
                    local sec = pe and U26.sectionFor(pe, rva)
                    if sec then r.section, r.section_offset = sec.name, rva - sec.rva end
                end
                results[i] = r
            end
        end
    end
    if multi then return { success = true, count = #results, results = results } end
    local single = results[1] or { found = false }
    single.success = true
    return single
end

function cmd_rva_to_va(params)
    local perr = requireProcess()
    if perr then return perr end
    local mod, merr = U26.findModule(params.module)
    if not mod then return merr end
    local list, multi = U26.toList(params.rva, params.rvas)
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil
    local results = {}
    for i, raw in ipairs(list) do
        local rva = tonumber(raw)
        if not rva then
            results[i] = { input = tostring(raw), error = "invalid rva" }
        else
            rva = math.tointeger(rva) or rva
            local r = { rva = rva, rva_hex = U26.hex(rva), address = U26.hex(mod.base + rva), module = mod.name, in_module = rva >= 0 and rva < mod.size }
            if ib then r.ida_address = U26.hex(ib + rva) end
            results[i] = r
        end
    end
    if multi then return { success = true, module = mod.name, base = U26.hex(mod.base), count = #results, results = results } end
    local single = results[1]
    single.success = true
    return single
end

-- Moves addresses between two images that are loaded at different bases:
--   from_base|from_module -> to_base|to_module   (e.g. an IDA address into a running module)
function cmd_rebase_address(params)
    local from = U26.baseOf(params.from_base or params.from_module)
    local to = U26.baseOf(params.to_base or params.to_module)
    if not from or not to then
        return U26.err("Give from_base|from_module and to_base|to_module (hex number or module name)", "INVALID_PARAMS")
    end
    local list, multi = U26.toList(params.address, params.addresses)
    local results = {}
    for i, raw in ipairs(list) do
        local a = U26.addr(raw)
        if not a then
            results[i] = { input = tostring(raw), error = "invalid address" }
        else
            results[i] = { from = U26.hex(a), to = U26.hex(a - from + to), rva = a - from, rva_hex = U26.hex(a - from) }
        end
    end
    if multi then return { success = true, from_base = U26.hex(from), to_base = U26.hex(to), count = #results, results = results } end
    local single = results[1]
    single.success = true
    return single
end

-- ---------------------------------------------------------------------------
-- exporting / importing names (CE <-> IDA)
-- ---------------------------------------------------------------------------
function U26.demangle(raw)
    local body = raw:match("^%.%?A[VUTW](.*)@@$")
    if not body then return raw end
    if body:find("?$", 1, true) then return body end        -- template instantiation: keep MSVC text
    local parts = {}
    for part in body:gmatch("[^@]+") do
        if part:match("^%?A0x%x+$") then part = "(anonymous namespace)" end   -- MSVC's unnamed namespace marker
        table.insert(parts, 1, part)
    end
    return table.concat(parts, "::")
end

function U26.idaName(s)
    s = s:gsub("[^%w_]", "_")
    if s:match("^%d") then s = "_" .. s end
    return s
end

function U26.pyStr(s)
    return '"' .. tostring(s):gsub("\\", "\\\\"):gsub('"', "'"):gsub("[\r\n]", " ") .. '"'
end

function cmd_export_names(params)
    local perr = requireProcess()
    if perr then return perr end
    local mod, merr = U26.findModule(params.module)
    if not mod then return merr end
    local wanted = {}
    for _, s in ipairs(type(params.sources) == "table" and params.sources or { "symbols", "rtti" }) do wanted[s] = true end
    local fmt = params.format or "json"
    if fmt ~= "json" and fmt ~= "idapython" then return U26.err("format must be 'json' or 'idapython'") end
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil

    local entries, notes = {}, {}
    if wanted.symbols then
        local ok, syms = pcall(enumRegisteredSymbols)
        if ok and type(syms) == "table" then
            for _, sym in ipairs(syms) do
                local a = sym and sym.address
                local name = sym and (sym.symbolname or sym.name)
                if a and name and a >= mod.base and a < mod.base + mod.size then
                    entries[#entries + 1] = { rva = a - mod.base, name = name, kind = "symbol" }
                end
            end
        end
    end
    local rtti = serverState.rtti_cache[mod.name:lower()]
    if wanted.rtti then
        if rtti then
            for _, c in ipairs(rtti) do
                entries[#entries + 1] = { rva = c.vtable_rva, name = c.class_name .. "::vftable", kind = "vtable",
                                          comment = c.class_name .. " vtable (" .. c.vfunc_count .. " virtual functions)" }
            end
        else
            notes[#notes + 1] = "No RTTI data cached for " .. mod.name .. "; run rtti_scan_module first."
        end
    end
    table.sort(entries, function(a, b) if a.rva ~= b.rva then return a.rva < b.rva end return a.name < b.name end)
    for _, e in ipairs(entries) do
        e.rva_hex = U26.hex(e.rva)
        e.ida_name = U26.idaName(e.name)
        if ib then e.ida_address = U26.hex(ib + e.rva) end
    end

    local out = { success = true, module = mod.name, base = U26.hex(mod.base), count = #entries, notes = notes }
    if params.include_types ~= false and rtti and wanted.rtti then
        local decl, seen = {}, {}
        for _, c in ipairs(rtti) do
            local n = U26.idaName(c.class_name)
            if c.vfunc_count > 0 and not seen[n] then
                seen[n] = true
                local slots = {}
                for i = 0, c.vfunc_count - 1 do slots[#slots + 1] = "    void *vf" .. i .. ";" end
                decl[#decl + 1] = "struct " .. n .. "_vtbl {\n" .. table.concat(slots, "\n") .. "\n};"
                decl[#decl + 1] = "struct " .. n .. " {\n    " .. n .. "_vtbl *vfptr;\n};" .. (#c.bases > 1 and ("  // bases: " .. table.concat(c.bases, ", ")) or "")
            end
        end
        out.c_declarations = table.concat(decl, "\n")
    end
    if fmt == "json" then
        out.names = entries
    else
        local lines = {
            "# Generated by cheatengine-mcp-bridge (export_names) for module " .. mod.name,
            "import idaapi, idc",
            "base = idaapi.get_imagebase()",
            "NAMES = [",
        }
        for _, e in ipairs(entries) do
            lines[#lines + 1] = string.format("    (0x%X, %s, %s),", e.rva, U26.pyStr(e.ida_name), U26.pyStr(e.comment or e.name))
        end
        lines[#lines + 1] = "]"
        lines[#lines + 1] = "for rva, name, comment in NAMES:"
        lines[#lines + 1] = "    ea = base + rva"
        lines[#lines + 1] = "    idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)"
        lines[#lines + 1] = "    idc.set_cmt(ea, comment, 0)"
        lines[#lines + 1] = 'print("applied %d names" % len(NAMES))'
        out.script = table.concat(lines, "\n")
    end
    return out
end

function cmd_import_names(params)
    local perr = requireProcess()
    if perr then return perr end
    local names = params.names
    if type(names) ~= "table" or #names == 0 then
        return U26.err("names must be a non-empty array of {name, rva|address}")
    end
    if #names > 5000 then return U26.err("At most 5000 names per call") end
    local mod
    if params.module and params.module ~= "" then
        local m, merr = U26.findModule(params.module)
        if not m then return merr end
        mod = m
    end
    local ib = params.ida_image_base and U26.baseOf(params.ida_image_base) or nil
    local prefix = params.prefix or ""
    local okCount, failures = 0, {}
    for i, n in ipairs(names) do
        local name = type(n) == "table" and n.name
        local address
        if type(n) == "table" then
            if n.address ~= nil then
                address = U26.addr(n.address)
                if address and ib and params.address_is_ida then address = address - ib + (mod and mod.base or 0) end
            elseif n.rva ~= nil and mod then
                local rva = tonumber(n.rva)
                address = rva and (mod.base + (math.tointeger(rva) or rva))
            end
        end
        if type(name) ~= "string" or name == "" or not address then
            failures[#failures + 1] = { index = i, error = "needs name and (rva with module) or address" }
        else
            local r = cmd_register_symbol({ name = prefix .. name, address = address, do_not_save = params.do_not_save ~= false })
            if r.success then okCount = okCount + 1 else failures[#failures + 1] = { index = i, name = name, error = r.error } end
        end
    end
    while #failures > 50 do table.remove(failures) end
    return { success = true, registered = okCount, failed = #names - okCount, failures = failures }
end

function U26.structType(vt)
    local map = {}
    map[vtByte] = "unsigned char"; map[vtWord] = "unsigned short"; map[vtDword] = "unsigned int"
    map[vtQword] = "unsigned __int64"; map[vtSingle] = "float"; map[vtDouble] = "double"
    map[vtPointer] = "void *"
    return map[vt]
end

-- C declarations for CE structure definitions (feed to IDA's declare_c_type / "Local Types").
function cmd_export_structures(params)
    local okC, count = pcall(getStructureCount)
    if not okC then return U26.err("getStructureCount failed: " .. tostring(count), "CE_API_UNAVAILABLE") end
    local only = type(params.name) == "string" and params.name ~= "" and params.name or nil
    local decls, structs = {}, {}
    for si = 0, count - 1 do
        local okS, s = pcall(getStructure, si)
        if okS and s then
            local okN, sname = pcall(function() return s.Name end)
            if okN and sname and (not only or sname == only) then
                local els = {}
                local okCnt, cnt = pcall(function() return s.Count end)
                for i = 0, (okCnt and cnt or 0) - 1 do
                    local okE, el = pcall(function() return s.getElement(i) end)
                    if okE and el then
                        local name, offset, vt, size
                        pcall(function() name = el.Name end)
                        pcall(function() offset = el.Offset end)
                        pcall(function() vt = el.Vartype end)
                        pcall(function() size = el.Bytesize end)
                        els[#els + 1] = { name = (name and name ~= "") and name or ("field_" .. string.format("%X", offset or 0)), offset = offset or 0, vt = vt, size = size or 0 }
                    end
                end
                table.sort(els, function(a, b) return a.offset < b.offset end)
                local okSz, total = pcall(function() return s.Size end)
                local lines, pos, padN = {}, 0, 0
                for _, el in ipairs(els) do
                    local ctype = U26.structType(el.vt)
                    local sz = el.size
                    local declLine
                    if ctype and el.size > 0 then
                        declLine = "    " .. ctype .. " " .. U26.idaName(el.name) .. ";"
                    elseif el.size > 0 then
                        declLine = "    unsigned char " .. U26.idaName(el.name) .. "[" .. el.size .. "];"
                    end
                    if declLine then
                        if el.offset < pos then
                            lines[#lines + 1] = "    // overlapping field '" .. el.name .. "' at +" .. U26.hex(el.offset) .. " skipped"
                        else
                            if el.offset > pos then
                                padN = padN + 1
                                lines[#lines + 1] = "    unsigned char _pad" .. padN .. "[" .. (el.offset - pos) .. "];"
                            end
                            lines[#lines + 1] = declLine .. "  // +" .. U26.hex(el.offset)
                            pos = el.offset + sz
                        end
                    end
                end
                if okSz and total and total > pos then
                    padN = padN + 1
                    lines[#lines + 1] = "    unsigned char _pad" .. padN .. "[" .. (total - pos) .. "];"
                end
                decls[#decls + 1] = "struct " .. U26.idaName(sname) .. " {\n" .. table.concat(lines, "\n") .. "\n};"
                structs[#structs + 1] = { name = sname, elements = #els, size = okSz and total or nil }
            end
        end
    end
    return { success = true, count = #structs, structures = structs, c_declarations = table.concat(decls, "\n\n") }
end

-- ---------------------------------------------------------------------------
-- time-sliced chunk engine shared by the scanning jobs (rtti_scan, find_string_refs, find_code_caves)
-- stage = { ranges = {{base,size}...}, process = fn(job, data, dataBase), carry = N, onStart = fn, onDone = fn }
-- `carry` bytes of each chunk's tail are prepended to the next chunk so patterns can span chunk borders.
-- ---------------------------------------------------------------------------
function U26.stageStep(job, deadline)
    local stages = job._stages
    while os.clock() < deadline do
        local st = stages[job._si]
        if not st then return job._finish(job) end
        if job._started ~= job._si then
            job._started = job._si
            if st.onStart then st.onStart(job) end
        end
        local r = st.ranges[job._ri]
        if not r then
            if st.onDone then st.onDone(job) end
            job._si, job._ri, job._off, job._carry = job._si + 1, 1, 0, ""
        elseif job._off >= r.size then
            job._ri, job._off, job._carry = job._ri + 1, 0, ""
        else
            local n = math.min(U26.CHUNK, r.size - job._off)
            local addr = r.base + job._off
            local s = U26.rd(addr, n)
            if s then
                local carry = job._carry
                st.process(job, carry .. s, addr - #carry)
                local keep = st.carry or 0
                job._carry = keep > 0 and s:sub(-keep) or ""
            else
                job._carry = ""
                for sub = 0, n - 1, 4096 do      -- unreadable somewhere: salvage the readable pages
                    local ps = U26.rd(addr + sub, math.min(4096, n - sub))
                    if ps then st.process(job, ps, addr + sub) end
                end
            end
            job._off = job._off + n
            job.progress.current = job.progress.current + n
        end
    end
    return false
end

function U26.startStages(job, stages, finish)
    local total = 0
    for _, st in ipairs(stages) do for _, r in ipairs(st.ranges) do total = total + r.size end end
    job._stages, job._finish = stages, finish
    job._si, job._ri, job._off, job._carry, job._started = 1, 1, 0, "", 0
    job.progress = { current = 0, total = total }
    job.phase = "processing"
    job._step = U26.stageStep
    ensurePump()
end

function U26.sectionRanges(pe, mod, wantExec, includeDiscardable)
    local ranges = {}
    for _, sec in ipairs(pe.sections) do
        local size = math.max(sec.vsize, sec.raw_size)
        if size > 0 and sec.exec == wantExec and (includeDiscardable or not sec.discardable) then
            ranges[#ranges + 1] = { base = mod.base + sec.rva, size = size, name = sec.name }
        end
    end
    return ranges
end

function U26.inRanges(ranges, v)
    for _, r in ipairs(ranges) do
        if v >= r.base and v < r.base + r.size then return r end
    end
    return nil
end

-- Lua pattern class matching exactly these byte values. Punctuation must be escaped: a bare '%' (0x25) or '-' (0x2D)
-- inside a hand-written class changes its meaning (the old literal class silently lost modrm 0x25 = reg 4 = r12).
function U26.byteClass(bytes)
    local t = {}
    for i, b in ipairs(bytes) do
        local c = string.char(b)
        t[i] = c:match("%p") and ("%" .. c) or c
    end
    return "[" .. table.concat(t) .. "]"
end
U26.MODRM_RIP = U26.byteClass({ 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D })   -- mod=00 rm=101 for every reg value
U26.LEA_RIP = "[\72\76\73\77]\141" .. U26.MODRM_RIP                                   -- REX.W/WR/WB/WRB + lea + [rip+disp32]

-- ---------------------------------------------------------------------------
-- job: rtti_scan  (MSVC RTTI: classes, vtables, virtual function counts, base classes)
-- ---------------------------------------------------------------------------
function U26.countVfuncs(vtAddr, P, maxEntries, execRanges)
    local count = 0
    local fmt = P == 8 and "<I8" or "<I4"
    while count < maxEntries do
        local want = math.min(32, maxEntries - count)
        local raw = U26.rd(vtAddr + count * P, want * P)
        local slots = want
        if not raw then
            raw = U26.rd(vtAddr + count * P, P)
            slots = 1
            if not raw then break end
        end
        for i = 0, slots - 1 do
            local v = string.unpack(fmt, raw, i * P + 1)
            if not U26.inRanges(execRanges, v) then return count end
            count = count + 1
        end
    end
    return count
end

JOB_STARTERS.rtti_scan = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local is64, P = pe.is64, pe.ptrSize
    local maxEntries = clampInt(p.max_vtable_entries or 256, 1, 4096)
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    local execRanges = U26.sectionRanges(pe, mod, true, true)
    local tdSet, colSet, vtables = {}, {}, {}

    local stages = {
        { ranges = dataRanges, carry = 3, process = function(jb, data, dbase)
            local pos = 1
            while true do
                local s = data:find(".?A", pos, true)
                if not s then break end
                local kind = data:sub(s + 3, s + 3)
                if kind == "V" or kind == "U" then
                    local a = dbase + s - 1
                    local name, terminated = U26.cstr(a, 512)
                    if terminated and name:sub(-2) == "@@" then
                        local td = a - 2 * P
                        tdSet[is64 and (td - mod.base) or td] = { td = td, name = name, is_struct = (kind == "U") }
                    end
                end
                pos = s + 3
            end
        end },
        { ranges = dataRanges, process = function(jb, data, dbase)
            local first = ((4 - dbase % 4) % 4) + 1
            for i = first, #data - 3, 4 do
                local v = string.unpack("<I4", data, i)
                local td = tdSet[v]
                if td then
                    local col = dbase + i - 1 - 12
                    local raw = U26.rd(col, is64 and 24 or 20)
                    if raw then
                        local sig, thisOff, _, tdRef, cdRef, selfRef = string.unpack(is64 and "<I4I4I4I4I4I4" or "<I4I4I4I4I4", raw)
                        local ok
                        if is64 then
                            ok = (sig == 1 and selfRef == col - mod.base)
                        else
                            -- x86 locators carry no self reference, so sanity-check the class hierarchy descriptor too
                            -- (a base-class-descriptor reference to the same type would otherwise pass as a "locator")
                            ok = (sig == 0 and cdRef >= mod.base and cdRef < mod.base + mod.size)
                            if ok then
                                local chd = U26.rd(cdRef, 16)
                                if chd then
                                    local _, _, nb, arr = string.unpack("<I4I4I4I4", chd)
                                    ok = nb >= 1 and nb <= 64 and arr >= mod.base and arr < mod.base + mod.size
                                else
                                    ok = false
                                end
                            end
                        end
                        if ok then colSet[col] = { td = td, this_offset = thisOff, cd = cdRef } end
                    end
                end
            end
        end },
        { ranges = dataRanges, process = function(jb, data, dbase)
            local fmt = is64 and "<I8" or "<I4"
            local first = ((P - dbase % P) % P) + 1
            for i = first, #data - P + 1, P do
                local v = string.unpack(fmt, data, i)
                local info = colSet[v]
                if info then vtables[#vtables + 1] = { loc = dbase + i - 1, col = v, info = info } end
            end
        end },
    }

    U26.startStages(job, stages, function(jb)
        local items, classes = {}, {}
        for _, vt in ipairs(vtables) do
            local vtAddr = vt.loc + P
            local bases = {}
            for _, b in ipairs(U26.readBases(mod, pe, vt.info.cd)) do bases[#bases + 1] = b.name end
            local item = {
                class_name = U26.demangle(vt.info.td.name), raw_name = vt.info.td.name,
                kind = vt.info.td.is_struct and "struct" or "class",
                vtable = U26.hex(vtAddr), vtable_rva = vtAddr - mod.base,
                col = U26.hex(vt.col), this_offset = vt.info.this_offset,
                vfunc_count = U26.countVfuncs(vtAddr, P, maxEntries, execRanges), bases = bases,
            }
            items[#items + 1] = item
            classes[item.class_name] = true
        end
        table.sort(items, function(a, b) return a.vtable_rva < b.vtable_rva end)
        local nClasses = 0
        for _ in pairs(classes) do nClasses = nClasses + 1 end
        serverState.rtti_cache[mod.name:lower()] = items
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, arch = pe.machine_name, class_count = nClasses, vtable_count = #items },
            list_key = "classes", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_string_refs  (string text or address -> code/data that references it)
-- ---------------------------------------------------------------------------
function U26.utf16le(s)
    local out = {}
    for _, cp in utf8.codes(s) do
        if cp >= 0x10000 then
            cp = cp - 0x10000
            out[#out + 1] = string.pack("<I2I2", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF))
        else
            out[#out + 1] = string.pack("<I2", cp)
        end
    end
    return table.concat(out)
end

JOB_STARTERS.find_string_refs = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local is64, P = pe.is64, pe.ptrSize
    local targets, ntargets = {}, 0
    local needle
    if p.address ~= nil and p.address ~= "" then
        local a = U26.addr(p.address)
        if not a then return U26.err("Invalid address", "INVALID_ADDRESS") end
        targets[a], ntargets = true, 1
    elseif type(p.text) == "string" and p.text ~= "" then
        needle = p.wide and U26.utf16le(p.text) or p.text
    else
        return U26.err("Give 'text' (string to look for) or 'address' (of the string)")
    end
    local anyMatch = (p.match == "any")
    local includeData = p.include_data ~= false
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    local codeRanges = U26.sectionRanges(pe, mod, true, true)
    local hits, seen, packed = {}, {}, {}

    local function addHit(addr, kind, target)
        local key = kind .. addr
        if seen[key] or #hits >= 20000 then return end
        seen[key] = true
        hits[#hits + 1] = { addr = addr, kind = kind, target = target }
    end
    local function packTargets()
        packed = {}
        for t in pairs(targets) do packed[#packed + 1] = { t = t, bytes = is64 and string.pack("<I8", t) or string.pack("<I4", t & 0xFFFFFFFF) } end
    end
    local function scanAbsolute(data, dbase, kind, aligned)
        for _, pk in ipairs(packed) do
            local pos = 1
            while true do
                local s = data:find(pk.bytes, pos, true)
                if not s then break end
                local a = dbase + s - 1
                if not aligned or a % P == 0 then addHit(a, kind, pk.t) end
                pos = s + 1
            end
        end
    end

    local stages = {}
    if needle then
        stages[#stages + 1] = { ranges = dataRanges, carry = #needle, process = function(jb, data, dbase)
            local pos = 1
            while ntargets < 64 do
                local s = data:find(needle, pos, true)
                if not s then break end
                if anyMatch or s == 1 or data:byte(s - 1) == 0 then
                    local a = dbase + s - 1
                    if not targets[a] then targets[a] = true; ntargets = ntargets + 1 end
                end
                pos = s + 1
            end
        end }
    end
    stages[#stages + 1] = { ranges = codeRanges, carry = 7, onStart = packTargets, process = function(jb, data, dbase)
        if is64 then
            local pos, lastStart = 1, #data - 6
            while true do
                local s = data:find(U26.LEA_RIP, pos)
                if not s or s > lastStart then break end
                local tgt = dbase + s - 1 + 7 + string.unpack("<i4", data, s + 3)
                if targets[tgt] then addHit(dbase + s - 1, "rip_lea", tgt) end
                pos = s + 1
            end
        end
        scanAbsolute(data, dbase, "abs_code", false)
    end }
    if includeData then
        stages[#stages + 1] = { ranges = dataRanges, carry = 7, process = function(jb, data, dbase)
            scanAbsolute(data, dbase, "abs_data", true)
        end }
    end

    U26.startStages(job, stages, function(jb)
        table.sort(hits, function(a, b) if a.addr ~= b.addr then return a.addr < b.addr end return a.kind < b.kind end)
        local items = {}
        for i, h in ipairs(hits) do
            local rva = h.addr - mod.base
            local item = { address = U26.hex(h.addr), kind = h.kind, target = U26.hex(h.target), rva = rva, expression = mod.name .. "+" .. U26.hex(rva) }
            local sec = U26.sectionFor(pe, rva)
            if sec then item.section = sec.name end
            local fn = U26.functionAt(mod, pe, rva)
            if fn then
                item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)
                item.function_rva = fn.primary.begin_rva
            end
            if h.kind ~= "abs_data" then item.instruction = disassemble(h.addr) or "???" end
            items[i] = item
        end
        local tlist = {}
        for t in pairs(targets) do tlist[#tlist + 1] = t end
        table.sort(tlist)
        for i, t in ipairs(tlist) do tlist[i] = U26.hex(t) end
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, string_addresses = tlist, found = #items, note = is64 and "x64: rip-relative lea + absolute pointers" or "x86: absolute pointers" },
            list_key = "references", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_code_caves  (runs of padding bytes in executable sections)
-- ---------------------------------------------------------------------------
JOB_STARTERS.find_code_caves = function(job, p)
    local mod, pe, _, err = U26.peFor(p)
    if not mod then return err end
    local byte = tonumber(p.byte or 0xCC)
    if byte ~= 0x00 and byte ~= 0x90 and byte ~= 0xCC then
        return U26.err("byte must be 0x00, 0x90 or 0xCC (padding bytes)")
    end
    local minSize = clampInt(p.min_size or 16, 2, 0x100000)
    local ranges
    if p.sections ~= "all" then
        ranges = U26.sectionRanges(pe, mod, true, true)
    else
        ranges = {}
        for _, sec in ipairs(pe.sections) do
            local size = math.max(sec.vsize, sec.raw_size)
            if size > 0 and not sec.discardable then ranges[#ranges + 1] = { base = mod.base + sec.rva, size = size, name = sec.name } end
        end
    end
    local pat = "[" .. string.char(byte) .. "]+"
    local caves, run = {}, nil

    local function closeRun()
        if run and run.len >= minSize and #caves < 100000 then caves[#caves + 1] = { addr = run.start, size = run.len } end
        run = nil
    end

    local stages = { { ranges = ranges, onDone = closeRun, process = function(jb, data, dbase)
        local pos = 1
        if run then
            if run.nextAddr == dbase then
                local s, e = data:find("^" .. pat)
                if s then
                    run.len, run.nextAddr = run.len + e, dbase + #data
                    if e == #data then return end          -- run continues into the next chunk
                    pos = e + 1
                end
            end
            closeRun()
        end
        while true do
            local s, e = data:find(pat, pos)
            if not s then break end
            if e == #data then
                run = { start = dbase + s - 1, len = e - s + 1, nextAddr = dbase + #data }
                break
            end
            if e - s + 1 >= minSize and #caves < 100000 then caves[#caves + 1] = { addr = dbase + s - 1, size = e - s + 1 } end
            pos = e + 1
        end
    end } }

    U26.startStages(job, stages, function(jb)
        table.sort(caves, function(a, b) if a.size ~= b.size then return a.size > b.size end return a.addr < b.addr end)
        local items = {}
        for i, c in ipairs(caves) do
            local rva = c.addr - mod.base
            local item = { address = U26.hex(c.addr), size = c.size, rva = rva, expression = mod.name .. "+" .. U26.hex(rva) }
            local sec = U26.sectionFor(pe, rva)
            if sec then item.section = sec.name end
            items[i] = item
        end
        jb.progress.current = jb.progress.total
        jobFinish(jb, "done", { result = {
            fields = { module = mod.name, byte = string.format("0x%02X", byte), min_size = minSize, found = #items },
            list_key = "caves", items = items } })
        return true
    end)
end

-- ---------------------------------------------------------------------------
-- job: find_pointer_path  (reverse pointer search: which static [[base]+o1]+o2... reaches an address)
-- One value-between memscan per frontier address per level (CE has no scripted pointer scanner).
-- ---------------------------------------------------------------------------
JOB_STARTERS.find_pointer_path = function(job, p)
    local target = U26.addr(p.address)
    if not target then return U26.err("Invalid address", "INVALID_ADDRESS") end
    local is64 = targetIs64Bit()
    local P = is64 and 8 or 4
    local maxDepth = clampInt(p.max_depth or 3, 1, 6)
    local maxOffset = clampInt(p.max_offset or 0x400, 0, 0x100000)
    local beam = clampInt(p.max_per_level or 16, 1, 256)
    local perScan = clampInt(p.max_results_per_scan or 2000, 10, 50000)
    local maxFound = clampInt(p.max_results or 100, 1, 1000)
    local protect = p.protection or "+W"
    if p.save_as ~= nil then
        local _, nerr = U26.psName(p.save_as)             -- fail now, not after minutes of scanning
        if nerr then return nerr end
    end
    local mods = U26.listModules()
    local st = { frontier = { { t = target, offs = {} } }, qi = 1, depth = 1, nextc = {}, found = {}, scans = 0, truncated = false, seen = {} }
    local onScan

    local function chainExpression(base, offs)
        local expr = "[" .. base .. "]"
        for i, o in ipairs(offs) do
            expr = expr .. "+" .. U26.hex(o)
            if i < #offs then expr = "[" .. expr .. "]" end
        end
        return expr
    end

    local function finish(j)
        table.sort(st.found, function(a, b)
            if #a.offs ~= #b.offs then return #a.offs < #b.offs end
            return a.cost < b.cost
        end)
        local items, keep = {}, {}
        for i, f in ipairs(st.found) do
            if i > maxFound then break end
            local baseStr = f.module .. "+" .. U26.hex(f.rva)
            local chain = resolveChain(f.base, f.offs)
            local hexOffs = {}
            for k, o in ipairs(f.offs) do hexOffs[k] = U26.hex(o) end
            local verified = (chain.ok == true and chain.final_address == target)
            items[#items + 1] = {
                base = baseStr, base_address = U26.hex(f.base), offsets = f.offs, offsets_hex = hexOffs,
                depth = #f.offs, expression = chainExpression(baseStr, f.offs),
                verified = verified,
            }
            if verified then keep[#keep + 1] = { module = f.module, rva = f.rva, offsets = f.offs, runs = 1 } end
        end
        j.progress = { current = st.scans, total = math.max(st.scans, 1) }
        local fields = { target = U26.hex(target), arch = is64 and "x64" or "x86", max_depth = maxDepth, max_offset = maxOffset,
                         scans = st.scans, truncated = st.truncated, found = #items,
                         hint = "After the target restarts, find the same value again and run compare_pointer_paths(name=<set>, target=<new address>); " ..
                                "pass save_as here to keep these chains in a set. (validate_pointer_chains takes the chains inline.)" }
        if p.save_as ~= nil then
            local s, why = U26.psSaveFound(p.save_as, keep, target)
            if s then
                fields.saved_as, fields.set = s.name, U26.psSummary(s)
            else
                fields.save_note = "not saved: " .. why
            end
        end
        jobFinish(j, "done", { result = { fields = fields, list_key = "chains", items = items } })
        return true
    end

    local function launch(j)
        local entry = st.frontier[st.qi]
        st.cur = entry
        local lo = entry.t - maxOffset
        if lo < 1 then lo = 1 end
        local ms = createMemScan()
        j._ms, j._temp, j._scan_done = ms, true, false
        j.phase = "scanning"
        j._after_scan = onScan
        ms.OnScanDone = onScanDone(j)
        ms.firstScan(soValueBetween, is64 and vtQword or vtDword, rtRounded, string.format("%d", lo), string.format("%d", entry.t),
                     0, USER_MODE_MAX, protect, fsmAligned, tostring(P), false, false, false, false)
    end

    onScan = function(j)
        local entry, ms = st.cur, j._ms
        local fl = createFoundList(ms)
        fl.initialize()
        local n = fl.getCount()
        if n > perScan then st.truncated = true end
        for i = 0, math.min(n, perScan) - 1 do
            local loc = tonumber(fl.getAddress(i), 16)
            local val = loc and U26.ptr(loc, is64)
            if val and val <= entry.t and entry.t - val <= maxOffset then
                local offs, cost = { entry.t - val }, entry.t - val
                for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end
                local m = U26.moduleFor(mods, loc)
                if m then
                    st.found[#st.found + 1] = { module = m.name, rva = loc - m.base, base = loc, offs = offs, cost = cost }
                elseif st.depth < maxDepth and not st.seen[loc] then
                    st.seen[loc] = true
                    st.nextc[#st.nextc + 1] = { t = loc, offs = offs, cost = cost }
                end
            end
        end
        pcall(function() fl.destroy() end)
        pcall(function() ms.destroy() end)
        j._ms = nil
        st.scans = st.scans + 1
        st.qi = st.qi + 1
        if st.qi > #st.frontier then
            if #st.found >= maxFound or st.depth >= maxDepth or #st.nextc == 0 then return finish(j) end
            table.sort(st.nextc, function(a, b) return a.cost < b.cost end)
            local nxt = {}
            for i = 1, math.min(beam, #st.nextc) do nxt[i] = st.nextc[i] end
            st.frontier, st.nextc, st.qi, st.depth = nxt, {}, 1, st.depth + 1
        end
        j.progress = { current = st.scans, total = st.scans + (#st.frontier - st.qi + 1) }
        launch(j)
    end

    if U26.moduleFor(mods, target) then      -- already static: nothing to search for
        local m = U26.moduleFor(mods, target)
        st.found[1] = { module = m.name, rva = target - m.base, base = target, offs = {}, cost = 0 }
        finish(job)
        return nil
    end
    job.progress = { current = 0, total = 1 }
    launch(job)
end

JOB_KIND_NAMES = JOB_KIND_NAMES .. ", find_pointer_path, rtti_scan, find_string_refs, find_code_caves"

-- ---------------------------------------------------------------------------
-- snapshots: for "unknown value" hunting without running scans
-- ---------------------------------------------------------------------------
function U26.readRegion(addr, size)
    local parts, bad = {}, {}
    local pos = 0
    while pos < size do
        local n = math.min(U26.CHUNK, size - pos)
        local s = U26.rd(addr + pos, n)
        if s then
            parts[#parts + 1] = s
        else
            for sub = 0, n - 1, 4096 do
                local m = math.min(4096, n - sub)
                local ps = U26.rd(addr + pos + sub, m)
                if ps then
                    parts[#parts + 1] = ps
                else
                    parts[#parts + 1] = string.rep("\0", m)
                    bad[#bad + 1] = { pos + sub, m }
                end
            end
        end
        pos = pos + n
    end
    return table.concat(parts), bad
end

function U26.snapSummary(s)
    return { name = s.name, address = U26.hex(s.address), size = s.size, unreadable_bytes = s.bad_bytes, taken = s.taken }
end

function cmd_snapshot_region(params)
    local perr = requireProcess()
    if perr then return perr end
    local addr, size
    if params.module and params.module ~= "" then
        local mod, pe, _, err = U26.peFor(params)
        if not mod then return err end
        local want = tostring(params.section or ".data")
        local sec
        for _, s in ipairs(pe.sections) do if s.name == want then sec = s end end
        if not sec then return U26.err("Section not found: " .. want, "NOT_FOUND") end
        addr, size = mod.base + sec.rva, math.max(sec.vsize, sec.raw_size)
    else
        addr, size = U26.addr(params.address), tonumber(params.size)
    end
    if not addr then return U26.err("Invalid address", "INVALID_ADDRESS") end
    if not size or size < 1 then return U26.err("size must be positive") end
    size = math.floor(size)
    if size > U26.SNAP_MAX_ONE then return U26.err("A snapshot is limited to " .. U26.SNAP_MAX_ONE .. " bytes") end

    serverState.snapshot_seq = serverState.snapshot_seq + 1
    local name = params.name
    if type(name) ~= "string" or name == "" then name = "snap_" .. serverState.snapshot_seq end
    if name == "live" then return U26.err("'live' is reserved for diff_snapshots") end
    local old = serverState.snapshots[name]
    local count, total = 0, serverState.snapshot_bytes - (old and old.size or 0)
    for _ in pairs(serverState.snapshots) do count = count + 1 end
    if not old and count >= U26.SNAP_MAX_COUNT then
        return U26.err("At most " .. U26.SNAP_MAX_COUNT .. " snapshots; delete_snapshot one first", "OUT_OF_RESOURCES")
    end
    if total + size > U26.SNAP_MAX_TOTAL then
        return U26.err("Snapshots would exceed " .. U26.SNAP_MAX_TOTAL .. " bytes in total; delete_snapshot one first", "OUT_OF_RESOURCES")
    end

    local data, bad = U26.readRegion(addr, size)
    local badBytes = 0
    for _, b in ipairs(bad) do badBytes = badBytes + b[2] end
    if badBytes == size then return U26.err("Region is completely unreadable at " .. U26.hex(addr), "INVALID_ADDRESS") end
    serverState.snapshots[name] = { name = name, address = addr, size = size, data = data, bad = bad, bad_bytes = badBytes, taken = os.time() }
    serverState.snapshot_bytes = total + size
    local out = U26.snapSummary(serverState.snapshots[name])
    out.success = true
    return out
end

function cmd_list_snapshots(params)
    local list = {}
    for _, s in pairs(serverState.snapshots) do list[#list + 1] = U26.snapSummary(s) end
    table.sort(list, function(a, b) return a.taken ~= b.taken and a.taken < b.taken or a.name < b.name end)
    return { success = true, count = #list, total_bytes = serverState.snapshot_bytes, snapshots = list }
end

function cmd_delete_snapshot(params)
    if params.all == true then
        local n = 0
        for _ in pairs(serverState.snapshots) do n = n + 1 end
        serverState.snapshots, serverState.snapshot_bytes = {}, 0
        return { success = true, deleted = n }
    end
    local s = serverState.snapshots[params.name]
    if not s then return U26.err("No such snapshot: " .. tostring(params.name), "NOT_FOUND") end
    serverState.snapshot_bytes = serverState.snapshot_bytes - s.size
    serverState.snapshots[params.name] = nil
    return { success = true, deleted = 1 }
end

function U26.decodeUnit(s, unit)
    local fmt = ({ [1] = "<I1", [2] = "<I2", [4] = "<I4", [8] = "<I8" })[unit]
    return (string.unpack(fmt, s))
end

-- names: 2+ snapshot names, optionally "live" (read now). pattern: one char per consecutive pair:
-- C = must have changed, U = must be unchanged, ? = don't care. Default: all C.
function cmd_diff_snapshots(params)
    local names = params.snapshots
    if type(names) ~= "table" or #names < 2 then
        return U26.err("snapshots must list at least two snapshot names (\"live\" reads current memory)")
    end
    local n = #names
    local unit = tonumber(params.unit or 4)
    if unit ~= 1 and unit ~= 2 and unit ~= 4 and unit ~= 8 then return U26.err("unit must be 1, 2, 4 or 8") end
    local pattern = params.pattern or string.rep("C", n - 1)
    if #pattern ~= n - 1 or pattern:find("[^CU?]") then
        return U26.err("pattern needs " .. (n - 1) .. " characters from C (changed), U (unchanged), ? (any)")
    end

    local ref
    for _, nm in ipairs(names) do
        if nm ~= "live" then
            ref = serverState.snapshots[nm]
            if not ref then return U26.err("No such snapshot: " .. tostring(nm), "NOT_FOUND") end
            break
        end
    end
    if not ref then return U26.err("At least one entry must be a real snapshot (it defines address and size)") end
    local snaps = {}
    for i, nm in ipairs(names) do
        local s
        if nm == "live" then
            local perr = requireProcess()
            if perr then return perr end
            local data, bad = U26.readRegion(ref.address, ref.size)
            s = { name = "live", address = ref.address, size = ref.size, data = data, bad = bad }
        else
            s = serverState.snapshots[nm]
            if not s then return U26.err("No such snapshot: " .. tostring(nm), "NOT_FOUND") end
            if s.address ~= ref.address or s.size ~= ref.size then
                return U26.err("Snapshot '" .. nm .. "' covers a different region than '" .. ref.name .. "'")
            end
        end
        snaps[i] = s
    end

    local BLK = 4096
    local badBlocks = {}
    for _, s in ipairs(snaps) do
        for _, b in ipairs(s.bad) do
            for blk = b[1] // BLK, (b[1] + b[2] - 1) // BLK do badBlocks[blk] = true end
        end
    end

    local lo = math.max(0, math.floor(tonumber(params.offset or 0)))
    local hi = ref.size
    if params.length then hi = math.min(hi, lo + math.floor(tonumber(params.length))) end
    lo = lo - lo % unit
    local limit = clampInt(params.limit or 200, 1, 1000)
    local gap = tonumber(params.merge_gap or unit)
    local matches, groups, total = {}, {}, 0
    local pc = {}
    for k = 1, n - 1 do pc[k] = pattern:sub(k, k) end

    local blk = lo // BLK
    while blk * BLK < hi do
        local b0, b1 = math.max(lo, blk * BLK), math.min(hi, (blk + 1) * BLK)
        b1 = b0 + ((b1 - b0) // unit) * unit
        local skip = badBlocks[blk] or b1 <= b0
        if not skip then
            for k = 1, n - 1 do        -- identical block in a 'C' pair: nothing in here can match
                if pc[k] == "C" and snaps[k].data:sub(b0 + 1, b1) == snaps[k + 1].data:sub(b0 + 1, b1) then skip = true; break end
            end
        end
        if not skip then
            for u = b0, b1 - unit, unit do
                local vals = {}
                for k = 1, n do vals[k] = snaps[k].data:sub(u + 1, u + unit) end
                local ok = true
                for k = 1, n - 1 do
                    local same = (vals[k] == vals[k + 1])
                    if (pc[k] == "C" and same) or (pc[k] == "U" and not same) then ok = false; break end
                end
                if ok then
                    total = total + 1
                    local g = groups[#groups]
                    if g and u - (g.offset + g.size) <= gap then
                        g.size, g.units = u + unit - g.offset, g.units + 1
                    elseif #groups < 200 then
                        groups[#groups + 1] = { offset = u, size = unit, units = 1 }
                    end
                    if #matches < limit then
                        local m = { address = U26.hex(ref.address + u), offset = u, old = U26.decodeUnit(vals[1], unit), new = U26.decodeUnit(vals[n], unit) }
                        if unit == 8 and m.old < 0 then m.old = U26.hex(m.old) end
                        if unit == 8 and m.new < 0 then m.new = U26.hex(m.new) end
                        if unit == 4 then
                            m.old_float, m.new_float = (string.unpack("<f", vals[1])), (string.unpack("<f", vals[n]))
                        elseif unit == 8 then
                            m.old_double, m.new_double = (string.unpack("<d", vals[1])), (string.unpack("<d", vals[n]))
                        end
                        if n > 2 then
                            m.values = {}
                            for k = 1, n do m.values[k] = U26.decodeUnit(vals[k], unit) end
                        end
                        matches[#matches + 1] = m
                    end
                end
            end
        end
        blk = blk + 1
    end
    for _, g in ipairs(groups) do g.address = U26.hex(ref.address + g.offset) end
    return {
        success = true, address = U26.hex(ref.address), size = ref.size, unit = unit, pattern = pattern, snapshots = names,
        total_matches = total, returned = #matches, matches = matches, groups = groups,
        skipped_unreadable_blocks = (function() local c = 0 for _ in pairs(badBlocks) do c = c + 1 end return c end)(),
    }
end

-- >>> END UNIT-26 <<<

-- >>> BEGIN UNIT-27 Functions (.pdata), struct recovery <<<

-- ---------------------------------------------------------------------------
-- x64 function boundaries from the exception table (.pdata): exact start/end for every function that has
-- unwind data. (Leaf functions that never touch the stack have no entry; callers fall back to heuristics.)
-- ---------------------------------------------------------------------------
U26.pdataCache = {}

-- Returns { data = <raw RUNTIME_FUNCTION table>, count = n } or nil, reason
function U26.pdata(mod, pe)
    if pe.machine ~= 0x8664 then return nil, "no .pdata function table on this architecture (x64 only)" end
    local dir = pe.dirs[3]
    if not dir or dir.rva == 0 or dir.size < 12 then return nil, "module has no exception directory" end
    local key = string.format("%X:%X:%X", mod.base, pe.size_of_image, pe.timestamp)
    local cached = U26.pdataCache[key]
    if cached then return cached end
    local size = dir.size - dir.size % 12
    if size > 32 * 1024 * 1024 then return nil, "exception directory is implausibly large" end
    local data, bad = U26.readRegion(mod.base + dir.rva, size)
    if #bad > 0 then return nil, "exception directory is partially unreadable" end
    local n = 0
    for _ in pairs(U26.pdataCache) do n = n + 1 end
    if n >= 4 then U26.pdataCache = {} end
    local tbl = { data = data, count = size // 12 }
    U26.pdataCache[key] = tbl
    return tbl
end

function U26.pdataEntry(tbl, index)
    return string.unpack("<I4I4I4", tbl.data, index * 12 + 1)
end

-- Binary search (the table is sorted by BeginAddress). Returns begin, end, unwind (RVAs; end is exclusive) or nil.
function U26.pdataLookup(tbl, rva)
    local lo, hi = 0, tbl.count - 1
    while lo <= hi do
        local mid = (lo + hi) // 2
        local b, e, u = U26.pdataEntry(tbl, mid)
        if rva < b then hi = mid - 1
        elseif rva >= e then lo = mid + 1
        else return b, e, u end
    end
    return nil
end

U26.UNWIND_REGS = { [0] = "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }

-- UNWIND_INFO: flags (exception handler / termination handler / chained), prolog size, frame register, handler RVA
-- or the chained parent RUNTIME_FUNCTION.
function U26.unwindInfo(mod, unwindRva)
    local hdr = U26.rd(mod.base + unwindRva, 4)
    if not hdr then return nil end
    local b0, prolog, ncodes, frame = string.unpack("<BBBB", hdr)
    local flags = b0 >> 3
    local info = { version = b0 & 7, prolog_size = prolog, code_count = ncodes }
    if (frame & 0xF) ~= 0 then
        info.frame_register = U26.UNWIND_REGS[frame & 0xF]
        info.frame_offset = (frame >> 4) * 16
    end
    local names = {}
    if (flags & 1) ~= 0 then names[#names + 1] = "EHANDLER" end
    if (flags & 2) ~= 0 then names[#names + 1] = "UHANDLER" end
    if (flags & 4) ~= 0 then names[#names + 1] = "CHAININFO" end
    info.flags = names
    local tail = unwindRva + 4 + ((ncodes + 1) & ~1) * 2         -- unwind codes are padded to an even count
    if (flags & 4) ~= 0 then
        local raw = U26.rd(mod.base + tail, 12)
        if raw then
            local b, e, u = string.unpack("<I4I4I4", raw)
            info.chain = { begin_rva = b, end_rva = e, unwind_rva = u }
        end
    elseif (flags & 3) ~= 0 then
        local h = U26.u32(mod.base + tail)
        if h then info.handler_rva = h end
    end
    return info
end

-- The function covering `rva`. Chained entries (cold/split fragments) are resolved to their primary function.
-- Returns { entry, unwind, primary, primary_unwind, fragment } or nil, reason
function U26.functionAt(mod, pe, rva)
    local tbl, why = U26.pdata(mod, pe)
    if not tbl then return nil, why end
    local b, e, u = U26.pdataLookup(tbl, rva)
    if not b then return nil, "address is not covered by .pdata (leaf function, padding or data)" end
    local entry = { begin_rva = b, end_rva = e, unwind_rva = u }
    local info = U26.unwindInfo(mod, u)
    local primary, primaryInfo, hops = entry, info, 0
    while primaryInfo and primaryInfo.chain and hops < 8 do
        primary = { begin_rva = primaryInfo.chain.begin_rva, end_rva = primaryInfo.chain.end_rva, unwind_rva = primaryInfo.chain.unwind_rva }
        primaryInfo = U26.unwindInfo(mod, primary.unwind_rva)
        hops = hops + 1
    end
    return { entry = entry, unwind = info, primary = primary, primary_unwind = primaryInfo, fragment = (primary.begin_rva ~= entry.begin_rva) }
end

function U26.describeFunction(mod, fn, withUnwind)
    local p = fn.primary
    local out = {
        function_start = U26.hex(mod.base + p.begin_rva), function_end = U26.hex(mod.base + p.end_rva - 1),
        begin_rva = p.begin_rva, end_rva = p.end_rva, size = p.end_rva - p.begin_rva,
        expression = mod.name .. "+" .. U26.hex(p.begin_rva),
    }
    if fn.fragment then
        out.fragment = { begin_rva = fn.entry.begin_rva, end_rva = fn.entry.end_rva, address = U26.hex(mod.base + fn.entry.begin_rva) }
    end
    local info = fn.primary_unwind
    if withUnwind and info then
        out.unwind = info
        if fn.fragment and fn.unwind then out.fragment.unwind = fn.unwind end
    end
    if info and info.handler_rva then
        out.exception_handler = U26.hex(mod.base + info.handler_rva)
    end
    return out
end

-- Used by find_function_boundaries / analyze_function (defined earlier in the file, hence a global).
-- Returns { start, finish (exclusive), fragment, module } or nil when .pdata cannot answer.
function pdataFunctionBoundaries(addr)
    local mod = U26.moduleFor(U26.listModules(), addr)
    if not mod then return nil end
    local pe = U26.parsePE(mod.base)
    if not pe then return nil end
    local fn = U26.functionAt(mod, pe, addr - mod.base)
    if not fn then return nil end
    return { start = mod.base + fn.primary.begin_rva, finish = mod.base + fn.primary.end_rva,
             fragment = fn.fragment, module = mod, handler_rva = fn.primary_unwind and fn.primary_unwind.handler_rva }
end

-- pe_functions: with `address` -> the function that contains it; otherwise a page of the whole function table.
function cmd_pe_functions(params)
    local perr = requireProcess()
    if perr then return perr end
    local a
    if params.address ~= nil and params.address ~= "" then
        a = U26.addr(params.address)
        if not a then return U26.err("Invalid address", "INVALID_ADDRESS") end
    end
    local spec = params.module
    if (spec == nil or spec == "") and a then spec = a end
    local mod, pe, _, err = U26.peFor({ module = spec })
    if not mod then return err end
    local tbl, why = U26.pdata(mod, pe)
    if not tbl then
        return { success = true, module = mod.name, available = false, reason = why, total = 0, functions = {} }
    end

    if a then
        local fn, reason = U26.functionAt(mod, pe, a - mod.base)
        if not fn then
            return { success = true, module = mod.name, available = true, found = false, address = U26.hex(a), reason = reason }
        end
        local out = U26.describeFunction(mod, fn, true)
        out.success, out.module, out.available, out.found, out.address = true, mod.name, true, true, U26.hex(a)
        return out
    end

    local limit = clampInt(params.limit or 100, 1, 1000)
    local offset = clampInt(params.offset or 0, 0, math.max(0, tbl.count - 1))
    local list = {}
    for i = offset, math.min(tbl.count, offset + limit) - 1 do
        local b, e, u = U26.pdataEntry(tbl, i)
        local item = { begin_rva = b, end_rva = e, size = e - b, address = U26.hex(mod.base + b), expression = mod.name .. "+" .. U26.hex(b) }
        if params.include_unwind then
            local info = U26.unwindInfo(mod, u)
            if info then
                item.prolog_size, item.flags, item.frame_register = info.prolog_size, info.flags, info.frame_register
                if info.handler_rva then item.exception_handler = U26.hex(mod.base + info.handler_rva) end
                if info.chain then item.chained_to = mod.name .. "+" .. U26.hex(info.chain.begin_rva) end
            end
        end
        list[#list + 1] = item
    end
    return { success = true, module = mod.name, available = true, total = tbl.count, offset = offset, limit = limit, returned = #list, functions = list }
end

-- ---------------------------------------------------------------------------
-- Struct recovery: MSVC RTTI behind the object's vtable + field inference from live instances
-- ---------------------------------------------------------------------------

-- Base classes of a class hierarchy descriptor: { { name, offset, virtual, contained } ... } (first entry = the class itself)
function U26.readBases(mod, pe, cdRef)
    local is64, P = pe.is64, pe.ptrSize
    local bases = {}
    local hdr = U26.rd(is64 and (mod.base + cdRef) or cdRef, 16)
    if not hdr then return bases end
    local _, _, nb, arr = string.unpack("<I4I4I4I4", hdr)
    local arrAddr = is64 and (mod.base + arr) or arr
    for i = 0, math.min(nb, 64) - 1 do
        local e = U26.rd(arrAddr + i * 4, 4)
        if not e then break end
        local ref = string.unpack("<I4", e)
        local bcd = U26.rd(is64 and (mod.base + ref) or ref, 24)    -- type descriptor, contained bases, PMD{mdisp,pdisp,vdisp}, attributes
        if bcd then
            local tref, contained, mdisp, pdisp = string.unpack("<I4I4i4i4", bcd)
            local nm = U26.cstr((is64 and (mod.base + tref) or tref) + 2 * P, 512)
            bases[#bases + 1] = { name = U26.demangle(nm), offset = mdisp, virtual = (pdisp ~= -1), contained = contained }
        end
    end
    return bases
end

-- RTTI for the vtable at `vtAddr`: the complete object locator sits in the slot just before it.
-- Returns { module, pe, class_name, raw_name, is_struct, vtable, vtable_rva, this_offset, bases } or nil, reason
function U26.rttiAtVtable(vtAddr, mods, peCache)
    mods = mods or U26.listModules()
    peCache = peCache or {}
    local mod = U26.moduleFor(mods, vtAddr)
    if not mod then return nil, "the vtable pointer is not inside a loaded module" end
    local pe = peCache[mod.base]
    if pe == nil then
        pe = U26.parsePE(mod.base) or false
        peCache[mod.base] = pe
    end
    if not pe then return nil, "the module has no readable PE header" end
    local P, is64 = pe.ptrSize, pe.is64
    local colVa = U26.ptr(vtAddr - P, is64)
    if not colVa or colVa < mod.base or colVa >= mod.base + mod.size then return nil, "no object locator before the vtable" end
    local raw = U26.rd(colVa, is64 and 24 or 20)
    if not raw then return nil, "the object locator is unreadable" end
    local sig, thisOff, _, tdRef, cdRef, selfRef = string.unpack(is64 and "<I4I4I4I4I4I4" or "<I4I4I4I4I4", raw)
    if is64 then
        if sig ~= 1 or selfRef ~= colVa - mod.base then return nil, "not an RTTI object locator" end
    elseif sig ~= 0 then
        return nil, "not an RTTI object locator"
    end
    local name, terminated = U26.cstr((is64 and (mod.base + tdRef) or tdRef) + 2 * P, 512)
    if not terminated or not name:match("^%.%?A[VU]") then return nil, "the type descriptor has no class name" end
    return {
        module = mod, pe = pe, class_name = U26.demangle(name), raw_name = name, is_struct = (name:sub(4, 4) == "U"),
        vtable = vtAddr, vtable_rva = vtAddr - mod.base, this_offset = thisOff, bases = U26.readBases(mod, pe, cdRef),
    }
end

-- ---- value classification ------------------------------------------------------------------------
function U26.plausibleFloat(d)
    if d == 0 or d <= 0xFFFF or d >= 0xFFFF0000 then return false end      -- 0 and small ints (either sign) are ints
    local f = string.unpack("<f", string.pack("<I4", d))
    if f ~= f then return false end
    local a = math.abs(f)
    return a >= 1e-6 and a <= 1e7
end

function U26.plausibleDouble(q, low, high)
    if q == 0 then return false end
    local d = string.unpack("<d", string.pack("<I8", q))
    if d ~= d then return false end
    local a = math.abs(d)
    if a < 1e-9 or a > 1e12 then return false end
    -- A small non-zero low half is an int (or small negative int) sitting next to another field, not a mantissa.
    if low ~= 0 and (low <= 0xFFFF or low >= 0xFFFF0000) then return false end
    return not (U26.plausibleFloat(low) and U26.plausibleFloat(high))      -- two plausible floats side by side win
end

function U26.looksLikePointer(v, is64)
    if is64 then
        if v < 0x10000 or v > 0x7FFFFFFFFFFF then return false end
    elseif v < 0x10000 or v > 0xFFFEFFFF then
        return false
    end
    return U26.rd(v, 1) ~= nil
end

-- Printable ASCII text starting at addr (>= 4 chars, terminated by NUL within 32 bytes) or nil
function U26.printableAt(addr)
    local s
    for _, n in ipairs({ 32, 16, 8 }) do
        s = U26.rd(addr, n)
        if s then break end
    end
    if not s then return nil end
    local len = 0
    while len < #s do
        local b = s:byte(len + 1)
        if b < 0x20 or b > 0x7E then break end
        len = len + 1
    end
    if len >= 4 and (len == #s or s:byte(len + 1) == 0) then return s:sub(1, len) end
    return nil
end

-- What does a pointer value point at?  kind: vfptr | object | string | static | heap
function U26.describePointer(v, is64, mods, peCache)
    local mod = U26.moduleFor(mods, v)
    if mod then
        local info = U26.rttiAtVtable(v, mods, peCache)
        if info then return "vfptr", info.class_name end
        return "static", mod.name .. "+" .. U26.hex(v - mod.base)
    end
    local vp = U26.ptr(v, is64)
    if vp and vp >= 0x10000 and U26.moduleFor(mods, vp) then
        local info = U26.rttiAtVtable(vp, mods, peCache)
        if info then return "object", info.class_name end
    end
    local text = U26.printableAt(v)
    if text then return "string", text end
    return "heap", nil
end

function U26.cType(field)
    local k = field.kind
    if k == "vfptr" or k == "static" or k == "heap" then return "void *" end
    if k == "object" then return U26.idaName(field.points_to) .. " *" end
    if k == "string" then return "char *" end
    if k == "float" then return "float" end
    if k == "double" then return "double" end
    if k == "int" then return field.unsigned and "unsigned int" or "int" end
    return nil
end

U26.CE_STRUCT_TYPES = { vfptr = "pointer", static = "pointer", heap = "pointer", object = "pointer", string = "pointer",
                          float = "float", double = "double", int = "dword" }

-- Recover a class layout from live instance(s). `addresses` should be instances of the SAME class (more instances
-- = better type guesses: values that differ between instances are real data, equal ones may be constants).
function cmd_recover_struct(params)
    local perr = requireProcess()
    if perr then return perr end
    local rawList = type(params.addresses) == "table" and params.addresses or { params.address }
    if #rawList == 0 or #rawList > 16 then return U26.err("Give 1 to 16 instance addresses (address or addresses)") end
    local addrs = {}
    for i, v in ipairs(rawList) do
        addrs[i] = U26.addr(v)
        if not addrs[i] then return U26.err("Invalid address: " .. tostring(v), "INVALID_ADDRESS") end
    end
    local is64 = targetIs64Bit()
    local P = is64 and 8 or 4
    local mods, peCache = U26.listModules(), {}

    -- 1. which class is every instance?
    local info
    for i, a in ipairs(addrs) do
        local vptr = U26.ptr(a, is64)
        if not vptr then return U26.err("Unreadable memory at " .. U26.hex(a), "INVALID_ADDRESS") end
        local one, why = U26.rttiAtVtable(vptr, mods, peCache)
        if not one then
            return U26.err("No MSVC RTTI for the object at " .. U26.hex(a) .. " (" .. tostring(why) .. "). Only polymorphic classes with the vtable pointer at offset 0 can be identified.", "NOT_FOUND")
        end
        if i == 1 then
            info = one
        elseif one.raw_name ~= info.raw_name or one.vtable ~= info.vtable then
            return U26.err("Instances are of different classes: " .. info.class_name .. " (" .. U26.hex(addrs[1]) .. ") vs " .. one.class_name .. " (" .. U26.hex(a) .. ")")
        end
    end

    -- 2. read the instances (as much as is readable in all of them), drop the all-zero tail
    local want = clampInt(params.size or 0x100, 16, 0x4000)
    local data, size = {}, want
    for i, a in ipairs(addrs) do
        local n, s = want, nil
        while n >= 16 do
            s = U26.rd(a, n)
            if s then break end
            n = n // 2
        end
        if not s then return U26.err("Cannot read the object at " .. U26.hex(a), "INVALID_ADDRESS") end
        data[i] = s
        size = math.min(size, #s)
    end
    local last = 0
    for i = 1, #data do
        for o = size, 1, -1 do
            if data[i]:byte(o) ~= 0 then last = math.max(last, o); break end
        end
    end
    size = math.max(P, ((last + 3) // 4) * 4)

    -- 3. walk the object: vfptr, then pointers / text / doubles / floats / ints, zero runs become "unknown"
    local n = #addrs
    local fields = {}
    local function add(f) fields[#fields + 1] = f end
    local ptrFmt = is64 and "<I8" or "<I4"
    add({ offset = 0, size = P, kind = "vfptr", type = "vfptr", points_to = info.class_name, name = "vfptr",
          samples = { U26.hex(info.vtable) } })
    local off = P
    while off + 4 <= size do
        local done = false

        if off % P == 0 and off + P <= size then                    -- pointer-sized slot
            local vals, anyPtr, onlyPtrOrNull = {}, false, true
            for k = 1, n do
                local v = string.unpack(ptrFmt, data[k], off + 1)
                vals[k] = v
                if v ~= 0 then
                    if U26.looksLikePointer(v, is64) then anyPtr = true else onlyPtrOrNull = false end
                end
            end
            if anyPtr and onlyPtrOrNull then
                local first
                for k = 1, n do if vals[k] ~= 0 then first = vals[k]; break end end
                local kind, text = U26.describePointer(first, is64, mods, peCache)
                local f = { offset = off, size = P, kind = kind, points_to = text, samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = vals[k] == 0 and "null" or U26.hex(vals[k]) end
                if kind == "vfptr" then f.type, f.name = "vfptr (" .. text .. ")", string.format("vfptr_%X", off)
                elseif kind == "object" then f.type, f.name = text .. " *", string.format("obj_%X", off)
                elseif kind == "string" then f.type, f.name = "char *", string.format("str_%X", off); f.text = text
                elseif kind == "static" then f.type, f.name = "void * (" .. text .. ")", string.format("sptr_%X", off)
                else f.type, f.name = "void *", string.format("ptr_%X", off) end
                add(f)
                off, done = off + P, true
            end
        end

        if not done then                                              -- inline text (char buffer)
            local s1 = data[1]
            local len = 0
            while off + len < size do
                local b = s1:byte(off + len + 1)
                if b < 0x20 or b > 0x7E then break end
                len = len + 1
            end
            if len >= 4 and off + len < size and s1:byte(off + len + 1) == 0 then
                local total = ((len + 1 + 3) // 4) * 4
                local f = { offset = off, size = total, kind = "text", type = "char[" .. total .. "]", name = string.format("text_%X", off), samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = data[k]:sub(off + 1, off + len):gsub("[^\32-\126]", "?") end
                add(f)
                off, done = off + total, true
            end
        end

        if not done and off % 8 == 0 and off + 8 <= size then         -- double
            local q = string.unpack("<I8", data[1], off + 1)
            local low, high = q & 0xFFFFFFFF, (q >> 32) & 0xFFFFFFFF
            if U26.plausibleDouble(q, low, high) and not U26.looksLikePointer(q, true) then
                local ok = true
                for k = 2, n do
                    local qk = string.unpack("<I8", data[k], off + 1)
                    if qk ~= 0 and not U26.plausibleDouble(qk, qk & 0xFFFFFFFF, (qk >> 32) & 0xFFFFFFFF) then ok = false end
                end
                if ok then
                    local f = { offset = off, size = 8, kind = "double", type = "double", name = string.format("d_%X", off), samples = {} }
                    for k = 1, math.min(n, 3) do f.samples[k] = string.unpack("<d", data[k], off + 1) end
                    add(f)
                    off, done = off + 8, true
                end
            end
        end

        if not done then                                              -- 4-byte value: zero / float / int
            local vals, allZero, allFloat = {}, true, true
            for k = 1, n do
                local d = string.unpack("<I4", data[k], off + 1)
                vals[k] = d
                if d ~= 0 then
                    allZero = false
                    if not U26.plausibleFloat(d) then allFloat = false end
                end
            end
            local f
            if allZero then
                local prev = fields[#fields]
                if prev and prev.kind == "unknown" and prev.offset + prev.size == off then
                    prev.size = prev.size + 4
                    prev.type = "unknown[" .. prev.size .. "]"
                else
                    f = { offset = off, size = 4, kind = "unknown", type = "unknown[4]", name = string.format("unk_%X", off), samples = {} }
                end
            elseif allFloat then
                f = { offset = off, size = 4, kind = "float", type = "float", name = string.format("f_%X", off), samples = {} }
                for k = 1, math.min(n, 3) do f.samples[k] = string.unpack("<f", string.pack("<I4", vals[k])) end
            else
                f = { offset = off, size = 4, kind = "int", type = "int", name = string.format("i_%X", off), samples = {}, unsigned = true }
                for k = 1, math.min(n, 3) do
                    local sv = vals[k] >= 0x80000000 and vals[k] - 0x100000000 or vals[k]
                    f.samples[k] = sv
                    if sv < 0 then f.unsigned = false end
                end
            end
            if f then add(f) end
            off = off + 4
        end
    end

    -- 4. virtual functions (with exact sizes where .pdata knows them)
    local mod, pe = info.module, info.pe
    local vfCount = U26.countVfuncs(info.vtable, P, clampInt(params.max_vtable_entries or 64, 1, 512), U26.sectionRanges(pe, mod, true, true))
    local vfuncs = {}
    for i = 0, vfCount - 1 do
        local fa = U26.ptr(info.vtable + i * P, is64)
        local v = { index = i, address = U26.hex(fa), expression = mod.name .. "+" .. U26.hex(fa - mod.base) }
        local fn = U26.functionAt(mod, pe, fa - mod.base)
        if fn then v.function_size = fn.primary.end_rva - fn.primary.begin_rva end
        vfuncs[#vfuncs + 1] = v
    end

    -- 5. C declaration
    local cname = U26.idaName(info.class_name)
    local decl, forward, padN = {}, {}, 0
    local pos = 0
    for _, f in ipairs(fields) do
        if f.offset > pos then
            padN = padN + 1
            decl[#decl + 1] = string.format("    unsigned char _pad%d[%d];", padN, f.offset - pos)
        end
        local line
        if f.kind == "vfptr" and f.offset == 0 then
            line = "    void **vfptr;  // +0x0 " .. info.class_name .. " vtable"
        elseif f.kind == "text" then
            line = "    char " .. f.name .. "[" .. f.size .. "];"
        elseif f.kind == "unknown" then
            line = "    unsigned char " .. f.name .. "[" .. f.size .. "];"
        else
            local ct = U26.cType(f)
            if f.kind == "object" then forward[U26.idaName(f.points_to)] = true end
            line = "    " .. ct .. (ct:sub(-1) == "*" and "" or " ") .. f.name .. ";"
        end
        decl[#decl + 1] = line:find("//", 1, true) and line or (line .. string.format("  // +0x%X", f.offset))
        pos = f.offset + f.size
    end
    local fwd = {}
    for nm in pairs(forward) do if nm ~= cname then fwd[#fwd + 1] = "struct " .. nm .. ";" end end
    table.sort(fwd)
    local baseNames = {}
    for i, b in ipairs(info.bases) do if i > 1 then baseNames[#baseNames + 1] = b.name end end
    local text = (#fwd > 0 and (table.concat(fwd, "\n") .. "\n") or "") ..
        "struct " .. cname .. " {" .. (#baseNames > 0 and ("  // bases: " .. table.concat(baseNames, ", ")) or "") .. "\n" ..
        table.concat(decl, "\n") .. "\n};"

    local out = {
        success = true, class_name = info.class_name, raw_name = info.raw_name, kind = info.is_struct and "struct" or "class",
        module = mod.name, vtable = U26.hex(info.vtable), vtable_rva = info.vtable_rva, this_offset = info.this_offset,
        bases = info.bases, instances = n, size_analyzed = size, arch = is64 and "x64" or "x86",
        fields = fields, virtual_functions = vfuncs, c_declaration = text,
        notes = { n == 1 and "Single instance: pass several instances of the same class (addresses) to separate data from constants." or nil },
    }

    -- 6. optionally create the CE structure definition
    if params.create then
        local sname = (type(params.name) == "string" and params.name ~= "") and params.name or cname
        local okS, structure = pcall(createStructure, sname)
        if not okS or not structure then
            out.create_error = "createStructure failed: " .. tostring(structure)
        else
            pcall(function() structure.addToGlobalStructureList() end)
            local made = 0
            for _, f in ipairs(fields) do
                local vt = nil
                if f.kind == "text" then vt = vtString
                elseif U26.CE_STRUCT_TYPES[f.kind] then
                    vt = ({ pointer = vtPointer, float = vtSingle, double = vtDouble, dword = vtDword })[U26.CE_STRUCT_TYPES[f.kind]]
                end
                if vt then
                    local okE, el = pcall(function() return structure.addElement() end)
                    if okE and el then
                        pcall(function()
                            el.Name, el.Offset, el.Vartype = f.name, f.offset, vt
                            if f.kind == "text" then el.Bytesize = f.size end
                        end)
                        made = made + 1
                    end
                end
            end
            local id = serverState.structure_next_id
            serverState.structure_next_id = id + 1
            serverState.structures[id] = structure
            out.structure_id, out.structure_name, out.elements_created = id, sname, made
        end
    end
    return out
end

-- >>> END UNIT-27 <<<

-- >>> BEGIN UNIT-28 Cross-references <<<

-- ---------------------------------------------------------------------------
-- job: find_xrefs  (everything that references an address or a small range)
--   code: rel32/rel8 call, jmp and jcc; x64 rip-relative operands (lea/mov/cmp/call [rip+x] ...); absolute pointers
--   data: absolute pointers (pointer aligned) and, on x64, 32-bit RVAs (jump tables)
-- Hits are found by byte patterns and validated with the disassembler where an instruction is involved.
-- ---------------------------------------------------------------------------
U26.XREF_KINDS = { call = true, jmp = true, jcc = true, rip = true, abs_code = true, abs_data = true, rva = true }
U26.XREF_KIND_NAMES = "call, jmp, jcc, rip, abs (= abs_code + abs_data), abs_code, abs_data, rva"
U26.XREF_NEEDLE_LIMIT = 16                                   -- larger ranges are matched by value, not by byte string
U26.XREF_IMMS = { 0, 1, 2, 4 }                               -- immediate bytes that may follow a rip-relative displacement

-- kinds: nil/"" = all; otherwise a list or a comma separated string. Returns set  or  nil, message
function U26.xrefKinds(spec)
    local set, names = {}, {}
    if spec == nil or spec == "" or spec == "all" then
        for k in pairs(U26.XREF_KINDS) do set[k] = true end
        return set
    end
    if type(spec) == "string" then
        for w in spec:gmatch("[^,%s]+") do names[#names + 1] = w:lower() end
    elseif type(spec) == "table" then
        for _, w in ipairs(spec) do names[#names + 1] = tostring(w):lower() end
    else
        return nil, "kinds must be a list or a comma separated string"
    end
    for _, n in ipairs(names) do
        if n == "abs" then
            set.abs_code, set.abs_data = true, true
        elseif n == "all" then
            for k in pairs(U26.XREF_KINDS) do set[k] = true end
        elseif U26.XREF_KINDS[n] then
            set[n] = true
        else
            return nil, "Unknown kind '" .. n .. "'. Valid: " .. U26.XREF_KIND_NAMES
        end
    end
    if next(set) == nil then return nil, "kinds is empty" end
    return set
end

-- What does an instruction with a memory operand do to that memory? (read | write | read/write | address | call | jump)
-- Works on CE's "ADDR - BYTES - mnemonic operands" text as well as on the bare instruction.
U26.XREF_RMW = { add = 1, sub = 1, ["and"] = 1, ["or"] = 1, xor = 1, inc = 1, dec = 1, neg = 1, ["not"] = 1, adc = 1, sbb = 1,
                 xchg = 1, xadd = 1, cmpxchg = 1, cmpxchg8b = 1, cmpxchg16b = 1, bts = 1, btr = 1, btc = 1, shl = 1, shr = 1,
                 sar = 1, sal = 1, rol = 1, ror = 1, rcl = 1, rcr = 1, shld = 1, shrd = 1 }
U26.XREF_READONLY = { cmp = 1, test = 1, bt = 1, push = 1 }
function U26.xrefAccess(text)
    if type(text) ~= "string" then return nil end
    local ins = text:match("^.-%s%-%s.-%s%-%s(.*)$") or text
    while true do
        local rest = ins:match("^[Ll][Oo][Cc][Kk]%s+(.*)$") or ins:match("^[Rr][Ee][Pp][EeNnZz]*%s+(.*)$") or ins:match("^[Bb][Nn][Dd]%s+(.*)$")
        if not rest then break end
        ins = rest
    end
    local mn, ops = ins:lower():match("^(%S+)%s*(.*)$")
    if not mn then return nil end
    if mn == "lea" then return "address" end
    if mn == "call" then return "call" end
    if mn == "jmp" then return "jump" end
    local br = ops:find("[", 1, true)
    if not br then return nil end
    local comma = ops:find(",", 1, true)
    if comma and br > comma then return "read" end          -- memory is the source operand
    -- the memory operand is the destination (or the only operand)
    if mn:match("^v?mov") or mn:match("^set") or mn == "pop" or mn:match("^f?n?st") or mn:match("^fist") then return "write" end
    if U26.XREF_READONLY[mn] or mn:match("^v?u?comis") then return "read" end
    if U26.XREF_RMW[mn] then return "read/write" end
    if comma == nil then return "read" end                    -- push/mul/div/fld ... [mem]
    return "read/write"
end

-- Start of the instruction that contains the displacement/immediate field beginning at `fieldStart`, found by decoding
-- forward and taking the instruction that covers that byte. `ends` lists the end addresses the instruction may have; an
-- instruction that ends anywhere else (or starts at the field itself) means the bytes are not that kind of instruction.
-- Decoding starts at `floor` (a function start from .pdata: exact) or U26.XREF_RUNWAY bytes back (x86 decoding
-- resynchronises within a few instructions). Going backwards byte by byte would be ambiguous: the last byte of the
-- previous instruction often looks like a REX prefix (e.g. the 0x40 in `mov rax,[rax+40h]` before `call [rip+x]`).
-- Returns start, length  or nil.
U26.XREF_RUNWAY = 96
U26.XREF_RUNWAY_FROM_FUNCTION = 512
function U26.insnStart(fieldStart, ends, floor)
    local from = fieldStart - U26.XREF_RUNWAY
    if floor then from = math.max(floor, fieldStart - U26.XREF_RUNWAY_FROM_FUNCTION) end
    local pos = from
    while pos < fieldStart do
        local ok, len = pcall(getInstructionSize, pos)
        if not ok or type(len) ~= "number" or len < 1 then len = 1 end          -- undecodable byte: skip it
        local finish = pos + len
        if finish > fieldStart then
            for _, e in ipairs(ends) do
                if finish == e then return pos, e - pos end
            end
            return nil
        end
        pos = finish
    end
    return nil
end

-- Is `addr` the first byte of an instruction? Decodes forward from the same starting point as insnStart. Used for short
-- jumps: two bytes are enough for a coincidence (e.g. the `7D F0` of `cmp [rbp-10h],7` also reads as `jge -14`).
function U26.atBoundary(addr, floor)
    local pos = floor and math.max(floor, addr - U26.XREF_RUNWAY_FROM_FUNCTION) or (addr - U26.XREF_RUNWAY)
    while pos < addr do
        local ok, len = pcall(getInstructionSize, pos)
        if not ok or type(len) ~= "number" or len < 1 then len = 1 end
        pos = pos + len
    end
    return pos == addr
end

-- Builds the scan stages for one module. ctx: { want, lo, hiEx, exact, add(...), full() }
function U26.xrefModuleStages(ctx, mod, pe, stages)
    local is64, P = pe.is64, pe.ptrSize
    local mask = is64 and -1 or 0xFFFFFFFF
    local want, lo, hiEx, add = ctx.want, ctx.lo, ctx.hiEx, ctx.add
    local needles, rvaNeedles = {}, {}
    if ctx.exact then
        for t = lo, hiEx - 1 do
            if is64 or t <= 0xFFFFFFFF then
                needles[#needles + 1] = { t = t, bytes = is64 and string.pack("<I8", t) or string.pack("<I4", t) }
            end
            local r = t - mod.base
            if is64 and r >= 0 and r <= 0xFFFFFFFF then rvaNeedles[#rvaNeedles + 1] = { t = t, bytes = string.pack("<I4", r) } end
        end
    end

    -- ---- code
    local execRanges = U26.sectionRanges(pe, mod, true, true)
    local wantBranch = want.call or want.jmp or want.jcc
    if #execRanges > 0 and (wantBranch or (want.rip and is64) or want.abs_code) then
        stages[#stages + 1] = { ranges = execRanges, carry = 7, process = function(jb, data, dbase)
            if ctx.full() then return end
            local n = #data
            if want.call or want.jmp then
                local pos = 1
                while true do
                    local s = data:find("[\232\233]", pos)
                    if not s or s + 4 > n then break end
                    local kind = data:byte(s) == 232 and "call" or "jmp"
                    if want[kind] then
                        local a = dbase + s - 1
                        local t = (a + 5 + string.unpack("<i4", data, s + 1)) & mask
                        if t >= lo and t < hiEx then add(mod, pe, a, kind, t, { form = "rel32" }) end
                    end
                    pos = s + 1
                end
            end
            if want.jcc then
                local pos = 1
                while true do
                    local s = data:find("\15[\128-\143]", pos)
                    if not s or s + 5 > n then break end
                    local a = dbase + s - 1
                    local t = (a + 6 + string.unpack("<i4", data, s + 2)) & mask
                    if t >= lo and t < hiEx then add(mod, pe, a, "jcc", t, { form = "rel32" }) end
                    pos = s + 1
                end
            end
            if want.jmp or want.jcc then
                -- short jumps (EB, 70-7F) reach +-128 bytes, so only the positions around the target can match
                for a = math.max(dbase, lo - 129), math.min(dbase + n - 2, hiEx + 125) do
                    local b = data:byte(a - dbase + 1)
                    local kind = (b == 0xEB) and "jmp" or ((b >= 0x70 and b <= 0x7F) and "jcc" or nil)
                    if kind and want[kind] then
                        local rel = data:byte(a - dbase + 2)
                        if rel >= 128 then rel = rel - 256 end
                        local t = (a + 2 + rel) & mask
                        if t >= lo and t < hiEx then add(mod, pe, a, kind, t, { form = "rel8" }) end
                    end
                end
            end
            if want.rip and is64 then
                local imms = U26.XREF_IMMS
                local pos = 1
                while true do
                    local s = data:find(U26.MODRM_RIP, pos)
                    if not s or s + 4 > n then break end
                    local m = dbase + s - 1
                    local base = m + 5 + string.unpack("<i4", data, s + 1)
                    for i = 1, 4 do
                        local t = base + imms[i]
                        if t >= lo and t < hiEx then add(mod, pe, m, "rip", t, { imm = imms[i] }) end
                    end
                    pos = s + 1
                end
            end
            if want.abs_code then
                for _, nd in ipairs(needles) do
                    local pos = 1
                    while true do
                        local s = data:find(nd.bytes, pos, true)
                        if not s then break end
                        add(mod, pe, dbase + s - 1, "abs_code", nd.t, { width = P })
                        pos = s + 1
                    end
                end
            end
        end }
    end

    -- ---- data
    local dataRanges = U26.sectionRanges(pe, mod, false, false)
    if want.abs_data and #dataRanges > 0 then
        stages[#stages + 1] = { ranges = dataRanges, carry = P - 1, process = function(jb, data, dbase)
            if ctx.full() then return end
            if ctx.exact then
                for _, nd in ipairs(needles) do
                    local pos = 1
                    while true do
                        local s = data:find(nd.bytes, pos, true)
                        if not s then break end
                        local a = dbase + s - 1
                        if a % P == 0 then add(mod, pe, a, "abs_data", nd.t) end
                        pos = s + 1
                    end
                end
            else
                local fmt = is64 and "<I8" or "<I4"
                for i = ((P - dbase % P) % P) + 1, #data - P + 1, P do
                    local v = string.unpack(fmt, data, i)
                    if v >= lo and v < hiEx then add(mod, pe, dbase + i - 1, "abs_data", v) end
                end
            end
        end }
    end
    if want.rva and is64 then
        local ranges = {}
        for _, r in ipairs(dataRanges) do
            if r.name ~= ".pdata" then ranges[#ranges + 1] = r end       -- the exception table lists every function RVA
        end
        if #ranges > 0 then
            stages[#stages + 1] = { ranges = ranges, carry = 3, process = function(jb, data, dbase)
                if ctx.full() then return end
                if ctx.exact then
                    for _, nd in ipairs(rvaNeedles) do
                        local pos = 1
                        while true do
                            local s = data:find(nd.bytes, pos, true)
                            if not s then break end
                            local a = dbase + s - 1
                            if a % 4 == 0 then add(mod, pe, a, "rva", nd.t) end
                            pos = s + 1
                        end
                    end
                else
                    local rlo, rhi = lo - mod.base, hiEx - mod.base
                    for i = ((4 - dbase % 4) % 4) + 1, #data - 3, 4 do
                        local v = string.unpack("<I4", data, i)
                        if v >= rlo and v < rhi then add(mod, pe, dbase + i - 1, "rva", v + mod.base) end
                    end
                end
            end }
        end
    end
end

-- Turns one raw hit into a result item (or nil to drop a false positive).
function U26.xrefItem(st, r)
    local mod, pe = r.mod, r.pe
    local addr, item = r.addr, { kind = r.kind, target = U26.hex(r.target) }
    local fn
    if r.kind ~= "abs_data" and r.kind ~= "rva" then fn = U26.functionAt(mod, pe, r.addr - mod.base) end
    local floor = fn and (mod.base + fn.primary.begin_rva) or nil
    if r.form == "rel8" and not U26.atBoundary(r.addr, floor) then return nil end     -- two bytes in the middle of another instruction
    if r.kind == "rip" then
        local start = U26.insnStart(r.addr, { r.addr + 5 + r.imm }, floor)
        if not start then return nil end                          -- the bytes are not a rip-relative instruction
        addr = start
    elseif r.kind == "abs_code" then
        local ends = {}
        for i, e in ipairs(U26.XREF_IMMS) do ends[i] = r.addr + r.width + e end
        local start = U26.insnStart(r.addr, ends, floor)
        if start then
            addr = start
            item.field_address = U26.hex(r.addr)                  -- the pointer itself; `address` is the instruction
        end
    end
    local rva = addr - mod.base
    item.address, item.module, item.rva, item.expression = U26.hex(addr), mod.name, rva, mod.name .. "+" .. U26.hex(rva)
    if r.form then item.form = r.form end
    if st.size > 1 then item.offset_in_target = r.target - st.lo end
    local sec = U26.sectionFor(pe, rva)
    if sec then item.section = sec.name end
    if r.kind ~= "abs_data" and r.kind ~= "rva" then
        -- an absolute pointer that no instruction owns is data inside the code (e.g. an x86 switch table): no disassembly
        local text = (r.kind ~= "abs_code" or item.field_address) and disassemble(addr) or nil
        if text then
            item.instruction = text
            if r.kind == "rip" then item.access = U26.xrefAccess(text) end
        end
        if fn then
            item.function_start = mod.name .. "+" .. U26.hex(fn.primary.begin_rva)
            item.function_rva = fn.primary.begin_rva
        end
    end
    return item, addr
end

function U26.xrefResolveStep(job, deadline)
    local st = job._xr
    local recs = st.recs
    while st.i <= #recs do
        if os.clock() >= deadline then return false end
        local item, addr = U26.xrefItem(st, recs[st.i])
        if item then
            st.items[#st.items + 1] = { a = addr, base = recs[st.i].mod.base, item = item }
            if item.function_start then
                local g = st.groups[item.function_start]
                if g then g.count = g.count + 1 else st.groups[item.function_start] = { function_start = item.function_start, function_rva = item.function_rva, count = 1 } end
            end
        end
        st.i = st.i + 1
        job.progress.current = job.progress.current + 1
    end
    table.sort(st.items, function(x, y)
        if x.base ~= y.base then return x.base < y.base end
        if x.a ~= y.a then return x.a < y.a end
        return x.item.kind < y.item.kind
    end)
    local items, byKind = {}, {}
    for i, e in ipairs(st.items) do
        items[i] = e.item
        byKind[e.item.kind] = (byKind[e.item.kind] or 0) + 1
    end
    local groups = {}
    for _, g in pairs(st.groups) do groups[#groups + 1] = g end
    table.sort(groups, function(x, y) if x.count ~= y.count then return x.count > y.count end return x.function_rva < y.function_rva end)
    while #groups > 50 do groups[#groups] = nil end
    local fields = { target = U26.hex(st.lo), size = st.size, modules = st.modules, found = #items }
    if next(byKind) then fields.by_kind = byKind end
    if #groups > 0 then fields.functions = groups end
    if st.ctx.truncated then fields.truncated = true; st.notes[#st.notes + 1] = "stopped at max_results; raise it or narrow the module/kinds" end
    if #st.notes > 0 then fields.notes = st.notes end
    job.progress.current = job.progress.total
    jobFinish(job, "done", { result = { fields = fields, list_key = "references", items = items } })
    return true
end

JOB_STARTERS.find_xrefs = function(job, p)
    local perr = requireProcess()
    if perr then return perr end
    local target = U26.addr(p.address)
    if not target then return U26.err("Invalid address", "INVALID_ADDRESS") end
    local size = clampInt(p.size or 1, 1, 0x10000)
    local want, kerr = U26.xrefKinds(p.kinds)
    if not want then return U26.err(kerr) end
    local maxResults = clampInt(p.max_results or 5000, 1, 50000)

    local mods = U26.listModules()
    if #mods == 0 then return U26.err("No modules found (is a process attached?)", "NO_PROCESS") end
    local picked
    if p.module == "all" then
        picked = mods
    elseif p.module == nil or p.module == "" then
        picked = { U26.moduleFor(mods, target) or mods[1] }       -- the module that holds the target, else the main module
    else
        local m, merr = U26.findModule(p.module)
        if not m then return merr end
        picked = { m }
    end

    local recs, seen, notes = {}, {}, {}
    local ctx = { want = want, lo = target, hiEx = target + size, exact = size <= U26.XREF_NEEDLE_LIMIT, truncated = false }
    ctx.full = function() return ctx.truncated end
    ctx.add = function(mod, pe, addr, kind, tgt, extra)
        local key = kind .. ":" .. addr .. ":" .. tostring(extra and extra.imm or 0)
        if seen[key] then return end
        if #recs >= maxResults then ctx.truncated = true; return end
        seen[key] = true
        local r = { mod = mod, pe = pe, addr = addr, kind = kind, target = tgt }
        if extra then for k, v in pairs(extra) do r[k] = v end end
        recs[#recs + 1] = r
    end

    local stages, scanned = {}, {}
    for _, mod in ipairs(picked) do
        local pe = U26.parsePE(mod.base)
        if pe then
            scanned[#scanned + 1] = mod.name
            U26.xrefModuleStages(ctx, mod, pe, stages)
        else
            notes[#notes + 1] = mod.name .. ": no readable PE header, skipped"
        end
    end
    if #scanned == 0 then return U26.err("None of the selected modules has a readable PE header", "INTERNAL_ERROR") end
    if not ctx.exact and want.abs_code then
        notes[#notes + 1] = "absolute pointers in code are only searched for targets of at most " .. U26.XREF_NEEDLE_LIMIT .. " bytes (size)"
    end

    U26.startStages(job, stages, function(jb)
        table.sort(recs, function(x, y)
            if x.mod.base ~= y.mod.base then return x.mod.base < y.mod.base end
            if x.addr ~= y.addr then return x.addr < y.addr end
            return x.kind < y.kind
        end)
        jb._xr = { recs = recs, i = 1, items = {}, groups = {}, lo = ctx.lo, size = size, modules = scanned, notes = notes, ctx = ctx }
        jb.progress.total = jb.progress.total + #recs         -- resolving the hits (disassembly, functions) is the second half
        jb._step = U26.xrefResolveStep
        return false
    end)
end
JOB_KIND_NAMES = JOB_KIND_NAMES .. ", find_xrefs"

-- >>> END UNIT-28 <<<

-- >>> BEGIN UNIT-30 Pointer path sets: comparing pointer chains across runs <<<
-- A pointer chain found in one run is only worth something if it still works after the target restarts. A "set" is a
-- named list of chains {module+RVA, offsets} kept inside the bridge, so it outlives target restarts (not a reload of the
-- bridge). find_pointer_path(save_as=) fills one in run 1; after the restart compare_pointer_paths re-resolves every
-- chain against the new address of the same value and keeps those that land on it. Saving the survivors back narrows
-- the set: a chain with runs=3 has reached its value in three separate runs.
U26.PS_MAX_SETS, U26.PS_MAX_CHAINS, U26.PS_MAX_DEPTH, U26.PS_MAX_HISTORY = 16, 5000, 16, 20
serverState.path_sets = {}

function U26.psName(v)
    if type(v) == "string" and #v <= 48 and v:match("^[%w_%.%-]+$") then return v end
    return nil, U26.err("Set names use letters, digits, '_', '.' and '-' (at most 48 characters)")
end

function U26.psCount()
    local n = 0
    for _ in pairs(serverState.path_sets) do n = n + 1 end
    return n
end

function U26.psInt(v)
    if type(v) == "string" then v = tonumber(v) end
    if math.type(v) == "float" then return math.tointeger(v) end
    if math.type(v) == "integer" then return v end
    return nil
end

function U26.psProcess()
    local ok, name = pcall(function() return process end)
    return { pid = getOpenedProcessID(), process = (ok and type(name) == "string") and name or nil }
end

function U26.psSigned(n) return n < 0 and "-" .. U26.hex(-n) or U26.hex(n) end

-- One chain as a client sends it ({base = "module+0xRVA" | address, offsets = {...}, runs = n}) -> stored record.
-- An address inside a loaded module is stored module-relative: that is the part that survives a restart.
function U26.psParseChain(c, mods)
    if type(c) ~= "table" then return nil, "not an object with base and offsets" end
    local raw = c.offsets
    if raw == nil then raw = {} end
    if type(raw) ~= "table" or #raw > U26.PS_MAX_DEPTH then
        return nil, "offsets must be a list of at most " .. U26.PS_MAX_DEPTH .. " integers"
    end
    local offs = {}
    for i, o in ipairs(raw) do
        local n = U26.psInt(o)
        if not n then return nil, "offsets[" .. i .. "] is not an integer" end
        offs[i] = n
    end
    local rec = { offsets = offs, runs = U26.psInt(c.runs) or 0 }
    local base = c.base
    if type(base) == "string" then
        local name, tail = base:match("^(.+)%+(%w+)$")
        local rva = tail and (tail:match("^0[xX]%x+$") and tonumber(tail) or (tail:match("^%x+$") and tonumber(tail, 16)))
        if name and rva then
            local lname = name:lower()
            for _, m in ipairs(mods) do        -- the loaded module's own spelling, so "GAME.EXE+10" and "game.exe+10" are one chain
                if m.name:lower() == lname then name = m.name; break end
            end
            rec.module, rec.rva = name, rva
            return rec
        end
        base = U26.addr(base)
    end
    base = U26.psInt(base)
    if not base then return nil, "base must be 'module+0xRVA' or an address" end
    local m = U26.moduleFor(mods, base)
    if m then rec.module, rec.rva = m.name, base - m.base else rec.abs = base end
    return rec
end

function U26.psBaseString(r)
    if r.module then return r.module .. "+" .. U26.hex(r.rva) end
    return U26.hex(r.abs)
end

-- CE-style expression: [[base]+o1]+o2 (a chain without offsets is just the base)
function U26.psExpression(r)
    if #r.offsets == 0 then return U26.psBaseString(r) end
    local expr = "[" .. U26.psBaseString(r) .. "]"
    for i, o in ipairs(r.offsets) do
        expr = expr .. (o < 0 and "-" .. U26.hex(-o) or "+" .. U26.hex(o))
        if i < #r.offsets then expr = "[" .. expr .. "]" end
    end
    return expr
end

function U26.psView(r)
    local hexOffs = {}
    for i, o in ipairs(r.offsets) do hexOffs[i] = U26.psSigned(o) end
    return { base = U26.psBaseString(r), offsets = r.offsets, offsets_hex = hexOffs, depth = #r.offsets,
             expression = U26.psExpression(r), runs = r.runs }
end

function U26.psCost(r)
    local c = 0
    for _, o in ipairs(r.offsets) do c = c + math.abs(o) end
    return c
end

function U26.psSummary(s)
    return { name = s.name, chain_count = #s.chains, runs = s.runs, arch = s.arch, created = s.created, updated = s.updated,
             history = s.history }
end

-- Follow one chain in the CURRENT process: "ok", finalAddress | "module_missing" | "unreadable"
function U26.psEval(rec, byName, is64)
    local cur = rec.abs
    if rec.module then
        local m = byName[rec.module:lower()]
        if not m then return "module_missing" end
        cur = m.base + rec.rva
    end
    for _, off in ipairs(rec.offsets) do
        local ptr = U26.ptr(cur, is64)
        if not ptr then return "unreadable" end
        cur = ptr + off
        if not is64 then cur = cur & 0xFFFFFFFF end
    end
    return "ok", cur
end

-- Store (replace) a set. Returns the set, or nil + reason. Never stores an empty set.
function U26.psPut(name, chains, runs, history)
    local n, nerr = U26.psName(name)
    if not n then return nil, nerr.error end
    if #chains == 0 then return nil, "nothing to store (an existing set is never overwritten with an empty one)" end
    if #chains > U26.PS_MAX_CHAINS then return nil, "a set holds at most " .. U26.PS_MAX_CHAINS .. " chains" end
    local old = serverState.path_sets[name]
    if not old and U26.psCount() >= U26.PS_MAX_SETS then
        return nil, "at most " .. U26.PS_MAX_SETS .. " sets are kept; drop_pointer_set one first"
    end
    while #history > U26.PS_MAX_HISTORY do table.remove(history, 1) end
    local now = os.time()
    local s = { name = name, chains = chains, runs = runs, history = history, created = old and old.created or now, updated = now,
                arch = targetIs64Bit() and "x64" or "x86" }
    serverState.path_sets[name] = s
    return s
end

-- find_pointer_path(save_as=): run 1 of a comparison
function U26.psSaveFound(name, recs, target)
    local pr = U26.psProcess()
    return U26.psPut(name, recs, 1, { { run = 1, at = os.time(), pid = pr.pid, process = pr.process, target = U26.hex(target),
                                         tested = #recs, survivors = #recs, source = "find_pointer_path" } })
end

-- Re-resolve every chain of a stored set (name) or an inline list (chains) against the address of the same value in
-- the process as it is NOW (target). Chains that land exactly on it have been confirmed in one more run.
function cmd_compare_pointer_paths(params)
    local perr = requireProcess()
    if perr then return perr end
    local target = U26.addr(params.target)
    if not target then return U26.err("Invalid target address", "INVALID_ADDRESS") end
    if (params.name == nil) == (params.chains == nil) then
        return U26.err("Give exactly one of name (a stored set) or chains (a list of {base, offsets})")
    end
    local saveAs = params.save_as
    if saveAs ~= nil then
        local _, nerr = U26.psName(saveAs)
        if nerr then return nerr end
    end
    local nearDelta = clampInt(params.near_delta or 0x100, 0, 0x10000)
    local nearLimit = clampInt(params.near_limit or 10, 0, 100)

    local mods = U26.listModules()
    local src, input, duplicates = nil, {}, 0
    if params.name ~= nil then
        src = serverState.path_sets[params.name]
        if not src then return U26.err("No such pointer set: " .. tostring(params.name) .. " (list_pointer_sets shows them)", "NOT_FOUND") end
        input = src.chains
    else
        if type(params.chains) ~= "table" or #params.chains == 0 then return U26.err("chains must be a non-empty list") end
        if #params.chains > U26.PS_MAX_CHAINS then
            return U26.err("Too many chains (max " .. U26.PS_MAX_CHAINS .. "); compare them in pages")
        end
        local seenKey = {}
        for i, c in ipairs(params.chains) do
            local rec, why = U26.psParseChain(c, mods)
            if not rec then return U26.err("chains[" .. i .. "]: " .. why) end
            local key = U26.psExpression(rec)          -- the same chain written another way counts once
            if seenKey[key] then
                duplicates = duplicates + 1
            else
                seenKey[key] = true
                input[#input + 1] = rec
            end
        end
    end

    local is64 = targetIs64Bit()
    local byName = {}
    for _, m in ipairs(mods) do
        local k = m.name:lower()
        if not byName[k] then byName[k] = m end
    end

    local hits, near = {}, {}
    local counts = { missed = 0, unreadable = 0, module_missing = 0 }
    for idx, r in ipairs(input) do
        local status, final = U26.psEval(r, byName, is64)
        if status == "ok" and final == target then
            hits[#hits + 1] = { rec = r, idx = idx }
        elseif status == "ok" then
            counts.missed = counts.missed + 1
            local delta = final - target
            if nearLimit > 0 and math.abs(delta) <= nearDelta then near[#near + 1] = { rec = r, idx = idx, final = final, delta = delta } end
        else
            counts[status] = counts[status] + 1
        end
    end

    -- survivors: confirmed in the most runs first, then the shortest and smallest chains
    local survivors = {}
    for i, h in ipairs(hits) do
        local r = h.rec
        survivors[i] = { module = r.module, rva = r.rva, abs = r.abs, offsets = r.offsets, runs = r.runs + 1, idx = h.idx }
    end
    table.sort(survivors, function(a, b)
        if a.runs ~= b.runs then return a.runs > b.runs end
        if #a.offsets ~= #b.offsets then return #a.offsets < #b.offsets end
        local ca, cb = U26.psCost(a), U26.psCost(b)
        if ca ~= cb then return ca < cb end
        return a.idx < b.idx
    end)

    table.sort(near, function(a, b)
        local da, db = math.abs(a.delta), math.abs(b.delta)
        if da ~= db then return da < db end
        return a.idx < b.idx
    end)
    local nearOut = {}
    for i = 1, math.min(#near, nearLimit) do
        local n = near[i]
        local v = U26.psView(n.rec)
        v.final_address = U26.hex(n.final)
        v.delta = (n.delta >= 0 and "+" or "-") .. U26.hex(math.abs(n.delta))
        if #n.rec.offsets > 0 then          -- the last field moved by `delta`: the same chain with that offset corrected
            local fix = {}
            for k, o in ipairs(n.rec.offsets) do fix[k] = o end
            fix[#fix] = fix[#fix] - n.delta
            v.suggested_offsets = fix
        end
        nearOut[i] = v
    end

    local pr = U26.psProcess()
    local last = src and src.history[#src.history]
    local runNo = (src and src.runs or 0) + 1
    local notes = {}
    local sameProcess = last ~= nil and last.pid ~= nil and last.pid == pr.pid
    if sameProcess then
        notes[#notes + 1] = "Same process instance (pid " .. tostring(pr.pid) .. ") as the previous run: the target was not restarted, " ..
                            "so this only shows that the chains survive whatever happened since (level change, reallocation), not a restart."
    end
    if #hits == 0 then
        notes[#notes + 1] = "No chain reaches " .. U26.hex(target) .. ". Is it the same value in this run? Compare in a fresh state, or search again with find_pointer_path."
        if #near > 0 then
            notes[#notes + 1] = #near .. " chain(s) miss by a small distance (near_misses): the last offset probably moved; suggested_offsets shows the corrected chain."
        end
    end

    local out = { success = true, target = U26.hex(target), run = runNo, compared = #input, hits = #hits, missed = counts.missed,
                  unreadable = counts.unreadable, module_missing = counts.module_missing, same_process = sameProcess }
    if src then out.name = src.name end
    if duplicates > 0 then out.duplicates_ignored = duplicates end

    if saveAs ~= nil then
        if #hits == 0 then
            out.save_note = "not saved: no chain survived, so " .. (serverState.path_sets[saveAs] and "the existing set is unchanged" or "there is nothing to store")
        else
            local recs = {}
            for i, s in ipairs(survivors) do recs[i] = { module = s.module, rva = s.rva, abs = s.abs, offsets = s.offsets, runs = s.runs } end
            local hist = {}
            if src then for i, h in ipairs(src.history) do hist[i] = h end end
            hist[#hist + 1] = { run = runNo, at = os.time(), pid = pr.pid, process = pr.process, target = U26.hex(target),
                                tested = #input, survivors = #hits, source = src and "compare" or "inline" }
            local s, why = U26.psPut(saveAs, recs, runNo, hist)
            if s then
                out.saved_as, out.set = s.name, U26.psSummary(s)
            else
                out.save_note = "not saved: " .. why
            end
        end
    end
    if #notes > 0 then out.notes = notes end
    if #nearOut > 0 then out.near_misses = nearOut end

    local limit, offset, page, total = paginate(params, survivors, 100)
    local views = {}
    for i, s in ipairs(page) do views[i] = U26.psView(s) end
    out.total, out.offset, out.limit, out.returned = total, offset, limit, #views
    out.chains = views
    return out
end

function cmd_list_pointer_sets(params)
    local list = {}
    for _, s in pairs(serverState.path_sets) do list[#list + 1] = U26.psSummary(s) end
    table.sort(list, function(a, b)
        if a.created ~= b.created then return a.created < b.created end
        return a.name < b.name
    end)
    return { success = true, count = #list, sets = list }
end

function cmd_get_pointer_set(params)
    local s = serverState.path_sets[params.name]
    if not s then return U26.err("No such pointer set: " .. tostring(params.name), "NOT_FOUND") end
    local out = U26.psSummary(s)
    out.success = true
    local limit, offset, page, total = paginate(params, s.chains, 100)
    local views = {}
    for i, r in ipairs(page) do views[i] = U26.psView(r) end
    out.total, out.offset, out.limit, out.returned = total, offset, limit, #views
    out.chains = views
    return out
end

function cmd_drop_pointer_set(params)
    if params.all == true then
        local n = U26.psCount()
        serverState.path_sets = {}
        return { success = true, deleted = n }
    end
    if not serverState.path_sets[params.name] then
        return U26.err("No such pointer set: " .. tostring(params.name), "NOT_FOUND")
    end
    serverState.path_sets[params.name] = nil
    return { success = true, deleted = 1 }
end

-- >>> END UNIT-30 <<<

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,

    -- >>> BEGIN UNIT-07 Process Lifecycle <<<
    open_process = cmd_open_process,
    get_process_list = cmd_get_process_list,
    get_processid_from_name = cmd_get_processid_from_name,
    get_foreground_process = cmd_get_foreground_process,
    create_process = cmd_create_process,
    get_opened_process_id = cmd_get_opened_process_id,
    get_opened_process_handle = cmd_get_opened_process_handle,
    -- >>> END UNIT-07 <<<
    
    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- More accurate, uses native API
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,

    -- Threading & Synchronization (Unit-22)
    create_thread           = cmd_create_thread,
    get_global_variable     = cmd_get_global_variable,
    set_global_variable     = cmd_set_global_variable,
    queue_to_main_thread    = cmd_queue_to_main_thread,
    check_synchronize       = cmd_check_synchronize,
    in_main_thread          = cmd_in_main_thread,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    analyze_pointer_access = cmd_analyze_pointer_access,
    validate_pointer_chains = cmd_validate_pointer_chains,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,

    -- Debug Output & Multimedia (Unit 23)
    output_debug_string = cmd_output_debug_string,
    speak_text = cmd_speak_text,
    play_sound = cmd_play_sound,
    beep = cmd_beep,
    set_progress_state = cmd_set_progress_state,
    set_progress_value = cmd_set_progress_value,
    -- Unit-21: Kernel Mode / DBVM Extensions
    dbk_get_cr0 = cmd_dbk_get_cr0,
    dbk_get_cr3 = cmd_dbk_get_cr3,
    dbk_get_cr4 = cmd_dbk_get_cr4,
    read_process_memory_cr3 = cmd_read_process_memory_cr3,
    write_process_memory_cr3 = cmd_write_process_memory_cr3,
    map_memory = cmd_map_memory,
    unmap_memory = cmd_unmap_memory,
    dbk_writes_ignore_write_protection = cmd_dbk_writes_ignore_write_protection,
    get_physical_address_cr3 = cmd_get_physical_address_cr3,

    -- Shell Execution (UNIT-20b) - Security gate enforced on Python side
    run_command = cmd_run_command,
    shell_execute = cmd_shell_execute,
    file_exists = cmd_file_exists,
    delete_file = cmd_delete_file,
    get_file_list = cmd_get_file_list,
    get_directory_list = cmd_get_directory_list,
    get_temp_folder = cmd_get_temp_folder,
    get_file_version = cmd_get_file_version,
    read_clipboard = cmd_read_clipboard,
    write_clipboard = cmd_write_clipboard,

    -- >>> BEGIN UNIT-19 dispatcher entries <<<
    create_structure           = cmd_create_structure,
    get_structure_by_name      = cmd_get_structure_by_name,
    add_element_to_structure   = cmd_add_element_to_structure,
    get_structure_elements     = cmd_get_structure_elements,
    export_structure_to_xml    = cmd_export_structure_to_xml,
    delete_structure           = cmd_delete_structure,
    -- >>> END UNIT-19 <<<
    -- >>> BEGIN UNIT-18 dispatcher entries <<<
    load_table               = cmd_load_table,
    save_table               = cmd_save_table,
    get_address_list         = cmd_get_address_list,
    get_memory_record        = cmd_get_memory_record,
    create_memory_record     = cmd_create_memory_record,
    delete_memory_record     = cmd_delete_memory_record,
    get_memory_record_value  = cmd_get_memory_record_value,
    set_memory_record_value  = cmd_set_memory_record_value,
    -- >>> END UNIT-18 <<<
    -- Input Automation (Unit-17) — system-wide, no process guard required
    get_pixel = cmd_get_pixel,
    get_mouse_pos = cmd_get_mouse_pos,
    set_mouse_pos = cmd_set_mouse_pos,
    is_key_pressed = cmd_is_key_pressed,
    key_down = cmd_key_down,
    key_up = cmd_key_up,
    do_key_press = cmd_do_key_press,
    get_screen_info = cmd_get_screen_info,

    -- Window / GUI (Unit-16)
    find_window             = cmd_find_window,
    get_window_caption      = cmd_get_window_caption,
    get_window_class_name   = cmd_get_window_class_name,
    get_window_process_id   = cmd_get_window_process_id,
    send_window_message     = cmd_send_window_message,
    show_message            = cmd_show_message,
    input_query             = cmd_input_query,
    show_selection_list     = cmd_show_selection_list,
    -- Unit 15: Advanced Scanning
    aob_scan_unique           = cmd_aob_scan_unique,
    aob_scan_module           = cmd_aob_scan_module,
    aob_scan_module_unique    = cmd_aob_scan_module_unique,
    pointer_rescan            = cmd_pointer_rescan,
    create_persistent_scan    = cmd_create_persistent_scan,
    persistent_scan_first_scan    = cmd_persistent_scan_first_scan,
    persistent_scan_next_scan     = cmd_persistent_scan_next_scan,
    persistent_scan_get_results   = cmd_persistent_scan_get_results,
    persistent_scan_destroy       = cmd_persistent_scan_destroy,
    -- Memory Operations (Unit 14)
    copy_memory = cmd_copy_memory,
    compare_memory = cmd_compare_memory,
    write_region_to_file = cmd_write_region_to_file,
    read_region_from_file = cmd_read_region_from_file,
    md5_memory = cmd_md5_memory,
    md5_file = cmd_md5_file,
    create_section = cmd_create_section,
    map_view_of_section = cmd_map_view_of_section,
    -- Assembly & Compilation (Unit 13)
    assemble_instruction = cmd_assemble_instruction,
    auto_assemble_check = cmd_auto_assemble_check,
    compile_c_code = cmd_compile_c_code,
    compile_cs_code = cmd_compile_cs_code,
    generate_api_hook_script = cmd_generate_api_hook_script,
    generate_code_injection_script = cmd_generate_code_injection_script,
    -- >>> BEGIN UNIT-12 dispatcher entries <<<
    register_symbol                = cmd_register_symbol,
    unregister_symbol              = cmd_unregister_symbol,
    enum_registered_symbols        = cmd_enum_registered_symbols,
    delete_all_registered_symbols  = cmd_delete_all_registered_symbols,
    enable_windows_symbols         = cmd_enable_windows_symbols,
    enable_kernel_symbols          = cmd_enable_kernel_symbols,
    get_symbol_info                = cmd_get_symbol_info,
    get_module_size                = cmd_get_module_size,
    load_new_symbols               = cmd_load_new_symbols,
    reinitialize_symbol_handler    = cmd_reinitialize_symbol_handler,
    -- >>> END UNIT-12 <<<
    -- Unit-11: Debug Context + Per-Thread Breakpoints
    debug_get_context                  = cmd_debug_get_context,
    debug_set_context                  = cmd_debug_set_context,
    debug_get_xmm_pointer              = cmd_debug_get_xmm_pointer,
    debug_set_last_branch_recording    = cmd_debug_set_last_branch_recording,
    debug_get_last_branch_record       = cmd_debug_get_last_branch_record,
    debug_set_breakpoint_for_thread    = cmd_debug_set_breakpoint_for_thread,
    debug_remove_breakpoint_for_thread = cmd_debug_remove_breakpoint_for_thread,
    -- Debugger Control (Unit 10)
    debug_process                      = cmd_debug_process,
    debug_is_debugging                 = cmd_debug_is_debugging,
    debug_get_current_debugger_interface = cmd_debug_get_current_debugger_interface,
    debug_break_thread                 = cmd_debug_break_thread,
    debug_continue                     = cmd_debug_continue,
    debug_detach                       = cmd_debug_detach,
    pause_process                      = cmd_pause_process,
    unpause_process                    = cmd_unpause_process,
    -- Code Injection & Execution (Unit-09)
    inject_dll            = cmd_inject_dll,
    inject_dotnet_dll     = cmd_inject_dotnet_dll,
    execute_code          = cmd_execute_code,
    execute_code_ex       = cmd_execute_code_ex,
    execute_method        = cmd_execute_method,
    execute_code_local    = cmd_execute_code_local,
    execute_code_local_ex = cmd_execute_code_local_ex,
    -- >>> BEGIN UNIT-08 dispatcher entries <<<
    allocate_memory        = cmd_allocate_memory,
    free_memory            = cmd_free_memory,
    allocate_shared_memory = cmd_allocate_shared_memory,
    get_memory_protection  = cmd_get_memory_protection,
    set_memory_protection  = cmd_set_memory_protection,
    full_access            = cmd_full_access,
    allocate_kernel_memory = cmd_allocate_kernel_memory,
    -- >>> END UNIT-08 <<<

    -- >>> BEGIN UNIT-25 <<<
    bridge_status  = cmd_bridge_status,
    read_struct    = cmd_read_struct,
    batch          = cmd_batch,
    start_job      = cmd_start_job,
    get_job        = cmd_get_job,
    get_job_result = cmd_get_job_result,
    cancel_job     = cmd_cancel_job,
    list_jobs      = cmd_list_jobs,
    -- >>> END UNIT-25 <<<

    -- >>> BEGIN UNIT-26 <<<
    pe_info             = cmd_pe_info,
    pe_imports          = cmd_pe_imports,
    pe_exports          = cmd_pe_exports,
    pe_tls_callbacks    = cmd_pe_tls_callbacks,
    va_to_rva           = cmd_va_to_rva,
    rva_to_va           = cmd_rva_to_va,
    rebase_address      = cmd_rebase_address,
    export_names        = cmd_export_names,
    export_structures   = cmd_export_structures,
    import_names        = cmd_import_names,
    snapshot_region     = cmd_snapshot_region,
    list_snapshots      = cmd_list_snapshots,
    delete_snapshot     = cmd_delete_snapshot,
    diff_snapshots      = cmd_diff_snapshots,
    -- >>> END UNIT-26 <<<

    -- >>> BEGIN UNIT-27 <<<
    pe_functions        = cmd_pe_functions,
    recover_struct      = cmd_recover_struct,
    get_halted_state    = cmd_get_halted_state,
    -- >>> END UNIT-27 <<<

    -- >>> BEGIN UNIT-30 <<<
    compare_pointer_paths = cmd_compare_pointer_paths,
    list_pointer_sets   = cmd_list_pointer_sets,
    get_pointer_set     = cmd_get_pointer_set,
    drop_pointer_set    = cmd_drop_pointer_set,
    -- >>> END UNIT-30 <<<
}
serverState.dispatch = commandHandlers   -- used by cmd_batch / cmd_bridge_status

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================

-- json.encode can throw (circular tables, unsupported types); never let that
-- escape, or the client would wait for a reply that is never written.
local function encodeReply(tbl)
    local ok, out = pcall(json.encode, tbl)
    if ok then return out end
    local ok2, out2 = pcall(json.encode, { jsonrpc = "2.0", error = { code = -32603, message = "Response encoding failed: " .. tostring(out) }, id = tbl.id })
    if ok2 then return out2 end
    return '{"jsonrpc":"2.0","error":{"code":-32603,"message":"Response encoding failed"},"id":null}'
end

local function errorReply(code, message, id)
    return encodeReply({ jsonrpc = "2.0", error = { code = code, message = message }, id = id })
end

local function executeCommand(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or type(request) ~= "table" then
        return errorReply(-32700, "Parse error", nil)
    end

    local method = request.method
    local params = request.params
    if type(params) ~= "table" then params = {} end
    local id = request.id

    local handler = commandHandlers[method]
    if not handler then
        return errorReply(-32601, "Method not found: " .. tostring(method), id)
    end

    local t0 = os.clock()
    local ok2, result = pcall(handler, params)
    local stats = serverState.stats
    stats.requests = stats.requests + 1
    stats.last_method = method
    stats.last_ms = math.floor((os.clock() - t0) * 1000)
    if stats.last_ms > (stats.slowest_ms or 0) then
        stats.slowest_ms, stats.slowest_method = stats.last_ms, method
    end
    if not ok2 then
        stats.errors = stats.errors + 1
        stats.last_error = tostring(result)
        return errorReply(-32603, "Internal error: " .. tostring(result), id)
    end

    return encodeReply({ jsonrpc = "2.0", result = result, id = id })
end

-- ============================================================================
-- THREAD-BASED PIPE SERVER (NON-BLOCKING GUI)
-- ============================================================================
-- Replaces v10 Timer architecture to prevent GUI Freezes.
-- I/O happens in Worker Thread. Execution happens in Main Thread.

local MAX_FRAME_BYTES = 32 * 1024 * 1024

local function sendFrame(pipe, response)
    local rLen = #response
    pipe.writeBytes({ rLen % 256, math.floor(rLen / 256) % 256, math.floor(rLen / 65536) % 256, math.floor(rLen / 16777216) % 256 })
    pipe.writeString(response)
end

local function PipeWorker(thread)
    log("Worker Thread Started - Waiting for connection...")

    while not thread.Terminated do
        -- Create Pipe Instance per connection attempt
        -- Increased buffer size to 256KB for better throughput
        local pipe = createPipe(PIPE_NAME, 262144, 262144)  -- 256 KB buffers (was 64 KB)
        if not pipe then
            log("Fatal: Failed to create pipe")
            return
        end

        -- Store reference so we can destroy it from main thread (stopServer) to break blocking calls
        serverState.workerPipe = pipe

        -- We DO NOT set pipe.Timeout because it auto-disconnects on timeout.
        -- We rely on blocking reads and pipe.destroy() from stopServer to break the block.

        -- Wait for client (Blocking, but in thread so GUI is fine)
        pcall(function()
            pipe.acceptConnection()
        end)

        if pipe.Connected and not thread.Terminated then
            log("Client Connected")
            serverState.connected = true

            while not thread.Terminated and pipe.Connected do
                local ok, lenBytes = pcall(function() return pipe.readBytes(4) end)

                if ok and lenBytes and #lenBytes == 4 then
                    local len = lenBytes[1] + (lenBytes[2] * 256) + (lenBytes[3] * 65536) + (lenBytes[4] * 16777216)

                    if len > 0 and len < MAX_FRAME_BYTES then
                        local rok, payload = pcall(function() return pipe.readString(len) end)

                        if rok and payload then
                            -- CRITICAL: EXECUTE ON MAIN THREAD
                            local response = nil
                            thread.synchronize(function()
                                local okc, resp = pcall(executeCommand, payload)
                                if okc and resp then
                                    response = resp
                                else
                                    response = errorReply(-32603, "Internal error: " .. tostring(resp), nil)
                                end
                            end)

                            -- Write response back (Worker Thread)
                            if not pcall(sendFrame, pipe, response) then
                                log("Failed to write response; dropping connection")
                                break
                            end
                        else
                            -- Payload unreadable: the byte stream is out of sync. Tell the
                            -- client, then drop the connection so it reconnects cleanly.
                            pcall(sendFrame, pipe, errorReply(-32700, "Unreadable request payload", nil))
                            break
                        end
                    else
                        pcall(sendFrame, pipe, errorReply(-32600, "Invalid frame length: " .. tostring(len), nil))
                        break
                    end
                elseif pipe.Connected then
                    sleep(5)  -- failed read on a live pipe: avoid a busy loop
                end
            end

            serverState.connected = false
            log("Client Disconnected")
        end

        -- Clean up pipe
        serverState.workerPipe = nil
        pcall(function() pipe.destroy() end)

        -- Brief sleep before recreating pipe to accept new connection
        if not thread.Terminated then sleep(50) end
    end

    log("Worker Thread Terminated")
end

-- ============================================================================
-- MAIN CONTROL
-- ============================================================================

function StopMCPBridge()
    if serverState.workerThread then
        log("Stopping Server (Terminating Thread)...")
        serverState.workerThread.terminate()
        
        -- Force destroy the pipe if it's currently blocking on acceptConnection or read
        if serverState.workerPipe then
            pcall(function() serverState.workerPipe.destroy() end)
            serverState.workerPipe = nil
        end
        
        serverState.workerThread = nil
        serverState.running = false
    end
    
    if serverState.timer then
        serverState.timer.destroy()
        serverState.timer = nil
    end
    
    -- CRITICAL: Cleanup all zombie resources (breakpoints, DBVM watches, scans)
    cleanupZombieState()
    
    log("Server Stopped")
end

function StartMCPBridge()
    StopMCPBridge()  -- This now also calls cleanupZombieState()
    
    -- Update Global State
    log("Starting MCP Bridge v" .. VERSION)
    
    serverState.running = true
    serverState.connected = false
    
    -- Create the Worker Thread
    serverState.workerThread = createThread(PipeWorker)
    
    log("===========================================")
    log("MCP Server Listening on: " .. PIPE_NAME)
    log("Architecture: Threaded I/O + Synchronized Execution")
    log("Cleanup: Zombie Prevention Active")
    log("===========================================")
end

-- Auto-start
StartMCPBridge()
