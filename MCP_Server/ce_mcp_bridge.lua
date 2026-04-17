-- ============================================================================
-- CHEATENGINE MCP BRIDGE v11.4 - FORTIFIED EDITION
-- ============================================================================
-- Combines timer-based pipe communication (v10) with complete command set (v8)
-- This is the PRODUCTION version with all tools for AI-powered reverse engineering
-- v11.4.0: Added robust cleanup on start/stop to prevent zombie breakpoints/watches
--          Ensures clean state on script reload even if resources are active
-- v11.3.1: Universal 32/64-bit handling, improved breakpoint capture, robust analysis
--          Fixed analyze_function, readPointer for pointer chains
-- ============================================================================

local PIPE_NAME = "CE_MCP_Bridge_v99"
local VERSION = "11.4.0"

-- Global State
local serverState = {
    running = false,
    timer = nil,
    pipe = nil,
    connected = false,
    scan_memscan = nil,
    scan_foundlist = nil,
    breakpoints = {},
    breakpoint_hits = {},
    hw_bp_slots = {},      -- Hardware breakpoint slots (max 4)
    active_watches = {}    -- DBVM watch IDs for hypervisor-level tracing
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

    -- Reset all tracking tables
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    serverState.active_watches = {}
    
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
local function encode_string(val) return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"' end
local function encode_number(val) if val ~= val or val <= -math.huge or val >= math.huge then return "null" end return string.format("%.14g", val) end
local type_func_map = { ["nil"] = encode_nil, ["table"] = encode_table, ["string"] = encode_string, ["number"] = encode_number, ["boolean"] = tostring, ["function"] = function() return "null" end, ["userdata"] = function() return "null" end }
encode = function(val, stack) local t = type(val) local f = type_func_map[t] if f then return f(val, stack) end error("unexpected type '" .. t .. "'") end
json.encode = encode

local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
local decode
local function decode_string(str, pos)
  local startpos = pos + 1
  local endpos = pos
  while true do
    endpos = str:find('["\\]', endpos + 1)
    if not endpos then return nil, "expected closing quote" end
    if str:sub(endpos, endpos) == '"' then break end
    endpos = endpos + 1
  end
  local s = str:sub(startpos, endpos - 1)
  s = s:gsub("\\.", function(c) return escape_char_map_inv[c:sub(2)] or c end)
  s = s:gsub("\\u(%x%x%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
  return s, endpos + 1
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
    local val val, pos = decode(str, pos)
    n = n + 1 arr[n] = val
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
    local key key, pos = decode_string(str, pos) if not key then return nil, "expected string key" end
    pos = decode_scanwhite(str, pos)
    if str:sub(pos, pos) ~= ":" then return nil, "expected ':'" end
    pos = decode_scanwhite(str, pos + 1)
    local val val, pos = decode(str, pos) obj[key] = val
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

local function cmd_get_process_info(params)
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

        -- Use real process name when available; otherwise use the export-directory name of the first module
        local name = (process ~= "" and process) or mainModuleName or moduleList[1].name

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

local function cmd_enum_modules(params)
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
    
    local fallback_used = #result > 0 and result[1] and result[1].source ~= nil
    local limit, offset, page, total = paginate(params, result, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, modules = page, fallback_used = fallback_used }

    -- If both enumModules and the AOB fallback failed to produce any modules, report failure honestly
    if #result == 0 and (pid or 0) > 0 then
        return {
            success = false,
            error = "Process attached but cannot enumerate modules (likely anti-cheat interference). Try enum_modules directly, or attach to a different process.",
            error_code = "CE_API_UNAVAILABLE",
            process_id = pid
        }
    end

    return { success = true, modules = result, count = #result, fallback_used = #result > 0 and result[1] and result[1].source ~= nil }
end

local function cmd_get_symbol_address(params)
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

local function cmd_read_memory(params)
    local addr = params.address
    local size = math.max(1, math.min(params.size or 256, 1048576))  -- 1 MB max
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local bytes = readBytes(addr, size, true)
    if not bytes then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    local hex = {}
    for i, b in ipairs(bytes) do hex[i] = string.format("%02X", b) end
    
    return { 
        success = true, 
        address = toHex(addr), 
        size = #bytes, 
        data = table.concat(hex, " "),
        bytes = bytes
    }
end

local function cmd_read_integer(params)
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

local function cmd_read_string(params)
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

local function cmd_read_pointer(params)
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

local function cmd_aob_scan(params)
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

local function cmd_scan_all(params)
    local value = params.value
    local vtype = params.type or "dword"
    
    local ms = createMemScan()
    local scanOpt = soExactValue
    local varType = vtDword
    
    if vtype == "byte" then varType = vtByte
    elseif vtype == "word" then varType = vtWord
    elseif vtype == "qword" then varType = vtQword
    elseif vtype == "float" then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString end
    
    -- Use specific protection flags if provided (defaults to +W-C from Python)
    -- CRITICAL: Limit scan to User Mode space (0x7FFFFFFFFFFFFFFF) to prevent BSODs in Kernel/Guard regions
    local protect = params.protection or "+W-C"
    ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil, 0, 0x7FFFFFFFFFFFFFFF, protect, fsmNotAligned, "1", false, false, false, false)
    ms.waitTillDone()
    
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

    return { success = true, count = count }
end

local function cmd_get_scan_results(params)
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

local function cmd_next_scan(params)
    local value = params.value
    local scanType = params.scan_type or "exact"
    
    if not serverState.scan_memscan then
        return { success = false, error = "No previous scan. Run scan_all first." }
    end
    
    local ms = serverState.scan_memscan
    local scanOpt = soExactValue
    
    if scanType == "increased" then scanOpt = soIncreasedValue
    elseif scanType == "decreased" then scanOpt = soDecreasedValue
    elseif scanType == "changed" then scanOpt = soChanged
    elseif scanType == "unchanged" then scanOpt = soUnchanged
    elseif scanType == "bigger" then scanOpt = soBiggerThan
    elseif scanType == "smaller" then scanOpt = soSmallerThan
    end
    
    if scanOpt == soExactValue then
        ms.nextScan(scanOpt, rtRounded, tostring(value), nil, false, false, false, false, false)
    else
        ms.nextScan(scanOpt, rtRounded, nil, nil, false, false, false, false, false)
    end
    ms.waitTillDone()
    
    if serverState.scan_foundlist then
        serverState.scan_foundlist.destroy()
    end
    local fl = createFoundList(ms)
    fl.initialize()
    serverState.scan_foundlist = fl
    
    return { success = true, count = fl.getCount() }
end

local function cmd_write_integer(params)
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

local function cmd_write_memory(params)
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

local function cmd_write_string(params)
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

local function cmd_disassemble(params)
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

local function cmd_get_instruction_info(params)
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

local function cmd_find_function_boundaries(params)
    local addr = params.address
    local maxSearch = params.max_search or 4096

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()

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
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

local function cmd_analyze_function(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()

    local funcStart, prologueType = findFunctionPrologue(addr, 4096)

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
    
    while currentAddr < funcStart + 0x2000 do
        local instSize = getInstructionSize(currentAddr)
        if not instSize or instSize == 0 then break end
        
        local b1 = readBytes(currentAddr, 1, false)
        if b1 == 0xC3 or b1 == 0xC2 then
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
    
    return {
        success = true,
        function_start = toHex(funcStart),
        function_end = funcEnd and toHex(funcEnd) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        call_count = #calls,
        calls = calls
    }
end

-- ============================================================================
-- COMMAND HANDLERS - REFERENCE FINDING
-- ============================================================================

local function cmd_find_references(params)
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

local function cmd_find_call_references(params)
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

local function cmd_set_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
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
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end

    -- Remove existing breakpoint at this address
    pcall(function() debug_removeBreakpoint(addr) end)

    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, 1, bptExecute, bpmDebugRegister, function()
        local hitData = {
            id = bpId,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_execute"
        }
        
        if captureRegs then
            hitData.registers = captureRegisters()
        end
        
        if captureStackFlag then
            hitData.stack = captureStack(stackDepth)
        end
        
        table.insert(serverState.breakpoint_hits[bpId], hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "execute" }
    return { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register" }
end

local function cmd_set_data_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local accessType = params.access_type or "w"  -- r, w, rw
    local size = params.size or 4
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
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
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end

    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end
    
    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, size, bpType, bpmDebugRegister, function()
        local arch = getArchInfo()
        local instPtr = arch.instPtr
        local hitData = {
            id = bpId,
            type = "data_" .. accessType,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_data",
            value = arch.is64bit and readQword(addr) or readInteger(addr),
            registers = captureRegisters(),
            instruction = instPtr and disassemble(instPtr) or "???",
            arch = arch.is64bit and "x64" or "x86"
        }
        
        table.insert(serverState.breakpoint_hits[bpId], hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "data" }
    
    return { success = true, id = bpId, address = toHex(addr), slot = slot, access_type = accessType, method = "hardware_debug_register" }
end

local function cmd_remove_breakpoint(params)
    local bpId = params.id
    
    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        pcall(function() debug_removeBreakpoint(bp.address) end)
        
        if bp.slot then
            serverState.hw_bp_slots[bp.slot] = nil
        end
        
        serverState.breakpoints[bpId] = nil
        return { success = true, id = bpId }
    end
    
    return { success = false, error = "Breakpoint not found: " .. tostring(bpId) }
end

local function cmd_get_breakpoint_hits(params)
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
        if clear then serverState.breakpoint_hits = {} end
    end

    local limit, offset, page, total = paginate(params, hits, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, hits = page }
end

local function cmd_list_breakpoints(params)
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        table.insert(list, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot
        })
    end
    return { success = true, count = #list, breakpoints = list }
end

local function cmd_clear_all_breakpoints(params)
    local count = 0
    for id, bp in pairs(serverState.breakpoints) do
        pcall(function() debug_removeBreakpoint(bp.address) end)
        count = count + 1
    end
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

local function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end
    
    local fn, err = load(code, "mcp_evaluate_lua", "t")
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end
    
    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end
    
    return { success = true, result = tostring(result) }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

local function cmd_get_memory_regions(params)
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

local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

local function cmd_search_string(params)
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
local function cmd_dissect_structure(params)
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
local function cmd_get_thread_list(params)
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
local function cmd_auto_assemble(params)
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
local function cmd_enum_memory_regions_full(params)
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
local function cmd_read_pointer_chain(params)
    local base = params.base
    local offsets = params.offsets or {}
    
    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local chain = { { step = 0, address = toHex(currentAddr), description = "base" } }
    
    for i, offset in ipairs(offsets) do
        -- Read pointer at current address
        local ptr = readPointer(currentAddr)
        if not ptr then
            return {
                success = false,
                error = "Failed to read pointer at step " .. i,
                partial_chain = chain,
                failed_at_address = toHex(currentAddr)
            }
        end
        
        -- Apply offset
        currentAddr = ptr + offset
        table.insert(chain, {
            step = i,
            address = toHex(currentAddr),
            offset = offset,
            hex_offset = string.format("+0x%X", offset),
            pointer_value = toHex(ptr)
        })
    end
    
    -- Try to read a value at the final address (using readPointer for 32/64-bit compatibility)
    local finalValue = nil
    pcall(function()
        finalValue = readPointer(currentAddr)
    end)
    
    return {
        success = true,
        base = toHex(base),
        offsets = offsets,
        final_address = toHex(currentAddr),
        final_value = finalValue,
        chain = chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
local function cmd_get_rtti_classname(params)
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
local function cmd_get_address_info(params)
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
local function cmd_checksum_memory(params)
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
local function cmd_generate_signature(params)
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
local function cmd_get_physical_address(params)
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
local function cmd_start_dbvm_watch(params)
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
local function cmd_poll_dbvm_watch(params)
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
local function cmd_stop_dbvm_watch(params)
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

local function cmd_allocate_memory(params)
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

local function cmd_free_memory(params)
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

local function cmd_allocate_shared_memory(params)
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

local function cmd_get_memory_protection(params)
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

local function cmd_set_memory_protection(params)
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

local function cmd_full_access(params)
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

local function cmd_allocate_kernel_memory(params)
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

local function cmd_open_process(params)
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

local function cmd_get_process_list(params)
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

local function cmd_get_processid_from_name(params)
    local name = params.name
    if not name then return { success = false, error = "Missing name" } end

    local ok, pid = pcall(getProcessIDFromProcessName, name)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "Process not found", error_code = "NOT_FOUND" }
    end

    return { success = true, process_id = pid }
end

local function cmd_get_foreground_process(params)
    local ok, pid = pcall(getForegroundProcess)
    if not ok then return { success = false, error = tostring(pid) } end

    local hwnd = 0
    local ok2, wh = pcall(getForegroundWindow)
    if ok2 and wh then hwnd = wh end

    return { success = true, process_id = pid or 0, window_handle = toHex(hwnd) }
end

local function cmd_create_process(params)
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

local function cmd_get_opened_process_id(params)
    local ok, pid = pcall(getOpenedProcessID)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return { success = true, process_id = pid }
end

local function cmd_get_opened_process_handle(params)
    local ok, handle = pcall(getOpenedProcessHandle)
    if not ok then return { success = false, error = tostring(handle) } end
    return { success = true, handle = toHex(handle or 0) }
end

-- >>> END UNIT-07 <<<

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

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
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
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

    -- >>> BEGIN UNIT-08 dispatcher entries <<<
    allocate_memory        = cmd_allocate_memory,
    free_memory            = cmd_free_memory,
    allocate_shared_memory = cmd_allocate_shared_memory,
    get_memory_protection  = cmd_get_memory_protection,
    set_memory_protection  = cmd_set_memory_protection,
    full_access            = cmd_full_access,
    allocate_kernel_memory = cmd_allocate_kernel_memory,
    -- >>> END UNIT-08 <<<
}

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================

local function executeCommand(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or not request then
        return json.encode({ jsonrpc = "2.0", error = { code = -32700, message = "Parse error" }, id = nil })
    end
    
    local method = request.method
    local params = request.params or {}
    local id = request.id
    
    local handler = commandHandlers[method]
    if not handler then
        return json.encode({ jsonrpc = "2.0", error = { code = -32601, message = "Method not found: " .. tostring(method) }, id = id })
    end
    
    local ok2, result = pcall(handler, params)
    if not ok2 then
        return json.encode({ jsonrpc = "2.0", error = { code = -32603, message = "Internal error: " .. tostring(result) }, id = id })
    end
    
    return json.encode({ jsonrpc = "2.0", result = result, id = id })
end

-- ============================================================================
-- THREAD-BASED PIPE SERVER (NON-BLOCKING GUI)
-- ============================================================================
-- Replaces v10 Timer architecture to prevent GUI Freezes.
-- I/O happens in Worker Thread. Execution happens in Main Thread.

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
        
        -- timeout for blocking operations (connect/read)
        -- We DO NOT set pipe.Timeout because it auto-disconnects on timeout.
        -- We rely on blocking reads and pipe.destroy() from stopServer to break the block.
        -- pipe.Timeout = 0 (Default, Infinite)
        
        -- Wait for client (Blocking, but in thread so GUI is fine)
        -- LuaPipeServer uses acceptConnection().
        -- note: acceptConnection might not return a boolean, so we check pipe.Connected afterwards.
        
        -- log("Thread: Calling acceptConnection()...")
        pcall(function()
            pipe.acceptConnection()
        end)
        
        if pipe.Connected and not thread.Terminated then
            log("Client Connected")
            serverState.connected = true
            
            while not thread.Terminated and pipe.Connected do
                -- Try to read header (4 bytes)
                -- We use pcall to handle timeouts/errors gracefully
                local ok, lenBytes = pcall(function() return pipe.readBytes(4) end)
                
                if ok and lenBytes and #lenBytes == 4 then
                    local len = lenBytes[1] + (lenBytes[2] * 256) + (lenBytes[3] * 65536) + (lenBytes[4] * 16777216)
                    
                    -- Sanity check length
                    if len > 0 and len < 32 * 1024 * 1024 then
                        local payload = pipe.readString(len)
                        
                        if payload then
                            -- CRITICAL: EXECUTE ON MAIN THREAD
                            -- We pause the worker and run logic on GUI thread to be safe
                            local response = nil
                            thread.synchronize(function()
                                response = executeCommand(payload)
                            end)
                            
                            -- Write response back (Worker Thread)
                            if response then
                                local rLen = #response
                                local b1 = rLen % 256
                                local b2 = math.floor(rLen / 256) % 256
                                local b3 = math.floor(rLen / 65536) % 256
                                local b4 = math.floor(rLen / 16777216) % 256
                                
                                pipe.writeBytes({b1, b2, b3, b4})
                                pipe.writeString(response)
                            end
                        else
                             -- log("Thread: Read payload failed (nil)")
                        end
                    end
                else
                    -- Read failed. If pipe disconnected, the loop will terminate on next check.
                    if not pipe.Connected then
                        -- Client disconnected gracefully
                    end
                end
            end
            
            serverState.connected = false
            log("Client Disconnected")
        else
            -- Debug: acceptConnection returned but pipe not valid
            -- This usually happens on termination or weird state
            if not thread.Terminated then
                -- log("Thread: Helper log - connection attempt invalid")
            end
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
