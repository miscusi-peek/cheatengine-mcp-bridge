-- >>> BEGIN UNIT-03 Pattern Scanning <<<
do
local function cmd_aob_scan(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local pattern = params.pattern
    local protection = params.protection or "+X"
    local limit = params.limit or 100

    if not pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end

    local ok, results = pcall(AOBScan, pattern, protection)
    if not ok then
        return {
            success = false,
            error = "AOBScan failed: " .. tostring(results),
            error_code = "CE_API_UNAVAILABLE",
        }
    end
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
    pcall(function() results.destroy() end)

    return { success = true, count = #addresses, pattern = pattern, addresses = addresses }
end

local function cmd_scan_all(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local value = params.value
    local vtype = params.type or "dword"

    if value == nil or (type(value) ~= "string" and type(value) ~= "number") then
        return {
            success = false,
            error = "Missing or invalid 'value' parameter",
            error_code = "INVALID_PARAMS",
        }
    end

    local ms_ok, ms = pcall(createMemScan)
    if not ms_ok or not ms then
        return {
            success = false,
            error = "createMemScan failed: " .. tostring(ms),
            error_code = "CE_API_UNAVAILABLE",
        }
    end
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
    local fs_ok, fs_err = pcall(function()
        ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil, 0, 0x7FFFFFFFFFFFFFFF, protect, fsmNotAligned, "1", false, false, false, false)
        ms.waitTillDone()
    end)
    if not fs_ok then
        pcall(function() ms.destroy() end)
        return {
            success = false,
            error = "firstScan failed: " .. tostring(fs_err),
            error_code = "INTERNAL_ERROR",
        }
    end

    local fl_ok, fl = pcall(createFoundList, ms)
    if not fl_ok or not fl then
        pcall(function() ms.destroy() end)
        return {
            success = false,
            error = "createFoundList failed: " .. tostring(fl),
            error_code = "CE_API_UNAVAILABLE",
        }
    end
    pcall(function() fl.initialize() end)
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
        return {
            success = false,
            error = "No scan results. Run scan_all first.",
            error_code = "NOT_FOUND",
        }
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
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local value = params.value
    local scanType = params.scan_type or "exact"

    if not serverState.scan_memscan then
        return {
            success = false,
            error = "No previous scan. Run scan_all first.",
            error_code = "NOT_FOUND",
        }
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

    local ns_ok, ns_err = pcall(function()
        if scanOpt == soExactValue then
            ms.nextScan(scanOpt, rtRounded, tostring(value), nil, false, false, false, false, false)
        else
            ms.nextScan(scanOpt, rtRounded, nil, nil, false, false, false, false, false)
        end
        ms.waitTillDone()
    end)
    if not ns_ok then
        return {
            success = false,
            error = "nextScan failed: " .. tostring(ns_err),
            error_code = "INTERNAL_ERROR",
        }
    end

    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
    end
    local fl_ok, fl = pcall(createFoundList, ms)
    if not fl_ok or not fl then
        return {
            success = false,
            error = "createFoundList failed: " .. tostring(fl),
            error_code = "CE_API_UNAVAILABLE",
        }
    end
    pcall(function() fl.initialize() end)
    serverState.scan_foundlist = fl

    return { success = true, count = fl.getCount() }
end

    commandHandlers.aob_scan         = cmd_aob_scan
    commandHandlers.pattern_scan      = cmd_aob_scan  -- Alias
    commandHandlers.scan_all          = cmd_scan_all
    commandHandlers.next_scan         = cmd_next_scan
    commandHandlers.get_scan_results  = cmd_get_scan_results
end
-- >>> END UNIT-03 Pattern Scanning <<<
