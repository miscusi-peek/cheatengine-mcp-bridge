-- >>> BEGIN UNIT-06a Breakpoints <<<
do
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
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local bpId = params.id
    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

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
        return {
            success = false,
            error = "No free hardware breakpoint slots (max 4 debug registers)",
            error_code = "OUT_OF_RESOURCES",
        }
    end

    -- Remove existing breakpoint at this address
    pcall(function() debug_removeBreakpoint(addr) end)

    serverState.breakpoint_hits[bpId] = {}

    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    local ok, err = pcall(debug_setBreakpoint, addr, 1, bptExecute, bpmDebugRegister, function()
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

    if not ok then
        serverState.breakpoint_hits[bpId] = nil
        return {
            success = false,
            error = "debug_setBreakpoint failed: " .. tostring(err),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "execute" }
    return { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register" }
end

local function cmd_set_data_breakpoint(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local bpId = params.id
    local accessType = params.access_type or "w"  -- r, w, rw
    local size = params.size or 4

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

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
        return {
            success = false,
            error = "No free hardware breakpoint slots (max 4 debug registers)",
            error_code = "OUT_OF_RESOURCES",
        }
    end

    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end

    serverState.breakpoint_hits[bpId] = {}

    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    local ok, err = pcall(debug_setBreakpoint, addr, size, bpType, bpmDebugRegister, function()
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

    if not ok then
        serverState.breakpoint_hits[bpId] = nil
        return {
            success = false,
            error = "debug_setBreakpoint failed: " .. tostring(err),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

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
    
    return {
        success = false,
        error = "Breakpoint not found: " .. tostring(bpId),
        error_code = "NOT_FOUND",
    }
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

    commandHandlers.set_breakpoint           = cmd_set_breakpoint
    commandHandlers.set_execution_breakpoint = cmd_set_breakpoint  -- Alias
    commandHandlers.set_data_breakpoint      = cmd_set_data_breakpoint
    commandHandlers.set_write_breakpoint     = cmd_set_data_breakpoint  -- Alias
    commandHandlers.remove_breakpoint        = cmd_remove_breakpoint
    commandHandlers.get_breakpoint_hits      = cmd_get_breakpoint_hits
    commandHandlers.list_breakpoints         = cmd_list_breakpoints
    commandHandlers.clear_all_breakpoints    = cmd_clear_all_breakpoints
end
-- >>> END UNIT-06a Breakpoints <<<
