-- >>> BEGIN UNIT-10 Debugger Control <<<
do
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

local function cmd_debug_process(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
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

local function cmd_debug_is_debugging(params)
    local ok, result = pcall(debug_isDebugging)
    if not ok then
        return { success = false, error = tostring(result) }
    end
    return { success = true, is_debugging = result == true }
end

local function cmd_debug_get_current_debugger_interface(params)
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
        return {
            success = false,
            error = "Debugger is not attached. Call debug_process() first.",
            error_code = "CE_API_UNAVAILABLE",
        }
    end
end

-- Calls fn() with no args, guarded by a NO_PROCESS check. Returns {success}.
local function callWithProcessGuard(fn)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local ok, err = pcall(fn)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_debug_break_thread(params)
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

local function cmd_debug_continue(params)
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
    return { success = true }
end

local function cmd_debug_detach(params)
    local ok, result = pcall(detachIfPossible)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, detached = result == true }
end

local function cmd_pause_process(params)   return callWithProcessGuard(pause)   end
local function cmd_unpause_process(params) return callWithProcessGuard(unpause) end

    -- Register Unit-10 handlers in the dispatcher
    commandHandlers.debug_break_thread = cmd_debug_break_thread
    commandHandlers.debug_continue = cmd_debug_continue
    commandHandlers.debug_detach = cmd_debug_detach
    commandHandlers.debug_get_current_debugger_interface = cmd_debug_get_current_debugger_interface
    commandHandlers.debug_is_debugging = cmd_debug_is_debugging
    commandHandlers.debug_process = cmd_debug_process
    commandHandlers.pause_process = cmd_pause_process
    commandHandlers.unpause_process = cmd_unpause_process
end
-- >>> END UNIT-10 <<<
