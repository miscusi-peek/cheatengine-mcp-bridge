-- >>> BEGIN UNIT-09 Code Injection <<<
do
-- ============================================================================
-- COMMAND HANDLERS - CODE INJECTION & EXECUTION
-- ============================================================================

-- Lua 5.1 compat: 'unpack' moved to 'table.unpack' in Lua 5.2+
local unpack = unpack or table.unpack

local function requireProcess()
    local pid = getOpenedProcessID()
    return pid and pid > 0
end

local function cmd_inject_dll(params)
    if not requireProcess() then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end
    local filepath = params.filepath
    if not filepath then return { success = false, error = "No filepath provided" } end
    local skip = params.skip_symbol_reload or false

    local ok, result = pcall(injectDLL, filepath, skip)
    if not ok then
        return { success = false, error = "injectDLL failed: " .. tostring(result) }
    end
    return { success = result == true }
end

local function cmd_inject_dotnet_dll(params)
    if not requireProcess() then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end
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

local function cmd_execute_code(params)
    if not requireProcess() then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end
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

local function cmd_execute_code_ex(params)
    if not requireProcess() then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end
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

local function cmd_execute_method(params)
    if not requireProcess() then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end
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
local function cmd_execute_code_local(params)
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
local function cmd_execute_code_local_ex(params)
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

    -- Register Unit-09 handlers in the dispatcher
    commandHandlers.execute_code = cmd_execute_code
    commandHandlers.execute_code_ex = cmd_execute_code_ex
    commandHandlers.execute_code_local = cmd_execute_code_local
    commandHandlers.execute_code_local_ex = cmd_execute_code_local_ex
    commandHandlers.execute_method = cmd_execute_method
    commandHandlers.inject_dll = cmd_inject_dll
    commandHandlers.inject_dotnet_dll = cmd_inject_dotnet_dll
end
-- >>> END UNIT-09 <<<
