-- >>> BEGIN UNIT-22 Threading Sync <<<
do
-- ============================================================================
-- COMMAND HANDLERS - THREADING & SYNCHRONIZATION
-- These operate on CE's Lua scripting host, NOT the target process.
-- No process guard is needed or appropriate here.
-- ============================================================================

local _unit22_thread_counter = 0

local function cmd_create_thread(params)
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

local function cmd_get_global_variable(params)
    local name = params.name
    if not name then return { success = false, error = "No variable name provided" } end

    local ok, value = pcall(getGlobalVariable, name)
    if not ok then
        return { success = false, error = "getGlobalVariable failed: " .. tostring(value) }
    end
    return { success = true, value = tostring(value) }
end

local function cmd_set_global_variable(params)
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

local function cmd_queue_to_main_thread(params)
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

local function cmd_check_synchronize(params)
    local ok, err = pcall(checkSynchronize)
    if not ok then
        return { success = false, error = "checkSynchronize failed: " .. tostring(err) }
    end
    return { success = true }
end

local function cmd_in_main_thread(params)
    local ok, result = pcall(inMainThread)
    if not ok then
        return { success = false, error = "inMainThread failed: " .. tostring(result) }
    end
    return { success = true, is_main_thread = result == true }
end

    -- Register Unit-22 handlers in the dispatcher
    commandHandlers.check_synchronize = cmd_check_synchronize
    commandHandlers.create_thread = cmd_create_thread
    commandHandlers.get_global_variable = cmd_get_global_variable
    commandHandlers.in_main_thread = cmd_in_main_thread
    commandHandlers.queue_to_main_thread = cmd_queue_to_main_thread
    commandHandlers.set_global_variable = cmd_set_global_variable
end
-- >>> END UNIT-22 <<<
