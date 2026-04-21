-- >>> BEGIN UNIT-07 Process Lifecycle <<<
do

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

    -- Register Unit-07 handlers in the dispatcher
    commandHandlers.create_process = cmd_create_process
    commandHandlers.get_foreground_process = cmd_get_foreground_process
    commandHandlers.get_opened_process_handle = cmd_get_opened_process_handle
    commandHandlers.get_opened_process_id = cmd_get_opened_process_id
    commandHandlers.get_process_list = cmd_get_process_list
    commandHandlers.get_processid_from_name = cmd_get_processid_from_name
    commandHandlers.open_process = cmd_open_process
end
-- >>> END UNIT-07 <<<
