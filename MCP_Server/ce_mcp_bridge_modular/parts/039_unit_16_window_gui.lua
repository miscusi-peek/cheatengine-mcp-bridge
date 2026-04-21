-- >>> BEGIN UNIT-16 Window GUI <<<
do
-- ============================================================================
-- WINDOW / GUI COMMAND HANDLERS
-- No process guard required: these APIs are system-wide window operations.
-- ============================================================================

-- Shared helper: parse a hex window-handle string into a number.
-- Returns the number, or nil if the string is missing/invalid.
local function parseHandle(hexStr)
    if type(hexStr) == "number" then return hexStr end
    if type(hexStr) ~= "string" then return nil end
    -- Accept both "0x1234" and bare "1234" — Lua's tonumber with an explicit
    -- base=16 rejects a "0x" prefix (it sees 'x' as a non-hex digit), so we
    -- strip it first. Callers feed us the output of toHex() which has 0x.
    local clean = hexStr:gsub("^0[xX]", "")
    return tonumber(clean, 16)
end

local function cmd_find_window(params)
    local title      = params.title
    local class_name = params.class_name

    if not title and not class_name then
        return {
            success = false,
            error = "At least one of title or class_name must be provided",
            error_code = "INVALID_PARAMS",
        }
    end

    local ok, handle = pcall(function()
        return findWindow(class_name, title)
    end)

    if not ok then
        return { success = false, error = tostring(handle), error_code = "CE_API_UNAVAILABLE" }
    end

    if not handle or handle == 0 then
        return { success = false, error = "Window not found", error_code = "NOT_FOUND" }
    end

    return { success = true, handle = toHex(handle) }
end

local function cmd_get_window_caption(params)
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

local function cmd_get_window_class_name(params)
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

local function cmd_get_window_process_id(params)
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

local function cmd_send_window_message(params)
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
local function cmd_show_message(params)
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
local function cmd_input_query(params)
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
local function cmd_show_selection_list(params)
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

    -- Register Unit-16 handlers in the dispatcher
    commandHandlers.find_window = cmd_find_window
    commandHandlers.get_window_caption = cmd_get_window_caption
    commandHandlers.get_window_class_name = cmd_get_window_class_name
    commandHandlers.get_window_process_id = cmd_get_window_process_id
    commandHandlers.input_query = cmd_input_query
    commandHandlers.send_window_message = cmd_send_window_message
    commandHandlers.show_message = cmd_show_message
    commandHandlers.show_selection_list = cmd_show_selection_list
end
-- >>> END UNIT-16 <<<
