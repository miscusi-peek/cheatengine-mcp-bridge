-- >>> BEGIN UNIT-20a File IO Clipboard <<<
do
-- ============================================================================
-- UNIT-20a: Safe File I/O and Clipboard Tools
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f == "" then return nil, "Invalid filename" end
    if f:find("%.%.") then return nil, "Path traversal not allowed" end
    return f, nil
end

local function cmd_file_exists(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(fileExists, f)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, exists = result == true }
end

local function cmd_delete_file(params)
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

local function cmd_get_file_list(params)
    return listPathEntries(params.path, getFileList, "files")
end

local function cmd_get_directory_list(params)
    return listPathEntries(params.path, getDirectoryList, "directories")
end

local function cmd_get_temp_folder(params)
    local ok, result = pcall(getTempFolder)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, path = tostring(result) }
end

local function cmd_get_file_version(params)
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

local function cmd_read_clipboard(params)
    local ok, result = pcall(readFromClipboard)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, text = tostring(result or "") }
end

local function cmd_write_clipboard(params)
    local text = params.text
    if type(text) ~= "string" then return { success = false, error = "text must be a string" } end
    local ok, err = pcall(writeToClipboard, text)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

    -- Register Unit-20a handlers in the dispatcher
    commandHandlers.delete_file = cmd_delete_file
    commandHandlers.file_exists = cmd_file_exists
    commandHandlers.get_directory_list = cmd_get_directory_list
    commandHandlers.get_file_list = cmd_get_file_list
    commandHandlers.get_file_version = cmd_get_file_version
    commandHandlers.get_temp_folder = cmd_get_temp_folder
    commandHandlers.read_clipboard = cmd_read_clipboard
    commandHandlers.write_clipboard = cmd_write_clipboard
end
-- >>> END UNIT-20a <<<
