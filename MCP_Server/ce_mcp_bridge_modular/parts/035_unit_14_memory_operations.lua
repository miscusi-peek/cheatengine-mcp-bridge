-- >>> BEGIN UNIT-14 Memory Operations <<<
do
-- ============================================================================
-- COMMAND HANDLERS - MEMORY OPERATIONS (Unit 14)
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f:find("%.%.") then return nil, "Invalid filename" end
    return f, nil
end

local function cmd_copy_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

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

local function cmd_compare_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

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

local function cmd_write_region_to_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

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

local function cmd_read_region_from_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

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

local function cmd_md5_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

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

    -- Return key matches cmd_checksum_memory for consistency across the v12 surface.
    return { success = true, md5_hash = tostring(result) }
end

local function cmd_md5_file(params)
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    local ok, result = pcall(md5file, sanitized)
    if not ok or not result then
        return { success = false, error = "md5file failed: " .. tostring(result) }
    end

    return { success = true, md5_hash = tostring(result) }
end

local function cmd_create_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local size = params.size
    if not size or size <= 0 then
        return { success = false, error = "Missing or invalid size", error_code = "INVALID_PARAMS" }
    end

    local ok, handle = pcall(createSection, size)
    if not ok or not handle then
        return {
            success = false,
            error = "createSection failed: " .. tostring(handle),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    -- Track handle so cleanupZombieState can release it on script reload.
    serverState.sections = serverState.sections or {}
    serverState.sections[toHex(handle)] = handle

    return { success = true, handle = toHex(handle) }
end

local function cmd_map_view_of_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached", error_code = "NO_PROCESS" } end

    local handle = params.handle
    local address = params.address  -- optional preferred base

    if not handle then
        return { success = false, error = "Missing handle", error_code = "INVALID_PARAMS" }
    end

    -- Lua 5.3's tonumber(str, 16) rejects a "0x" prefix because 'x' isn't
    -- a hex digit. Strip the prefix before converting. (Unit-16 has its
    -- own parseHandle helper but it lives inside a different do-block and
    -- isn't in scope here.)
    if type(handle) == "string" then
        local clean = handle:gsub("^0[xX]", "")
        handle = tonumber(clean, 16)
    end
    if not handle then
        return { success = false, error = "Invalid handle", error_code = "INVALID_PARAMS" }
    end

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

    -- Register Unit-14 handlers in the dispatcher
    commandHandlers.compare_memory = cmd_compare_memory
    commandHandlers.copy_memory = cmd_copy_memory
    commandHandlers.create_section = cmd_create_section
    commandHandlers.map_view_of_section = cmd_map_view_of_section
    commandHandlers.md5_file = cmd_md5_file
    commandHandlers.md5_memory = cmd_md5_memory
    commandHandlers.read_region_from_file = cmd_read_region_from_file
    commandHandlers.write_region_to_file = cmd_write_region_to_file
end
-- >>> END UNIT-14 <<<
