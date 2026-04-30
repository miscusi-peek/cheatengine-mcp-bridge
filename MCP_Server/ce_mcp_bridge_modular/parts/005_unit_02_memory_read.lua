-- >>> BEGIN UNIT-02 Memory Read <<<
do
local function cmd_read_memory(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local size = math.max(1, math.min(params.size or 256, 1048576))  -- 1 MB max

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local bytes = readBytes(addr, size, true)
    if not bytes then
        return { success = false, error = "Failed to read at " .. toHex(addr), error_code = "NOT_FOUND" }
    end
    
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
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local itype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" } end

    local val
    if itype == "byte" then
        local b = readBytes(addr, 1, true)
        if b and #b > 0 then val = b[1] end
    elseif itype == "word" then val = readSmallInteger(addr)
    elseif itype == "dword" then val = readInteger(addr)
    elseif itype == "qword" then val = readQword(addr)
    elseif itype == "float" then val = readFloat(addr)
    elseif itype == "double" then val = readDouble(addr)
    else return { success = false, error = "Unknown type: " .. tostring(itype), error_code = "INVALID_PARAMS" } end

    if val == nil then return { success = false, error = "Failed to read at " .. toHex(addr), error_code = "NOT_FOUND" } end

    return { success = true, address = toHex(addr), value = val, type = itype, hex = toHex(val) }
end

local function cmd_read_string(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local maxlen = params.max_length or 256
    local wide = params.wide or false
    -- encoding: "ascii" | "utf8" | "utf16le" | "raw" (default "utf8")
    -- Backward compat: wide=true maps to utf16le unless encoding is explicitly set
    local encoding = params.encoding or (wide and "utf16le" or "utf8")

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

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
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local base = params.base or params.address
    local offsets = params.offsets or {}

    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then
        return { success = false, error = "Invalid base address", error_code = "INVALID_ADDRESS" }
    end

    local currentAddr = base
    local path = { toHex(base) }

    for i, offset in ipairs(offsets) do
        -- Use readPointer for 32/64-bit compatibility (readInteger on 32-bit, readQword on 64-bit)
        local ok, ptr = pcall(readPointer, currentAddr)
        if not ok or not ptr then
            return {
                success = false,
                error = "Failed to read pointer at " .. toHex(currentAddr),
                error_code = "NOT_FOUND",
                path = path,
            }
        end
        currentAddr = ptr + offset
        table.insert(path, toHex(currentAddr))
    end

    -- Read final value using readPointer for 32/64-bit compatibility.
    -- Value is an address-shaped integer, so emit it as a hex string to match
    -- the v12 address-encoding convention.
    local ok, finalValue = pcall(readPointer, currentAddr)
    return {
        success = true,
        base = toHex(base),
        final_address = toHex(currentAddr),
        value = (ok and finalValue) and toHex(finalValue) or nil,
        path = path
    }
end

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

    commandHandlers.read_memory  = cmd_read_memory
    commandHandlers.read_bytes   = cmd_read_memory  -- Alias
    commandHandlers.read_integer = cmd_read_integer
    commandHandlers.read_string  = cmd_read_string
    commandHandlers.read_pointer = cmd_read_pointer
end
-- >>> END UNIT-02 Memory Read <<<
