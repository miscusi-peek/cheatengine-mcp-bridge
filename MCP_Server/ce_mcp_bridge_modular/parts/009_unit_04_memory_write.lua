-- >>> BEGIN UNIT-04 Memory Write <<<
do
local function cmd_write_integer(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    if vtype == "byte" then
        if type(value) ~= "number" or value < 0 or value > 0xFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "word" or vtype == "2bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "dword" or vtype == "4bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFFFFFF then
            return { success = false, error = "Value too large for type", error_code = "INVALID_PARAMS" }
        end
    end

    local ok, err
    if vtype == "byte" then
        ok, err = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, err = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, err = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, err = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, err = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, err = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype), error_code = "INVALID_PARAMS" }
    end

    if not ok then
        return {
            success = false,
            error = "Write failed: " .. tostring(err),
            error_code = "PERMISSION_DENIED",
            address = toHex(addr),
        }
    end

    return { success = true, address = toHex(addr), value = value, type = vtype }
end

local function cmd_write_memory(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local bytes = params.bytes

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end
    if not bytes or #bytes == 0 then
        return { success = false, error = "No bytes provided", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(writeBytes, addr, bytes)

    if not ok then
        return {
            success = false,
            error = "Write failed: " .. tostring(err),
            error_code = "PERMISSION_DENIED",
            address = toHex(addr),
        }
    end

    return { success = true, address = toHex(addr), bytes_written = #bytes }
end

local function cmd_write_string(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end
    if not str then
        return { success = false, error = "No string provided", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(writeString, addr, str, wide)

    if not ok then
        return {
            success = false,
            error = "Write failed: " .. tostring(err),
            error_code = "PERMISSION_DENIED",
            address = toHex(addr),
        }
    end

    return { success = true, address = toHex(addr), length = #str, wide = wide }
end


-- ============================================================================
-- COMMAND HANDLERS - DISASSEMBLY & ANALYSIS
-- ============================================================================

    commandHandlers.write_integer = cmd_write_integer
    commandHandlers.write_memory  = cmd_write_memory
    commandHandlers.write_string  = cmd_write_string
end
-- >>> END UNIT-04 Memory Write <<<
