-- >>> BEGIN UNIT-06b Analysis & Utility <<<
do
local function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end
    
    local fn, err = load(code, "mcp_evaluate_lua", "t")
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end
    
    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end
    
    return { success = true, result = tostring(result) }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

local function cmd_get_memory_regions(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local regions = {}
    local maxRegions = params.max or 100
    local pageSize = 0x1000  -- 4KB pages
    
    -- Sample memory at common base addresses to find valid regions
    local sampleAddresses = {
        0x00010000, 0x00400000, 0x10000000, 0x20000000, 0x30000000,
        0x40000000, 0x50000000, 0x60000000, 0x70000000
    }
    
    -- Also add addresses from modules we found via AOB scan
    local mzScan = AOBScan("4D 5A 90 00 03 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, 20) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then table.insert(sampleAddresses, addr) end
        end
        mzScan.destroy()
    end
    
    -- Check each sample address for memory protection
    for _, baseAddr in ipairs(sampleAddresses) do
        if #regions >= maxRegions then break end
        
        local ok, prot = pcall(getMemoryProtection, baseAddr)
        if ok and prot then
            -- Found a valid memory page
            local protStr = ""
            if prot.r then protStr = protStr .. "R" end
            if prot.w then protStr = protStr .. "W" end
            if prot.x then protStr = protStr .. "X" end
            
            -- Try to find region size by scanning forward
            local regionSize = pageSize
            for offset = pageSize, 0x1000000, pageSize do
                local ok2, prot2 = pcall(getMemoryProtection, baseAddr + offset)
                if not ok2 or not prot2 or 
                   prot2.r ~= prot.r or prot2.w ~= prot.w or prot2.x ~= prot.x then
                    break
                end
                regionSize = offset + pageSize
            end
            
            table.insert(regions, {
                base = toHex(baseAddr),
                size = regionSize,
                protection = protStr,
                readable = prot.r or false,
                writable = prot.w or false,
                executable = prot.x or false
            })
        end
    end
    
    return { success = true, count = #regions, regions = regions }
end

-- ============================================================================
-- COMMAND HANDLERS - UTILITY
-- ============================================================================

local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

local function cmd_search_string(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local searchStr = params.string or params.pattern
    local wide = params.wide or false
    local limit = params.limit or 100

    if not searchStr then
        return { success = false, error = "No search string", error_code = "INVALID_PARAMS" }
    end

    -- Convert string to AOB pattern
    local pattern = ""
    for i = 1, #searchStr do
        if i > 1 then pattern = pattern .. " " end
        pattern = pattern .. string.format("%02X", searchStr:byte(i))
        if wide then pattern = pattern .. " 00" end
    end

    local ok, results = pcall(AOBScan, pattern)
    if not ok then
        return {
            success = false,
            error = "AOBScan failed: " .. tostring(results),
            error_code = "CE_API_UNAVAILABLE",
        }
    end
    if not results then return { success = true, count = 0, addresses = {} } end

    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addr = tonumber(results.getString(i), 16)
        local preview = readString(addr, 50, wide) or ""
        table.insert(addresses, {
            address = "0x" .. results.getString(i),
            preview = preview
        })
    end
    pcall(function() results.destroy() end)

    return { success = true, count = #addresses, addresses = addresses }
end

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
local function cmd_dissect_structure(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local address = params.address
    local size = params.size or 256

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure: " .. tostring(struct), error_code = "CE_API_UNAVAILABLE" }
    end

    -- Use the Structure class autoGuess method
    pcall(function() struct:autoGuess(address, 0, size) end)

    local elements = {}
    local count = struct.Count or 0

    for i = 0, count - 1 do
        local elem = struct.Element[i]
        if elem then
            local val = nil
            -- Try to get current value
            pcall(function() val = elem:getValue(address) end)

            table.insert(elements, {
                offset = elem.Offset,
                hex_offset = string.format("+0x%X", elem.Offset),
                name = elem.Name or "",
                vartype = elem.Vartype,
                bytesize = elem.Bytesize,
                current_value = val
            })
        end
    end

    -- Release: hide from GUI and destroy to reclaim the CE structure object.
    -- Skipping :destroy() leaks a CE structure on every invocation.
    pcall(function() struct:removeFromGlobalStructureList() end)
    pcall(function() struct:destroy() end)

    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
local function cmd_get_thread_list(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local list_ok, list = pcall(createStringlist)
    if not list_ok or not list then
        return {
            success = false,
            error = "createStringlist failed: " .. tostring(list),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    local ok, err = pcall(getThreadlist, list)
    if not ok then
        pcall(function() list.destroy() end)
        return {
            success = false,
            error = "getThreadlist failed: " .. tostring(err),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    local allThreads = {}
    for i = 0, (list.Count or 0) - 1 do
        local idHex = list[i]
        allThreads[#allThreads + 1] = { id_hex = idHex, id_int = tonumber(idHex, 16) }
    end
    pcall(function() list.destroy() end)

    local limit, offset, page, total = paginate(params, allThreads, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, threads = page }
end

-- AutoAssemble: Execute an AutoAssembler script
local function cmd_auto_assemble(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local script = params.script or params.code
    local disable = params.disable or false

    if not script then
        return { success = false, error = "No script provided", error_code = "INVALID_PARAMS" }
    end

    -- CE's autoAssemble(text, disableInfo OPTIONAL): when disableInfo is a table,
    -- the [DISABLE] section runs instead of [ENABLE]. An empty table is enough to
    -- flip the branch; there's no persisted alloc state to reverse for a script
    -- executed only from MCP, so callers using disable=true are expected to have
    -- their own deallocation markers inside the script.
    local ok, success, disableInfo
    if disable then
        ok, success, disableInfo = pcall(autoAssemble, script, {})
    else
        ok, success, disableInfo = pcall(autoAssemble, script)
    end

    if not ok then
        return {
            success = false,
            error = "AutoAssemble threw: " .. tostring(success),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    if success then
        local result = {
            success = true,
            executed = true,
            section = disable and "disable" or "enable",
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and type(disableInfo) == "table" and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo),
            error_code = "INVALID_PARAMS",
        }
    end
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
local function cmd_enum_memory_regions_full(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return {
            success = false,
            error = "enumMemoryRegions failed",
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    local allRegions = {}
    for i, r in ipairs(regions) do
        local prot = r.Protect or 0
        local state = r.State or 0
        local protStr
        if     prot == 0x10 then protStr = "X"
        elseif prot == 0x20 then protStr = "RX"
        elseif prot == 0x40 then protStr = "RWX"
        elseif prot == 0x80 then protStr = "WX"
        elseif prot == 0x02 then protStr = "R"
        elseif prot == 0x04 then protStr = "RW"
        elseif prot == 0x08 then protStr = "W"
        else                     protStr = string.format("0x%X", prot)
        end

        allRegions[#allRegions + 1] = {
            base             = toHex(r.BaseAddress or 0),
            allocation_base  = toHex(r.AllocationBase or 0),
            size             = r.RegionSize or 0,
            state            = state,
            protect          = prot,
            protect_string   = protStr,
            type             = r.Type or 0,
            is_committed     = state == 0x1000,
            is_reserved      = state == 0x2000,
            is_free          = state == 0x10000
        }
    end

    local limit, offset, page, total = paginate(params, allRegions, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, regions = page }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
local function cmd_read_pointer_chain(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local base = params.base
    local offsets = params.offsets or {}

    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then
        return { success = false, error = "Invalid base address", error_code = "INVALID_ADDRESS" }
    end

    local currentAddr = base
    local chain = { { step = 0, address = toHex(currentAddr), description = "base" } }

    for i, offset in ipairs(offsets) do
        -- Read pointer at current address
        local ok, ptr = pcall(readPointer, currentAddr)
        if not ok or not ptr then
            return {
                success = false,
                error = "Failed to read pointer at step " .. i,
                error_code = "NOT_FOUND",
                partial_chain = chain,
                failed_at_address = toHex(currentAddr),
            }
        end

        -- Apply offset
        currentAddr = ptr + offset
        table.insert(chain, {
            step = i,
            address = toHex(currentAddr),
            offset = offset,
            hex_offset = string.format("+0x%X", offset),
            pointer_value = toHex(ptr)
        })
    end

    -- Try to read a value at the final address (using readPointer for 32/64-bit compatibility).
    -- Emit as hex string to match the v12 address-encoding convention.
    local finalValue = nil
    pcall(function()
        finalValue = readPointer(currentAddr)
    end)

    return {
        success = true,
        base = toHex(base),
        offsets = offsets,
        final_address = toHex(currentAddr),
        final_value = finalValue and toHex(finalValue) or nil,
        chain = chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
local function cmd_get_rtti_classname(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local address = params.address

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local ok, className = pcall(getRTTIClassName, address)

    if ok and className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
local function cmd_get_address_info(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
local function cmd_checksum_memory(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local address = params.address
    local size = params.size or 256

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local ok, hash = pcall(md5memory, address, size)

    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash),
            error_code = "NOT_FOUND",
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
local function cmd_generate_signature(params)
    local proc_err = requireProcess()
    if proc_err then return proc_err end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)

    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    if not signature or signature == "" then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature - pattern not unique enough",
            error_code = "NOT_FOUND",
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

-- ============================================================================
-- DBVM HYPERVISOR TOOLS (Safe Dynamic Tracing - Ring -1)
-- ============================================================================
-- These tools use DBVM (Debuggable Virtual Machine) for hypervisor-level tracing.
-- They are 100% invisible to anti-cheat: no game memory modification, no debug registers.
-- DBVM works at the hypervisor level, beneath the OS, making it undetectable.
-- ============================================================================

-- Get Physical Address: Converts virtual address to physical RAM address
-- Required for DBVM operations which work on physical memory

    commandHandlers.evaluate_lua             = cmd_evaluate_lua
    commandHandlers.get_memory_regions       = cmd_get_memory_regions
    commandHandlers.enum_memory_regions_full = cmd_enum_memory_regions_full
    commandHandlers.ping                     = cmd_ping
    commandHandlers.search_string            = cmd_search_string
    commandHandlers.dissect_structure        = cmd_dissect_structure
    commandHandlers.get_thread_list          = cmd_get_thread_list
    commandHandlers.auto_assemble            = cmd_auto_assemble
    commandHandlers.read_pointer_chain       = cmd_read_pointer_chain
    commandHandlers.get_rtti_classname       = cmd_get_rtti_classname
    commandHandlers.get_address_info         = cmd_get_address_info
    commandHandlers.checksum_memory          = cmd_checksum_memory
    commandHandlers.generate_signature       = cmd_generate_signature
end
-- >>> END UNIT-06b Analysis & Utility <<<
