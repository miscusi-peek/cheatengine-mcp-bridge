-- >>> BEGIN UNIT-13 Assembly & Compilation <<<
do
-- ============================================================================
-- ASSEMBLY & COMPILATION TOOLS (Unit 13)
-- ============================================================================

-- Helper: check process is attached (for tools that need a target process address)
local function requireProcess()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

local function cmd_assemble_instruction(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local line = params.line
    local address = params.address
    local preference = params.preference or 0
    local skipRangeCheck = params.skip_range_check or false

    if not line or line == "" then
        return {
            success = false,
            error = "No instruction line provided",
            error_code = "INVALID_PARAMS",
        }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return {
            success = false,
            error = "Invalid address: " .. tostring(params.address),
            error_code = "INVALID_ADDRESS",
        }
    end

    -- assemble() accepts nil address; it skips relative-offset resolution in that case
    local asmOk, result = pcall(assemble, line, address, preference, skipRangeCheck)

    if not asmOk then
        return {
            success = false,
            error = "assemble() raised error: " .. tostring(result),
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    if not result then
        return {
            success = false,
            error = "assemble() returned nil (invalid instruction or address)",
            error_code = "INVALID_PARAMS",
        }
    end

    local bytes = {}
    for i = 1, #result do bytes[i] = result[i] end

    return { success = true, bytes = bytes, size = #bytes }
end

local function cmd_auto_assemble_check(params)
    local script = params.script
    local enable = params.enable
    if enable == nil then enable = true end
    local targetSelf = params.target_self or false

    if not script or script == "" then
        return {
            success = false,
            error = "No script provided",
            error_code = "INVALID_PARAMS",
        }
    end

    local checkOk, valid, errMsg = pcall(autoAssembleCheck, script, enable, targetSelf)

    if not checkOk then
        return {
            success = false,
            valid = false,
            errors = { tostring(valid) },
            error_code = "CE_API_UNAVAILABLE",
        }
    end

    if valid then
        return { success = true, valid = true, errors = {} }
    end

    local errors = {}
    if errMsg then table.insert(errors, tostring(errMsg)) end
    return { success = true, valid = false, errors = errors }
end

local function cmd_compile_c_code(params)
    -- No NO_PROCESS guard: pure compilation without an address doesn't require a target process
    local source = params.source
    local address = params.address
    local targetSelf = params.target_self or false
    local kernelMode = params.kernelmode or false

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compile) ~= "function" then
        return { success = false, error = "TCC compiler not available", error_code = "CE_API_UNAVAILABLE" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address) }
    end

    local compOk, symbols, errMsg = pcall(compile, source, address, targetSelf, kernelMode, false)

    if not compOk then
        return { success = false, symbols = {}, errors = { tostring(symbols) } }
    end

    if not symbols then
        local errors = {}
        if errMsg then table.insert(errors, tostring(errMsg)) end
        return { success = false, symbols = {}, errors = errors }
    end

    local symResult = {}
    for name, addr in pairs(symbols) do
        symResult[tostring(name)] = toHex(addr)
    end

    return { success = true, symbols = symResult, errors = {} }
end

local function cmd_compile_cs_code(params)
    local source = params.source
    local references = params.references or {}
    local coreAssembly = params.core_assembly

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compileCS) ~= "function" then
        return { success = false, error = ".NET runtime or compileCS not available", error_code = "CE_API_UNAVAILABLE" }
    end

    -- compileCS(text, references, coreAssembly OPTIONAL) — pass coreAssembly only when provided
    local csOk, result = pcall(compileCS, source, references, coreAssembly)

    if not csOk then
        return { success = false, assembly_handle = nil, error = tostring(result) }
    end

    if not result then
        return { success = false, assembly_handle = nil, error = "compileCS returned nil" }
    end

    return { success = true, assembly_handle = tostring(result) }
end

local function cmd_generate_api_hook_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    local targetAddress = params.target_address
    local codeToExecute = params.code_to_execute or ""

    if not address then return { success = false, error = "No address provided" } end
    if not targetAddress then return { success = false, error = "No target_address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if type(targetAddress) == "string" then targetAddress = getAddressSafe(targetAddress) end

    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end
    if not targetAddress then return { success = false, error = "Invalid target_address: " .. tostring(params.target_address) } end

    -- CE signature: generateAPIHookScript(address, addresstojumpto, addresstogetnewcalladdress OPT, ext OPT, targetself OPT)
    -- code_to_execute maps to ext (4th param); 3rd param (new-call-address) is unused here
    local ext = codeToExecute ~= "" and codeToExecute or nil
    local genOk, result = pcall(generateAPIHookScript, address, targetAddress, nil, ext)

    if not genOk then
        return { success = false, error = "generateAPIHookScript failed: " .. tostring(result) }
    end

    if not result then
        return { success = false, error = "generateAPIHookScript returned nil" }
    end

    return { success = true, script = tostring(result) }
end

local function cmd_generate_code_injection_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    if not address then return { success = false, error = "No address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end

    -- generateCodeInjectionScript(script: TStrings, address, farjmp) mutates TStrings in-place
    local sl = createStringlist()
    local genOk, genErr = pcall(generateCodeInjectionScript, sl, address)

    if not genOk then
        sl.destroy()
        return { success = false, error = "generateCodeInjectionScript failed: " .. tostring(genErr) }
    end

    local script = sl.Text
    sl.destroy()

    if not script or script == "" then
        return { success = false, error = "generateCodeInjectionScript produced empty script" }
    end

    return { success = true, script = script }
end

    -- Register Unit-13 handlers in the dispatcher
    commandHandlers.assemble_instruction = cmd_assemble_instruction
    commandHandlers.auto_assemble_check = cmd_auto_assemble_check
    commandHandlers.compile_c_code = cmd_compile_c_code
    commandHandlers.compile_cs_code = cmd_compile_cs_code
    commandHandlers.generate_api_hook_script = cmd_generate_api_hook_script
    commandHandlers.generate_code_injection_script = cmd_generate_code_injection_script
end
-- >>> END UNIT-13 <<<
