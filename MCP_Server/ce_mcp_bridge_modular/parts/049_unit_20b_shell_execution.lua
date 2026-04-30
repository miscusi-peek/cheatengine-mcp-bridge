-- >>> BEGIN UNIT-20b Shell Execution <<<
do
-- UNIT-20b: Shell Execution Handlers
-- NOTE: Security gate (CE_MCP_ALLOW_SHELL env var check) is enforced on the
--       Python side, before this Lua code is ever reached.
-- ============================================================================

-- run_command: Wraps CE's runCommand(exepath, parameters, pathtoexecutein)
-- Returns output string and exit code. SECURITY: arbitrary code execution.
local function cmd_run_command(params)
    local command = params.command
    local args = params.args or ""

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    local ok, output, exitCode = pcall(runCommand, command, args)

    if not ok then
        return { success = false, error = "runCommand failed: " .. tostring(output) }
    end

    return {
        success = true,
        output = tostring(output or ""),
        exit_code = tonumber(exitCode) or 0
    }
end

-- shell_execute: Wraps CE's shellExecute(command, parameters, folder, showcommand)
-- SECURITY: arbitrary code execution via Windows ShellExecute.
local function cmd_shell_execute(params)
    local command = params.command
    local args = params.args or ""
    local workingDir = params.working_dir or ""

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    local ok, err = pcall(shellExecute, command, args, workingDir ~= "" and workingDir or nil)

    if not ok then
        return { success = false, error = "shellExecute failed: " .. tostring(err) }
    end

    return { success = true }
end

    -- Register Unit-20b handlers in the dispatcher
    commandHandlers.run_command = cmd_run_command
    commandHandlers.shell_execute = cmd_shell_execute
end
-- >>> END UNIT-20b <<<
