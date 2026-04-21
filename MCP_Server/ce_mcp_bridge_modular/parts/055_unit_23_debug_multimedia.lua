-- >>> BEGIN UNIT-23 Debug Multimedia <<<
do

local progressStateMap = {
    none          = tbpsNone,
    normal        = tbpsNormal,
    paused        = tbpsPaused,
    error         = tbpsError,
    indeterminate = tbpsIndeterminate,
}

local function cmd_output_debug_string(params)
    local message = params.message
    if type(message) ~= "string" then
        return { success = false, error = "message must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(outputDebugString, message)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_speak_text(params)
    local text = params.text
    if type(text) ~= "string" then
        return { success = false, error = "text must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err
    if params.english_only then
        ok, err = pcall(speakEnglish, text)
    else
        ok, err = pcall(speak, text)
    end
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_play_sound(params)
    if type(params.filename) ~= "string" or params.filename:find("%.%.") then
        return { success = false, error = "Invalid filename", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(playSound, params.filename)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_beep(params)
    local ok, err = pcall(beep)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_set_progress_state(params)
    local tbState = progressStateMap[params.state]
    if not tbState then
        return { success = false, error = "state must be one of: none, normal, paused, error, indeterminate", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressState, tbState)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

local function cmd_set_progress_value(params)
    local current = params.current
    local max = params.max
    if type(current) ~= "number" or type(max) ~= "number" then
        return { success = false, error = "current and max must be numbers", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressValue, current, max)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

    -- Register Unit-23 handlers in the dispatcher
    commandHandlers.beep = cmd_beep
    commandHandlers.output_debug_string = cmd_output_debug_string
    commandHandlers.play_sound = cmd_play_sound
    commandHandlers.set_progress_state = cmd_set_progress_state
    commandHandlers.set_progress_value = cmd_set_progress_value
    commandHandlers.speak_text = cmd_speak_text
end
-- >>> END UNIT-23 <<<
