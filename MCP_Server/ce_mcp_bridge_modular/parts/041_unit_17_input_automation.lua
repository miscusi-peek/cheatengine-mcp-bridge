-- >>> BEGIN UNIT-17 Input Automation <<<
do
-- ============================================================================
-- COMMAND HANDLERS - INPUT AUTOMATION (mouse, keyboard, screen)
-- These APIs operate system-wide and require NO attached process.
-- ============================================================================

-- Shared helpers (local to this section)
local function parse_xy(params)
    if params.x == nil then return nil, nil, "Missing parameter: x" end
    if params.y == nil then return nil, nil, "Missing parameter: y" end
    local x, y = tonumber(params.x), tonumber(params.y)
    if x == nil or y == nil then return nil, nil, "Parameters x and y must be numbers" end
    return x, y, nil
end

local function parse_vk(params)
    if params.vk == nil then return nil, "Missing parameter: vk (Windows virtual-key code, e.g. 0x41 for 'A')" end
    local vk = tonumber(params.vk)
    if vk == nil then return nil, "Parameter vk must be a number" end
    return vk, nil
end

-- Execute a no-return CE key API (keyDown / keyUp / doKeyPress) and return {success}.
local function run_key_action(fn, vk, fn_name)
    local ok, err = pcall(fn, vk)
    if not ok then return { success = false, error = fn_name .. " failed: " .. tostring(err) } end
    return { success = true }
end

local function cmd_get_pixel(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, rgb = pcall(getPixel, x, y)
    if not ok then return { success = false, error = "getPixel failed: " .. tostring(rgb) } end
    -- Windows COLORREF format: 0x00BBGGRR
    local r = rgb % 256
    local g = math.floor(rgb / 256) % 256
    local b = math.floor(rgb / 65536) % 256
    return { success = true, r = r, g = g, b = b, rgb = rgb }
end

local function cmd_get_mouse_pos(params)
    local ok, x, y = pcall(getMousePos)
    if not ok then return { success = false, error = "getMousePos failed: " .. tostring(x) } end
    return { success = true, x = x, y = y }
end

local function cmd_set_mouse_pos(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, e = pcall(setMousePos, x, y)
    if not ok then return { success = false, error = "setMousePos failed: " .. tostring(e) } end
    return { success = true }
end

local function cmd_is_key_pressed(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end

    local ok, pressed = pcall(isKeyPressed, vk)
    if not ok then return { success = false, error = "isKeyPressed failed: " .. tostring(pressed) } end
    return { success = true, pressed = pressed == true }
end

local function cmd_key_down(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyDown, vk, "keyDown")
end

local function cmd_key_up(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyUp, vk, "keyUp")
end

local function cmd_do_key_press(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(doKeyPress, vk, "doKeyPress")
end

local function cmd_get_screen_info(params)
    local ok_w, width  = pcall(getScreenWidth)
    local ok_h, height = pcall(getScreenHeight)
    local ok_d, dpi    = pcall(getScreenDPI)

    if not ok_w then return { success = false, error = "getScreenWidth failed: " .. tostring(width) } end
    if not ok_h then return { success = false, error = "getScreenHeight failed: " .. tostring(height) } end
    if not ok_d then return { success = false, error = "getScreenDPI failed: " .. tostring(dpi) } end

    return { success = true, width = width, height = height, dpi = dpi }
end

    -- Register Unit-17 handlers in the dispatcher
    commandHandlers.do_key_press = cmd_do_key_press
    commandHandlers.get_mouse_pos = cmd_get_mouse_pos
    commandHandlers.get_pixel = cmd_get_pixel
    commandHandlers.get_screen_info = cmd_get_screen_info
    commandHandlers.is_key_pressed = cmd_is_key_pressed
    commandHandlers.key_down = cmd_key_down
    commandHandlers.key_up = cmd_key_up
    commandHandlers.set_mouse_pos = cmd_set_mouse_pos
end
-- >>> END UNIT-17 <<<
