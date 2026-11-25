-- CE MCP Bridge Loader ---------------------------------------------------------------------------
-- Autorun 範本：於 Cheat Engine 主選單新增一個入口，用來載入 MCP Bridge。
-- 參考 DDLEditor.lua 的選單建立方式。

local BRIDGE_SCRIPT = [[C:/path/to/cheatengine-mcp-bridge/MCP_Server/ce_mcp_bridge.lua]]

local mf = getMainForm().Menu.Items
local miExtra
--Find "Extra" item in main menu. Create one if not found.
for i = 0, mf.Count - 1 do
	if mf[i].Name == 'miExtra' then miExtra = mf[i] end
end
if miExtra == nil then
	miExtra = createMenuItem(mf)
	miExtra.Name = 'miExtra'
	miExtra.Caption = 'Extra'
	mf.insert(mf.Count - 2, miExtra)
end

--Add "Start CE MCP Bridge" item to "Extra" submenu.
local miBridge = createMenuItem(miExtra)
miBridge.Caption = 'Start CE MCP Bridge'
miBridge.onClick =
function()
	local ok, err = pcall(dofile, BRIDGE_SCRIPT)
	if ok then
		print('[CE_MCP_Bridge_Loader] loaded: ' .. BRIDGE_SCRIPT)
	else
		messageDialog('Failed to load bridge:\r\n' .. tostring(err), mtError, mbOK)
	end
end
miExtra.add(miBridge)
