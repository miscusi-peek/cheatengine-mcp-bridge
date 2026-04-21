# ce_mcp_bridge Modular Source

This directory is generated from `ce_mcp_bridge.lua` by `bridge_builder.py`.

## Layout

- `manifest.json`: ordered list of parts
- `parts/`: editable Lua sections in assembly order

## Commands

Split the current monolithic bridge into parts:

```powershell
python MCP_Server/bridge_builder.py split
```

Rebuild the monolithic bridge from the modular parts:

```powershell
python MCP_Server/bridge_builder.py build
```

Verify that the modular source round-trips to the current bridge:

```powershell
python MCP_Server/bridge_builder.py verify
```

Only edit files under `parts/` if you want those changes preserved by rebuilds.
