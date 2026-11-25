@echo off
setlocal
cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
    echo [ERROR] uv not found. Install it first: https://docs.astral.sh/uv/ 1>&2
    exit /b 1
)

rem MCP speaks JSON-RPC over stdio: keep stdout clean (uv output goes to stderr).
uv run --quiet --with-requirements MCP_Server\requirements.txt ^
    python MCP_Server\mcp_cheatengine.py %*
