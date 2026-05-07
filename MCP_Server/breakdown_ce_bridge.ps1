param(
    [switch]$Verify
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$builder = Join-Path $scriptDir "bridge_builder.py"

Write-Host "Breaking down ce_mcp_bridge.lua into modular parts..."
& python $builder split --force

if ($Verify) {
    Write-Host "Verifying modular parts rebuild back to ce_mcp_bridge.lua..."
    & python $builder verify
}

Write-Host "Bridge breakdown complete."
