param(
    [switch]$Resplit,
    [switch]$KeepRebuilt
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$builder = Join-Path $scriptDir "bridge_builder.py"
$rebuilt = Join-Path $scriptDir "ce_mcp_bridge.REBUILT.lua"

if ($Resplit) {
    Write-Host "Resplitting ce_mcp_bridge.lua into modular parts..."
    & python $builder split --force
}

Write-Host "Rebuilding ce_mcp_bridge.lua from modular parts..."
& python $builder build

Write-Host "Verifying rebuilt output matches ce_mcp_bridge.lua..."
& python $builder verify

if (-not $KeepRebuilt -and (Test-Path $rebuilt)) {
    Remove-Item -LiteralPath $rebuilt -Force
}

Write-Host "Bridge rebuild complete."
