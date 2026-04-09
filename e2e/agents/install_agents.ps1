# AXIS Agent Installer for Windows (PowerShell)
#
# Installs agent runtimes into contained %LOCALAPPDATA%\axis\tools\ directory.
# Creates wrapper scripts that run agents through AXIS sandbox.
#
# Usage:
#   .\install_agents.ps1 -Agents aider,codex
#   .\install_agents.ps1 -All
#   .\install_agents.ps1 -List
#
# Agents are installed to %LOCALAPPDATA%\axis\tools\<agent>\ and wrapper
# scripts in %LOCALAPPDATA%\axis\bin\ run them through AXIS sandbox.

param(
    [string[]]$Agents,
    [switch]$All,
    [switch]$List
)

$ErrorActionPreference = "Continue"

$AxisRoot = "$env:LOCALAPPDATA\axis"
$ToolsDir = "$AxisRoot\tools"
$BinDir = "$AxisRoot\bin"
$PoliciesDir = "$AxisRoot\policies\agents"

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
New-Item -ItemType Directory -Path $PoliciesDir -Force | Out-Null

# ── Agent definitions ────────────────────────────────────────────────────

$AgentDefs = @{
    "claude-code" = @{ Binary = "claude"; Policy = "claude-code.yaml"; Install = "Install-ClaudeCode" }
    "codex"       = @{ Binary = "codex";  Policy = "codex.yaml";       Install = "Install-Codex" }
    "openclaw"    = @{ Binary = "openclaw"; Policy = "openclaw.yaml";   Install = "Install-OpenClaw" }
    "ironclaw"    = @{ Binary = "ironclaw"; Policy = "ironclaw.yaml";   Install = "Install-Ironclaw" }
    "aider"       = @{ Binary = "aider";  Policy = "hermes.yaml";      Install = "Install-Aider" }
    "goose"       = @{ Binary = "goose";  Policy = "hermes.yaml";      Install = "Install-Goose" }
}

$AllAgents = @("claude-code", "codex", "openclaw", "ironclaw", "aider", "goose")

# ── Install functions ────────────────────────────────────────────────────

function Install-ClaudeCode {
    $dir = "$ToolsDir\claude-code"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    # Try official installer
    try {
        $installer = "$env:TEMP\claude-install.ps1"
        Invoke-WebRequest -Uri "https://claude.ai/install.ps1" -OutFile $installer -UseBasicParsing
        & powershell -File $installer
        Remove-Item $installer -Force -ErrorAction SilentlyContinue
    } catch {}

    # Find the binary
    $bin = Get-Command claude -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    $localBin = "$env:LOCALAPPDATA\Programs\claude\claude.exe"
    if (Test-Path $localBin) { return $localBin }

    return $null
}

function Install-Codex {
    $dir = "$ToolsDir\codex"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir @openai/codex 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\codex.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command codex -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return $null
}

function Install-OpenClaw {
    $dir = "$ToolsDir\openclaw"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "  Installing via npm..."
        & npm install --prefix $dir openclaw@latest 2>&1 | Out-Null
        $bin = "$dir\node_modules\.bin\openclaw.cmd"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command openclaw -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return $null
}

function Install-Ironclaw {
    $dir = "$ToolsDir\ironclaw"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    try {
        $url = "https://github.com/nearai/ironclaw/releases/latest/download/ironclaw-x86_64-windows.exe"
        Invoke-WebRequest -Uri $url -OutFile "$dir\ironclaw.exe" -UseBasicParsing
        return "$dir\ironclaw.exe"
    } catch {}

    $bin = Get-Command ironclaw -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return $null
}

function Install-Aider {
    $dir = "$ToolsDir\aider"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
                 elseif (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
                 else { $null }

    if ($pythonCmd) {
        Write-Host "  Creating venv..."
        & $pythonCmd -m venv "$dir\venv" 2>&1 | Out-Null
        Write-Host "  Installing aider-chat..."
        & "$dir\venv\Scripts\pip.exe" install -q aider-chat 2>&1 | Out-Null
        $bin = "$dir\venv\Scripts\aider.exe"
        if (Test-Path $bin) { return $bin }
    }

    $bin = Get-Command aider -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return $null
}

function Install-Goose {
    $dir = "$ToolsDir\goose"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    try {
        $url = "https://github.com/block/goose/releases/download/stable/goose-x86_64-windows.exe"
        Invoke-WebRequest -Uri $url -OutFile "$dir\goose.exe" -UseBasicParsing
        return "$dir\goose.exe"
    } catch {}

    $bin = Get-Command goose -ErrorAction SilentlyContinue
    if ($bin) { return $bin.Source }

    return $null
}

# ── Wrapper generator ────────────────────────────────────────────────────

function New-AgentWrapper {
    param(
        [string]$AgentName,
        [string]$BinaryName,
        [string]$BinaryPath,
        [string]$PolicyFile
    )

    # Find axis binary.
    $axisBin = Get-Command axis -ErrorAction SilentlyContinue
    $axisPath = if ($axisBin) { $axisBin.Source } else { "axis" }

    # Create .cmd wrapper (works in cmd.exe and PowerShell).
    $cmdWrapper = "$BinDir\$BinaryName.cmd"
    @"
@echo off
REM AXIS-sandboxed $BinaryName
REM All execution goes through the AXIS sandbox with default-deny policy.
REM Agent state: %LOCALAPPDATA%\axis\agents\
REM Policy:      $PolicyFile
REM Real binary: $BinaryPath
set "AXIS_BIN=%AXIS_BIN%"
if "%AXIS_BIN%"=="" set "AXIS_BIN=$axisPath"
"%AXIS_BIN%" run --policy "$PolicyFile" -- "$BinaryPath" %*
"@ | Set-Content -Path $cmdWrapper -Encoding ASCII

    # Create .ps1 wrapper for PowerShell.
    $ps1Wrapper = "$BinDir\$BinaryName.ps1"
    @"
# AXIS-sandboxed $BinaryName
# Usage: $BinaryName [args...]       (when $BinDir is in PATH)
#    or: axis $BinaryName [args...]  (via axis subcommand extension)
`$axisBin = if (`$env:AXIS_BIN) { `$env:AXIS_BIN } else { "$axisPath" }
& `$axisBin run --policy "$PolicyFile" -- "$BinaryPath" @args
"@ | Set-Content -Path $ps1Wrapper -Encoding UTF8

    Write-Host "  Wrapper: $cmdWrapper"
    Write-Host "  Wrapper: $ps1Wrapper"
}

# ── Main ─────────────────────────────────────────────────────────────────

if ($List) {
    Write-Host "Available agents:"
    foreach ($agent in $AllAgents) {
        $installed = if (Test-Path "$ToolsDir\$agent") { " [installed]" } else { "" }
        Write-Host "  $agent$installed"
    }
    exit 0
}

if (-not $All -and -not $Agents) {
    Write-Host "AXIS Agent Installer (Windows)"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\install_agents.ps1 -All"
    Write-Host "  .\install_agents.ps1 -List"
    Write-Host "  .\install_agents.ps1 -Agents aider,codex"
    Write-Host ""
    Write-Host "Available: $($AllAgents -join ', ')"
    Write-Host ""
    Write-Host "Agents install to $ToolsDir and run through AXIS sandbox."
    exit 0
}

$targetAgents = if ($All) { $AllAgents } else { $Agents }

Write-Host ""
Write-Host "  AXIS Agent Installer (Windows)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install dir: $ToolsDir"
Write-Host "  Wrappers:    $BinDir"
Write-Host ""

$installed = 0
$failed = 0

foreach ($agent in $targetAgents) {
    Write-Host "--- Installing: $agent ---"

    $def = $AgentDefs[$agent]
    if (-not $def) {
        Write-Host "  Unknown agent: $agent" -ForegroundColor Red
        $failed++
        continue
    }

    $binaryPath = & $def.Install

    if ($binaryPath -and (Test-Path $binaryPath)) {
        Write-Host "  Binary: $binaryPath" -ForegroundColor Green

        $policyFile = "$PoliciesDir\$($def.Policy)"
        if (-not (Test-Path $policyFile)) {
            Write-Host "  Warning: policy not found, using base-deny"
            $policyFile = "$PoliciesDir\base-deny.yaml"
        }

        New-AgentWrapper -AgentName $agent -BinaryName $def.Binary `
            -BinaryPath $binaryPath -PolicyFile $policyFile
        $installed++
        Write-Host "  OK" -ForegroundColor Green
    } else {
        Write-Host "  Failed to install" -ForegroundColor Red
        $failed++
    }
    Write-Host ""
}

Write-Host "=================================================="
Write-Host "Installed: $installed  Failed: $failed"
Write-Host ""

if ($installed -gt 0) {
    # Check if BinDir is in PATH.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$BinDir*") {
        Write-Host "Adding $BinDir to PATH..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
        $env:Path = "$BinDir;$env:Path"
    }

    Write-Host "Run agents through AXIS sandbox:" -ForegroundColor Cyan
    Write-Host ""
    foreach ($agent in $targetAgents) {
        $def = $AgentDefs[$agent]
        if ($def -and (Test-Path "$BinDir\$($def.Binary).cmd")) {
            Write-Host "  $($def.Binary) --version        # runs through AXIS sandbox"
            Write-Host "  axis $($def.Binary) --version   # same thing, explicit"
        }
    }
}
