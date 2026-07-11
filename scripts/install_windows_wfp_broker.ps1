# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$SkipBuild,
    [string]$LogPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($LogPath) {
    Set-Content -LiteralPath $LogPath -Value "" -Encoding UTF8
}

trap {
    if ($LogPath) {
        $_ | Out-String | Set-Content -LiteralPath $LogPath -Encoding UTF8
    }
    throw
}

$serviceName = "AxisWfpBroker"
$repoRoot = Split-Path -Parent $PSScriptRoot
$installDir = Join-Path $env:ProgramFiles "Axis"
$installedBinary = Join-Path $installDir "axis-wfp-broker.exe"
$leaseDir = Join-Path $env:ProgramData "axis\wfp-leases"
$builtBinary = Join-Path $repoRoot "target\release\axis-wfp-broker.exe"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run from an elevated PowerShell session because WFP policy installation is a privileged host operation."
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Test-ServiceExists {
    & "$env:SystemRoot\System32\sc.exe" query $serviceName *> $null
    return $LASTEXITCODE -eq 0
}

if ($Uninstall) {
    $activeJournals = @(Get-ChildItem -LiteralPath $leaseDir -Filter "*.json" -ErrorAction SilentlyContinue)
    if ($activeJournals.Count -ne 0) {
        throw "Refusing to uninstall while WFP lease journals exist. Let active sandboxes exit, or restart the broker so it can reap a crashed lease."
    }
    if (Test-ServiceExists) {
        & "$env:SystemRoot\System32\sc.exe" stop $serviceName *> $null
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $service -or $service.Status -eq "Stopped") {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        Invoke-Sc -Arguments @("delete", $serviceName)
    }
    if (Test-Path -LiteralPath $installedBinary) {
        Remove-Item -LiteralPath $installedBinary -Force
    }
    Write-Host "AXIS WFP broker service removed."
    exit 0
}

if (-not $SkipBuild) {
    & cargo build --release -p axis-sandbox --bin axis-wfp-broker --manifest-path (Join-Path $repoRoot "Cargo.toml")
    if ($LASTEXITCODE -ne 0) {
        throw "AXIS WFP broker build failed with exit code $LASTEXITCODE"
    }
}
if (-not (Test-Path -LiteralPath $builtBinary -PathType Leaf)) {
    throw "Built broker not found at $builtBinary. Run without -SkipBuild first."
}

if (Test-ServiceExists) {
    & "$env:SystemRoot\System32\sc.exe" stop $serviceName *> $null
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service.Status -eq "Stopped") {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if ((Get-Service -Name $serviceName).Status -ne "Stopped") {
        throw "Existing $serviceName service did not stop"
    }
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -LiteralPath $builtBinary -Destination $installedBinary -Force
New-Item -ItemType Directory -Path $leaseDir -Force | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $leaseDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "failed to restrict the WFP lease journal ACL"
}

if (-not (Test-ServiceExists)) {
    $quotedCommand = '"{0}" service' -f $installedBinary
    New-Service `
        -Name $serviceName `
        -BinaryPathName $quotedCommand `
        -DisplayName "AXIS WFP strict-proxy broker" `
        -StartupType Automatic | Out-Null
    Invoke-Sc -Arguments @("description", $serviceName, "Installs lease-scoped WFP filters for suspended AXIS MXC ProcessContainer children.")
    Invoke-Sc -Arguments @("failure", $serviceName, "reset=", "86400", "actions=", "restart/1000/restart/5000/none/0")
}

Set-Service -Name $serviceName -StartupType Automatic

Invoke-Sc -Arguments @("start", $serviceName)
$pipePath = "\\.\pipe\axis-wfp-broker-v1"
for ($attempt = 0; $attempt -lt 100; $attempt++) {
    if ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains $pipePath) {
        break
    }
    Start-Sleep -Milliseconds 100
}
if (-not ([System.IO.Directory]::GetFiles("\\.\pipe\") -contains $pipePath)) {
    throw "The $serviceName service started but its lease pipe did not become available"
}

& $installedBinary probe
if ($LASTEXITCODE -ne 0) {
    throw "The installed broker could not open the Windows Filtering Platform engine"
}

Write-Host "AXIS WFP broker installed and running."
Write-Host "Service: $serviceName"
Write-Host "Binary:  $installedBinary"
Write-Host "Pipe:    $pipePath"
