# AXIS installer for Windows PowerShell
#
# Usage:
#   irm https://raw.githubusercontent.com/axis-sandbox/axis/main/install.ps1 | iex
#
#   # Or with options:
#   $env:AXIS_CHANNEL = "nightly"
#   irm https://raw.githubusercontent.com/axis-sandbox/axis/main/install.ps1 | iex
#
# Options (set as env vars before running):
#   AXIS_CHANNEL   "release" (default) or "nightly"
#   AXIS_VERSION   Specific version (e.g., "0.1.0")
#   AXIS_DIR       Install directory (default: %LOCALAPPDATA%\axis\bin)

$ErrorActionPreference = "Stop"

$Repo = "axis-sandbox/axis"
$Channel = if ($env:AXIS_CHANNEL) { $env:AXIS_CHANNEL } else { "release" }
$Version = $env:AXIS_VERSION
$InstallDir = if ($env:AXIS_DIR) { $env:AXIS_DIR } else { "$env:LOCALAPPDATA\axis\bin" }

function Get-Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "windows-x86_64" }
        "Arm64" { return "windows-aarch64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Get-DownloadUrl {
    param([string]$Platform)

    if ($Channel -eq "nightly") {
        $tag = "nightly"
    } elseif ($Version) {
        $tag = "v$Version"
    } else {
        # Get latest release tag.
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -ErrorAction SilentlyContinue
        if (-not $release) {
            throw "Cannot determine latest release. Try setting `$env:AXIS_VERSION`"
        }
        $tag = $release.tag_name
    }

    return "https://github.com/$Repo/releases/download/$tag/axis-$Platform.zip"
}

function Install-AXIS {
    $platform = Get-Platform

    Write-Host ""
    Write-Host "AXIS Installer" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Platform: $platform"
    Write-Host "  Channel:  $Channel"
    Write-Host "  Install:  $InstallDir"
    Write-Host ""

    $url = Get-DownloadUrl $platform
    Write-Host "  Download: $url"
    Write-Host ""

    # Create temp directory.
    $tmpDir = Join-Path $env:TEMP "axis-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $archivePath = Join-Path $tmpDir "axis.zip"

    try {
        # Download.
        Write-Host "Downloading..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing
        } catch {
            Write-Host ""
            Write-Host "Error: Download failed." -ForegroundColor Red
            Write-Host "  URL: $url"
            Write-Host ""
            Write-Host "If this is a new release, binaries may not be uploaded yet."
            Write-Host "Try: `$env:AXIS_CHANNEL = 'nightly'"
            throw
        }

        # Extract.
        Write-Host "Extracting..." -ForegroundColor Yellow
        $extractDir = Join-Path $tmpDir "extracted"
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        # Install binaries.
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

        $binaries = Get-ChildItem -Path $extractDir -Recurse -Filter "*.exe"
        foreach ($bin in $binaries) {
            $dest = Join-Path $InstallDir $bin.Name
            Copy-Item $bin.FullName $dest -Force
            Write-Host "  Installed: $dest" -ForegroundColor Green
        }

        # Copy policy files.
        $yamls = Get-ChildItem -Path $extractDir -Recurse -Filter "*.yaml"
        if ($yamls.Count -gt 0) {
            $policyDir = Join-Path $InstallDir ".." "policies"
            New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
            foreach ($yaml in $yamls) {
                Copy-Item $yaml.FullName (Join-Path $policyDir $yaml.Name) -Force
            }
            Write-Host "  Policies:  $policyDir" -ForegroundColor Green
        }

        Write-Host ""

        # Check PATH.
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$InstallDir*") {
            Write-Host "Adding to PATH..." -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable(
                "Path",
                "$InstallDir;$userPath",
                "User"
            )
            $env:Path = "$InstallDir;$env:Path"
            Write-Host "  Added $InstallDir to user PATH" -ForegroundColor Green
            Write-Host ""
            Write-Host "  NOTE: Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "AXIS installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  axis --version"
        Write-Host "  axis run -- echo 'Hello from sandbox'"
        Write-Host ""

    } finally {
        # Cleanup.
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-AXIS
