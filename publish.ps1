# Publish-AutoSecureVPN.ps1
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ApiKey,
    [Parameter(Mandatory = $false, Position = 1)]
    [switch]$AutoIncrement = $true,
    [Parameter(Mandatory = $false, Position = 2)]
    [switch]$WhatIf
)

$ModulePath = Join-Path $PSScriptRoot 'src\module'
$ManifestPath = Join-Path $ModulePath 'AutoSecure-VPN.psd1'
if (-not (Test-Path $ManifestPath)) { Throw 'Module manifest not found at expected path.' }

# Auto-increment version if requested
if ($AutoIncrement) {
    Write-Host "Auto-incrementing version..." -ForegroundColor Yellow

    # Read current version from manifest
    $manifestContent = Get-Content -Path $ManifestPath -Raw
    $versionMatch = [regex]::Match($manifestContent, "ModuleVersion\s*=\s*'([^']+)'")
    if ($versionMatch.Success) {
        $currentVersion = $versionMatch.Groups[1].Value
        Write-Host "Current version: $currentVersion" -ForegroundColor Cyan

        # Parse version (assuming semantic versioning: major.minor.patch)
        $versionParts = $currentVersion -split '\.'
        if ($versionParts.Length -eq 3) {
            $major = [int]$versionParts[0]
            $minor = [int]$versionParts[1]
            $patch = [int]$versionParts[2]

            # Increment patch version
            $patch++
            $newVersion = "$major.$minor.$patch"

            Write-Host "New version: $newVersion" -ForegroundColor Green

            # Update manifest
            $newManifestContent = $manifestContent -replace "ModuleVersion\s*=\s*'[^']*'", "ModuleVersion     = '$newVersion'"
            Set-Content -Path $ManifestPath -Value $newManifestContent -Encoding UTF8
        } else {
            Write-Warning "Could not parse version '$currentVersion' as semantic version (major.minor.patch). Skipping auto-increment."
        }
    } else {
        Write-Warning "Could not find ModuleVersion in manifest. Skipping auto-increment."
    }
}

Write-Host "Publishing AutoSecure-VPN from $ModulePath..." -ForegroundColor Cyan

# Create a temporary directory named after the module for publishing
$TempModulePath = Join-Path ([System.IO.Path]::GetTempPath()) 'AutoSecure-VPN'
if (Test-Path $TempModulePath) { Remove-Item -Path $TempModulePath -Recurse -Force }
New-Item -Path $TempModulePath -ItemType Directory | Out-Null

# Copy module files to the temp directory
Get-ChildItem -Path $ModulePath -File | ForEach-Object { Copy-Item -Path $_.FullName -Destination $TempModulePath -Force }

# Copy config example files to the temp directory (not the actual config files)
$ConfigPath = Join-Path (Split-Path $ModulePath -Parent) 'config'
if (Test-Path $ConfigPath) {
    Copy-Item -Path (Join-Path $ConfigPath 'Stable.psd1.example') -Destination $TempModulePath -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $ConfigPath 'Variable.psd1.example') -Destination $TempModulePath -Force -ErrorAction SilentlyContinue
}

try {
    $publishParams = @{
        Path = $TempModulePath
        NuGetApiKey = $ApiKey
        Verbose = $true
    }
    if ($WhatIf) {
        $publishParams.WhatIf = $true
    }
    Publish-Module @publishParams
    Write-Host "Successfully published to PowerShell Gallery!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to publish: $_"
}
finally {
    # Clean up temp directory
    if (Test-Path $TempModulePath) {
        Remove-Item -Path $TempModulePath -Recurse -Force
    }
}
