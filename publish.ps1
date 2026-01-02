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

    # Get the latest version from PowerShell Gallery
    try {
        $latestModule = Find-Module -Name 'AutoSecure-VPN' -Repository 'PSGallery' -ErrorAction Stop
        $currentVersion = $latestModule.Version.ToString()
        Write-Host "Latest version in gallery: $currentVersion" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Could not find module in gallery. Using local manifest version."
        # Fallback to local manifest
        $manifestContent = Get-Content -Path $ManifestPath -Raw
        $versionMatch = [regex]::Match($manifestContent, "ModuleVersion\s*=\s*'([^']+)'")
        if ($versionMatch.Success) {
            $currentVersion = $versionMatch.Groups[1].Value
            Write-Host "Current local version: $currentVersion" -ForegroundColor Cyan
        } else {
            Write-Warning "Could not find ModuleVersion in manifest. Skipping auto-increment."
            $AutoIncrement = $false
        }
    }

    if ($AutoIncrement) {
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
            $manifestContent = Get-Content -Path $ManifestPath -Raw
            $newManifestContent = $manifestContent -replace "ModuleVersion\s*=\s*'[^']*'", "ModuleVersion     = '$newVersion'"
            Set-Content -Path $ManifestPath -Value $newManifestContent -Encoding UTF8
        } else {
            Write-Warning "Could not parse version '$currentVersion' as semantic version (major.minor.patch). Skipping auto-increment."
        }
    }

}


Write-Host "Publishing AutoSecure-VPN from $ModulePath..." -ForegroundColor Cyan

# Create a temporary directory named after the module for publishing
$TempModulePath = Join-Path ([System.IO.Path]::GetTempPath()) 'AutoSecure-VPN'
if (Test-Path $TempModulePath) { Remove-Item -Path $TempModulePath -Recurse -Force }
New-Item -Path $TempModulePath -ItemType Directory | Out-Null

# Copy module manifest
Copy-Item -Path $ManifestPath -Destination $TempModulePath -Force

# Build the single psm1 file from dev files
$devPath = Join-Path $ModulePath 'dev'
if (Test-Path $devPath) {
    Write-Host "Building single psm1 file from dev sources..." -ForegroundColor Cyan
    $coreContent = Get-Content (Join-Path $devPath 'core.ps1') -Raw
    $openvpnContent = Get-Content (Join-Path $devPath 'openvpn.ps1') -Raw
    $wireguardContent = Get-Content (Join-Path $devPath 'wireguard.ps1') -Raw
    
    $fullContent = $coreContent + "`n" + $openvpnContent + "`n" + $wireguardContent
    Set-Content -Path (Join-Path $TempModulePath 'AutoSecure-VPN.psm1') -Value $fullContent -Encoding UTF8
}
else {
    # Fallback if dev folder doesn't exist (e.g. already built)
    Write-Warning "Dev folder not found, copying existing psm1 file."
    Copy-Item -Path (Join-Path $ModulePath 'AutoSecure-VPN.psm1') -Destination $TempModulePath -Force
}

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
