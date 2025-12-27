# Function comments are generated with AI assistance.

#Requires -Version 7.0

# Dot-source functional files from the current folder
Get-ChildItem -Path "$PSScriptRoot\*.ps1" -Exclude "AutoSecureVPN.psm1" | ForEach-Object { . $_.FullName }

# Load module settings from src/config/Stable.psd1 and Variable.psd1 (if present)
# Use $PSScriptRoot and $Script: scope so the module is import-safe in test runspaces.
$Script:Settings = @{}

# Only load config files if $PSScriptRoot is available (not available when loaded via Invoke-Expression)
if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    try {
        # Load stable settings first
        $stableConfigPath = Join-Path $PSScriptRoot '..\config\Stable.psd1'
        if (Test-Path $stableConfigPath) {
            $stableSettings = Import-PowerShellDataFile -Path $stableConfigPath -ErrorAction Stop
            if ($stableSettings) { $Script:Settings = $stableSettings.Clone() }
        }
        
        # Load variable settings and merge (variable overrides stable)
        $variableConfigPath = Join-Path $PSScriptRoot '..\config\Variable.psd1'
        if (Test-Path $variableConfigPath) {
            $variableSettings = Import-PowerShellDataFile -Path $variableConfigPath -ErrorAction Stop
            if ($variableSettings) {
                foreach ($key in $variableSettings.Keys) {
                    $Script:Settings[$key] = $variableSettings[$key]
                }
            }
        }
    }
    catch {
        Write-Log "Kon settings niet laden: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Set BasePath only if PSScriptRoot is available
if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $Script:BasePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
else {
    # Fallback for remote execution via Invoke-Expression
    $Script:BasePath = "C:\Temp"
}



