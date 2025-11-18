#region Menu en UI functies

function Show-Menu {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Options,
        [ConsoleColor]$HeaderColor = 'Cyan',
        [ConsoleColor]$OptionColor = 'White',
        [ConsoleColor]$FooterColor = 'Cyan',
        [string]$SeparatorChar = '=',
        [switch]$NoPrompt,
        [string]$Prompt = 'Keuze: '
    )

    Clear-Host
    $sep = ($SeparatorChar * 30)
    Write-Host $sep -ForegroundColor $HeaderColor
    Write-Host "      $Title" -ForegroundColor $HeaderColor
    Write-Host $sep -ForegroundColor $HeaderColor

    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num = $i + 1
        Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
    }

    Write-Host $sep -ForegroundColor $FooterColor

    if ($NoPrompt) { return $null }

    while ($true) {
        $userInput = Read-Host -Prompt $Prompt
        if ($userInput -match '^[0-9]+$') {
            $n = [int]$userInput
            if ($n -ge 1 -and $n -le $Options.Count) { return $n }
        }
        Write-Host "Ongeldige keuze, probeer opnieuw." -ForegroundColor Red
    }
}

function Pause {
	param([string]$Message = 'Druk Enter om door te gaan...')
	Read-Host -Prompt $Message | Out-Null
}

#endregion Menu en UI functies

# Load module settings from src/config/Settings.psd1 (if present)
# Use $PSScriptRoot and $Script: scope so the module is import-safe in test runspaces.
$Script:Settings = @{}
try {
    $configPath = Join-Path $PSScriptRoot '..\config\Settings.psd1'
    if (Test-Path $configPath) {
        $loaded = Import-PowerShellDataFile -Path $configPath -ErrorAction Stop
        if ($loaded) { $Script:Settings = $loaded }
    }
}
catch {
    Write-Host "Kon settings niet laden: $($_.Exception.Message)" -ForegroundColor Yellow
}

#region Configuratie functies  

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile = $null
    )
    
    if (-not $LogFile) {
        $logsPath = Join-Path $PSScriptRoot "..\..\$($Script:Settings.logsPath)"
        if (-not (Test-Path $logsPath)) {
            New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
        }
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Host "Kan niet schrijven naar logbestand: $_" -ForegroundColor Red
    }
    
    # Also write to console based on level
    switch ($Level.ToUpper()) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

#endregion Configuratie functies

