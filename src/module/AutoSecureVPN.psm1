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
        $input = Read-Host -Prompt $Prompt
        if ($input -match '^[0-9]+$') {
            $n = [int]$input
            if ($n -ge 1 -and $n -le $Options.Count) { return $n }
        }
        Write-Host "Ongeldige keuze, probeer opnieuw." -ForegroundColor Red
    }
}



function Pause {
	param([string]$Message = 'Druk Enter om door te gaan...')
	Read-Host -Prompt $Message | Out-Null
}

# Load module settings from src/config/Settings.psd1 (if present)
$Module:Settings = @{}
try {
    $moduleDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $configPath = Join-Path $moduleDir '..\config\Settings.psd1'
    if (Test-Path $configPath) {
        $loaded = Import-PowerShellDataFile -Path $configPath -ErrorAction Stop
        if ($loaded) { $Module:Settings = $loaded }
    }
}
catch {
    Write-Host "Kon settings niet laden: $($_.Exception.Message)" -ForegroundColor Yellow
}


function Add-ServerOpenVPNMSILocal {
    param(
        [string]$Url = 'https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.15-I001-amd64.msi', # Deze mag niet hardcoded zijn, dus later nog aanpassen
        [string]$DestinationPath,
        [switch]$KeepInstaller
    )

    # Controleer admin rechten
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Deze actie vereist administratorrechten. Start PowerShell als Administrator en probeer opnieuw.' -ForegroundColor Red
        return $false
    }

    # Bepaal destination
    if (-not $DestinationPath) {
        $tmp = [System.IO.Path]::GetTempPath()
        $fileName = [System.IO.Path]::GetFileName($Url)
        if (![string]::IsNullOrEmpty($fileName)) { $DestinationPath = Join-Path $tmp $fileName } else { $DestinationPath = Join-Path $tmp 'openvpn-install.msi' }
    }

    # Controleer bestaande installatie (eenvoudig check op map)
    $installedPath = 'C:\Program Files\OpenVPN'
    if (Test-Path $installedPath) {
        Write-Host "OpenVPN lijkt al geïnstalleerd te zijn op $installedPath." -ForegroundColor Yellow
        $resp = Read-Host -Prompt 'Wil je opnieuw installeren? (y/n)'
        if ($resp -notin @('y','Y')) { return $true }
    }

    try {
        Write-Host "Downloading installer from: $Url" -ForegroundColor Cyan
        Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Host "Download mislukt: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    try {
        Write-Host 'Start installatie (stil)...' -ForegroundColor Cyan
        $args = "/i `"$DestinationPath`" /qn /norestart"
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host 'OpenVPN succesvol geïnstalleerd.' -ForegroundColor Green
        }
        else {
            Write-Host "msiexec returned exit code $($proc.ExitCode)" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Installatie mislukt: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    if (-not $KeepInstaller) {
        try { Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue } catch { }
    }

    return $true
}
