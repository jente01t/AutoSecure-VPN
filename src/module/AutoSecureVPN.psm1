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

#region Installatie functies

function Install-OpenVPN {
    param(
        [string]$Url = $Script:Settings.installerUrl
    )
    
    if (-not $Url) {
        $Url = $Script:Settings.installerUrl
    }
    
    $installedPath = $Script:Settings.installedPath
    if (Test-Path $installedPath) {
        Write-Log "OpenVPN lijkt al geïnstalleerd te zijn op $installedPath" -Level "INFO"
        return $true
    }
    
    Write-Log "OpenVPN installatie gestart" -Level "INFO"
    
    $tempPath = [System.IO.Path]::GetTempFileName() + ".msi"
    
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tempPath -UseBasicParsing
        Write-Log "OpenVPN MSI gedownload naar $tempPath" -Level "INFO"
        
        $arguments = "/i `"$tempPath`" /qn /norestart"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "OpenVPN succesvol geïnstalleerd" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "OpenVPN installatie mislukt met exit code $($process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Fout tijdens OpenVPN installatie: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force
        }
    }
}

#endregion Installatie functies

#region Firewall functies

function Configure-Firewall {
    param(
        [int]$Port = $Script:Settings.port,
        [string]$Protocol = $Script:Settings.protocol
    )
    
    Write-Log "Firewall configuratie gestart voor poort $Port $Protocol" -Level "INFO"
    
    try {
        # Enable firewall rule for OpenVPN
        $ruleName = "OpenVPN-Inbound-$Protocol-$Port"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log "Firewall regel bestaat al: $ruleName" -Level "INFO"
            return $true
        }
        
        New-NetFirewallRule -Name $ruleName `
                           -DisplayName "OpenVPN $Protocol $Port" `
                           -Direction Inbound `
                           -Protocol $Protocol `
                           -LocalPort $Port `
                           -Action Allow `
                           -Profile Any
        
        Write-Log "Firewall regel toegevoegd: $ruleName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens firewall configuratie: $_" -Level "ERROR"
        return $false
    }
}

#endregion Firewall functies

#region Server configuratie functies

function Get-ServerConfiguration {
    param()
    
    $config = @{}
    
    Write-Host ""
    $config.ServerName = Read-Host "  Servernaam (bijv. vpn-server)"
    if ([string]::IsNullOrWhiteSpace($config.ServerName)) {
        $config.ServerName = $Script:Settings.serverNameDefault
    }
    
    $config.ServerIP = Read-Host "  Server WAN IP of DDNS (bijv. vpn.example.com)"
    while ([string]::IsNullOrWhiteSpace($config.ServerIP)) {
        Write-Host "  ! Server IP/DDNS is verplicht" -ForegroundColor Red
        $config.ServerIP = Read-Host "  Server WAN IP of DDNS"
    }
    
    $lanSubnet = Read-Host "  LAN subnet (default 192.168.1.0, druk Enter voor skip)"
    if (-not [string]::IsNullOrWhiteSpace($lanSubnet)) {
        $config.LANSubnet = $Script:Settings.lanSubnetDefault
        $config.LANMask = $Script:Settings.lanMaskDefault
    }
    
    $noPassInput = Read-Host "  Certificaten zonder wachtwoord? (J/N, standaard N)"
    $config.NoPass = ($noPassInput -eq "J" -or $noPassInput -eq "j")
    
    if (-not $config.NoPass) {
        $config.Password = Read-Host "  Voer wachtwoord in voor certificaten"
    }
    
    Write-Log "Server configuratie verzameld: ServerName=$($config.ServerName), ServerIP=$($config.ServerIP)" -Level "INFO"
    
    return $config
}

#endregion Server configuratie functies

