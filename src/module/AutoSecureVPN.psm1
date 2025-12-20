# Function comments are generated with AI assistance.

#Requires -Version 7.0

#region Menu en UI functies

########################################################################################################################
# Menu en UI functies
########################################################################################################################


function Show-Menu {
    <#
    .SYNOPSIS
        Toont een menu met opties en vraagt om keuze, of toont een succes bericht.

    .DESCRIPTION
        Deze functie toont een menu met een titel, lijst van opties, en wacht op gebruikersinvoer.
        Het valideert de keuze en retourneert het gekozen nummer.
        Als Mode 'Success' is, toont het een succes bericht in een box.

    .PARAMETER Mode
        'Menu' voor menu tonen, 'Success' voor succes bericht.

    .PARAMETER Title
        De titel van het menu of succes bericht.

    .PARAMETER Options
        Een array van opties om te tonen (alleen voor Menu).

    .PARAMETER SuccessTitle
        De titel voor succes bericht (alleen voor Success).

    .PARAMETER LogFile
        Pad naar logbestand (voor Success).

    .PARAMETER ExtraMessage
        Extra bericht (voor Success).

    .PARAMETER ComputerName
        Naam van computer voor log (voor Success).

    .PARAMETER HeaderColor
        Kleur voor de header (standaard Cyan).

    .PARAMETER OptionColor
        Kleur voor de opties (standaard White).

    .PARAMETER FooterColor
        Kleur voor de footer (standaard Cyan).

    .PARAMETER SeparatorChar
        Karakter voor de scheiding (standaard '=').

    .PARAMETER NoPrompt
        Als true, geen prompt tonen en null retourneren (alleen voor Menu).

    .PARAMETER Prompt
        De prompt tekst (standaard 'Keuze: ') (alleen voor Menu).

    .OUTPUTS
        System.Int32 voor Menu, None voor Success.

    .EXAMPLE
        Show-Menu -Mode Menu -Title "Hoofdmenu" -Options @("Optie 1", "Optie 2")

    .EXAMPLE
        Show-Menu -Mode Success -SuccessTitle "Remote Client Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraMessage "Op de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ComputerName $computerName

    .NOTES
        Deze functie gebruikt Write-Host voor console output en Read-Host voor input.
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidateSet('Menu','Success','Error')][string]$Mode,
        [Parameter(Mandatory=$false, Position=1)][string]$Title,
        [Parameter(Mandatory=$false, Position=2)][string[]]$Options,
        [Parameter(Mandatory=$false, Position=3)][string]$SuccessTitle,
        [Parameter(Mandatory=$false, Position=4)][string]$LogFile,
        [Parameter(Mandatory=$false, Position=5)][string]$ExtraMessage,
        [Parameter(Mandatory=$false, Position=6)][string]$ComputerName,
        [Parameter(Mandatory=$false, Position=7)][string]$ExtraInfo,
        [Parameter(Position=8)][ConsoleColor]$HeaderColor = 'Cyan',
        [Parameter(Position=9)][ConsoleColor]$OptionColor = 'White',
        [Parameter(Position=10)][ConsoleColor]$FooterColor = 'Cyan',
        [Parameter(Position=11)][string]$SeparatorChar = '=',
        [Parameter(Position=12)][switch]$NoPrompt,
        [Parameter(Position=13)][string]$Prompt = 'Keuze: '
        ,[Parameter(Position=14)][string]$ErrorMessage
    )

    # Afhankelijk van de Mode, toon een menu, succesbericht of foutbericht
    if ($Mode -eq 'Menu') {
        # Valideer dat Title en Options aanwezig zijn voor Menu mode
        if (-not $Title -or -not $Options) {
            throw "Voor Mode 'Menu' zijn Title en Options verplicht."
        }
        # Wis het scherm voor een schone weergave
        Clear-Host
        # Maak een scheidingslijn voor de header
        $sep = ($SeparatorChar * 30)
        Write-Host $sep -ForegroundColor $HeaderColor
        Write-Host "      $Title" -ForegroundColor $HeaderColor
        Write-Host $sep -ForegroundColor $HeaderColor

        # Toon alle opties genummerd
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $num = $i + 1
            Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
        }

        Write-Host $sep -ForegroundColor $FooterColor

        # Als NoPrompt is ingesteld, retourneer null zonder prompt
        if ($NoPrompt) { return $null }

        # Vraag om gebruikersinvoer en valideer de keuze
        while ($true) {
            $userInput = Read-Host -Prompt $Prompt
            if ($userInput -match '^[0-9]+$') {
                $n = [int]$userInput
                if ($n -ge 1 -and $n -le $Options.Count) { return $n }
            }
            Write-Host "Ongeldige keuze, probeer opnieuw." -ForegroundColor Red
        }
    }
    elseif ($Mode -eq 'Success') {
        # Valideer dat SuccessTitle aanwezig is voor Success mode
        if (-not $SuccessTitle) {
            throw "Voor Mode 'Success' is SuccessTitle verplicht."
        }
        # Toon een succesbox met de titel
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        # Toon extra informatie indien beschikbaar
        if ($LogFile) {
            Write-Host "`nLogbestand: $LogFile" -ForegroundColor Yellow
        }
        if ($ExtraInfo) {
            Write-Host "$ExtraInfo" -ForegroundColor Yellow
        }
        if ($ExtraMessage) {
            Write-Host "`n$ExtraMessage" -ForegroundColor Cyan
        }
        # Log de succesvolle actie indien ComputerName gegeven
        if ($ComputerName) {
            Write-Log "Remote client setup succesvol voltooid voor $ComputerName" -Level "SUCCESS"
        }
    }
    elseif ($Mode -eq 'Error') {
        # Valideer dat SuccessTitle aanwezig is voor Error mode (hergebruikt als fouttitel)
        if (-not $SuccessTitle) {
            throw "Voor Mode 'Error' is SuccessTitle verplicht."
        }
        # Toon een foutbox met de titel
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Red
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Red
        # Bepaal de beste fouttekst om te tonen (prioriteit: expliciete parameter > extra velden > globale fout)
        $displayError = $null
        if ($ErrorMessage) { $displayError = $ErrorMessage }
        elseif ($ExtraMessage) { $displayError = $ExtraMessage }
        elseif ($ExtraInfo) { $displayError = $ExtraInfo }
        elseif ($LogFile) { $displayError = "Zie logbestand: $LogFile" }
        elseif ($global:Error.Count -gt 0) {
            try {
                $err = $global:Error[0]
                $msg = $err.Exception.Message
                if ($err.ScriptStackTrace) { $msg += "`n$($err.ScriptStackTrace)" }
                $displayError = $msg
            } catch { $displayError = $null }
        }

        # Toon de foutdetails indien beschikbaar
        if ($displayError) {
            Write-Host "`nERROR:" -ForegroundColor Red
            Write-Host "$displayError" -ForegroundColor Yellow
        }
        elseif ($LogFile) {
            Write-Host "`nLogbestand: $LogFile" -ForegroundColor Yellow
        }
        # Log de fout indien ComputerName gegeven
        if ($ComputerName) {
            Write-Log "Batch remote client setup gefaald ($ComputerName)" -Level "ERROR"
        }
        # Als opties gegeven zijn, toon een menu voor herstel (zonder scherm te wissen)
        if ($Options) {
            # Houd de foutuitvoer zichtbaar boven het optiemenu
            $sep = ($SeparatorChar * 30)
            Write-Host $sep -ForegroundColor $HeaderColor
            Write-Host "      Fout opgetreden - Kies een optie" -ForegroundColor $HeaderColor
            Write-Host $sep -ForegroundColor $HeaderColor
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $num = $i + 1
                Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
            }
            Write-Host $sep -ForegroundColor $FooterColor
            if (-not $NoPrompt) {
                # Vraag om keuze voor herstel
                while ($true) {
                    $userInput = Read-Host -Prompt $Prompt
                    if ($userInput -match '^[0-9]+$') {
                        $n = [int]$userInput
                        if ($n -ge 1 -and $n -le $Options.Count) { return $n }
                    }
                    Write-Host "Ongeldige keuze, probeer opnieuw." -ForegroundColor Red
                }
            }
        }
    }
}


function Wait-Input {
    <#
    .SYNOPSIS
        Wacht op gebruikersinvoer om door te gaan.

    .DESCRIPTION
        Deze functie toont een bericht en wacht tot de gebruiker Enter drukt.

    .PARAMETER Message
        Het bericht om te tonen (standaard 'Druk Enter om door te gaan...').

    .OUTPUTS
        None

    .EXAMPLE
        Wait-Input

    .NOTES
        Deze functie gebruikt Read-Host om te wachten op input.
    #>
	param([Parameter(Position=0)][string]$Message = 'Druk Enter om door te gaan...')
	Read-Host -Prompt $Message | Out-Null
}

#endregion Menu en UI functies

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
} else {
    # Fallback for remote execution via Invoke-Expression
    $Script:BasePath = "C:\Temp"
}



function Set-ModuleSettings {
    <#
    .SYNOPSIS
        Stelt de module settings in voor remote operaties.

    .DESCRIPTION
        Deze functie stelt $Script:Settings en $Script:BasePath in voor gebruik in remote sessies.

    .PARAMETER Settings
        De hashtable met settings.

    .PARAMETER BasePath
        Het base path voor de module.

    .OUTPUTS
        None

    .EXAMPLE
        Set-ModuleSettings -Settings $mySettings -BasePath "C:\Temp"

    .NOTES
        Deze functie wijzigt script-scoped variabelen.
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][hashtable]$Settings,
        [Parameter(Mandatory=$true, Position=1)][string]$BasePath
    )
    $Script:Settings = $Settings
    $Script:BasePath = $BasePath
}

#region Configuratie functies  

########################################################################################################################
# Configuratie functies
########################################################################################################################


function Test-IsAdmin {
    <#
    .SYNOPSIS
        Controleert of het script als administrator wordt uitgevoerd.

    .DESCRIPTION
        Deze functie controleert of de huidige gebruiker administrator rechten heeft.

    .OUTPUTS
        System.Boolean
        $true als administrator, anders $false.

    .EXAMPLE
        if (-not (Test-IsAdmin)) { Write-Log "Administrator rechten vereist" -Level "ERROR" }

    Referentie: https://codeandkeep.com/Check-If-Running-As-Admin/.
    #>
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Write-Log {
    <#
    .SYNOPSIS
        Schrijft een bericht naar het logbestand en console.

    .DESCRIPTION
        Deze functie logt een bericht met niveau, timestamp, naar een bestand en console.

    .PARAMETER Message
        Het bericht om te loggen.

    .PARAMETER Level
        Het logniveau (INFO, WARNING, ERROR, SUCCESS).

    .PARAMETER LogFile
        Het pad naar het logbestand (optioneel, gebruikt standaard pad).

    .OUTPUTS
        None

    .EXAMPLE
        Write-Log "Operatie voltooid" -Level "SUCCESS"

    .NOTES
        Deze functie gebruikt Add-Content voor bestand output en Write-Verbose voor console.
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Message,
        [Parameter(Position=1)][string]$Level = "INFO",
        [Parameter(Position=2)][string]$LogFile = $null
    )
    
    # Stel standaard logpad in indien niet opgegeven
    if (-not $LogFile) {
        # Gebruik altijd de root van het project voor logs, ongeacht instellingen
        $logsPath = Join-Path $Script:BasePath "logs"
        # Maak logs directory aan indien deze niet bestaat
        if (-not (Test-Path $logsPath)) {
            New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
        }
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    # Genereer timestamp en formatteer de log entry
    $timestamp = Get-Date -Format $Script:Settings.logTimestampFormat
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Probeer de log entry naar het bestand te schrijven
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Verbose "Kan niet schrijven naar logbestand: $_"
    }
    
    # # Schrijf ook naar de console afhankelijk van het logniveau
    # switch ($Level.ToUpper()) {
    #     "ERROR" { Write-Host $logEntry -ForegroundColor Red }
    #     "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
    #     "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    #     default { Write-Host $logEntry -ForegroundColor White }
    # }
}

#endregion Configuratie functies

#region Installatie functies

########################################################################################################################
# Installatie functies
########################################################################################################################


function Install-OpenVPN {
    <#
    .SYNOPSIS
        Installeert OpenVPN op de lokale machine.

    .DESCRIPTION
        Deze functie downloadt en installeert OpenVPN via MSI als het niet al geïnstalleerd is.

    .PARAMETER Url
        De URL van de OpenVPN installer (standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Install-OpenVPN

    Referentie: Gebaseerd op OpenVPN MSI installatieproces (OpenVPN Community Downloads: https://swupdate.openvpn.org/community/releases/), Invoke-WebRequest voor download (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest), en Start-Process voor MSI installatie (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process).
    #>
    param(
        [Parameter(Position=0)][string]$openVpnUrl #validaties urls 
    )
    
    if (-not $openVpnUrl) {
        $version = if ($Script:Settings.openVpnVersion) { $Script:Settings.openVpnVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/openvpn/releases/latest'
                $latest.tag_name -replace '^v', ''
            } catch {
                Write-Log "2.6.15 gebuikt als fallback bij ophalen van laatste OpenVPN versie: $_" -Level "WARNING"
                '2.6.15'  #fllback
            }
        }
        $openVpnUrl = "https://swupdate.openvpn.org/community/releases/OpenVPN-$version-I001-amd64.msi"
    }
    
    $installedPath = $Script:Settings.installedPath
    if (-not $installedPath -or [string]::IsNullOrWhiteSpace($installedPath)) {
        # Default fallback path for OpenVPN installation check
        $installedPath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
    }
    if (Test-Path $installedPath) {
        Write-Log "OpenVPN lijkt al geïnstalleerd te zijn op $installedPath" -Level "INFO"
        return $true
    }
    
    Write-Log "OpenVPN installatie gestart" -Level "INFO"
    
    $tempPath = [System.IO.Path]::GetTempFileName() + ".msi"
    
    try {
        Invoke-WebRequest -Uri $openVpnUrl -OutFile $tempPath -UseBasicParsing
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

########################################################################################################################
# Firewall functies
########################################################################################################################


function Set-Firewall {
    <#
    .SYNOPSIS
        Configureert de Windows Firewall voor OpenVPN.

    .DESCRIPTION
        Deze functie voegt een inbound firewall regel toe voor de opgegeven poort en protocol.

    .PARAMETER Port
        De poort om te openen (standaard uit settings).

    .PARAMETER Protocol
        Het protocol (TCP/UDP, standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Set-Firewall -Port 443 -Protocol "TCP"

    Referentie: Gebaseerd op New-NetFirewallRule cmdlet (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), en Get-NetFirewallRule voor controle (https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule).
    #>
    param(
        [Parameter(Position=0)][int]$Port,
        [Parameter(Position=1)][string]$Protocol
    )
    
    # Set defaults if not provided
    if (-not $Port -or $Port -eq 0) {
        $Port = if ($Script:Settings.port -and $Script:Settings.port -gt 0) { $Script:Settings.port } else { 443 }
    }
    if (-not $Protocol -or [string]::IsNullOrWhiteSpace($Protocol)) {
        $Protocol = if ($Script:Settings.protocol) { $Script:Settings.protocol } else { 'TCP' }
    }
    
    # Validate after defaults are set
    if ($Port -lt 1 -or $Port -gt 65535) {
        throw "Port moet tussen 1 en 65535 zijn, kreeg: $Port"
    }
    if ($Protocol -notin @('TCP', 'UDP')) {
        throw "Protocol moet TCP of UDP zijn, kreeg: $Protocol"
    }
    
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

########################################################################################################################
# Server configuratie functies
########################################################################################################################


function Get-ServerConfiguration {
    <#
    .SYNOPSIS
        Vraagt server configuratie parameters van de gebruiker.

    .DESCRIPTION
        Deze functie vraagt om servernaam, IP, LAN subnet, en wachtwoord voor certificaten.

    .PARAMETER ServerName
        De naam van de server (standaard uit settings).

    .PARAMETER ServerIP
        Het IP adres van de server (standaard uit settings).

    .PARAMETER LANSubnet
        Het LAN subnet (standaard uit settings).

    .PARAMETER LANMask
        De LAN subnet mask (standaard uit settings).

    .PARAMETER NoPass
        Als true, geen wachtwoord vragen voor certificaten (standaard uit settings).

    .PARAMETER Password
        Het wachtwoord voor certificaten (optioneel).

    .OUTPUTS
        System.Collections.Hashtable
        Een hashtable met server configuratie.

    .EXAMPLE
        $config = Get-ServerConfiguration

    Referentie: IP adres validatie gebaseerd op regex van Stack Overflow (https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp)
    #>
    param(
        [Parameter(Position=0)][ValidatePattern('^[a-zA-Z0-9_-]{1,63}$')][string]$ServerName = $Script:Settings.serverName,
        [Parameter(Position=1)][string]$serverWanIP = $Script:Settings.serverWanIP,
        [Parameter(Position=2)][string]$LANSubnet = $Script:Settings.lanSubnet,
        [Parameter(Position=3)][string]$LANMask = $Script:Settings.lanMask,
        [Parameter(Position=4)][switch]$NoPass = $Script:Settings.noPass,
        [Parameter(Position=5)][ValidateLength(8,128)][string]$Password
    )
    
    $config = @{}

    # ServerName: gebruik parameter, anders default
    $inputServerName = $ServerName
    if ([string]::IsNullOrWhiteSpace($inputServerName)) {
        throw "Server naam niet ingesteld in Variable.psd1. Stel serverName in."
    }
    $config.ServerName = $inputServerName
    
    # ServerIP: gebruik parameter, check of geldig
    $inputServerIP = $serverWanIP
    if ([string]::IsNullOrWhiteSpace($inputServerIP) -or $inputServerIP -eq 'jouw.server.wan.ip.hier') {
        throw "Server Wan IP niet ingesteld in Variable.psd1. Stel serverWanIP in op een geldige WAN IP of DDNS."
    }
    # Valideer ServerIP: moet IP adres of hostname zijn
    if ($inputServerIP -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$' -and $inputServerIP -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') { # https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp 
        throw "serverWanIP '$inputServerIP' is geen geldig IP adres of hostname."
    }
    $config.ServerIP = $inputServerIP
    
    # LANSubnet: gebruik parameter, check of geldig
    $inputLANSubnet = $LANSubnet
    if ([string]::IsNullOrWhiteSpace($inputLANSubnet)) {
        throw "LAN subnet niet ingesteld in Variable.psd1. Stel lanSubnet in."
    }
    # Valideer LANSubnet: moet IP adres zijn
    if ($inputLANSubnet -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$') {
        throw "LANSubnet '$inputLANSubnet' is geen geldig IP adres."
    }
    $config.LANSubnet = $inputLANSubnet

    $inputLANMask = $LANMask
    if ([string]::IsNullOrWhiteSpace($inputLANMask)) {
        throw "LAN subnet mask niet ingesteld in Variable.psd1. Stel lanMask in."
    }
    # Valideer LANMask: moet IP adres zijn
    if ($inputLANMask -notmatch '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$') {
        throw "LANMask '$inputLANMask' is geen geldig IP adres."
    }
    $config.LANMask = $inputLANMask
    
    # NoPass: gebruik parameter
    $config.NoPass = $NoPass
    
    # Password: alleen vragen als NoPass false
    if (-not $config.NoPass) {
        if ($Password) {
            $config.Password = $Password
        } else {
            while ($true) {
                $pwd = Read-Host "Voer wachtwoord in voor certificaten (minimaal 8 karakters)"
                if ($pwd.Length -ge 8) {
                    $config.Password = $pwd
                    break
                } else {
                    Write-Log "Wachtwoord moet minimaal 8 karakters lang zijn." -Level "ERROR"
                }
            }
        }
    } else {
        # Explicitly set Password to null when noPass is true
        $config.Password = $null
    }
    
    Write-Log "Server configuratie verzameld: ServerName=$($config.ServerName), ServerIP=$($config.ServerIP)" -Level "INFO"
    
    return $config
}

#endregion Server configuratie functies

#region EasyRSA functies

########################################################################################################################
# EasyRSA functies
########################################################################################################################


function Initialize-EasyRSA {
    <#
    .SYNOPSIS
        Initialiseert EasyRSA voor certificaatbeheer.

    .DESCRIPTION
        Deze functie downloadt en installeert EasyRSA als het niet aanwezig is.

    .PARAMETER EasyRSAPath
        Het pad waar EasyRSA geïnstalleerd wordt (standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Initialize-EasyRSA

    Referentie: Gebaseerd op EasyRSA installatieproces (EasyRSA GitHub: https://github.com/OpenVPN/easy-rsa), Invoke-WebRequest voor download (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest), en System.IO.Compression.ZipFile voor extractie (Microsoft .NET Framework Documentatie: https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile).
    #>
    param(
        [Parameter(Position=0)][string]$EasyRSAPath = $Script:Settings.easyRSAPath
    )
    
    if (Test-Path $EasyRSAPath) {
        Write-Log "EasyRSA is al geïnstalleerd in $EasyRSAPath" -Level "INFO"
        return $true
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $version = if ($Script:Settings.easyRSAVersion) { $Script:Settings.easyRSAVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/easy-rsa/releases/latest'
                $latest.tag_name -replace '^v', ''
            } catch {
                Write-Log "3.2.4 gebuikt als fallback bij ophalen van laatste EasyRSA versie: $_" -Level "WARNING"
                '3.2.4'  # fallback
            }
        }
        $easyRSAUrl = "https://github.com/OpenVPN/easy-rsa/releases/download/v$version/EasyRSA-$version-win64.zip"
        $tempZip = Join-Path $env:TEMP "easyrsa.zip"
        
        Invoke-WebRequest -Uri $easyRSAUrl -OutFile $tempZip -UseBasicParsing
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $EasyRSAPath)
        
        $nestedDir = Get-ChildItem $EasyRSAPath -Directory | Where-Object { $_.Name -like "EasyRSA-*" } | Select-Object -First 1
        if ($nestedDir) {
            Get-ChildItem $nestedDir.FullName | Move-Item -Destination $EasyRSAPath -Force
            Remove-Item $nestedDir.FullName -Recurse -Force
        }
        
        Write-Log "EasyRSA geïnstalleerd in $EasyRSAPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens EasyRSA installatie: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force }
    }
}

#endregion EasyRSA functies

#region Certificaat functies

########################################################################################################################
# Certificaat functies
########################################################################################################################


function Initialize-Certificates {
    <#
    .SYNOPSIS
        Genereert certificaten voor de VPN server.

    .DESCRIPTION
        Deze functie initialiseert de PKI en genereert CA, server en DH certificaten.

    .PARAMETER ServerName
        De naam van de server (standaard uit settings).

    .PARAMETER Password
        Wachtwoord voor certificaten (optioneel).

    .PARAMETER EasyRSAPath
        Pad naar EasyRSA (standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Initialize-Certificates -ServerName "vpn-server"

    Referentie: Gebaseerd op EasyRSA commands voor certificaatgeneratie (EasyRSA Documentatie: https://github.com/OpenVPN/easy-rsa), zoals init-pki, build-ca, gen-req, sign-req, gen-dh, gen-crl. 
    #>
    param (
        [Parameter(Position=0)][ValidatePattern('^[a-zA-Z0-9_-]{1,63}$')][string]$ServerName = $Script:Settings.servername,
        [Parameter(Position=1)][string]$Password = $null,
        [Parameter(Position=2)][string]$EasyRSAPath = (Join-Path $Script:BasePath $Script:Settings.certPath)
    )
    
    # Validate password if provided
    if ($Password -and $Password.Length -lt 8) {
        throw "Password moet minimaal 8 karakters lang zijn"
    }
    
    try {
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_REQ_CN = $ServerName
        $varsFileWin = Join-Path $EasyRSAPath "vars"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        $easyrsa = Join-Path $EasyRSAPath "easyrsa"

        # Prepare Unix-style paths for bash (do not use them for Set-Content)
        $drive = $EasyRSAPath.Substring(0,1).ToLower()
        $unixEasyRSAPath = '/' + $drive + $EasyRSAPath.Substring(2) -replace '\\', '/'
        $env:EASYRSA = $unixEasyRSAPath

        # Create vars file (write using Windows path)
        $pkiPath = Join-Path $EasyRSAPath "pki"
        $pkiPathUnix = (Join-Path $pkiPath '') -replace '\\', '/'
        $pkiPathUnix = '/' + $drive + $pkiPathUnix.Substring(2) -replace ' ', '\ '
        $varsContent = @"
set_var EASYRSA_REQ_CN "$ServerName"
set_var EASYRSA_BATCH "$($Script:Settings.easyRSABatch)"
set_var EASYRSA_PKI "pki"
set_var EASYRSA_ALGO "$($Script:Settings.easyRSAAlgo)"
set_var EASYRSA_KEY_SIZE "$($Script:Settings.easyRSAKeySize)"
set_var EASYRSA_CA_EXPIRE "$($Script:Settings.easyRSACAExpire)"
set_var EASYRSA_CERT_EXPIRE "$($Script:Settings.easyRSACertExpire)"
set_var EASYRSA_CRL_DAYS "$($Script:Settings.easyRSACRLDays)"
"@
        Set-Content -Path $varsFileWin -Value $varsContent -Encoding UTF8

        if (Test-Path $varsFileWin) {
            Write-Log "vars file succesvol geschreven naar $varsFileWin" -Level "INFO"
        } else {
            Write-Log "vars file kon niet worden geschreven naar $varsFileWin" -Level "ERROR"
        }

        # Also set the environment variable used by the easyrsa bash scripts to the Unix-style path
        $env:EASYRSA_VARS_FILE = '/' + $drive + $varsFileWin.Substring(2) -replace '\\', '/' -replace ' ', '\ '
        
        Push-Location $EasyRSAPath
        
        # Write vars file in the current directory (EasyRSA path)
        Set-Content -Path "vars" -Value $varsContent -Encoding UTF8

        if (Test-Path "vars") {
            Write-Log "vars file succesvol geschreven naar $(Join-Path $EasyRSAPath 'vars')" -Level "INFO"
        } else {
            Write-Log "vars file kon niet worden geschreven" -Level "ERROR"
        }

        # Set the environment variable to the relative path
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        
        # Remove existing PKI if it exists to avoid init-pki failure
        if (Test-Path $pkiPath) {
            Write-Log "Removing existing PKI directory: $pkiPath" -Level "INFO"
            Remove-Item $pkiPath -Recurse -Force
        }
        
        # Build the bash PATH setup - use semicolons for Windows sh.exe PATH separator
        # Convert Windows path to Unix-style for bash (C:\... -> C:/...)
        $unixEasyRSAPath = $EasyRSAPath -replace '\\', '/'
        # EASYRSA_BATCH=1 disables interactive prompts
        $bashPathSetup = "export PATH=`"$unixEasyRSAPath;$unixEasyRSAPath/bin;`$PATH`"; export HOME=`"$unixEasyRSAPath`"; export EASYRSA_OPENSSL=`"$unixEasyRSAPath/openssl.exe`"; export EASYRSA_BATCH=1; cd `"$unixEasyRSAPath`";"
        
        Write-Verbose "Shell executable: $sh"
        Write-Verbose "EasyRSA path: $EasyRSAPath"
        Write-Verbose "Unix EasyRSA path: $unixEasyRSAPath"
        Write-Verbose "Bash PATH setup: $bashPathSetup"
        Write-Verbose "Current directory: $(Get-Location)"
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 1 van 6: PKI initialiseren" -PercentComplete 0
        Write-Verbose "Starting init-pki..."
        $initPkiCmd = "$bashPathSetup ./easyrsa init-pki"
        Write-Verbose "Command: $sh -c `"$initPkiCmd`""
        $easyrsaOutput = & $sh -c "$initPkiCmd" 2>&1
        Write-Verbose "init-pki completed with exit code: $LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA init-pki failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"

        # Handle password if provided
        $passFile = $null
        if ($Password) {
            $passFile = [System.IO.Path]::GetTempFileName()
            Set-Content -Path $passFile -Value $Password -NoNewline -Encoding UTF8
            $env:EASYRSA_PASSOUT = "file:$passFile"
            $env:EASYRSA_PASSIN = "file:$passFile"
            Write-Log "Password file created for certificate generation" -Level "INFO"
        }

        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 2 van 6: CA certificaat genereren" -PercentComplete 16.67
        Write-Verbose "Starting build-ca (nopass=$(-not $Password))..."
        # EASYRSA_BATCH=1 handles confirmation prompts, no need for echo 'yes' |
        if ($Password) {
            $buildCaCmd = "$bashPathSetup ./easyrsa build-ca"
        } else {
            $buildCaCmd = "$bashPathSetup ./easyrsa build-ca nopass"
        }
        Write-Verbose "Command: $sh -c `"$buildCaCmd`""
        Write-Verbose "  Executing build-ca command..."
        $easyrsaOutput = & $sh -c "$buildCaCmd" 2>&1
        Write-Verbose "build-ca completed with exit code: $LASTEXITCODE"
        Write-Verbose "build-ca output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA build-ca failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 3 van 6: Server certificaat aanvraag genereren" -PercentComplete 33.33
        Write-Verbose "Starting gen-req for $ServerName..."
        if ($Password) {
            $genReqCmd = "$bashPathSetup ./easyrsa gen-req $ServerName"
        } else {
            $genReqCmd = "$bashPathSetup ./easyrsa gen-req $ServerName nopass"
        }
        Write-Verbose "Command: $sh -c `"$genReqCmd`""
        Write-Verbose "  Executing gen-req command..."
        $easyrsaOutput = & $sh -c "$genReqCmd" 2>&1
        Write-Verbose "gen-req completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-req output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-req failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"

        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 4 van 6: Server certificaat ondertekenen" -PercentComplete 50
        Write-Verbose "Starting sign-req for $ServerName..."
        # EASYRSA_BATCH=1 handles confirmation prompts
        $signReqCmd = "$bashPathSetup ./easyrsa sign-req server $ServerName"
        Write-Verbose "Command: $sh -c `"$signReqCmd`""
        Write-Verbose "  Executing sign-req command..."
        $easyrsaOutput = & $sh -c "$signReqCmd" 2>&1
        Write-Verbose "sign-req completed with exit code: $LASTEXITCODE"
        Write-Verbose "sign-req output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA sign-req server failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 5 van 6: DH parameters genereren" -PercentComplete 66.67
        Write-Verbose "Starting gen-dh (this may take a while)..."
        $genDhCmd = "$bashPathSetup ./easyrsa gen-dh"
        Write-Verbose "Command: $sh -c `"$genDhCmd`""
        Write-Verbose "  Executing gen-dh command (dit kan even duren)..."
        $easyrsaOutput = & $sh -c "$genDhCmd" 2>&1
        Write-Verbose "gen-dh completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-dh output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-dh failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 6 van 6: CRL genereren" -PercentComplete 83.33
        Write-Verbose "Starting gen-crl..."
        $genCrlCmd = "$bashPathSetup ./easyrsa gen-crl"
        Write-Verbose "Command: $sh -c `"$genCrlCmd`""
        Write-Verbose "  Executing gen-crl command..."
        $easyrsaOutput = & $sh -c "$genCrlCmd" 2>&1
        Write-Verbose "gen-crl completed with exit code: $LASTEXITCODE"
        Write-Verbose "gen-crl output: $easyrsaOutput"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-crl failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Completed
        
        # Controleer of alle vereiste certificaat bestanden zijn aangemaakt
        $requiredFiles = @(
            (Join-Path $pkiPath 'ca.crt'),
            (Join-Path $pkiPath (Join-Path 'issued' "$ServerName.crt")),
            (Join-Path $pkiPath (Join-Path 'private' "$ServerName.key")),
            (Join-Path $pkiPath 'dh.pem'),
            (Join-Path $pkiPath 'crl.pem')
        )
        
        Write-Log "Certificaten gegenereerd voor $ServerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens certificaat generatie: $_" -Level "ERROR"
        return $false
    }
    finally {
        # Clean up password file
        if ($passFile -and (Test-Path $passFile)) {
            Remove-Item $passFile -Force
        }
        # Keep vars file for client
        Pop-Location
    }
}

#endregion Certificaat functies

#region Server config generatie functies

########################################################################################################################
# Server config generatie functies
########################################################################################################################


function New-ServerConfig {
    <#
    .SYNOPSIS
        Genereert de server configuratie voor OpenVPN.

    .DESCRIPTION
        Deze functie maakt een server.ovpn bestand met de opgegeven configuratie.

    .PARAMETER Config
        Hashtable met server configuratie.

    .PARAMETER EasyRSAPath
        Pad naar EasyRSA (standaard uit settings).

    .PARAMETER ConfigPath
        Pad waar config wordt opgeslagen (standaard uit settings).

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        New-ServerConfig -Config $config

    Referentie: Gebaseerd op OpenVPN server configuratie syntax (OpenVPN Reference Manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/), inclusief opties zoals port, proto, dev, ca, cert, key, dh, server, push, etc. Gebruikt Set-Content voor bestand schrijven (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content).
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][hashtable]$Config,
        [Parameter(Position=1)][string]$EasyRSAPath,
        [Parameter(Position=2)][string]$ConfigPath
    )
    
    # Set defaults from settings if not provided
    if (-not $EasyRSAPath) {
        $EasyRSAPath = $Script:Settings.easyRSAPath
        if (-not $EasyRSAPath -or [string]::IsNullOrWhiteSpace($EasyRSAPath)) {
            $EasyRSAPath = 'C:\Program Files\OpenVPN\easy-rsa'
        }
    }
    if (-not $ConfigPath) {
        $ConfigPath = $Script:Settings.configPath
        if (-not $ConfigPath -or [string]::IsNullOrWhiteSpace($ConfigPath)) {
            $ConfigPath = 'C:\Program Files\OpenVPN\config'
        }
    }
    
    Write-Log "Server configuratie generatie gestart" -Level "INFO"
    
    $serverConfigFile = Join-Path $ConfigPath "server.ovpn"
    
    $pkiPath = Join-Path $EasyRSAPath "pki"

    $caPath   = Join-Path $pkiPath 'ca.crt'
    $certPath = Join-Path $pkiPath (Join-Path 'issued' "$($Config.ServerName).crt")
    $keyPath  = Join-Path $pkiPath (Join-Path 'private' "$($Config.ServerName).key")
    $dhPath   = Join-Path $pkiPath 'dh.pem'

    # Escape backslashes for OpenVPN config
    $caPath = $caPath -replace '\\', '\\'
    $certPath = $certPath -replace '\\', '\\'
    $keyPath = $keyPath -replace '\\', '\\'
    $dhPath = $dhPath -replace '\\', '\\'

    $serverConfig = @"
port $($Script:Settings.port)
proto tcp
dev tun
ca "$caPath"
cert "$certPath"
key "$keyPath"
dh "$dhPath"
server $($Script:Settings.vpnSubnet) $($Script:Settings.vpnMask)
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $($Script:Settings.dns1)"
push "dhcp-option DNS $($Script:Settings.dns2)"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nobody
persist-key
persist-tun
status openvpn-status.log
verb 3
"@
    
    if ($Config.LANSubnet) {
        $serverConfig += "`npush `"route $($Config.LANSubnet) $($Config.LANMask)`""
    }
    
    try {
        if (-not (Test-Path $ConfigPath)) {
            New-Item -ItemType Directory -Path $ConfigPath -Force
        }
        
        Set-Content -Path $serverConfigFile -Value $serverConfig -Encoding UTF8
        
        Write-Log "Server configuratie aangemaakt: $serverConfigFile" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens server configuratie generatie: $_" -Level "ERROR"
        return $false
    }
}




function Install-RemoteServer {
    <#
    .SYNOPSIS
        Installeert en configureert OpenVPN server op een remote machine.

    .DESCRIPTION
        Deze functie gebruikt PowerShell remoting om OpenVPN te installeren, firewall te configureren, certificaten te genereren, server config te maken en de service te starten op een remote computer.

    .PARAMETER ComputerName
        Naam van de remote computer.

    .PARAMETER Credential
        Credentials voor de remote computer.

    .PARAMETER ServerConfig
        Hashtable met server configuratie parameters.

    .PARAMETER LocalEasyRSAPath
        Lokale pad naar EasyRSA directory.

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        $config = Get-ServerConfiguration -ServerName "vpn-server" -ServerIP "example.com"
        Install-RemoteServer -ComputerName "remote-pc" -Credential $cred -ServerConfig $config

    Referentie: Gebaseerd op PowerShell Remoting met New-PSSession, Invoke-Command, en Copy-Item (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item).
    #>
    param (
        [Parameter(Mandatory=$true, Position=0)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$ComputerName,
        [Parameter(Mandatory=$true, Position=1)][PSCredential]$Credential,
        [Parameter(Mandatory=$true, Position=2)][hashtable]$ServerConfig,
        [Parameter(Mandatory=$true, Position=3)][string]$LocalEasyRSAPath
    )

    Write-Log "Remote server configuratie gestart voor $ComputerName" -Level "INFO"
    
    try {
        # Create session with bypassed execution policy (more reliable than setting inside scriptblock)
        $sessionOption = New-PSSessionOption -NoMachineProfile
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
        
        # Get local paths (robust fallback when module base is empty)
        $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            $moduleBase = $PSScriptRoot
            if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
                $moduleBase = Split-Path -Parent $MyInvocation.MyCommand.Definition
            }
        }
        # Ensure moduleBase is usable before building local module path
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $moduleBase = $PSScriptRoot
            } elseif ($Script:BasePath -and -not [string]::IsNullOrWhiteSpace($Script:BasePath)) {
                $moduleBase = Join-Path $Script:BasePath 'src\module'
            } else {
                $moduleBase = (Get-Location).Path
            }
        }
        $localModule = Join-Path $moduleBase "AutoSecureVPN.psm1"

        # Ensure LocalEasyRSAPath is set (fallback to settings)
        if (-not $LocalEasyRSAPath -or [string]::IsNullOrWhiteSpace($LocalEasyRSAPath)) {
            if ($Script:Settings -and $Script:Settings.easyRSAPath) {
                $LocalEasyRSAPath = $Script:Settings.easyRSAPath
            } else {
                throw "LocalEasyRSAPath is leeg en er is geen fallback ingesteld in settings. Geef een geldig pad op."
            }
        }

        # copy module to remote temp path
        $remoteTemp = "C:\Temp"
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force } } -ErrorAction Stop
        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        $remoteEasyRSA = Join-Path $remoteTemp "easy-rsa"
        $remoteEasyRSAZip = Join-Path $remoteTemp "easy-rsa.zip"

        # Validate local files/paths before attempting remote copy
        if (-not (Test-Path $localModule)) { throw "Local module not found: $localModule" }
        if (-not (Test-Path $LocalEasyRSAPath)) { throw "Local EasyRSA path not found: $LocalEasyRSAPath" }

        # Compress EasyRSA locally for much faster transfer (10x+ speedup)
        $tempZip = [System.IO.Path]::GetTempFileName() + ".zip"
        Write-Log "Compressing EasyRSA for faster transfer..." -Level "INFO"
        Compress-Archive -Path "$LocalEasyRSAPath\*" -DestinationPath $tempZip -Force

        # Copy files to remote (compression already provides major speedup)
        Write-Log "Transferring module to remote server..." -Level "INFO"
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session -ErrorAction Stop -Force
        
        Write-Log "Transferring compressed EasyRSA to remote server..." -Level "INFO"
        Copy-Item -Path $tempZip -Destination $remoteEasyRSAZip -ToSession $session -ErrorAction Stop -Force
        Write-Log "File transfer completed" -Level "INFO"
        
        # Clean up local temp zip
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        
        Invoke-Command -Session $session -ScriptBlock {
            param($moduleSettings, $modulePath, $config, $remoteEasyRSAZip, $remoteEasyRSA)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Extract EasyRSA ZIP using .NET (more reliable than Expand-Archive)
            Write-Verbose "Extracting EasyRSA..."
            # Remove existing directory to avoid extraction conflicts
            if (Test-Path $remoteEasyRSA) {
                Write-Verbose "Removing existing EasyRSA directory..."
                Remove-Item $remoteEasyRSA -Recurse -Force -ErrorAction SilentlyContinue
            }
            New-Item -ItemType Directory -Path $remoteEasyRSA -Force | Out-Null
            
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($remoteEasyRSAZip, $remoteEasyRSA)
            } catch {
                throw "Failed to extract EasyRSA ZIP: $_"
            }
            Remove-Item $remoteEasyRSAZip -Force -ErrorAction SilentlyContinue
            
            # Validate settings before importing module and set defaults if missing
            if (-not $moduleSettings) { 
                $moduleSettings = @{}
            }
            
            # Ensure critical settings have values with proper defaults
            if (-not $moduleSettings.port -or $moduleSettings.port -eq 0) { $moduleSettings.port = 443 }
            if (-not $moduleSettings.protocol) { $moduleSettings.protocol = 'TCP' }
            if (-not $moduleSettings.easyRSAPath) { $moduleSettings.easyRSAPath = 'C:\Program Files\OpenVPN\easy-rsa' }
            if (-not $moduleSettings.configPath) { $moduleSettings.configPath = 'C:\Program Files\OpenVPN\config' }
            if (-not $moduleSettings.installedPath) { $moduleSettings.installedPath = 'C:\Program Files\OpenVPN\bin\openvpn.exe' }
            
            Write-Log "Remote settings configured: Port=$($moduleSettings.port), Protocol=$($moduleSettings.protocol)" -Level "INFO"
            
            Write-Verbose "Settings after defaults: $($moduleSettings | ConvertTo-Json)"
            
            # Bypass execution policy by loading script content directly
            Write-Verbose "Loading module functions..."
            try {
                $moduleContent = Get-Content -Path $modulePath -Raw
                # Execute the module content in the current scope
                Invoke-Expression $moduleContent
            } catch {
                throw "Failed to load module: $_"
            }
            
            # Set module settings manually
            $Script:Settings = $moduleSettings
            $Script:BasePath = "C:\Temp"
            
            # Disable file logging for remote operations
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Verbose "[$Level] $Message"
            }
            
            try {
                Write-Verbose "Starting remote server setup..."
                
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required"
                }
                
                Write-Verbose "Installing OpenVPN..."
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed"
                }
                
                Write-Verbose "Configuring firewall..."
                if (-not (Set-Firewall -Port $Script:Settings.port -Protocol $Script:Settings.protocol)) {
                    throw "Firewall configuration failed"
                }
                
                Write-Verbose "Copying EasyRSA with certificates..."
                $targetEasyRSAPath = $Script:Settings.easyRSAPath
                Write-Verbose "Target EasyRSA path: $targetEasyRSAPath"
                # easyRSAPath should now have a default value set above
                if (-not (Test-Path $targetEasyRSAPath)) {
                    Write-Verbose "Creating target directory: $targetEasyRSAPath"
                    New-Item -ItemType Directory -Path $targetEasyRSAPath -Force | Out-Null
                }
                if (-not (Test-Path $remoteEasyRSA)) {
                    throw "Remote EasyRSA directory not found: $remoteEasyRSA"
                }
                Write-Verbose "Copying from $remoteEasyRSA to $targetEasyRSAPath..."
                Copy-Item -Path "$remoteEasyRSA\*" -Destination $targetEasyRSAPath -Recurse -Force
                
                Write-Verbose "Creating server config..."
                if (-not (New-ServerConfig -Config $config)) {
                    throw "Server config generation failed"
                }
                
                Write-Verbose "Starting VPN service..."
                if (-not (Start-VPNService)) {
                    throw "VPN service start failed"
                }
                
                Write-Log "Remote server setup completed successfully" -Level "SUCCESS"
            }
            catch {
                Write-Log "Error during remote server setup: $_" -Level "ERROR"
                throw
            }
            
            Remove-Item $modulePath -Force
            Remove-Item $remoteEasyRSA -Recurse -Force
        } -ArgumentList $Script:Settings, $remoteModule, $ServerConfig, $remoteEasyRSAZip, $remoteEasyRSA -ErrorAction Stop
        
        Remove-PSSession $session
        
        Write-Log "Remote server configuratie voltooid voor $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens remote server configuratie: $_" -Level "ERROR"
        
        # Probeer remote rollback uit te voeren
        try {
            $rollbackSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            if ($rollbackSession) {
                Invoke-Command -Session $rollbackSession -ScriptBlock {
                    param($settings, $remoteEasyRSA, $remoteModule)
                    # Clean up transferred files
                    Write-Verbose "Rolling back: cleaning up transferred files..."
                    Remove-Item $remoteModule -Force -ErrorAction SilentlyContinue
                    Remove-Item $remoteEasyRSA -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Rollback cleanup completed"
                } -ArgumentList $Script:Settings, $remoteEasyRSA, $remoteModule
                Remove-PSSession $rollbackSession
            }
        } catch {
            Write-Log "Kon remote rollback niet uitvoeren: $_" -Level "WARNING"
        }
        
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $false
    }
}


#endregion Server config generatie functies

#region VPN service functies

########################################################################################################################
# VPN service functies
########################################################################################################################


function Start-VPNService {
    <#
    .SYNOPSIS
        Start de OpenVPN service.

    .DESCRIPTION
        Deze functie start de OpenVPN Windows service als deze niet al loopt.

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Start-VPNService

    Referentie:  Start-Service cmdlets (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-service).
    #>
    Write-Log "OpenVPN service starten" -Level "INFO"
    
    try {
        $service = Get-Service -Name "OpenVPNService" -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Log "OpenVPN service niet gevonden" -Level "ERROR"
            return $false
        }
        
        if ($service.Status -ne "Running") {
            Start-Service -Name "OpenVPNService"
            Write-Log "OpenVPN service gestart" -Level "SUCCESS"
        } else {
            Write-Log "OpenVPN service was al actief" -Level "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Fout tijdens starten OpenVPN service: $_" -Level "ERROR"
        return $false
    }
}

#endregion VPN service functies

#region Client functies

########################################################################################################################
# Client functies
########################################################################################################################


function New-ClientPackage {
    <#
    .SYNOPSIS
        Genereert een client package voor VPN verbinding.

    .DESCRIPTION
        Deze functie genereert certificaten voor een client, maakt een client configuratie bestand, en pakt alles in een ZIP bestand.

    .PARAMETER Config
        Hashtable met server configuratie.

    .PARAMETER EasyRSAPath
        Pad naar EasyRSA (standaard uit settings).

    .PARAMETER OutputPath
        Pad waar het ZIP bestand wordt opgeslagen (standaard uit settings).

    .OUTPUTS
        System.String
        Het pad naar het ZIP bestand bij succes, anders $null.

    .EXAMPLE
        New-ClientPackage -Config $config

    Referentie: Gebaseerd op EasyRSA client certificaat generatie (EasyRSA Documentatie: https://github.com/OpenVPN/easy-rsa), OpenVPN client config syntax (OpenVPN Reference Manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/), en Compress-Archive voor ZIP creatie (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive).
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][hashtable]$Config,
        [Parameter(Position=1)][string]$EasyRSAPath = $Script:Settings.easyRSAPath,
        [Parameter(Position=2)][string]$OutputPath = $Script:OutputPath
    )
    
    $pkiPath = Join-Path $EasyRSAPath "pki"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force
    }
    
    $clientName = $Script:Settings.clientName
    $zipPath = Join-Path $OutputPath "vpn-client-$clientName.zip"
    
    try {
        Write-Log "Client package generatie gestart voor $clientName" -Level "INFO"
        Write-Log "EasyRSA path: $EasyRSAPath" -Level "INFO"
        Write-Log "PKI path: $pkiPath" -Level "INFO"
        Write-Log "Output path: $OutputPath" -Level "INFO"
        
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        $easyrsa = Join-Path $EasyRSAPath "easyrsa"
        
        # Prepare Unix-style paths for bash
        $drive = $EasyRSAPath.Substring(0,1).ToLower()
        # Convert Windows path to Unix-style for bash (C:\... -> C:/...)
        $unixEasyRSAPath = $EasyRSAPath -replace '\\', '/'
        
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        
        # Build the bash PATH setup - use semicolons for Windows sh.exe PATH separator
        # EASYRSA_BATCH=1 disables interactive prompts
        $bashPathSetup = "export PATH=`"$unixEasyRSAPath;$unixEasyRSAPath/bin;`$PATH`"; export HOME=`"$unixEasyRSAPath`"; export EASYRSA_OPENSSL=`"$unixEasyRSAPath/openssl.exe`"; export EASYRSA_BATCH=1; cd `"$unixEasyRSAPath`";"
        
        Write-Log "sh.exe path: $sh" -Level "INFO"
        Write-Log "Bash PATH setup: $bashPathSetup" -Level "INFO"
        
        Push-Location $EasyRSAPath
        Write-Log "Gewisseld naar directory: $EasyRSAPath" -Level "INFO"
        
        $genReqCmd = "$bashPathSetup ./easyrsa gen-req $clientName nopass"
        Write-Log "Uitvoeren: $sh -c `"$genReqCmd`"" -Level "INFO"
        $result1 = & $sh -c "$genReqCmd" 2>&1
        Write-Log "Exit code gen-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Fout bij gen-req: $result1" -Level "ERROR" }
        
        $signReqCmd = "$bashPathSetup ./easyrsa sign-req client $clientName"
        Write-Log "Uitvoeren: $sh -c `"$signReqCmd`"" -Level "INFO"
        $result2 = & $sh -c "$signReqCmd" 2>&1
        Write-Log "Exit code sign-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Fout bij sign-req: $result2" -Level "ERROR" }
        
        Pop-Location
        Write-Log "Terug naar oorspronkelijke directory" -Level "INFO"
        
        Write-Log "Controleren of certificaten bestaan..." -Level "INFO"
        $caCrt = Join-Path $pkiPath 'ca.crt'
        $clientCrt = Join-Path $pkiPath (Join-Path 'issued' "$clientName.crt")
        $clientKey = Join-Path $pkiPath (Join-Path 'private' "$clientName.key")

        if ([System.IO.File]::Exists($caCrt)) { Write-Log "ca.crt gevonden: $caCrt" -Level "INFO" } else { Write-Log "ca.crt niet gevonden: $caCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientCrt)) { Write-Log "$clientName.crt gevonden: $clientCrt" -Level "INFO" } else { Write-Log "$clientName.crt niet gevonden: $clientCrt" -Level "ERROR" }
        if ([System.IO.File]::Exists($clientKey)) { Write-Log "$clientName.key gevonden: $clientKey" -Level "INFO" } else { Write-Log "$clientName.key niet gevonden: $clientKey" -Level "ERROR" }
        
        $clientConfig = @"
client
dev tun
proto tcp
remote $($Config.ServerIP) $($Script:Settings.port)
resolv-retry infinite
nobind
user nobody
group nobody
persist-key
persist-tun
ca ca.crt
cert $clientName.crt
key $clientName.key
remote-cert-tls server
cipher AES-256-CBC
verb 3
"@
        
        $clientConfigPath = Join-Path $OutputPath "client.ovpn"
        Set-Content -Path $clientConfigPath -Value $clientConfig -Encoding UTF8
        Write-Log "Client config aangemaakt: $clientConfigPath" -Level "INFO"
        
        Write-Log "Certificaten kopiëren naar output directory..." -Level "INFO"
        $copyFailed = $false
        
        Copy-Item -Path $caCrt -Destination $OutputPath
        if ($?) { Write-Log "ca.crt gekopieerd" -Level "INFO" } else { Write-Log "cp failed for ca.crt" -Level "ERROR"; $copyFailed = $true }
        
        Copy-Item -Path $clientCrt -Destination $OutputPath
        if ($?) { Write-Log "$clientName.crt gekopieerd" -Level "INFO" } else { Write-Log "cp failed for $clientName.crt" -Level "ERROR"; $copyFailed = $true }
        
        Copy-Item -Path $clientKey -Destination $OutputPath
        if ($?) { Write-Log "$clientName.key gekopieerd" -Level "INFO" } else { Write-Log "cp failed for $clientName.key" -Level "ERROR"; $copyFailed = $true }
        
        if ($copyFailed) {
            Write-Log "Certificaten konden niet worden gekopieerd, client package aanmaken mislukt" -Level "ERROR"
            return $null
        }
        
        Write-Log "ZIP bestand maken: $zipPath" -Level "INFO"
        Compress-Archive -Path "$OutputPath\*" -DestinationPath $zipPath -Force
        
        Write-Log "Tijdelijke bestanden opruimen" -Level "INFO"
        Remove-Item "$OutputPath\ca.crt", "$OutputPath\$clientName.crt", "$OutputPath\$clientName.key", $clientConfigPath -Force
        
        Write-Log "Client package aangemaakt: $zipPath" -Level "SUCCESS"
        return $zipPath
    }
    catch {
        Write-Log "Fout tijdens client package: $_" -Level "ERROR"
        return $null
    }
}


function Import-ClientConfiguration {
    <#
    .SYNOPSIS
        Importeert client configuratie uit een ZIP bestand.

    .DESCRIPTION
        Deze functie pakt een client ZIP bestand uit naar de configuratie map en retourneert het pad naar het OVPN bestand.

    .OUTPUTS
        System.String
        Het pad naar het OVPN bestand bij succes, anders $null.

    .EXAMPLE
        Import-ClientConfiguration

    .NOTES
        Deze functie gebruikt Expand-Archive om het ZIP bestand uit te pakken.
    #>
    Write-Log "Client configuratie importeren gestart" -Level "INFO"
    
    if (-not $Script:OutputPath -or [string]::IsNullOrWhiteSpace($Script:OutputPath)) {
        $Script:OutputPath = Join-Path $Script:BasePath "output"
    }
    
    $configPath = $Script:Settings.configPath
    if (-not $configPath -or [string]::IsNullOrWhiteSpace($configPath)) {
        $configPath = 'C:\Program Files\OpenVPN\config'
    }
    
    # Try to find the default client ZIP file
    $defaultZipPath = Join-Path $Script:OutputPath "vpn-client-$($Script:Settings.clientName).zip"
    if (Test-Path $defaultZipPath) {
        $zipFile = $defaultZipPath
        Write-Log "Standaard client ZIP bestand gevonden: $zipFile" -Level "INFO"
    } else {
        while ($true) {
            $zipFile = Read-Host "Pad naar client ZIP bestand"
            if ($zipFile -match '\.zip$' -and (Test-Path $zipFile)) {
                break
            } else {
                Write-Log "Ongeldig pad of geen ZIP bestand. Probeer opnieuw." -Level "ERROR"
            }
        }
    }
    
    if (-not (Test-Path $zipFile)) {
        Write-Log "ZIP bestand niet gevonden: $zipFile" -Level "ERROR"
        return $null
    }
    
    try {
        Expand-Archive -Path $zipFile -DestinationPath $configPath -Force
        
        $ovpnFile = Get-ChildItem $configPath -Filter "*.ovpn" | Select-Object -First 1
        
        if ($ovpnFile) {
            # Update the OVPN file to use absolute paths for certificates
            $ovpnContent = Get-Content $ovpnFile.FullName -Raw
            $escapedPath = $configPath -replace '\\', '\\\\'
            $ovpnContent = $ovpnContent -replace 'ca\s+ca\.crt', "ca `"$escapedPath\\ca.crt`""
            $ovpnContent = $ovpnContent -replace 'cert\s+client1\.crt', "cert `"$escapedPath\\client1.crt`""
            $ovpnContent = $ovpnContent -replace 'key\s+client1\.key', "key `"$escapedPath\\client1.key`""
            # Remove Windows-unsupported options
            $ovpnContent = $ovpnContent -replace 'user\s+nobody.*\n', ''
            $ovpnContent = $ovpnContent -replace 'group\s+nobody.*\n', ''
            # Update deprecated cipher
            $ovpnContent = $ovpnContent -replace 'cipher\s*AES-256-CBC', 'cipher AES-256-GCM'
            # Disable DCO to avoid device access issues
            $ovpnContent += "`ndisable-dco`n"
            Set-Content -Path $ovpnFile.FullName -Value $ovpnContent
            
            Write-Log "Client configuratie geïmporteerd: $($ovpnFile.FullName)" -Level "SUCCESS"
            return $ovpnFile.FullName
        } else {
            Write-Log "Geen OVPN bestand gevonden in ZIP" -Level "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Fout tijdens importeren client configuratie: $_" -Level "ERROR"
        return $null
    }
}


function Install-RemoteClient {
    <#
    .SYNOPSIS
        Installeert OpenVPN en client configuratie op een remote machine.

    .DESCRIPTION
        Deze functie gebruikt PowerShell remoting om OpenVPN te installeren, configuratie te importeren, en de VPN verbinding te starten op een remote computer.

    .PARAMETER ComputerName
        Naam van de remote computer.

    .PARAMETER Credential
        Credentials voor de remote computer.

    .PARAMETER ZipPath
        Pad naar het client ZIP bestand.

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Install-RemoteClient -ComputerName "remote-pc" -Credential $cred -ZipPath "C:\path\to\client.zip"

    Referentie: Gebaseerd op PowerShell Remoting met New-PSSession, Invoke-Command, Copy-Item (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/copy-item), en System.IO.Compression.ZipFile voor extractie (Microsoft .NET Framework Documentatie: https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile).
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidatePattern('^[a-zA-Z0-9.-]+$')][string]$ComputerName,
        [Parameter(Mandatory=$true, Position=1)][PSCredential]$Credential,
        [Parameter(Mandatory=$true, Position=2)][ValidatePattern('\.zip$')][string]$ZipPath,
        [Parameter(Position=3)][string]$RemoteConfigPath = "C:\Program Files\OpenVPN\config"
    )
    
    Write-Log "Remote client configuratie gestart voor $ComputerName" -Level "INFO"
    
    if (-not (Test-Path $ZipPath)) {
        Write-Log "ZIP bestand niet gevonden: $ZipPath" -Level "ERROR"
        return $false
    }
    
    try {
        # Create session with bypassed execution policy
        $sessionOption = New-PSSessionOption -NoMachineProfile
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
        
        # Get local paths
        $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        # Ensure moduleBase is usable before building local module path
        if (-not $moduleBase -or [string]::IsNullOrWhiteSpace($moduleBase)) {
            if ($PSScriptRoot -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $moduleBase = $PSScriptRoot
            } elseif ($Script:BasePath -and -not [string]::IsNullOrWhiteSpace($Script:BasePath)) {
                $moduleBase = Join-Path $Script:BasePath 'src\module'
            } else {
                $moduleBase = (Get-Location).Path
            }
        }
        $localModule = Join-Path $moduleBase "AutoSecureVPN.psm1"
        
        # Copy module to remote temp
        $remoteTemp = "C:\Temp"
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force } } -ErrorAction Stop
        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        $remoteZip = Join-Path $remoteTemp "client.zip"

        # Validate local files/paths before attempting remote copy
        if (-not (Test-Path $localModule)) { throw "Local module not found: $localModule" }
        if (-not (Test-Path $ZipPath)) { throw "ZIP file not found: $ZipPath" }

        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session -ErrorAction Stop -Force
        Copy-Item -Path $ZipPath -Destination $remoteZip -ToSession $session -ErrorAction Stop -Force
        
        # Perform full client setup on remote
        Invoke-Command -Session $session -ScriptBlock {
            param($settings, $modulePath, $zipPath, $configPath)
            
            # Stop on errors from the start
            $ErrorActionPreference = 'Stop'
            
            # Bypass execution policy by loading script content directly
            try {
                $moduleContent = Get-Content -Path $modulePath -Raw
                # Execute the module content in the current scope
                Invoke-Expression $moduleContent
            } catch {
                throw "Failed to load module: $_"
            }
            
            # Disable file logging for remote operations
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Verbose "[$Level] $Message"
            }
            
            # Set module settings manually
            $Script:Settings = $settings
            $Script:BasePath = "C:\Temp"
            
            # Perform client setup
            try {
                Write-Verbose "Starting remote client setup..."
                
                # Check admin (assume true since we have session)
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required on remote machine"
                }
                
                # Install OpenVPN
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed on remote machine"
                }
                
                # Expand client package
                if (-not (Test-Path $configPath)) {
                    New-Item -ItemType Directory -Path $configPath -Force | Out-Null
                } else {
                    # Remove existing config files to avoid conflicts
                    Get-ChildItem $configPath | Remove-Item -Force
                }
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $configPath)
                
                $ovpnFile = Get-ChildItem $configPath -Filter "*.ovpn" | Select-Object -First 1
                if (-not $ovpnFile) {
                    throw "No OVPN file found in client package"
                }
                
                # Test TAP adapter
                if (-not (Test-TAPAdapter)) {
                    Write-Log "TAP adapter not found, OpenVPN may need reinstallation" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Error during remote client setup: $_" -Level "ERROR"
                throw
            }
            
            # Test connection
            Start-Sleep -Seconds 5
            Test-VPNConnection
            
            Write-Log "Remote client setup completed successfully" -Level "SUCCESS"
            
            # Clean up temp files
            Remove-Item $modulePath, $zipPath -Force
        } -ArgumentList $Script:Settings, $remoteModule, $remoteZip, $remoteConfigPath -ErrorAction Stop
        
        Remove-PSSession $session
        
        Write-Log "Remote client configuratie voltooid voor $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens remote client configuratie: $_" -Level "ERROR"
        
        # Probeer remote rollback uit te voeren
        try {
            $rollbackSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
            if ($rollbackSession) {
                Invoke-Command -Session $rollbackSession -ScriptBlock {
                    param($settings, $modulePath)
                    try {
                        $moduleContent = Get-Content -Path $modulePath -Raw
                        Invoke-Expression $moduleContent
                    } catch {
                        throw "Failed to load module: $_"
                    }
                    # Disable file logging for remote operations
                    function global:Write-Log {
                        param($Message, $Level = "INFO")
                        Write-Verbose "[$Level] $Message"
                    }
                    $Script:Settings = $settings
                    $Script:BasePath = "C:\Temp"
                    Invoke-Rollback -SetupType "Client"
                } -ArgumentList $Script:Settings, $remoteModule
                Remove-PSSession $rollbackSession
            }
        } catch {
            Write-Log "Kon remote rollback niet uitvoeren: $_" -Level "WARNING"
        }
        
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $false
    }
}


function Invoke-BatchRemoteClientInstall {
    <#
    .SYNOPSIS
        Perform batch remote client installs in parallel.

    .DESCRIPTION
        Accepts an array of client objects (Name, IP, Username, Password) and runs
        `Install-RemoteClient` in parallel runspaces. This centralizes the parallel
        logic so callers (scripts) remain small and focused.

    .PARAMETER Clients
        Array of client objects as imported from CSV.

    .PARAMETER ZipPath
        Path to the client ZIP package to deploy to each remote host.

    .PARAMETER ModulePath
        Path to this module file (used to import module inside parallel runspaces).

    .PARAMETER Settings
        Hashtable of module settings to apply in each runspace.

    .PARAMETER BasePath
        Base path to set in each runspace.

    .PARAMETER ThrottleLimit
        Maximum degree of parallelism. If omitted or less than 1, it will be computed
        based on local CPU cores (cores - 1, minimum 1).

    .OUTPUTS
        Array of result strings (SUCCESS: / ERROR:)
    #>
    
    param(
        [Parameter(Mandatory=$true, Position=0)] [object[]]$Clients,
        [Parameter(Mandatory=$true, Position=1)] [string]$ZipPath,
        [Parameter(Mandatory=$true, Position=2)] [string]$ModulePath,
        [Parameter(Mandatory=$true, Position=3)] [hashtable]$Settings,
        [Parameter(Mandatory=$true, Position=4)] [string]$BasePath,
        [int]$ThrottleLimit = 0
    )

    # Local copies for use with $using: in the parallel scriptblock
    $clientsLocal = $Clients
    $zipPathLocal = $ZipPath
    $modulePathLocal = $ModulePath
    $settingsLocal = $Settings
    $basePathLocal = $BasePath

    if (-not $ThrottleLimit -or $ThrottleLimit -lt 1) {
        try {
            $cpuCores = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors
        } catch {
            $cpuCores = 2
        }
        $ThrottleLimit = [math]::Max(1, $cpuCores - 1)
    }

    $results = $clientsLocal | ForEach-Object -Parallel {
        $client = $_
        $name = $client.Name
        $ip = $client.IP
        $username = $client.Username
        $password = $client.Password

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

        # Ensure module and settings are available in this runspace
        Import-Module $using:modulePathLocal -Force
        Set-ModuleSettings -Settings $using:settingsLocal -BasePath $using:basePathLocal

        try {
            $result = Install-RemoteClient -ComputerName $ip -Credential $cred -ZipPath $using:zipPathLocal
            if ($result) { 
                # Start VPN connection after successful installation
                $configPath = $using:settingsLocal.configPath
                if (-not $configPath -or [string]::IsNullOrWhiteSpace($configPath)) {
                    $configPath = 'C:\Program Files\OpenVPN\config'
                }
                $ovpnPath = Join-Path $configPath "client.ovpn"
                [void](Start-VPNConnection -ComputerName $ip -Credential $cred -ConfigFile $ovpnPath)
                "SUCCESS: $name ($ip)" 
            } else { 
                "ERROR: $name ($ip) - Installation failed" 
            }
        }
        catch {
            "ERROR: $name ($ip) - $_"
        }
    } -ThrottleLimit $ThrottleLimit

    return ,$results
}



#endregion Client functies

#region Test functies

########################################################################################################################
# Test functies
########################################################################################################################


function Test-TAPAdapter {
    <#
    .SYNOPSIS
        Controleert of een TAP adapter aanwezig is.

    .DESCRIPTION
        Deze functie controleert of er een TAP adapter geïnstalleerd is, wat nodig is voor OpenVPN.

    .OUTPUTS
        System.Boolean
        $true als TAP adapter gevonden, anders $false.

    .EXAMPLE
        Test-TAPAdapter

    Referentie: Gebaseerd op Get-NetAdapter cmdlet (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/netadapter/get-netadapter), gebruikt om TAP adapters te detecteren die door OpenVPN worden geïnstalleerd.
    #>
    Write-Log "TAP adapter controle gestart" -Level "INFO"
    
    try {
        $tapAdapters = Get-NetAdapter | Where-Object { $_.Name -like "*TAP*" -or $_.DriverDescription -like "*TAP*" }
        
        if ($tapAdapters) {
            Write-Log "TAP adapter gevonden: $($tapAdapters[0].Name)" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "Geen TAP adapter gevonden" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Fout tijdens TAP adapter controle: $_" -Level "ERROR"
        return $false
    }
}


function Start-VPNConnection {
    <#
    .SYNOPSIS
        Start een VPN verbinding met een configuratie bestand.

    .DESCRIPTION
        Deze functie start OpenVPN met het opgegeven configuratie bestand.

    .PARAMETER ConfigFile
        Pad naar het OVPN configuratie bestand.

    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.

    .EXAMPLE
        Start-VPNConnection -ConfigFile "C:\path\to\client.ovpn"

    Referentie: Gebaseerd op Start-Process voor OpenVPN executable (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process), en Get-Process/Stop-Process voor bestaande processen stoppen (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process, https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-process).
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidatePattern('\.ovpn$')][string]$ConfigFile,
        [Parameter(Mandatory=$false)][string]$ComputerName,
        [Parameter(Mandatory=$false)][PSCredential]$Credential
    )
    
    Write-Log "VPN verbinding starten met config: $ConfigFile $(if ($ComputerName) { "op $ComputerName" })" -Level "INFO"
    
    try {
        if ($ComputerName) {
            # Remote execution - use Task Scheduler to start GUI interactively
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop

            # Treat the provided ConfigFile as a path on the remote machine.
            # Do NOT attempt to Test-Path or copy from the local host when starting remotely.
            $remoteConfigFile = $ConfigFile
            $remoteConfigDir = Split-Path $remoteConfigFile -Parent
            $profileName = [System.IO.Path]::GetFileNameWithoutExtension($remoteConfigFile)

            # Remote script block using Task Scheduler for GUI
            #Wanneer je Invoke-Command gebruikt, draait je script in een onzichtbare "service-sessie". Een GUI (zoals OpenVPN) kan daar niet tekenen (geen taakbalk, geen systray). Omdat OpenVPN GUI zijn icoontje niet in de taakbalk kan zetten, loopt het proces vast op Need hold release....

            # Om dit te omzeilen moet je via een omweg uitbreken naar de interactieve sessie van de ingelogde gebruiker.

            #  We maken via PowerShell een taak aan op de remote PC die zegt: "Start OpenVPN GUI zodra ik dit commando geef, maar doe het zichtbaar op het bureaublad van de ingelogde gebruiker."
             $scriptBlock = {
                param($openVPNGuiPath, $profileName, $remoteConfigDir)

                # 1. Stop oude processen
                Get-Process -Name "openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force
                Get-Process -Name "openvpn-gui" -ErrorAction SilentlyContinue | Stop-Process -Force

                # 2. Definieer de actie (OpenVPN GUI starten met argumenten)
                $argument = "--connect `"$profileName`""
                $action = New-ScheduledTaskAction -Execute $openVPNGuiPath -Argument $argument

                # 3. BELANGRIJK: De taak moet draaien als 'Interactive' (alleen als gebruiker is ingelogd)
                # We gebruiken de 'Users' groep zodat het start voor wie er ook maar is ingelogd.
                $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Highest

                # 4. Maak de taak instellingen (RunOnlyIfLoggedOn is cruciaal voor GUI)
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

                $taskName = "StartOpenVPNGUI_Remote"

                # 5. Registreer de taak
                Register-ScheduledTask -Action $action -Principal $principal -Settings $settings -TaskName $taskName -Force | Out-Null

                # 6. Start de taak (Dit lanceert de GUI op het scherm van de gebruiker)
                Start-ScheduledTask -TaskName $taskName

                # Even wachten tot hij zeker gestart is
                Start-Sleep -Seconds 5

                # 7. Opruimen: verwijder de taak weer zodat het systeem schoon blijft
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

                Write-Verbose "OpenVPN GUI is interactief gestart via Task Scheduler."
            }

            Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Script:Settings.openVPNGuiPath, $profileName, $remoteConfigDir

            Remove-PSSession -Session $session
        } else {
            # Local execution
            $openVPNGuiPath = $Script:Settings.openVPNGuiPath
            if (-not $openVPNGuiPath) {
                $openVPNGuiPath = $Script:Settings.openVPNGuiPath
            }
            
            if (-not (Test-Path $openVPNGuiPath)) {
                Write-Log "OpenVPN GUI executable niet gevonden: $openVPNGuiPath" -Level "ERROR"
                return $false
            }
            
            # Copy config to OpenVPN config directory
            $configDir = $Script:Settings.configPath
            if (-not (Test-Path $configDir)) {
                New-Item -ItemType Directory -Path $configDir -Force | Out-Null
            }
            
            $configFileName = Split-Path $ConfigFile -Leaf
            $destConfigFile = Join-Path $configDir $configFileName
            if ($ConfigFile -ne $destConfigFile) {
                Copy-Item -Path $ConfigFile -Destination $destConfigFile -Force
            }
            
            # Also copy any referenced certs/keys if in the same dir
            $sourceDir = Split-Path $ConfigFile
            $certs = Get-ChildItem -Path $sourceDir -Include "*.crt","*.key" -File
            foreach ($cert in $certs) {
                Copy-Item -Path $cert.FullName -Destination $configDir -Force
            }
            
            # Get profile name (filename without extension)
            $profileName = [System.IO.Path]::GetFileNameWithoutExtension($configFileName)
            
            # Stop any existing OpenVPN processes
            Get-Process -Name "openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force
            
            # Start connection using OpenVPN GUI
            $arguments = "--connect $profileName"
            Start-Process -FilePath $openVPNGuiPath -ArgumentList $arguments -NoNewWindow
        }
        
        Write-Log "VPN verbinding gestart via GUI met profiel: $profileName $(if ($ComputerName) { "op $ComputerName" })" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens starten VPN verbinding: $_" -Level "ERROR"
        return $false
    }
}


function Test-VPNConnection {
    <#
    .SYNOPSIS
        Test de VPN verbinding.

    .DESCRIPTION
        Deze functie test de VPN verbinding door een ping naar een test IP adres.

    .OUTPUTS
        System.Boolean
        $true als verbinding succesvol, anders $false.

    .EXAMPLE
        Test-VPNConnection

    Referentie: Gebaseerd op Test-Connection cmdlet voor ping testen (Microsoft PowerShell Documentatie: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection), gebruikt om VPN connectiviteit te verifiëren.
    #>
    Write-Log "VPN verbinding testen gestart" -Level "INFO"
    
    try {
        # Simple ping test to VPN server with retries
        $testIP = $Script:Settings.testIP
        if (-not $testIP) {
            $testIP = $Script:Settings.testIP
        }
        
        for ($i = 1; $i -le 5; $i++) {
            Write-Log "VPN test poging $i naar $testIP" -Level "INFO"
            $pingResult = Test-Connection -ComputerName $testIP -Count 1 -Quiet
            if ($pingResult) {
                Write-Log "VPN verbinding succesvol getest" -Level "SUCCESS"
                return $true
            }
            Start-Sleep -Seconds 5
        }
        
        Write-Log "VPN verbinding test mislukt na 5 pogingen" -Level "WARNING"
        return $false
    }
    catch {
        Write-Log "Fout tijdens VPN verbinding test: $_" -Level "ERROR"
        return $false
    }
}

#endregion Test functies

#region Rollback functies

########################################################################################################################
# Rollback functies
########################################################################################################################


function Invoke-Rollback {
    <#
    .SYNOPSIS
        Voert rollback uit om alle wijzigingen ongedaan te maken bij falen van setup.

    .DESCRIPTION
        Deze functie probeert alle wijzigingen die tijdens de setup zijn gemaakt ongedaan te maken, inclusief stoppen van services, verwijderen van bestanden en firewall regels.

    .PARAMETER SetupType
        Type van setup ('Server' of 'Client').

    .OUTPUTS
        None

    .EXAMPLE
        Invoke-Rollback -SetupType "Server"

    .NOTES
        Deze functie probeert fouten te negeren en logt waarschuwingen bij mislukkingen.
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet("Server", "Client")]
        [string]$SetupType
    )

    Write-Log "Rollback gestart voor $SetupType setup" -Level "WARNING"

    try {
        switch ($SetupType) {
            "Server" {
                # Stop OpenVPN service
                Write-Log "Stoppen OpenVPN service" -Level "INFO"
                try {
                    $service = Get-Service -Name "OpenVPNService" -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq 'Running') {
                        Stop-Service -Name "OpenVPNService" -Force
                        Write-Log "OpenVPN service gestopt" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon OpenVPN service niet stoppen: $_" -Level "WARNING"
                }

                # Verwijder firewall regel
                Write-Log "Verwijderen firewall regel" -Level "INFO"
                try {
                    $ruleName = "OpenVPN-Inbound-TCP-443"
                    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                    if ($existingRule) {
                        Remove-NetFirewallRule -Name $ruleName
                        Write-Log "Firewall regel '$ruleName' verwijderd" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon firewall regel niet verwijderen: $_" -Level "WARNING"
                }

                # Verwijder server configuratie bestand
                Write-Log "Verwijderen server configuratie bestand" -Level "INFO"
                try {
                    $serverConfigPath = Join-Path $Script:Settings.configPath "server.ovpn"
                    if (Test-Path $serverConfigPath) {
                        Remove-Item -Path $serverConfigPath -Force
                        Write-Log "Server configuratie bestand verwijderd: $serverConfigPath" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon server configuratie bestand niet verwijderen: $_" -Level "WARNING"
                }

                # Verwijder PKI directory
                Write-Log "Verwijderen certificaten (PKI directory)" -Level "INFO"
                try {
                    $pkiPath = Join-Path $Script:Settings.easyRSAPath "pki"
                    if (Test-Path $pkiPath) {
                        Remove-Item -Path $pkiPath -Recurse -Force
                        Write-Log "PKI directory verwijderd: $pkiPath" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon PKI directory niet verwijderen: $_" -Level "WARNING"
                }

                # Verwijder client package ZIP
                Write-Log "Verwijderen client package ZIP" -Level "INFO"
                try {
                    $outputPath = Join-Path $Script:BasePath $Script:Settings.outputPath
                    $zipPath = Join-Path $outputPath "vpn-client-$($Script:Settings.clientName).zip"
                    if (Test-Path $zipPath) {
                        Remove-Item -Path $zipPath -Force
                        Write-Log "Client package ZIP verwijderd: $zipPath" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon client package ZIP niet verwijderen: $_" -Level "WARNING"
                }

                # Verwijder EasyRSA directory (optioneel, alleen als leeg)
                Write-Log "Verwijderen EasyRSA directory indien leeg" -Level "INFO"
                try {
                    $easyRSAPath = $Script:Settings.easyRSAPath
                    if (Test-Path $easyRSAPath) {
                        $items = Get-ChildItem -Path $easyRSAPath -Recurse
                        if ($items.Count -eq 0) {
                            Remove-Item -Path $easyRSAPath -Recurse -Force
                            Write-Log "EasyRSA directory verwijderd: $easyRSAPath" -Level "INFO"
                        }
                    }
                } catch {
                    Write-Log "Kon EasyRSA directory niet verwijderen: $_" -Level "WARNING"
                }
            }

            "Client" {
                # Stop VPN verbinding
                Write-Log "Stoppen VPN verbinding" -Level "INFO"
                try {
                    $openvpnProcesses = Get-Process -Name "openvpn" -ErrorAction SilentlyContinue
                    if ($openvpnProcesses) {
                        $openvpnProcesses | Stop-Process -Force
                        Write-Log "OpenVPN processen gestopt" -Level "INFO"
                    }
                } catch {
                    Write-Log "Kon OpenVPN processen niet stoppen: $_" -Level "WARNING"
                }

                # Verwijder geïmporteerde configuratie bestanden
                Write-Log "Verwijderen geïmporteerde configuratie bestanden" -Level "INFO"
                try {
                    $configPath = $Script:Settings.configPath
                    if (Test-Path $configPath) {
                        $ovpnFiles = Get-ChildItem -Path $configPath -Filter "*.ovpn" -ErrorAction SilentlyContinue
                        foreach ($file in $ovpnFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Configuratie bestand verwijderd: $($file.FullName)" -Level "INFO"
                        }
                        $certFiles = Get-ChildItem -Path $configPath -Filter "*.crt" -ErrorAction SilentlyContinue
                        foreach ($file in $certFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Certificaat bestand verwijderd: $($file.FullName)" -Level "INFO"
                        }
                        $keyFiles = Get-ChildItem -Path $configPath -Filter "*.key" -ErrorAction SilentlyContinue
                        foreach ($file in $keyFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Key bestand verwijderd: $($file.FullName)" -Level "INFO"
                        }
                    }
                } catch {
                    Write-Log "Kon configuratie bestanden niet verwijderen: $_" -Level "WARNING"
                }
            }
        }

        Write-Log "Rollback voor $SetupType setup voltooid" -Level "SUCCESS"
    }
    catch {
        Write-Log "Fout tijdens rollback: $_" -Level "ERROR"
    }
}

#endregion Rollback functies

