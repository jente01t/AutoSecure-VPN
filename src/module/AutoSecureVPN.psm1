#region Menu en UI functies

<#
.SYNOPSIS
    Toont een menu met opties en vraagt om keuze.

.DESCRIPTION
    Deze functie toont een menu met een titel, lijst van opties, en wacht op gebruikersinvoer.
    Het valideert de keuze en retourneert het gekozen nummer.

.PARAMETER Title
    De titel van het menu.

.PARAMETER Options
    Een array van opties om te tonen.

.PARAMETER HeaderColor
    Kleur voor de header (standaard Cyan).

.PARAMETER OptionColor
    Kleur voor de opties (standaard White).

.PARAMETER FooterColor
    Kleur voor de footer (standaard Cyan).

.PARAMETER SeparatorChar
    Karakter voor de scheiding (standaard '=').

.PARAMETER NoPrompt
    Als true, geen prompt tonen en null retourneren.

.PARAMETER Prompt
    De prompt tekst (standaard 'Keuze: ').

.EXAMPLE
    Show-Menu -Title "Hoofdmenu" -Options @("Optie 1", "Optie 2")
#>
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

<#
.SYNOPSIS
    Wacht op gebruikersinvoer om door te gaan.

.DESCRIPTION
    Deze functie toont een bericht en wacht tot de gebruiker Enter drukt.

.PARAMETER Message
    Het bericht om te tonen (standaard 'Druk Enter om door te gaan...').

.EXAMPLE
    Wait-Input
#>
function Wait-Input {
	param([string]$Message = 'Druk Enter om door te gaan...')
	Read-Host -Prompt $Message | Out-Null
}

#endregion Menu en UI functies

# Load module settings from src/config/Stable.psd1 and Variable.psd1 (if present)
# Use $PSScriptRoot and $Script: scope so the module is import-safe in test runspaces.
$Script:Settings = @{}
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
    Write-Host "Kon settings niet laden: $($_.Exception.Message)" -ForegroundColor Yellow
}

$Script:BasePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

<#
.SYNOPSIS
    Stelt de module settings in voor remote operaties.

.DESCRIPTION
    Deze functie stelt $Script:Settings en $Script:BasePath in voor gebruik in remote sessies.

.PARAMETER Settings
    De hashtable met settings.

.PARAMETER BasePath
    Het base path voor de module.

.EXAMPLE
    Set-ModuleSettings -Settings $mySettings -BasePath "C:\Temp"
#>
function Set-ModuleSettings {
    param(
        [hashtable]$Settings,
        [string]$BasePath
    )
    $Script:Settings = $Settings
    $Script:BasePath = $BasePath
}

#region Configuratie functies  

<#
.SYNOPSIS
    Controleert of het script als administrator wordt uitgevoerd.

.DESCRIPTION
    Deze functie controleert of de huidige gebruiker administrator rechten heeft.

.EXAMPLE
    if (-not (Test-IsAdmin)) { Write-Host "Administrator rechten vereist" }
#>
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

.EXAMPLE
    Write-Log "Operatie voltooid" -Level "SUCCESS"
#>
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile = $null
    )
    
    if (-not $LogFile) {
        # Gebruik altijd de root van het project voor logs, ongeacht instellingen
        $logsPath = Join-Path $Script:BasePath "logs"
        if (-not (Test-Path $logsPath)) {
            New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
        }
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    $timestamp = Get-Date -Format $Script:Settings.logTimestampFormat
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

<#
.SYNOPSIS
    Installeert OpenVPN op de lokale machine.

.DESCRIPTION
    Deze functie downloadt en installeert OpenVPN via MSI als het niet al geïnstalleerd is.

.PARAMETER Url
    De URL van de OpenVPN installer (standaard uit settings).

.EXAMPLE
    Install-OpenVPN
#>
function Install-OpenVPN {
    param(
        [string]$Url #validaties urls 
    )
    
    if (-not $Url) {
        $version = if ($Script:Settings.openVpnVersion) { $Script:Settings.openVpnVersion } else { 
            try {
                $latest = Invoke-RestMethod -Uri 'https://api.github.com/repos/OpenVPN/openvpn/releases/latest'
                $latest.tag_name -replace '^v', ''
            } catch {
                '2.6.15'  # fallback
            }
        }
        $Url = "https://swupdate.openvpn.org/community/releases/OpenVPN-$version-I001-amd64.msi"
    }
    
    $installedPath = $Script:Settings.installedPath
    if (-not $installedPath) {
        $installedPath = $Script:Settings.installedPath
    }
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

<#
.SYNOPSIS
    Configureert de Windows Firewall voor OpenVPN.

.DESCRIPTION
    Deze functie voegt een inbound firewall regel toe voor de opgegeven poort en protocol.

.PARAMETER Port
    De poort om te openen (standaard uit settings).

.PARAMETER Protocol
    Het protocol (TCP/UDP, standaard uit settings).

.EXAMPLE
    Set-Firewall -Port 443 -Protocol "TCP"
#>
function Set-Firewall {
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

<#
.SYNOPSIS
    Vraagt server configuratie parameters van de gebruiker.

.DESCRIPTION
    Deze functie vraagt om servernaam, IP, LAN subnet, en wachtwoord voor certificaten.

.EXAMPLE
    $config = Get-ServerConfiguration
#>
function Get-ServerConfiguration {
    param(
        [string]$ServerName,
        [string]$ServerIP,
        [string]$LANSubnet,
        [string]$LANMask,
        [switch]$NoPass,
        [string]$Password
    )
    
    $config = @{}
    
    Write-Host ""
    $inputServerName = if ($ServerName) { $ServerName } else { Read-Host "  Servernaam (bijv. vpn-server)" }
    if ([string]::IsNullOrWhiteSpace($inputServerName)) {
        $inputServerName = $Script:Settings.serverNameDefault
    }
    $config.ServerName = $inputServerName
    
    $inputServerIP = if ($ServerIP) { $ServerIP } else { Read-Host "  Server WAN IP of DDNS (bijv. vpn.example.com)" }
    while ([string]::IsNullOrWhiteSpace($inputServerIP)) {
        Write-Host "  ! Server IP/DDNS is verplicht" -ForegroundColor Red
        $inputServerIP = Read-Host "  Server WAN IP of DDNS"
    }
    $config.ServerIP = $inputServerIP
    
    $inputLANSubnet = if ($PSBoundParameters.ContainsKey('LANSubnet')) { $LANSubnet } else { Read-Host "  LAN subnet (default $($Script:Settings.lanSubnetDefault), druk Enter voor skip)" }
    if (-not [string]::IsNullOrWhiteSpace($inputLANSubnet)) {
        $config.LANSubnet = $inputLANSubnet
        $config.LANMask = if ($LANMask) { $LANMask } else { $Script:Settings.lanMaskDefault }
    }
    
    if ($PSBoundParameters.ContainsKey('NoPass')) {
        $config.NoPass = $NoPass
    } else {
        $noPassInput = Read-Host "  Certificaten zonder wachtwoord? (J/N, standaard N)"
        $config.NoPass = ($noPassInput -eq "J" -or $noPassInput -eq "j")
    }
    
    if (-not $config.NoPass) {
        $config.Password = if ($Password) { $Password } else { Read-Host "  Voer wachtwoord in voor certificaten" }
    }
    
    Write-Log "Server configuratie verzameld: ServerName=$($config.ServerName), ServerIP=$($config.ServerIP)" -Level "INFO"
    
    return $config
}

#endregion Server configuratie functies

#region EasyRSA functies

<#
.SYNOPSIS
    Initialiseert EasyRSA voor certificaatbeheer.

.DESCRIPTION
    Deze functie downloadt en installeert EasyRSA als het niet aanwezig is.

.PARAMETER EasyRSAPath
    Het pad waar EasyRSA geïnstalleerd wordt (standaard uit settings).

.EXAMPLE
    Initialize-EasyRSA
#>
function Initialize-EasyRSA {
    param(
        [string]$EasyRSAPath = $Script:Settings.easyRSAPath
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

.EXAMPLE
    Initialize-Certificates -ServerName "vpn-server"
#>
function Initialize-Certificates {
    param (
        [string]$ServerName = $Script:Settings.serverNameDefault,
        [string]$Password = $null,
        [string]$EasyRSAPath = (Join-Path $Script:BasePath $Script:Settings.certPath)
    )
    
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
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 1 van 6: PKI initialiseren" -PercentComplete 0
        $easyrsaOutput = & $sh $easyrsa init-pki
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
            Write-Log "Password file created for certificate generation" -Level "INFO"
        }

        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 2 van 6: CA certificaat genereren" -PercentComplete 16.67
        if ($Password) {
            $easyrsaOutput = & $sh $easyrsa build-ca
        } else {
            $easyrsaOutput = & $sh $easyrsa build-ca nopass
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA build-ca failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 3 van 6: Server certificaat aanvraag genereren" -PercentComplete 33.33
        if ($Password) {
            $easyrsaOutput = & $sh $easyrsa gen-req $ServerName
        } else {
            $easyrsaOutput = & $sh $easyrsa gen-req $ServerName nopass
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-req failed with exit code $LASTEXITCODE. Output: $easyrsaOutput" -Level "ERROR"
            return $false
        }
        Write-Log "Easy-RSA output: $easyrsaOutput"

        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 4 van 6: Server certificaat ondertekenen" -PercentComplete 50
        & $sh $easyrsa sign-req server $ServerName
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA sign-req server failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 5 van 6: DH parameters genereren" -PercentComplete 66.67
        & $sh $easyrsa gen-dh
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-dh failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
        Write-Progress -Id 1 -Activity "Certificaat Generatie" -Status "Stap 6 van 6: CRL genereren" -PercentComplete 83.33
        & $sh $easyrsa gen-crl
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

.EXAMPLE
    New-ServerConfig -Config $config
#>
function New-ServerConfig {
    param(
        [hashtable]$Config,
        [string]$EasyRSAPath = $Script:Settings.easyRSAPath,
        [string]$ConfigPath = $Script:Settings.configPath
    )
    
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

.EXAMPLE
    $config = Get-ServerConfiguration -ServerName "vpn-server" -ServerIP "example.com"
    Install-RemoteServer -ComputerName "remote-pc" -Credential $cred -ServerConfig $config
#>
function Install-RemoteServer {
    param (
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][PSCredential]$Credential,
        [Parameter(Mandatory=$true)][hashtable]$ServerConfig,
        [Parameter(Mandatory=$true)][string]$LocalEasyRSAPath
    )

    Write-Log "Remote server configuratie gestart voor $ComputerName" -Level "INFO"
    
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
        
        # Get local paths
        $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        $localModule = Join-Path $moduleBase "AutoSecureVPN.psm1"

        # copy module to remote temp path
        $remoteTemp = "C:\Temp"
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force } }
        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        $remoteEasyRSA = Join-Path $remoteTemp "easy-rsa"
        
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session
        Copy-Item -Path $LocalEasyRSAPath -Destination $remoteEasyRSA -ToSession $session -Recurse
        
        Invoke-Command -Session $session -ScriptBlock {
            param($settings, $modulePath, $config, $remoteEasyRSA)
            
            # Set execution policy to allow scripts
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            
            # Stop on errors
            $ErrorActionPreference = 'Stop'
            
            Import-Module $modulePath -Force
            if (-not (Get-Module -Name "AutoSecureVPN")) { throw "Failed to import module" }
            

            Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
            
            # Disable file logging for remote operations
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Host "[$Level] $Message"
            }
            
            try {
                Write-Host "Starting remote server setup..."
                
                if (-not (Test-IsAdmin)) {
                    throw "Administrator rights required"
                }
                
                Write-Host "Installing OpenVPN..."
                if (-not (Install-OpenVPN)) {
                    throw "OpenVPN installation failed"
                }
                
                Write-Host "Configuring firewall..."
                if (-not (Set-Firewall)) {
                    throw "Firewall configuration failed"
                }
                
                Write-Host "Copying EasyRSA with certificates..."
                if (-not (Test-Path $settings.easyRSAPath)) {
                    New-Item -ItemType Directory -Path $settings.easyRSAPath -Force
                }
                Copy-Item -Path "$remoteEasyRSA\*" -Destination $settings.easyRSAPath -Recurse -Force
                
                Write-Host "Creating server config..."
                if (-not (New-ServerConfig -Config $config)) {
                    throw "Server config generation failed"
                }
                
                Write-Host "Starting VPN service..."
                if (-not (Start-VPNService)) {
                    throw "VPN service start failed"
                }
                
                Write-Host "Remote server setup completed successfully"
            }
            catch {
                Write-Host "Error during remote server setup: $_"
                throw
            }
            
            Remove-Item $modulePath -Force
            Remove-Item $remoteEasyRSA -Recurse -Force
        } -ArgumentList $Script:Settings, $remoteModule, $ServerConfig, $remoteEasyRSA
        
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
                    param($settings, $modulePath)
                    Import-Module $modulePath -Force
                    Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
                    Invoke-Rollback -SetupType "Server"
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


#endregion Server config generatie functies

#region VPN service functies

<#
.SYNOPSIS
    Start de OpenVPN service.

.DESCRIPTION
    Deze functie start de OpenVPN Windows service als deze niet al loopt.

.EXAMPLE
    Start-VPNService
#>
function Start-VPNService {
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

.EXAMPLE
    New-ClientPackage -Config $config
#>
function New-ClientPackage {
    param(
        [hashtable]$Config,
        [string]$EasyRSAPath = $Script:Settings.easyRSAPath,
        [string]$OutputPath = (Join-Path $Script:BasePath $Script:Settings.outputPath)
    )
    
    $pkiPath = Join-Path $EasyRSAPath "pki"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force
    }
    
    $clientName = $Script:Settings.clientNameDefault
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
        $unixEasyRSAPath = '/' + $drive + $EasyRSAPath.Substring(2) -replace '\\', '/'
        $env:EASYRSA = $unixEasyRSAPath
        
        $env:EASYRSA_BATCH = "1"
        $env:EASYRSA_VARS_FILE = "vars"
        $env:EASYRSA_PKI = "pki"
        $env:PATH = "$EasyRSAPath;$EasyRSAPath\bin;$env:PATH"
        $sh = Join-Path $EasyRSAPath "bin\sh.exe"
        $easyrsa = Join-Path $EasyRSAPath "easyrsa"
        
        Write-Log "Environment variables ingesteld: EASYRSA=$env:EASYRSA, EASYRSA_BATCH=$env:EASYRSA_BATCH, EASYRSA_VARS_FILE=$env:EASYRSA_VARS_FILE, EASYRSA_PKI=$env:EASYRSA_PKI" -Level "INFO"
        Write-Log "sh.exe path: $sh" -Level "INFO"
        Write-Log "easyrsa script path: $easyrsa" -Level "INFO"
        
        Push-Location $EasyRSAPath
        Write-Log "Gewisseld naar directory: $EasyRSAPath" -Level "INFO"
        
        Write-Log "Uitvoeren: $sh $easyrsa gen-req $clientName nopass" -Level "INFO"
        $result1 = & $sh $easyrsa gen-req $clientName nopass
        Write-Log "Exit code gen-req: $LASTEXITCODE" -Level "INFO"
        if ($LASTEXITCODE -ne 0) { Write-Log "Fout bij gen-req: $result1" -Level "ERROR" }
        
        Write-Log "Uitvoeren: $sh $easyrsa sign-req client $clientName" -Level "INFO"
        $result2 = & $sh $easyrsa sign-req client $clientName
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

<#
.SYNOPSIS
    Importeert client configuratie uit een ZIP bestand.

.DESCRIPTION
    Deze functie pakt een client ZIP bestand uit naar de configuratie map en retourneert het pad naar het OVPN bestand.

.EXAMPLE
    Import-ClientConfiguration
#>
function Import-ClientConfiguration {
    Write-Log "Client configuratie importeren gestart" -Level "INFO"
    
    $configPath = $Script:Settings.configPath
    
    # Try to find the default client ZIP file
    $defaultZipPath = Join-Path (Join-Path $Script:BasePath $Script:Settings.outputPath) "vpn-client-$($Script:Settings.clientNameDefault).zip"
    if (Test-Path $defaultZipPath) {
        $zipFile = $defaultZipPath
        Write-Log "Standaard client ZIP bestand gevonden: $zipFile" -Level "INFO"
    } else {
        Write-Host "Standaard client ZIP bestand niet gevonden op $defaultZipPath" -ForegroundColor Yellow
        $zipFile = Read-Host "Pad naar client ZIP bestand"
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

.PARAMETER RemoteConfigPath
    Pad op de remote machine waar config wordt geplaatst (standaard 'C:\Program Files\OpenVPN\config').

.EXAMPLE
    Install-RemoteClient -ComputerName "remote-pc" -Credential $cred -ZipPath "C:\path\to\client.zip"
#>
function Install-RemoteClient {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][PSCredential]$Credential,
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [string]$RemoteConfigPath = $Script:Settings.remoteConfigPath
    )
    
    Write-Log "Remote client configuratie gestart voor $ComputerName" -Level "INFO"
    
    if (-not (Test-Path $ZipPath)) {
        Write-Log "ZIP bestand niet gevonden: $ZipPath" -Level "ERROR"
        return $false
    }
    
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
        
        # Get local paths
        $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
        $localModule = Join-Path $moduleBase "AutoSecureVPN.psm1"
        
        # Copy module to remote temp
        $remoteTemp = "C:\Temp"
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force } }
        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        $remoteZip = Join-Path $remoteTemp "client.zip"
        
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session
        Copy-Item -Path $ZipPath -Destination $remoteZip -ToSession $session
        
        # Perform full client setup on remote
        Invoke-Command -Session $session -ScriptBlock {
            param($settings, $modulePath, $zipPath, $configPath)
            
            # Set execution policy to allow scripts
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            
            # Stop on errors
            $ErrorActionPreference = 'Stop'
            
            # Import module
            Import-Module $modulePath -Force
            if (-not (Get-Module -Name "AutoSecureVPN")) { throw "Failed to import module" }
            
            # Override settings
            Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
            
            # Disable file logging for remote operations
            function global:Write-Log {
                param($Message, $Level = "INFO")
                Write-Host "[$Level] $Message"
            }
            
            # Perform client setup
            try {
                Write-Host "Starting remote client setup..."
                
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
                    Write-Host "TAP adapter not found, OpenVPN may need reinstallation" -ForegroundColor Yellow
                }
                
                # Start VPN connection
                if (-not (Start-VPNConnection -ConfigFile $ovpnFile.FullName)) {
                    throw "Failed to start VPN connection on remote machine"
                }
            }
            catch {
                Write-Host "Error during remote client setup: $_"
                throw
            }
            
            # Test connection
            Start-Sleep -Seconds 5
            Test-VPNConnection
            
            Write-Host "Remote client setup completed successfully"
            
            # Clean up temp files
            Remove-Item $modulePath, $zipPath -Force
        } -ArgumentList $Script:Settings, $remoteModule, $remoteZip, $RemoteConfigPath
        
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
                    Import-Module $modulePath -Force
                    Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
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

#endregion Client functies

#region Test functies

<#
.SYNOPSIS
    Controleert of een TAP adapter aanwezig is.

.DESCRIPTION
    Deze functie controleert of er een TAP adapter geïnstalleerd is, wat nodig is voor OpenVPN.

.EXAMPLE
    Test-TAPAdapter
#>
function Test-TAPAdapter {
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

<#
.SYNOPSIS
    Start een VPN verbinding met een configuratie bestand.

.DESCRIPTION
    Deze functie start OpenVPN met het opgegeven configuratie bestand.

.PARAMETER ConfigFile
    Pad naar het OVPN configuratie bestand.

.EXAMPLE
    Start-VPNConnection -ConfigFile "C:\path\to\client.ovpn"
#>
function Start-VPNConnection {
    param(
        [string]$ConfigFile
    )
    
    Write-Log "VPN verbinding starten met config: $ConfigFile" -Level "INFO"
    
    try {
        $openVPNPath = $Script:Settings.openVPNExePath
        if (-not $openVPNPath) {
            $openVPNPath = $Script:Settings.openVPNExePath
        }
        
        if (-not (Test-Path $openVPNPath)) {
            Write-Log "OpenVPN executable niet gevonden: $openVPNPath" -Level "ERROR"
            return $false
        }
        
        # Stop any existing OpenVPN processes
        Get-Process -Name "openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force
        
        $arguments = "--config `"$ConfigFile`""
        $workingDir = Split-Path $ConfigFile
        Start-Process -FilePath $openVPNPath -ArgumentList $arguments -WorkingDirectory $workingDir -NoNewWindow
        
        Write-Log "VPN verbinding gestart" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens starten VPN verbinding: $_" -Level "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Test de VPN verbinding.

.DESCRIPTION
    Deze functie test de VPN verbinding door een ping naar een test IP adres.

.EXAMPLE
    Test-VPNConnection
#>
function Test-VPNConnection {
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

<#
.SYNOPSIS
    Voert rollback uit om alle wijzigingen ongedaan te maken bij falen van setup.

.DESCRIPTION
    Deze functie probeert alle wijzigingen die tijdens de setup zijn gemaakt ongedaan te maken, inclusief stoppen van services, verwijderen van bestanden en firewall regels.

.PARAMETER SetupType
    Type van setup ('Server' of 'Client').

.EXAMPLE
    Invoke-Rollback -SetupType "Server"
#>
function Invoke-Rollback {
    param(
        [Parameter(Mandatory=$true)]
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
                    $zipPath = Join-Path $outputPath "vpn-client-$($Script:Settings.clientNameDefault).zip"
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



