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

#region EasyRSA functies

function Initialize-EasyRSA {
    param(
        [string]$EasyRSAPath = $Script:Settings.easyRSAPath
    )
    
    if (Test-Path $EasyRSAPath) {
        Write-Log "EasyRSA is al geïnstalleerd in $EasyRSAPath" -Level "INFO"
        return $true
    }
    
    try {
        $easyRSAUrl = $Script:Settings.easyRSAUrl
        $tempZip = Join-Path $env:TEMP "easyrsa.zip"
        
        Invoke-WebRequest -Uri $easyRSAUrl -OutFile $tempZip -UseBasicParsing
        Expand-Archive -Path $tempZip -DestinationPath $EasyRSAPath -Force
        
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

function Initialize-Certificates {
    param(
        [string]$ServerName = $Script:Settings.serverNameDefault,
        [string]$Password = $null,
        [string]$EasyRSAPath = (Join-Path $PSScriptRoot "..\..\$($Script:Settings.certPath)")
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
set_var EASYRSA_BATCH "1"
set_var EASYRSA_PKI "pki"
set_var EASYRSA_ALGO "rsa"
set_var EASYRSA_KEY_SIZE "2048"
set_var EASYRSA_CA_EXPIRE "3650"
set_var EASYRSA_CERT_EXPIRE "3650"
set_var EASYRSA_CRL_DAYS "180"
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

        
        & $sh $easyrsa sign-req server $ServerName
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA sign-req server failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        & $sh $easyrsa gen-dh
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-dh failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        & $sh $easyrsa gen-crl
        if ($LASTEXITCODE -ne 0) {
            Write-Log "EasyRSA gen-crl failed with exit code $LASTEXITCODE" -Level "ERROR"
            return $false
        }
        
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

function Generate-ServerConfig {
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

#endregion Server config generatie functies

#region VPN service functies

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

function New-ClientPackage {
    param(
        [hashtable]$Config,
        [string]$EasyRSAPath = $Script:Settings.easyRSAPath,
        [string]$OutputPath = (Join-Path $PSScriptRoot "..\..\$($Script:Settings.outputPath)")
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
        $pkiPathUnix = '/' + $drive + $pkiPath.Substring(2) -replace '\\', '/'
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

function Import-ClientConfiguration {
    Write-Log "Client configuratie importeren gestart" -Level "INFO"
    
    $configPath = $Script:Settings.configPath
    
    $zipFile = Read-Host "Pad naar client ZIP bestand"
    
    if (-not (Test-Path $zipFile)) {
        Write-Log "ZIP bestand niet gevonden: $zipFile" -Level "ERROR"
        return $null
    }
    
    try {
        Expand-Archive -Path $zipFile -DestinationPath $configPath -Force
        
        $ovpnFile = Get-ChildItem $configPath -Filter "*.ovpn" | Select-Object -First 1
        
        if ($ovpnFile) {
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

#endregion Client functies

#region Test functies

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

function Start-VPNConnection {
    param(
        [string]$ConfigFile
    )
    
    Write-Log "VPN verbinding starten met config: $ConfigFile" -Level "INFO"
    
    try {
        $openVPNPath = $Script:Settings.openVPNExePath
        
        if (-not (Test-Path $openVPNPath)) {
            Write-Log "OpenVPN executable niet gevonden: $openVPNPath" -Level "ERROR"
            return $false
        }
        
        $arguments = "--config `"$ConfigFile`""
        Start-Process -FilePath $openVPNPath -ArgumentList $arguments -NoNewWindow
        
        Write-Log "VPN verbinding gestart" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens starten VPN verbinding: $_" -Level "ERROR"
        return $false
    }
}

