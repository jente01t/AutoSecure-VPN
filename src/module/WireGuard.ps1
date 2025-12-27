# WireGuard functional files for the AutoSecureVPN module

function Install-WireGuard {
    <#
    .SYNOPSIS
        Installeert WireGuard op de lokale machine.

    .DESCRIPTION
        Deze functie downloadt en installeert WireGuard.
        
    .PARAMETER Url
        De URL van de WireGuard installer (optioneel).
        
    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.
    #>
    param(
        [Parameter(Position = 0)][string]$wgUrl
    )
    
    $wgExePath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (Test-Path $wgExePath) {
        Write-Log "WireGuard lijkt al geïnstalleerd te zijn" -Level "INFO"
        return $true
    }

    Write-Log "WireGuard installatie gestart" -Level "INFO"
    
    # Bepaal download URL
    if (-not $wgUrl) {
        # Gebruik vaste stabiele versie als fallback
        $wgUrl = $Script:Settings.wireGuardInstallerUrlFallback
    }

    $tempPath = [System.IO.Path]::GetTempFileName() + ".msi"
    
    try {
        # Probeer dynamisch de laatste versie te vinden
        try {
            $content = Invoke-WebRequest -Uri $Script:Settings.wireGuardVersionCheckUrl -UseBasicParsing -ErrorAction SilentlyContinue
            if ($content.Content -match $Script:Settings.wireGuardVersionRegex) {
                $latestMsi = $matches[1]
                $wgUrl = "$($Script:Settings.wireGuardVersionCheckUrl)$latestMsi"
                Write-Log "Laatste WireGuard versie online gevonden: $latestMsi" -Level "INFO"
            }
        }
        catch {
            Write-Log "Kon online versie check niet uitvoeren, gebruik fallback url" -Level "WARNING"
        }

        Write-Log "WireGuard MSI downloaden van $wgUrl..." -Level "INFO"
        Invoke-WebRequest -Uri $wgUrl -OutFile $tempPath -UseBasicParsing
        Write-Log "WireGuard MSI gedownload naar $tempPath" -Level "INFO"
        
        # Silent install options
        # DO_NOT_LAUNCH=1 voorkomt dat de GUI direct start
        $arguments = $Script:Settings.wireGuardInstallerArguments -f $tempPath
        
        Write-Log "Installeren..." -Level "INFO"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "WireGuard succesvol geïnstalleerd" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "WireGuard installatie mislukt met exit code $($process.ExitCode)" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Fout tijdens WireGuard installatie: $_" -Level "ERROR"
        return $false
    }
    finally {
        if (Test-Path $tempPath) {
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
function Initialize-WireGuardKeys {
    <#
    .SYNOPSIS
        Genereert Private en Public keys voor WireGuard.
    
    .OUTPUTS
        Hashtable met PrivateKey en PublicKey.
    #>
    param(
        [string]$WgPath,
        [hashtable]$Settings = $null
    )
    
    if (-not $WgPath) {
        if ($Settings -and $Settings.ContainsKey('wireGuardKeysExePath') -and $Settings.wireGuardKeysExePath) {
            $WgPath = $Settings.wireGuardKeysExePath
        }
        elseif ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardKeysExePath') -and $Script:Settings.wireGuardKeysExePath) {
            $WgPath = $Script:Settings.wireGuardKeysExePath
        }
        else {
            $WgPath = "C:\Program Files\WireGuard\wg.exe"
            Write-Log "Geen wg.exe pad opgegeven, gebruik standaard fallback: $WgPath" -Level "WARNING"
        }
    }
    
    if (-not (Test-Path $WgPath)) {
        throw "wg.exe niet gevonden op $WgPath. Controleer wireGuardKeysExePath in je settings of installeer WireGuard eerst."
    }
    
    try {
        # Genereer private key
        $privateKey = & $WgPath genkey
        if (-not $privateKey) { throw "Kon private key niet genereren" }
        
        # Genereer public key van private key
        # Gebruik input object om via pipe te sturen
        $publicKey = $privateKey | & $WgPath pubkey
        if (-not $publicKey) { throw "Kon public key niet genereren" }
        
        return @{
            PrivateKey = $privateKey.Trim()
            PublicKey  = $publicKey.Trim()
        }
    }
    catch {
        Write-Log "Fout bij genereren keys: $_" -Level "ERROR"
        throw
    }
}
function New-WireGuardServerConfig {
    <#
    .SYNOPSIS
        Maakt een WireGuard server configuratie.
    #>
    param(
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ClientKeys,
        [Parameter(Mandatory = $true)]$Port,
        [Parameter(Mandatory = $true)]$Address, # e.g. 10.13.13.1/24
        [Parameter(Mandatory = $true)]$PeerAddress, # e.g. 10.13.13.2/32
        [Parameter(Mandatory = $true)]$ServerType,
        [string]$OutputPath
    )
    
    $configContent = @"
[Interface]
PrivateKey = $($ServerKeys.PrivateKey)
ListenPort = $Port
Address = $Address

[Peer]
PublicKey = $($ClientKeys.PublicKey)
AllowedIPs = $PeerAddress
"@

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $configContent
        Write-Log "Server config opgeslagen in $OutputPath" -Level "INFO"
    }
    
    return $configContent
}
function New-WireGuardClientConfig {
    <#
    .SYNOPSIS
        Maakt een WireGuard client configuratie.
    #>
    param(
        [Parameter(Mandatory = $true)]$ClientKeys,
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ServerAvailableIP, # WAN IP
        [Parameter(Mandatory = $true)]$Port,
        [Parameter(Mandatory = $true)]$Address, # e.g. 10.13.13.2/24
        [string]$DNS,
        [string]$OutputPath
    )
    
    if ([string]::IsNullOrWhiteSpace($DNS)) {
        $dnsFromSettings = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardDefaultDns')) {
            $dnsFromSettings = $Script:Settings.wireGuardDefaultDns
        }

        if (-not [string]::IsNullOrWhiteSpace($dnsFromSettings)) {
            $DNS = $dnsFromSettings
        }
        else {
            Write-Log "Geen DNS opgegeven voor WireGuard client; gebruik fallback 8.8.8.8" -Level "WARNING"
            $DNS = '8.8.8.8'
        }
    }
    
    $configContent = @"
[Interface]
PrivateKey = $($ClientKeys.PrivateKey)
Address = $Address
DNS = $DNS

[Peer]
PublicKey = $($ServerKeys.PublicKey)
Endpoint = ${ServerAvailableIP}:${Port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $($Script:Settings.wireGuardDefaultPersistentKeepalive)
"@

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $configContent
        Write-Log "Client config opgeslagen in $OutputPath" -Level "INFO"
    }
    
    return $configContent
}
function Start-WireGuardService {
    <#
    .SYNOPSIS
        Installeert en start de WireGuard tunnel service.
    #>
    param(
        [Parameter(Mandatory = $true)]$ConfigPath
    )
    
    $wgPath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (-not (Test-Path $wgPath)) {
        throw "WireGuard executable niet gevonden"
    }
    
    try {
        # Stop eerst bestaande WireGuard services om conflicten te voorkomen
        Stop-WireGuardService | Out-Null
        
        # wireguard /installtunnelservice <path>
        # Dit installeert een service met naam "WireGuardTunnel$Name"
        
        Write-Log "Starten van WireGuard tunnel met config $ConfigPath..." -Level "INFO"
        
        $process = Start-Process -FilePath $wgPath -ArgumentList "/installtunnelservice `"$ConfigPath`"" -Wait -PassThru
        
        # Start GUI Manager
        # WireGuard GUI manager is gewoon dezelfde exe zonder argumenten (of user voert het uit)
        Write-Log "Starten van WireGuard GUI Manager..." -Level "INFO"
        Start-Process -FilePath $wgPath -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log "WireGuard service succesvol geïnstalleerd en gestart" -Level "SUCCESS"
            return $true
        }
        else {
            # Check if likely already running or installed
            Write-Log "WireGuard service start gaf exit code $($process.ExitCode). Mogelijk draait de service al." -Level "WARNING"
            return $true # Treat as success or handled manually
        }
    }
    catch {
        Write-Log "Fout bij starten WireGuard service: $_" -Level "ERROR"
        return $false
    }
}
function Stop-WireGuardService {
    <#
    .SYNOPSIS
        Stopt alle draaiende WireGuard tunnel services.
    #>
    param()
    
    $wgPath = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardInstalledPath') -and $Script:Settings.wireGuardInstalledPath) { $Script:Settings.wireGuardInstalledPath } else { "C:\Program Files\WireGuard\wireguard.exe" }
    if (-not (Test-Path $wgPath)) {
        Write-Log "WireGuard executable niet gevonden, kan niet stoppen" -Level "WARNING"
        return $false
    }
    
    try {
        # Stop alle WireGuard tunnel services
        $services = Get-Service | Where-Object { $_.Name -like "WireGuardTunnel*" -and $_.Status -eq "Running" }
        foreach ($service in $services) {
            Write-Log "Stoppen van WireGuard service: $($service.Name)" -Level "INFO"
            Stop-Service -Name $service.Name -Force
            # Verwijder de service - haal tunnel naam uit service naam
            $tunnelName = $service.Name -replace '^WireGuardTunnel\$', ''
            Start-Process -FilePath $wgPath -ArgumentList "/uninstalltunnelservice $tunnelName" -Wait -PassThru | Out-Null
        }
        
        Write-Log "Alle WireGuard services gestopt" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Fout bij stoppen WireGuard services: $_" -Level "ERROR"
        return $false
    }
}
function New-WireGuardQRCode {
    <#
    .SYNOPSIS
        Maakt een QR-code voor de WireGuard client configuratie.
    #>
    param(
        [Parameter(Mandatory = $true)]$ConfigContent,
        [Parameter(Mandatory = $true)]$OutputPath
    )
    
    # Controleer of QrCodes module is geïnstalleerd
    if (-not (Get-Module -Name QrCodes -ListAvailable)) {
        try {
            Write-Log "QrCodes module installeren..." -Level "INFO"
            Install-Module -Name QrCodes -Force -Scope CurrentUser -ErrorAction Stop
        }
        catch {
            Write-Log "Kon QrCodes module niet installeren: $_" -Level "WARNING"
            return $false
        }
    }
    
    try {
        Import-Module QrCodes -ErrorAction Stop
        Out-BarcodeImage -Content $ConfigContent -Path $OutputPath
        Write-Log "QR-code opgeslagen in $OutputPath" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Fout bij maken QR-code: $_" -Level "ERROR"
        return $false
    }
}
function Install-RemoteWireGuardServer {
    <#
    .SYNOPSIS
        Installeert WireGuard Server op een remote machine.
    #>
    param(
        [Parameter(Mandatory = $true)]$ComputerName,
        [Parameter(Mandatory = $true)]$Credential,
        [Parameter(Mandatory = $true)]$ServerConfigContent, # De inhoud van wg_server.conf
        [Parameter(Mandatory = $true)]$RemoteConfigPath, # Waar op te slaan (directory of full path?)
        [int]$Port
    )
    
    if (-not $Port) {
        # Probeer poort uit settings te halen als niet opgegeven
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardPort') -and $Script:Settings.wireGuardPort) {
            $Port = [int]$Script:Settings.wireGuardPort
        }
        else {
            throw "Port niet opgegeven en 'wireGuardPort' ontbreekt of is leeg in Settings. Geef -Port op of voeg waarde toe aan de config."
        }
    }

    # Bepaal VPN subnet vanuit settings (veilig controleren)
    $vpnSubnet = $null
    if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardBaseSubnet)) {
        $vpnSubnet = "${($Script:Settings.wireGuardBaseSubnet)}.0/24"
    }
    else {
        throw "'wireGuardBaseSubnet' ontbreekt of is leeg in Settings. Voeg een waarde toe aan de config."
    }

    # Remote temp path fallback
    if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteTempPath') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteTempPath)) {
        $remoteTemp = $Script:Settings.wireGuardRemoteTempPath
    }
    else {
        $remoteTemp = 'C:\Temp'
    }
    
    Write-Log "Starten remote WireGuard server installatie op $ComputerName..." -Level "INFO"
    Write-Verbose "Verbinden met remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    Write-Verbose "PSSession opgezet"
    
    try {
        # 1. Module kopiëren
        Write-Verbose "Module kopiëren naar remote..."
        Invoke-Command -Session $session -ScriptBlock { param($path) if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force } } -ArgumentList $remoteTemp
        
        $localModule = Join-Path $PSScriptRoot "AutoSecureVPN.psm1" 
        # Fallback als PSScriptRoot niet is ingesteld (bijv. tijdens test)
        if (-not $localModule -or -not (Test-Path $localModule)) {
            $localModule = (Get-Module AutoSecureVPN).Path
        }

        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session -Force
        Write-Verbose "Module gekopieerd"
        
        # 2. Uitvoeren op remote met output capture
        Write-Verbose "Uitvoeren installatie op remote..."
        $remoteResult = Invoke-Command -Session $session -ScriptBlock {
            param($modulePath, $configContent, $configDir, $port, $vpnSubnet, $settings)
            
            $log = @()
            $log += "=== Remote WireGuard Server Setup Start ==="
            
            try {
                # Module laden
                $log += "Module laden..."
                $moduleContent = Get-Content -Path $modulePath -Raw
                Invoke-Expression $moduleContent
                
                Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
                
                # Override Write-Log to capture output
                $script:remoteLog = @()
                function global:Write-Log { 
                    param($Message, $Level) 
                    $script:remoteLog += "[$Level] $Message"
                }
                
                # 1. Installeren WireGuard
                $log += "Installeren WireGuard..."
                if (-not (Install-WireGuard)) { 
                    $log += "ERROR: WireGuard installatie mislukt"
                    throw "Remote WireGuard installatie mislukt" 
                }
                $log += "OK: WireGuard geinstalleerd"
                
                # 2. NAT configureren (dit roept ook Enable-IPForwarding aan)
                $log += "Configureren NAT voor internet toegang..."
                $natResult = Enable-VPNNAT -VPNSubnet $vpnSubnet
                $log += $script:remoteLog  # Voeg NAT logs toe
                if (-not $natResult) { 
                    $log += "WARNING: NAT configuratie mogelijk niet volledig"
                }
                else {
                    $log += "OK: NAT geconfigureerd"
                }
                
                # 3. Firewall
                $log += "Configureren firewall (UDP $port)..."
                if (-not (Set-Firewall -Port $port -Protocol "UDP")) { 
                    $log += "ERROR: Firewall configuratie mislukt"
                    throw "Remote Firewall configuratie mislukt" 
                }
                $log += "OK: Firewall geconfigureerd"
                
                # 4. Config opslaan
                $log += "Opslaan config naar $configDir..."
                if (-not (Test-Path $configDir)) { 
                    New-Item -ItemType Directory -Path $configDir -Force | Out-Null 
                }
                $serverConfigPath = Join-Path $configDir "wg_server.conf"
                Set-Content -Path $serverConfigPath -Value $configContent
                $log += "OK: Config opgeslagen naar $serverConfigPath"
                
                # 5. Service starten
                $log += "Starten WireGuard service..."
                if (-not (Start-WireGuardService -ConfigPath $serverConfigPath)) { 
                    $log += "ERROR: Service start mislukt"
                    throw "Remote Service start mislukt" 
                }
                $log += "OK: Service gestart"
                
                $log += "=== Remote Setup Voltooid ==="
                
                return @{
                    Success = $true
                    Log     = $log
                }
            }
            catch {
                $log += "FOUT: $_"
                return @{
                    Success = $false
                    Log     = $log
                    Error   = $_.ToString()
                }
            }
        } -ArgumentList $remoteModule, $ServerConfigContent, $RemoteConfigPath, $Port, $vpnSubnet, $Script:Settings
        
        # Toon remote output
        if ($remoteResult.Log) {
            Write-Host "`n--- Remote Server Output ---" -ForegroundColor Cyan
            foreach ($line in $remoteResult.Log) {
                if ($line -like "*ERROR*") {
                    Write-Host "  $line" -ForegroundColor Red
                }
                elseif ($line -like "*WARNING*") {
                    Write-Host "  $line" -ForegroundColor Yellow
                }
                elseif ($line -like "*OK*") {
                    Write-Host "  $line" -ForegroundColor Green
                }
                else {
                    Write-Host "  $line" -ForegroundColor Gray
                }
            }
            Write-Host "----------------------------`n" -ForegroundColor Cyan
        }
        
        if (-not $remoteResult.Success) {
            throw "Remote installatie gefaald: $($remoteResult.Error)"
        }
        
        Write-Verbose "Remote installatie voltooid"
        
        Write-Log "Remote WireGuard Server configuratie voltooid voor $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens remote WireGuard server installatie: $_" -Level "ERROR"
        Write-Verbose "Fout tijdens remote installatie: $_"
        return $false
    }
    finally {
        if ($session) { 
            Write-Verbose "PSSession sluiten..."
            Remove-PSSession $session 
            Write-Verbose "PSSession gesloten"
        }
    }
}
function Install-RemoteWireGuardClient {
    <#
    .SYNOPSIS
        Installeert WireGuard Client op een remote machine.
    #>
    param(
        [Parameter(Mandatory = $true)]$ComputerName,
        [Parameter(Mandatory = $true)]$Credential,
        [Parameter(Mandatory = $true)]$ClientConfigContent
    )
    
    $remoteTemp = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteTempPath') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteTempPath)) { $Script:Settings.wireGuardRemoteTempPath } else { 'C:\Temp' }
    $configDir = if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardRemoteClientConfigDir') -and -not [string]::IsNullOrWhiteSpace($Script:Settings.wireGuardRemoteClientConfigDir)) { $Script:Settings.wireGuardRemoteClientConfigDir } else { 'C:\Program Files\WireGuard\config' }
    
    Write-Log "Starten remote WireGuard client installatie op $ComputerName..." -Level "INFO"
    Write-Verbose "Verbinden met remote machine $ComputerName..."
    
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    Write-Verbose "PSSession opgezet"
    
    try {
        # 1. Module kopiëren
        Write-Verbose "Module kopiëren naar remote..."
        Invoke-Command -Session $session -ScriptBlock { param($path) if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force } } -ArgumentList $remoteTemp
        
        $localModule = Join-Path $PSScriptRoot "AutoSecureVPN.psm1"
        if (-not $localModule -or -not (Test-Path $localModule)) {
            $localModule = (Get-Module AutoSecureVPN).Path
        }

        $remoteModule = Join-Path $remoteTemp "AutoSecureVPN.psm1"
        Copy-Item -Path $localModule -Destination $remoteModule -ToSession $session -Force
        Write-Verbose "Module gekopieerd"
        
        # 2. Uitvoeren op remote
        Write-Verbose "Uitvoeren installatie op remote..."
        Invoke-Command -Session $session -ScriptBlock {
            param($modulePath, $configContent, $configDir, $settings)
            
            # Module laden
            $moduleContent = Get-Content -Path $modulePath -Raw
            Invoke-Expression $moduleContent
            
            Set-ModuleSettings -Settings $settings -BasePath "C:\Temp"
            
            function global:Write-Log { param($Message, $Level) Write-Verbose "[$Level] $Message" }
            
            Write-Verbose "Installeren WireGuard..."
            # Installeren
            if (-not (Install-WireGuard)) { throw "Remote WireGuard installatie mislukt" }
            
            Write-Verbose "Opslaan config..."
            # Config opslaan
            if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
            $clientConfigPath = Join-Path $configDir "wg-client.conf"
            Set-Content -Path $clientConfigPath -Value $configContent
            
            Write-Verbose "Starten service..."
            # Service starten
            if (-not (Start-WireGuardService -ConfigPath $clientConfigPath)) { throw "Remote Service start mislukt" }
            
        } -ArgumentList $remoteModule, $ClientConfigContent, $configDir, $Script:Settings
        Write-Verbose "Remote installatie voltooid"
        
        Write-Log "Remote WireGuard Client configuratie voltooid voor $ComputerName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Fout tijdens remote WireGuard client installatie: $_" -Level "ERROR"
        Write-Verbose "Fout tijdens remote installatie: $_"
        return $false
    }
    finally {
        if ($session) { 
            Write-Verbose "PSSession sluiten..."
            Remove-PSSession $session 
            Write-Verbose "PSSession gesloten"
        }
    }
}

function Invoke-BatchRemoteWireGuardClientInstall {
    <#
    .SYNOPSIS
        Installeert WireGuard op meerdere clients en genereert unieke configs.
    #>
    param(
        [Parameter(Mandatory = $true)]$Clients,
        [Parameter(Mandatory = $true)]$ServerKeys,
        [Parameter(Mandatory = $true)]$ServerEndpoint, # IP:Port
        [Parameter(Mandatory = $true)]$ModulePath,
        [Parameter(Mandatory = $true)]$Settings, # Pass configs
        [int]$ThrottleLimit = 5
    )
    
    # Basis IP ophalen uit settings of default
    $baseSubnet = if ($Settings.ContainsKey('wireGuardBaseSubnet') -and -not [string]::IsNullOrEmpty($Settings.wireGuardBaseSubnet)) { $Settings.wireGuardBaseSubnet } else { "10.13.13" }
    
    $i = 0
    $results = $Clients | ForEach-Object -Parallel {
        $client = $_
        # Increment IP index (naive approach, works for small batches)
        # Note: $using:i doesn't work for incrementing in parallel.
        # We need to pre-calculate IPs or pass them.
        
        # Oplossing: we doen setup sequentially voor key generation en pre-calc, dan parallel install.
        # Maar we moeten keys genereren. Kan lokaal.
        
        # Dit blok is parallel, dus logic moet zelfstandig zijn.
        # ECHTER, Install-WireGuard vereist geen keys, CreateConf wel.
        # We verplaatsen de logica naar buiten of we doen alles parallel en geven unieke IP mee in input object.
    }
    
    # Pre-process clients: Generate Keys & Configs Locally
    Write-Log "Voorbereiden WireGuard configuraties voor batch..." -Level "INFO"
    Write-Verbose "Voorbereiden configuraties voor $($Clients.Count) clients..."
    
    $preparedClients = @()
    foreach ($client in $Clients) {
        $i++
        $clientIpSuffix = 10 + $i # Start from .11
        if ($clientIpSuffix -gt 254) { throw "Te veel clients voor subnet" }
        $clientIp = "$baseSubnet.$clientIpSuffix"
        
        Write-Log "Genereren keys voor $($client.Name)..." -Level "INFO"
        Write-Verbose "Genereren keys voor $($client.Name)..."
        $keys = Initialize-WireGuardKeys -WgPath $Settings.wireGuardKeysExePath -Settings $Settings
        
        # Generate Client Config Content
        $configContent = @"
[Interface]
PrivateKey = $($keys.PrivateKey)
Address = $clientIp/24
DNS = $($Script:Settings.wireGuardDefaultDns)

[Peer]
PublicKey = $($ServerKeys.PublicKey)
Endpoint = $ServerEndpoint
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $($Script:Settings.wireGuardDefaultPersistentKeepalive)
"@

        $preparedClients += [PSCustomObject]@{
            Name          = $client.Name
            IP            = $client.IP # Remote Access IP
            Username      = $client.Username
            Password      = $client.Password
            ConfigContent = $configContent
            VPNIP         = $clientIp
            PublicKey     = $keys.PublicKey # Needed to update server?
        }
    }
    Write-Verbose "Alle configuraties voorbereid"
    
    # NOTE: Server config must be updated to include these peers!
    # Dit script update momenteel niet de server config.
    # We loggen de Public Keys zodat de admin ze kan toevoegen.
    
    $serverUpdates = ""
    foreach ($pc in $preparedClients) {
        $serverUpdates += "`n[Peer] # User: $($pc.Name)`nPublicKey = $($pc.PublicKey)`nAllowedIPs = $($pc.VPNIP)/32`n"
    }
    
    $serverUpdateFile = Join-Path $Script:Settings.outputPath "wg_server_additions.txt"
    Set-Content -Path $serverUpdateFile -Value $serverUpdates
    Write-Log "BELANGRIJK: Voeg de peers toe aan je server config! Opgeslagen in $serverUpdateFile" -Level "WARNING"
   
    # Instructies voor de admin zichtbaar maken in de console
    Write-Host ""
    Write-Host "=== HANDLEIDING: Peers toevoegen aan WireGuard server ===" -ForegroundColor Yellow
    Write-Host "1) Open het serverconfig bestand op de WireGuard server (bijv. C:\WireGuard\wg_server.conf)" -ForegroundColor Cyan
    Write-Host "2) Kopieer de inhoud van '$serverUpdateFile' en plak deze aan het einde van wg_server.conf" -ForegroundColor Cyan
    Write-Host "`n--- Te kopiëren inhoud ---" -ForegroundColor Magenta
    try {
        $contentToShow = Get-Content -Path $serverUpdateFile -Raw -ErrorAction Stop
        Write-Host $contentToShow -ForegroundColor Green
    }
    catch {
        Write-Host "Kan $serverUpdateFile niet lezen: $_" -ForegroundColor Red
    }
    Write-Host "`n3) Na toevoegen: herstart WireGuard service" -ForegroundColor Cyan
    Write-Host "4) Controleer of clients kunnen verbinden" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Yellow 
    Write-Verbose "Server updates opgeslagen in $serverUpdateFile - voeg deze handmatig toe aan je server config!"
    
    # Run Parallel Install
    Write-Verbose "Starten parallel installatie op $($preparedClients.Count) clients..."
    $localModulePath = $ModulePath
    
    $parallelResults = $preparedClients | ForEach-Object -Parallel {
        $pc = $_
        
        $securePassword = ConvertTo-SecureString $pc.Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($pc.Username, $securePassword)
        
        # Load Module
        Import-Module $using:localModulePath -Force
        
        if (Install-RemoteWireGuardClient -ComputerName $pc.IP -Credential $cred -ClientConfigContent $pc.ConfigContent) {
            "SUCCESS: $($pc.Name) ($($pc.IP))"
        }
        else {
            "ERROR: $($pc.Name) ($($pc.IP))"
        }
        
    } -ThrottleLimit $ThrottleLimit
    
    Write-Verbose "Parallel installatie voltooid"
    return $parallelResults
}
