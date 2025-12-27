# Core functional files for the AutoSecureVPN module



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
        [Parameter(Mandatory = $true, Position = 0)][ValidateSet('Menu', 'Success', 'Error')][string]$Mode,
        [Parameter(Mandatory = $false, Position = 1)][string]$Title,
        [Parameter(Mandatory = $false, Position = 2)][string[]]$Options,
        [Parameter(Mandatory = $false, Position = 3)][string]$SuccessTitle,
        [Parameter(Mandatory = $false, Position = 4)][string]$LogFile,
        [Parameter(Mandatory = $false, Position = 5)][string]$ExtraMessage,
        [Parameter(Mandatory = $false, Position = 6)][string]$ComputerName,
        [Parameter(Mandatory = $false, Position = 7)][string]$ExtraInfo,
        [Parameter(Position = 8)][ConsoleColor]$HeaderColor = 'Cyan',
        [Parameter(Position = 9)][ConsoleColor]$OptionColor = 'White',
        [Parameter(Position = 10)][ConsoleColor]$FooterColor = 'Cyan',
        [Parameter(Position = 11)][string]$SeparatorChar = '=',
        [Parameter(Position = 12)][switch]$NoPrompt,
        [Parameter(Position = 13)][string]$Prompt = 'Keuze: '
        , [Parameter(Position = 14)][string]$ErrorMessage
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
            }
            catch { $displayError = $null }
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
    param([Parameter(Position = 0)][string]$Message = 'Druk Enter om door te gaan...')
    Read-Host -Prompt $Message | Out-Null
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
        [Parameter(Mandatory = $true, Position = 0)][hashtable]$Settings,
        [Parameter(Mandatory = $true, Position = 1)][string]$BasePath
    )
    $Script:Settings = $Settings
    $Script:BasePath = $BasePath
}

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
        [Parameter(Mandatory = $true, Position = 0)][string]$Message,
        [Parameter(Position = 1)][string]$Level = "INFO",
        [Parameter(Position = 2)][string]$LogFile = $null
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
        [Parameter(Position = 0)][int]$Port,
        [Parameter(Position = 1)][string]$Protocol
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
function Enable-VPNNAT {
    <#
    .SYNOPSIS
        Configureert NAT voor VPN subnet (WireGuard of OpenVPN).
    
    .DESCRIPTION
        Deze functie configureert Network Address Translation (NAT) zodat
        VPN clients internettoegang hebben via de server.
        Werkt voor zowel WireGuard als OpenVPN.
        Probeert eerst NetNat, valt terug op ICS bij "Invalid class" errors.
        
    .PARAMETER VPNSubnet
        Het VPN subnet in CIDR notatie (bijv. 10.13.13.0/24).
        
    .PARAMETER InterfaceAlias
        De naam van de internet-facing network interface (optioneel, auto-detect).
    
    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.
        
    .EXAMPLE
        Enable-VPNNAT -VPNSubnet "10.13.13.0/24"
    #>
    param(
        [Parameter(Mandatory = $false)][string]$VPNSubnet,
        [Parameter(Mandatory = $false)][string]$InterfaceAlias
    )
    
    # Compacte en veilige fallback:
    # - Gebruik expliciet doorgegeven $VPNSubnet als deze niet leeg is
    # - Anders gebruik instelling $Script:Settings.wireGuardBaseSubnet als die bestaat en niet leeg is
    # - Als beide ontbreken: expliciete fout zodat admin de setting kan corrigeren
    if ([string]::IsNullOrWhiteSpace($VPNSubnet)) {
        $base = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet')) {
            $base = $Script:Settings.wireGuardBaseSubnet
        }

        if (-not [string]::IsNullOrWhiteSpace($base)) {
            $VPNSubnet = "${base}.0/24"
        }
        else {
            throw "VPNSubnet niet opgegeven en 'wireGuardBaseSubnet' ontbreekt of is leeg in Settings. Voeg een waarde toe aan de config of geef -VPNSubnet op."
        }
    }
    
    try {
        # Eerst IP Forwarding inschakelen
        if (-not (Enable-IPForwarding)) {
            Write-Log "Kon IP Forwarding niet inschakelen" -Level "ERROR"
            return $false
        }
        
        # ICS Persistence fix - voorkom dat Windows ICS automatisch uitschakelt
        try {
            $icsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess"
            Set-ItemProperty -Path $icsRegPath -Name "EnableRebootPersistConnection" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Log "ICS persistence ingeschakeld (voorkomt auto-reset)" -Level "INFO"
        }
        catch {
            Write-Log "Kon ICS persistence registry niet instellen: $_" -Level "WARNING"
        }
        
        # Bepaal de internet-facing interface als niet opgegeven
        if (-not $InterfaceAlias) {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object { $_.NextHop -ne "0.0.0.0" } | 
            Select-Object -First 1
            
            if ($defaultRoute) {
                $InterfaceAlias = (Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Log "Internet interface gedetecteerd: $InterfaceAlias" -Level "INFO"
            }
            
            if (-not $InterfaceAlias) {
                $InterfaceAlias = (Get-NetAdapter | Where-Object { 
                        $_.Status -eq "Up" -and 
                        $_.Name -notlike "*WireGuard*" -and
                        $_.Name -notlike "*Loopback*"
                    } | Select-Object -First 1).Name
                
                if (-not $InterfaceAlias) {
                    throw "Kon geen internet interface detecteren"
                }
            }
        }
        
        Write-Log "Configureren NAT voor $VPNSubnet via $InterfaceAlias..." -Level "INFO"
        
        $natConfigured = $false
        
        # Methode 1: Probeer NetNat (kan "Invalid class" geven op sommige systemen)
        try {
            $netNatAvailable = Get-Command -Name "New-NetNat" -ErrorAction SilentlyContinue
            if ($netNatAvailable) {
                $natName = "WireGuardNAT"
                
                # Test of NetNat WMI class werkt
                $testNat = Get-NetNat -ErrorAction Stop 2>&1
                
                # Verwijder bestaande NAT met dezelfde naam
                $existingNat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
                if ($existingNat) {
                    Remove-NetNat -Name $natName -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Log "Bestaande NAT regel verwijderd" -Level "INFO"
                }
                
                # Maak nieuwe NAT regel
                New-NetNat -Name $natName -InternalIPInterfaceAddressPrefix $VPNSubnet -ErrorAction Stop
                Write-Log "NAT regel '$natName' aangemaakt voor $VPNSubnet" -Level "SUCCESS"
                $natConfigured = $true
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "Invalid class|not found|WBEM|WMI") {
                Write-Log "NetNat niet beschikbaar (WMI error), probeer ICS fallback..." -Level "WARNING"
            }
            else {
                Write-Log "NetNat error: $errorMsg - probeer ICS fallback..." -Level "WARNING"
            }
        }
        
        # Methode 2: Registry-based ICS (meer betrouwbaar dan COM)
        if (-not $natConfigured) {
            try {
                Write-Log "Configureren ICS via registry methode..." -Level "INFO"
                
                # Haal GUID van interfaces op
                $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
                $wgAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" } | Select-Object -First 1
                
                if (-not $internetAdapter -or -not $wgAdapter) {
                    Write-Log "Kon adapters niet vinden voor ICS" -Level "WARNING"
                }
                else {
                    # Get the interface GUIDs from registry
                    $netCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                    
                    $internetGuid = $null
                    $wgGuid = $null
                    
                    Get-ChildItem $netCfgPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $connPath = Join-Path $_.PSPath "Connection"
                        if (Test-Path $connPath) {
                            $connName = (Get-ItemProperty $connPath -Name "Name" -ErrorAction SilentlyContinue).Name
                            if ($connName -eq $InterfaceAlias) {
                                $internetGuid = $_.PSChildName
                            }
                            if ($connName -eq $wgAdapter.Name) {
                                $wgGuid = $_.PSChildName
                            }
                        }
                    }
                    
                    if ($internetGuid -and $wgGuid) {
                        Write-Log "Internet GUID: $internetGuid, WireGuard GUID: $wgGuid" -Level "INFO"
                        
                        # Stop SharedAccess service
                        Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        
                        # Clear existing ICS configuration in registry
                        $icsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess"
                        
                        # Remove old SharingConnections
                        Remove-ItemProperty -Path $icsRegPath -Name "SharingPublicInterface" -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $icsRegPath -Name "SharingPrivateInterface" -ErrorAction SilentlyContinue
                        
                        # Set new ICS configuration
                        # Note: ICS expects interface Device GUIDs
                        Set-ItemProperty -Path $icsRegPath -Name "SharingPublicInterface" -Value $internetGuid -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $icsRegPath -Name "SharingPrivateInterface" -Value $wgGuid -ErrorAction SilentlyContinue
                        
                        # Start SharedAccess service
                        Set-Service SharedAccess -StartupType Manual -ErrorAction SilentlyContinue
                        Start-Service SharedAccess -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 2
                        
                        Write-Log "ICS geconfigureerd via registry: $InterfaceAlias -> $($wgAdapter.Name)" -Level "SUCCESS"
                        $natConfigured = $true
                    }
                    else {
                        Write-Log "Kon interface GUIDs niet vinden" -Level "WARNING"
                    }
                }
            }
            catch {
                Write-Log "Registry ICS configuratie mislukt: $_" -Level "WARNING"
            }
        }
        
        # Methode 3: COM-based ICS met service restart (fallback)
        if (-not $natConfigured) {
            try {
                Write-Log "Probeer ICS via COM met service restart..." -Level "INFO"
                
                # Stop SharedAccess first to clear state
                Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Start-Service SharedAccess -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                $netShare = New-Object -ComObject HNetCfg.HNetShare
                $connections = $netShare.EnumEveryConnection
                
                # Eerst ALLE sharing uitschakelen
                foreach ($conn in $connections) {
                    try {
                        $cfg = $netShare.INetSharingConfigurationForINetConnection($conn)
                        $cfg.DisableSharing()
                    }
                    catch {}
                }
                
                # Wacht even
                Start-Sleep -Seconds 1
                
                # Zoek connecties opnieuw
                $internetConnection = $null
                $wgConnection = $null
                
                foreach ($conn in $connections) {
                    try {
                        $props = $netShare.NetConnectionProps($conn)
                        if ($props.Name -eq $InterfaceAlias) { $internetConnection = $conn }
                        if ($props.Name -like "*wg*" -or $props.Name -like "*WireGuard*") { $wgConnection = $conn }
                    }
                    catch {}
                }
                
                if ($internetConnection) {
                    $cfg = $netShare.INetSharingConfigurationForINetConnection($internetConnection)
                    $cfg.EnableSharing(0)  # Public
                    Write-Log "ICS Public enabled op $InterfaceAlias" -Level "SUCCESS"
                    
                    if ($wgConnection) {
                        Start-Sleep -Milliseconds 500
                        $wgCfg = $netShare.INetSharingConfigurationForINetConnection($wgConnection)
                        $wgCfg.EnableSharing(1)  # Private
                        Write-Log "ICS Private enabled op WireGuard" -Level "SUCCESS"
                    }
                    
                    $natConfigured = $true
                }
            }
            catch {
                Write-Log "COM ICS configuratie mislukt: $_" -Level "WARNING"
            }
        }
        
        # Methode 4: Handmatige routing + netsh als laatste fallback
        if (-not $natConfigured) {
            try {
                Write-Log "Probeer netsh routing als laatste fallback..." -Level "INFO"
                
                $wgAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" } | Select-Object -First 1
                $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
                
                if ($wgAdapter -and $internetAdapter) {
                    Set-NetIPInterface -InterfaceIndex $wgAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
                    Set-NetIPInterface -InterfaceIndex $internetAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
                }
                
                $null = netsh routing ip nat install 2>&1
                $null = netsh routing ip nat add interface "$InterfaceAlias" full 2>&1
                
                Write-Log "Netsh routing geconfigureerd" -Level "SUCCESS"
                $natConfigured = $true
            }
            catch {
                Write-Log "Netsh routing mislukt: $_" -Level "WARNING"
            }
        }
        
        # Configureer Windows Firewall voor forwarding
        try {
            $fwRuleName = "WireGuard-VPN-Forward"
            $existingFwRule = Get-NetFirewallRule -Name $fwRuleName -ErrorAction SilentlyContinue
            
            if (-not $existingFwRule) {
                New-NetFirewallRule -Name $fwRuleName `
                    -DisplayName "WireGuard VPN Forwarding" `
                    -Direction Inbound `
                    -Action Allow `
                    -RemoteAddress $VPNSubnet `
                    -Profile Any `
                    -Enabled True | Out-Null
                    
                New-NetFirewallRule -Name "$fwRuleName-Out" `
                    -DisplayName "WireGuard VPN Forwarding Out" `
                    -Direction Outbound `
                    -Action Allow `
                    -RemoteAddress $VPNSubnet `
                    -Profile Any `
                    -Enabled True | Out-Null
                    
                Write-Log "Firewall regels toegevoegd voor VPN forwarding" -Level "INFO"
            }
        }
        catch {
            Write-Log "Firewall configuratie warning: $_" -Level "WARNING"
        }
        
        # VERIFICATIE: Check of ICS daadwerkelijk werkt
        $icsActuallyEnabled = $false
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            foreach ($conn in $netShare.EnumEveryConnection) {
                try {
                    $props = $netShare.NetConnectionProps($conn)
                    $config = $netShare.INetSharingConfigurationForINetConnection($conn)
                    if ($props.Name -eq $InterfaceAlias -and $config.SharingEnabled -and $config.SharingConnectionType -eq 0) {
                        $icsActuallyEnabled = $true
                        Write-Log "VERIFICATIE: ICS is actief op $InterfaceAlias" -Level "SUCCESS"
                        break
                    }
                }
                catch {}
            }
        }
        catch {
            Write-Log "Kon ICS status niet verifieren" -Level "WARNING"
        }
        
        if ($icsActuallyEnabled) {
            Write-Log "NAT/ICS configuratie voltooid en geverifieerd voor WireGuard VPN" -Level "SUCCESS"
            return $true
        }
        elseif ($natConfigured) {
            # Methodes rapporteerden succes maar verificatie faalde
            Write-Log "NAT methodes uitgevoerd maar ICS niet geverifieerd - mogelijk herstart nodig" -Level "WARNING"
            Write-Log "=======================================" -Level "WARNING"
            Write-Log "HANDMATIGE ACTIE VEREIST:" -Level "WARNING"
            Write-Log "1. Open Netwerkcentrum (ncpa.cpl)" -Level "WARNING"
            Write-Log "2. Rechtsklik op 'WiFi' -> Properties -> Sharing tab" -Level "WARNING"
            Write-Log "3. Vink aan: 'Allow other network users to connect...'" -Level "WARNING"
            Write-Log "4. Selecteer 'wg_server' als Home networking connection" -Level "WARNING"
            Write-Log "5. Klik OK" -Level "WARNING"
            Write-Log "=======================================" -Level "WARNING"
            return $true  # Return true zodat setup doorgaat, user ziet warning
        }
        else {
            Write-Log "NAT configuratie gefaald - handmatige configuratie nodig" -Level "ERROR"
            Write-Log "TIP: Schakel Internet Connection Sharing handmatig in via Netwerkcentrum" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-Log "Fout bij configureren NAT: $_" -Level "ERROR"
        return $false
    }
}
function Enable-IPForwarding {
    <#
    .SYNOPSIS
        Schakelt IP Forwarding in op Windows voor VPN routing.
    
    .DESCRIPTION
        Deze functie schakelt IP routing in via het Windows register.
        Dit is vereist om VPN verkeer door te sturen naar het internet.
        
    .OUTPUTS
        System.Boolean
        $true bij succes, anders $false.
        
    .EXAMPLE
        Enable-IPForwarding
        
    .NOTES
        Vereist admin rechten. Een herstart kan nodig zijn voor activatie.
    #>
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        $currentValue = Get-ItemProperty -Path $regPath -Name "IPEnableRouter" -ErrorAction SilentlyContinue
        
        if ($currentValue.IPEnableRouter -eq 1) {
            Write-Log "IP Forwarding is al ingeschakeld" -Level "INFO"
            return $true
        }
        
        Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value 1 -Type DWord
        Write-Log "IP Forwarding ingeschakeld in register. Herstart mogelijk vereist." -Level "SUCCESS"
        
        # Probeer ook RemoteAccess service te starten voor directe activatie
        try {
            $rasService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
            if ($rasService) {
                if ($rasService.Status -ne "Running") {
                    Set-Service -Name "RemoteAccess" -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
                    Write-Log "RemoteAccess service gestart voor IP routing" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log "RemoteAccess service kon niet gestart worden, herstart nodig: $_" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Fout bij inschakelen IP Forwarding: $_" -Level "ERROR"
        return $false
    }
}
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
        [Parameter(Mandatory = $true, Position = 0)]
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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
                }
                catch {
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