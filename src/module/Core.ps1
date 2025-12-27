# Core functional files for the AutoSecureVPN module



function Show-Menu {
    <#
    .SYNOPSIS
        Displays a menu with options and asks for choice, or shows a success message.

    .DESCRIPTION
        This function displays a menu with a title, list of options, and waits for user input.
        It validates the choice and returns the chosen number.
        If Mode is 'Success', it displays a success message in a box.

    .PARAMETER Mode
        'Menu' for displaying menu, 'Success' for success message.

    .PARAMETER Title
        The title of the menu or success message.

    .PARAMETER Options
        An array of options to display (Menu only).

    .PARAMETER SuccessTitle
        The title for success message (Success only).

    .PARAMETER LogFile
        Path to log file (for Success).

    .PARAMETER ExtraMessage
        Extra message (for Success).

    .PARAMETER ComputerName
        Name of computer for log (for Success).

    .PARAMETER HeaderColor
        Color for the header (default Cyan).

    .PARAMETER OptionColor
        Color for the options (default White).

    .PARAMETER FooterColor
        Color for the footer (default Cyan).

    .PARAMETER SeparatorChar
        Character for the separator (default '=').

    .PARAMETER NoPrompt
        If true, do not show prompt and return null (Menu only).

    .PARAMETER Prompt
        The prompt text (default 'Choice: ') (Menu only).

    .OUTPUTS
        System.Int32 for Menu, None for Success.

    .EXAMPLE
        Show-Menu -Mode Menu -Title "Hoofdmenu" -Options @("Optie 1", "Optie 2")

    .EXAMPLE
        Show-Menu -Mode Success -SuccessTitle "Remote Client Setup Succesvol Voltooid!" -LogFile $script:LogFile -ExtraMessage "Op de remote machine kun je nu de VPN verbinding starten via OpenVPN." -ComputerName $computerName

    .NOTES
        This function uses Write-Host for console output and Read-Host for input.
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
        [Parameter(Mandatory = $false, Position = 12)][switch]$NoPrompt,
        [Parameter(Position = 13)][string]$Prompt = 'Choice: '
        , [Parameter(Position = 14)][string]$ErrorMessage
    )

    # Depending on the Mode, show a menu, success message or error message
    if ($Mode -eq 'Menu') {
        # Validate that Title and Options are present for Menu mode
        if (-not $Title -or -not $Options) {
            throw "For Mode 'Menu', Title and Options are required."
        }
        # Clear the screen for a clean display
        Clear-Host
        # Create a separator line for the header
        $sep = ($SeparatorChar * 30)
        Write-Host $sep -ForegroundColor $HeaderColor
        Write-Host "      $Title" -ForegroundColor $HeaderColor
        Write-Host $sep -ForegroundColor $HeaderColor

        # Show all options numbered
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $num = $i + 1
            Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
        }

        Write-Host $sep -ForegroundColor $FooterColor

        # If NoPrompt is set, return null without prompt
        if ($NoPrompt) { return $null }

        # Ask for user input and validate the choice
        while ($true) {
            $userInput = Read-Host -Prompt $Prompt
            if ($userInput -match '^[0-9]+$') {
                $n = [int]$userInput
                if ($n -ge 1 -and $n -le $Options.Count) { return $n }
            }
            Write-Host "Invalid choice, please try again." -ForegroundColor Red
        }
    }
    elseif ($Mode -eq 'Success') {
        # Validate that SuccessTitle is present for Success mode
        if (-not $SuccessTitle) {
            throw "For Mode 'Success', SuccessTitle is required."
        }
        # Show a success box with the title
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
        # Show extra information if available
        if ($LogFile) {
            Write-Host "`nLog file: $LogFile" -ForegroundColor Yellow
        }
        if ($ExtraInfo) {
            Write-Host "$ExtraInfo" -ForegroundColor Yellow
        }
        if ($ExtraMessage) {
            Write-Host "`n$ExtraMessage" -ForegroundColor Cyan
        }
        # Log the successful action if ComputerName given
        if ($ComputerName) {
            Write-Log "Remote client setup successfully completed for $ComputerName" -Level "SUCCESS"
        }
    }
    elseif ($Mode -eq 'Error') {
        # Validate that SuccessTitle is present for Error mode (reused as error title)
        if (-not $SuccessTitle) {
            throw "For Mode 'Error', SuccessTitle is required."
        }
        # Show an error box with the title
        Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║  $SuccessTitle  ║" -ForegroundColor Red
        Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Red
        # Determine the best error text to show (priority: explicit parameter > extra fields > global error)
        $displayError = $null
        if ($ErrorMessage) { $displayError = $ErrorMessage }
        elseif ($ExtraMessage) { $displayError = $ExtraMessage }
        elseif ($ExtraInfo) { $displayError = $ExtraInfo }
        elseif ($LogFile) { $displayError = "See log file: $LogFile" }
        elseif ($global:Error.Count -gt 0) {
            try {
                $err = $global:Error[0]
                $msg = $err.Exception.Message
                if ($err.ScriptStackTrace) { $msg += "`n$($err.ScriptStackTrace)" }
                $displayError = $msg
            }
            catch { $displayError = $null }
        }

        # Show the error details if available
        if ($displayError) {
            Write-Host "`nERROR:" -ForegroundColor Red
            Write-Host "$displayError" -ForegroundColor Yellow
        }
        elseif ($LogFile) {
            Write-Host "`nLog file: $LogFile" -ForegroundColor Yellow
        }
        # Log the error if ComputerName given
        if ($ComputerName) {
            Write-Log "Batch remote client setup failed ($ComputerName)" -Level "ERROR"
        }
        # If options are given, show a menu for recovery (without clearing the screen)
        if ($Options) {
            # Keep the error output visible above the option menu
            $sep = ($SeparatorChar * 30)
            Write-Host $sep -ForegroundColor $HeaderColor
            Write-Host "      Error occurred - Choose an option" -ForegroundColor $HeaderColor
            Write-Host $sep -ForegroundColor $HeaderColor
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $num = $i + 1
                Write-Host "$num. $($Options[$i])" -ForegroundColor $OptionColor
            }
            Write-Host $sep -ForegroundColor $FooterColor
            if (-not $NoPrompt) {
                # Ask for recovery choice
                while ($true) {
                    $userInput = Read-Host -Prompt $Prompt
                    if ($userInput -match '^[0-9]+$') {
                        $n = [int]$userInput
                        if ($n -ge 1 -and $n -le $Options.Count) { return $n }
                    }
                    Write-Host "Invalid choice, please try again." -ForegroundColor Red
                }
            }
        }
    }
}
function Wait-Input {
    <#
    .SYNOPSIS
        Waits for user input to continue.

    .DESCRIPTION
        This function displays a message and waits until the user presses Enter.

    .PARAMETER Message
        The message to display (default 'Press Enter to continue...').

    .OUTPUTS
        None

    .EXAMPLE
        Wait-Input

    .NOTES
        This function uses Read-Host to wait for input.
    #>
    param([Parameter(Position = 0)][string]$Message = 'Press Enter to continue...')
    Read-Host -Prompt $Message | Out-Null
}

function Set-ModuleSettings {
    <#
    .SYNOPSIS
        Sets the module settings for remote operations.

    .DESCRIPTION
        This function sets $Script:Settings and $Script:BasePath for use in remote sessions.

    .PARAMETER Settings
        The hashtable with settings.

    .PARAMETER BasePath
        The base path for the module.

    .OUTPUTS
        None

    .EXAMPLE
        Set-ModuleSettings -Settings $mySettings -BasePath "C:\Temp"

    .NOTES
        This function modifies script-scoped variables.
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
        Checks if the script is run as administrator.

    .DESCRIPTION
        This function checks if the current user has administrator privileges.

    .OUTPUTS
        System.Boolean
        $true if administrator, otherwise $false.

    .EXAMPLE
        if (-not (Test-IsAdmin)) { Write-Log "Administrator privileges required" -Level "ERROR" }

    Reference: https://codeandkeep.com/Check-If-Running-As-Admin/.
    #>
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file and console.

    .DESCRIPTION
        This function logs a message with level, timestamp, to a file and console.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        The log level (INFO, WARNING, ERROR, SUCCESS).

    .PARAMETER LogFile
        The path to the log file (optional, uses default path).

    .OUTPUTS
        None

    .EXAMPLE
        Write-Log "Operation completed" -Level "SUCCESS"

    .NOTES
        This function uses Add-Content for file output and Write-Verbose for console.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Message,
        [Parameter(Position = 1)][string]$Level = "INFO",
        [Parameter(Position = 2)][string]$LogFile = $null
    )
    
    # Set default log path if not specified
    if (-not $LogFile) {
        # Always use the project root for logs, regardless of settings
        $logsPath = Join-Path $Script:BasePath "logs"
        # Create logs directory if it does not exist
        if (-not (Test-Path $logsPath)) {
            New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
        }
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    # Generate timestamp and format the log entry
    $timestamp = Get-Date -Format $Script:Settings.logTimestampFormat
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Try to write the log entry to the file
    try {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Verbose "Cannot write to log file: $_"
    }
    
    # # Also write to the console depending on the log level
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
        Configures the Windows Firewall for OpenVPN.

    .DESCRIPTION
        This function adds an inbound firewall rule for the specified port and protocol.

    .PARAMETER Port
        The port to open (default from settings).

    .PARAMETER Protocol
        The protocol (TCP/UDP, default from settings).

    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.

    .EXAMPLE
        Set-Firewall -Port 443 -Protocol "TCP"

    Reference: Based on New-NetFirewallRule cmdlet (Microsoft PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), and Get-NetFirewallRule for check (https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule).
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
        throw "Port must be between 1 and 65535, received: $Port"
    }
    if ($Protocol -notin @('TCP', 'UDP')) {
        throw "Protocol must be TCP or UDP, received: $Protocol"
    }
    
    Write-Log "Firewall configuration started for port $Port $Protocol" -Level "INFO"
    
    try {
        # Enable firewall rule for OpenVPN
        $ruleName = "OpenVPN-Inbound-$Protocol-$Port"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log "Firewall rule already exists: $ruleName" -Level "INFO"
            return $true
        }
        
        New-NetFirewallRule -Name $ruleName `
            -DisplayName "OpenVPN $Protocol $Port" `
            -Direction Inbound `
            -Protocol $Protocol `
            -LocalPort $Port `
            -Action Allow `
            -Profile Any
        
        Write-Log "Firewall rule added: $ruleName" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during firewall configuration: $_" -Level "ERROR"
        return $false
    }
}
function Enable-VPNNAT {
    <#
    .SYNOPSIS
        Configures NAT for VPN subnet (WireGuard or OpenVPN).
    
    .DESCRIPTION
        This function configures Network Address Translation (NAT) so that
        VPN clients have internet access via the server.
        Works for both WireGuard and OpenVPN.
        Tries NetNat first, falls back to ICS on "Invalid class" errors.
        
    .PARAMETER VPNSubnet
        The VPN subnet in CIDR notation (e.g. 10.13.13.0/24).
        
    .PARAMETER InterfaceAlias
        The name of the internet-facing network interface (optional, auto-detect).
    
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
        
    .EXAMPLE
        Enable-VPNNAT -VPNSubnet "10.13.13.0/24"
    #>
    param(
        [Parameter(Mandatory = $false)][string]$VPNSubnet,
        [Parameter(Mandatory = $false)][string]$InterfaceAlias
    )
    
    # Compact and safe fallback:
    # - Use explicitly passed $VPNSubnet if it's not empty
    # - Otherwise use setting $Script:Settings.wireGuardBaseSubnet if it exists and is not empty
    # - If both are missing: explicit error so the admin can correct the setting
    if ([string]::IsNullOrWhiteSpace($VPNSubnet)) {
        $base = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet')) {
            $base = $Script:Settings.wireGuardBaseSubnet
        }

        if (-not [string]::IsNullOrWhiteSpace($base)) {
            $VPNSubnet = "${base}.0/24"
        }
        else {
            throw "VPNSubnet not specified and 'wireGuardBaseSubnet' is missing or empty in Settings. Add a value to the config or specify -VPNSubnet."
        }
    }
    
    try {
        # First enable IP Forwarding
        if (-not (Enable-IPForwarding)) {
            Write-Log "Could not enable IP Forwarding" -Level "ERROR"
            return $false
        }
        
        # ICS Persistence fix - prevent Windows from automatically disabling ICS
        try {
            $icsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess"
            Set-ItemProperty -Path $icsRegPath -Name "EnableRebootPersistConnection" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Log "ICS persistence enabled (prevents auto-reset)" -Level "INFO"
        }
        catch {
            Write-Log "Could not set ICS persistence registry: $_" -Level "WARNING"
        }
        
        # Determine the internet-facing interface if not specified
        if (-not $InterfaceAlias) {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object { $_.NextHop -ne "0.0.0.0" } | 
            Select-Object -First 1
            
            if ($defaultRoute) {
                $InterfaceAlias = (Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Log "Internet interface detected: $InterfaceAlias" -Level "INFO"
            }
            
            if (-not $InterfaceAlias) {
                $InterfaceAlias = (Get-NetAdapter | Where-Object { 
                        $_.Status -eq "Up" -and 
                        $_.Name -notlike "*WireGuard*" -and
                        $_.Name -notlike "*Loopback*"
                    } | Select-Object -First 1).Name
                
                if (-not $InterfaceAlias) {
                    throw "Could not detect any internet interface"
                }
            }
        }
        
        Write-Log "Configuring NAT for $VPNSubnet via $InterfaceAlias..." -Level "INFO"
        
        $natConfigured = $false
        
        # Method 1: Try NetNat (can give "Invalid class" on some systems)
        try {
            $netNatAvailable = Get-Command -Name "New-NetNat" -ErrorAction SilentlyContinue
            if ($netNatAvailable) {
                $natName = "WireGuardNAT"
                
                # Test if NetNat WMI class works
                Get-NetNat -ErrorAction Stop | Out-Null
                
                # Verwijder bestaande NAT met dezelfde naam
                $existingNat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
                if ($existingNat) {
                    Remove-NetNat -Name $natName -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Log "Existing NAT rule removed" -Level "INFO"
                }
                
                # Create new NAT rule
                New-NetNat -Name $natName -InternalIPInterfaceAddressPrefix $VPNSubnet -ErrorAction Stop
                Write-Log "NAT rule '$natName' created for $VPNSubnet" -Level "SUCCESS"
                $natConfigured = $true
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "Invalid class|not found|WBEM|WMI") {
                Write-Log "NetNat not available (WMI error), trying ICS fallback..." -Level "WARNING"
            }
            else {
                Write-Log "NetNat error: $errorMsg - trying ICS fallback..." -Level "WARNING"
            }
        }
        
        # Method 2: Registry-based ICS (more reliable than COM)
        if (-not $natConfigured) {
            try {
                Write-Log "Configuring ICS via registry method..." -Level "INFO"
                
                # Haal GUID van interfaces op
                $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
                $wgAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" } | Select-Object -First 1
                
                if (-not $internetAdapter -or -not $wgAdapter) {
                    Write-Log "Could not find adapters for ICS" -Level "WARNING"
                }
                else {
                    # Get the interface GUIDs from registry
                    $netCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                    
                    $guidResults = Get-ChildItem $netCfgPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $connPath = Join-Path $_.PSPath "Connection"
                        if (Test-Path $connPath) {
                            $connName = (Get-ItemProperty $connPath -Name "Name" -ErrorAction SilentlyContinue).Name
                            if ($connName -eq $InterfaceAlias) {
                                [PSCustomObject]@{ Type = "Internet"; Guid = $_.PSChildName }
                            }
                            elseif ($connName -eq $wgAdapter.Name) {
                                [PSCustomObject]@{ Type = "WG"; Guid = $_.PSChildName }
                            }
                        }
                    }
                    
                    $internetGuid = ($guidResults | Where-Object { $_.Type -eq "Internet" }).Guid
                    $wgGuid = ($guidResults | Where-Object { $_.Type -eq "WG" }).Guid
                    
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
                        
                        Write-Log "ICS configured via registry: $InterfaceAlias -> $($wgAdapter.Name)" -Level "SUCCESS"
                        $natConfigured = $true
                    }
                    else {
                        Write-Log "Could not find interface GUIDs" -Level "WARNING"
                    }
                }
            }
            catch {
                Write-Log "Registry ICS configuration failed: $_" -Level "WARNING"
            }
        }
        
        # Method 3: COM-based ICS with service restart (fallback)
        if (-not $natConfigured) {
            try {
                Write-Log "Trying ICS via COM with service restart..." -Level "INFO"
                
                # Stop SharedAccess first to clear state
                Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Start-Service SharedAccess -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                $netShare = New-Object -ComObject HNetCfg.HNetShare
                $connections = $netShare.EnumEveryConnection
                
                # First disable ALL sharing
                foreach ($conn in $connections) {
                    try {
                        $cfg = $netShare.INetSharingConfigurationForINetConnection($conn)
                        $cfg.DisableSharing()
                    }
                    catch {}
                }
                
                # Wait a bit
                Start-Sleep -Seconds 1
                
                # Find connections again
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
                    Write-Log "ICS Public enabled on $InterfaceAlias" -Level "SUCCESS"
                    
                    if ($wgConnection) {
                        Start-Sleep -Milliseconds 500
                        $wgCfg = $netShare.INetSharingConfigurationForINetConnection($wgConnection)
                        $wgCfg.EnableSharing(1)  # Private
                        Write-Log "ICS Private enabled on WireGuard" -Level "SUCCESS"
                    }
                    
                    $natConfigured = $true
                }
            }
            catch {
                Write-Log "COM ICS configuration failed: $_" -Level "WARNING"
            }
        }
        
        # Method 4: Manual routing + netsh as last fallback
        if (-not $natConfigured) {
            try {
                Write-Log "Trying netsh routing as last fallback..." -Level "INFO"
                
                $wgAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" } | Select-Object -First 1
                $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
                
                if ($wgAdapter -and $internetAdapter) {
                    Set-NetIPInterface -InterfaceIndex $wgAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
                    Set-NetIPInterface -InterfaceIndex $internetAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
                }
                
                $null = netsh routing ip nat install 2>&1
                $null = netsh routing ip nat add interface "$InterfaceAlias" full 2>&1
                
                Write-Log "Netsh routing configured" -Level "SUCCESS"
                $natConfigured = $true
            }
            catch {
                Write-Log "Netsh routing failed: $_" -Level "WARNING"
            }
        }
        
        # Configure Windows Firewall for forwarding
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
                    
                Write-Log "Firewall rules added for VPN forwarding" -Level "INFO"
            }
        }
        catch {
            Write-Log "Firewall configuration warning: $_" -Level "WARNING"
        }
        
        # VERIFICATION: Check if ICS actually works
        $icsActuallyEnabled = $false
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            foreach ($conn in $netShare.EnumEveryConnection) {
                try {
                    $props = $netShare.NetConnectionProps($conn)
                    $config = $netShare.INetSharingConfigurationForINetConnection($conn)
                    if ($props.Name -eq $InterfaceAlias -and $config.SharingEnabled -and $config.SharingConnectionType -eq 0) {
                        $icsActuallyEnabled = $true
                        Write-Log "VERIFICATION: ICS is active on $InterfaceAlias" -Level "SUCCESS"
                        break
                    }
                }
                catch {}
            }
        }
        catch {
            Write-Log "Could not verify ICS status" -Level "WARNING"
        }
        
        if ($icsActuallyEnabled) {
            Write-Log "NAT/ICS configuration completed and verified for WireGuard VPN" -Level "SUCCESS"
            return $true
        }
        elseif ($natConfigured) {
            # Methods reported success but verification failed
            Write-Log "NAT methods executed but ICS not verified - restart might be required" -Level "WARNING"
            Write-Log "=======================================" -Level "WARNING"
            Write-Log "MANUAL ACTION REQUIRED:" -Level "WARNING"
            Write-Log "1. Open Network Connections (ncpa.cpl)" -Level "WARNING"
            Write-Log "2. Right-click on 'WiFi' -> Properties -> Sharing tab" -Level "WARNING"
            Write-Log "3. Check: 'Allow other network users to connect...'" -Level "WARNING"
            Write-Log "4. Select 'wg_server' as Home networking connection" -Level "WARNING"
            Write-Log "5. Click OK" -Level "WARNING"
            Write-Log "=======================================" -Level "WARNING"
            return $true  # Return true so setup continues, user sees warning
        }
        else {
            Write-Log "NAT configuration failed - manual configuration required" -Level "ERROR"
            Write-Log "TIP: Enable Internet Connection Sharing manually via Network Connections" -Level "INFO"
            return $false
        }
    }
    catch {
        Write-Log "Error configuring NAT: $_" -Level "ERROR"
        return $false
    }
}
function Enable-IPForwarding {
    <#
    .SYNOPSIS
        Enables IP Forwarding on Windows for VPN routing.
    
    .DESCRIPTION
        This function enables IP routing via the Windows registry.
        This is required to forward VPN traffic to the internet.
        
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
        
    .EXAMPLE
        Enable-IPForwarding
        
    .NOTES
        Requires admin privileges. A restart may be required for activation.
    #>
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        $currentValue = Get-ItemProperty -Path $regPath -Name "IPEnableRouter" -ErrorAction SilentlyContinue
        
        if ($currentValue.IPEnableRouter -eq 1) {
            Write-Log "IP Forwarding is already enabled" -Level "INFO"
            return $true
        }
        
        Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value 1 -Type DWord
        Write-Log "IP Forwarding enabled in registry. Restart may be required." -Level "SUCCESS"
        
        # Probeer ook RemoteAccess service te starten voor directe activatie
        try {
            $rasService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
            if ($rasService) {
                if ($rasService.Status -ne "Running") {
                    Set-Service -Name "RemoteAccess" -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
                    Write-Log "RemoteAccess service started for IP routing" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log "RemoteAccess service could not be started, restart required: $_" -Level "WARNING"
        }
        
        return $true
    }
    catch {
        Write-Log "Error enabling IP Forwarding: $_" -Level "ERROR"
        return $false
    }
}
function Invoke-Rollback {
    <#
    .SYNOPSIS
        Performs rollback to undo all changes upon setup failure.

    .DESCRIPTION
        This function attempts to revert all changes made during setup, including stopping services, removing files and firewall rules.

    .PARAMETER SetupType
        Type of setup ('Server' or 'Client').

    .OUTPUTS
        None

    .EXAMPLE
        Invoke-Rollback -SetupType "Server"

    .NOTES
        This function tries to ignore errors and logs warnings on failures.
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Server", "Client")]
        [string]$SetupType
    )

    Write-Log "Rollback started for $SetupType setup" -Level "WARNING"

    try {
        switch ($SetupType) {
            "Server" {
                # Stop OpenVPN service
                Write-Log "Stopping OpenVPN service" -Level "INFO"
                try {
                    $service = Get-Service -Name "OpenVPNService" -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq 'Running') {
                        Stop-Service -Name "OpenVPNService" -Force
                        Write-Log "OpenVPN service stopped" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not stop OpenVPN service: $_" -Level "WARNING"
                }

                # Remove firewall rule
                Write-Log "Removing firewall rule" -Level "INFO"
                try {
                    $ruleName = "OpenVPN-Inbound-TCP-443"
                    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                    if ($existingRule) {
                        Remove-NetFirewallRule -Name $ruleName
                        Write-Log "Firewall rule '$ruleName' removed" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove firewall rule: $_" -Level "WARNING"
                }

                # Remove server configuration file
                Write-Log "Removing server configuration file" -Level "INFO"
                try {
                    $serverConfigPath = Join-Path $Script:Settings.configPath "server.ovpn"
                    if (Test-Path $serverConfigPath) {
                        Remove-Item -Path $serverConfigPath -Force
                        Write-Log "Server configuration file removed: $serverConfigPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove server configuration file: $_" -Level "WARNING"
                }

                # Remove PKI directory
                Write-Log "Removing certificates (PKI directory)" -Level "INFO"
                try {
                    $pkiPath = Join-Path $Script:Settings.easyRSAPath "pki"
                    if (Test-Path $pkiPath) {
                        Remove-Item -Path $pkiPath -Recurse -Force
                        Write-Log "PKI directory removed: $pkiPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove PKI directory: $_" -Level "WARNING"
                }

                # Remove client package ZIP
                Write-Log "Removing client package ZIP" -Level "INFO"
                try {
                    $outputPath = Join-Path $Script:BasePath $Script:Settings.outputPath
                    $zipPath = Join-Path $outputPath "vpn-client-$($Script:Settings.clientName).zip"
                    if (Test-Path $zipPath) {
                        Remove-Item -Path $zipPath -Force
                        Write-Log "Client package ZIP removed: $zipPath" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not remove client package ZIP: $_" -Level "WARNING"
                }

                # Remove EasyRSA directory (optional, only if empty)
                Write-Log "Removing EasyRSA directory if empty" -Level "INFO"
                try {
                    $easyRSAPath = $Script:Settings.easyRSAPath
                    if (Test-Path $easyRSAPath) {
                        $items = Get-ChildItem -Path $easyRSAPath -Recurse
                        if ($items.Count -eq 0) {
                            Remove-Item -Path $easyRSAPath -Recurse -Force
                            Write-Log "EasyRSA directory removed: $easyRSAPath" -Level "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "Could not remove EasyRSA directory: $_" -Level "WARNING"
                }
            }

            "Client" {
                # Stop VPN connection
                Write-Log "Stopping VPN connection" -Level "INFO"
                try {
                    $openvpnProcesses = Get-Process -Name "openvpn" -ErrorAction SilentlyContinue
                    if ($openvpnProcesses) {
                        $openvpnProcesses | Stop-Process -Force
                        Write-Log "OpenVPN processes stopped" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not stop OpenVPN processes: $_" -Level "WARNING"
                }

                # Remove imported configuration files
                Write-Log "Removing imported configuration files" -Level "INFO"
                try {
                    $configPath = $Script:Settings.configPath
                    if (Test-Path $configPath) {
                        $ovpnFiles = Get-ChildItem -Path $configPath -Filter "*.ovpn" -ErrorAction SilentlyContinue
                        foreach ($file in $ovpnFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Configuration file removed: $($file.FullName)" -Level "INFO"
                        }
                        $certFiles = Get-ChildItem -Path $configPath -Filter "*.crt" -ErrorAction SilentlyContinue
                        foreach ($file in $certFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Certificate file removed: $($file.FullName)" -Level "INFO"
                        }
                        $keyFiles = Get-ChildItem -Path $configPath -Filter "*.key" -ErrorAction SilentlyContinue
                        foreach ($file in $keyFiles) {
                            Remove-Item -Path $file.FullName -Force
                            Write-Log "Key file removed: $($file.FullName)" -Level "INFO"
                        }
                    }
                }
                catch {
                    Write-Log "Could not remove configuration files: $_" -Level "WARNING"
                }
            }
        }

        Write-Log "Rollback for $SetupType setup completed" -Level "SUCCESS"
    }
    catch {
        Write-Log "Error during rollback: $_" -Level "ERROR"
    }
}