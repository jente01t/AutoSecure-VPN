#regio Module Header
# Disclaimer: Function comments and inline comments are generated with Copilot.  


#region Module Header
<#
.SYNOPSIS
    AutoSecure-VPN Module - Automated VPN setup for OpenVPN and WireGuard.

.DESCRIPTION
    This module provides a complete automated setup for VPN server and client configurations.
    It supports both OpenVPN and WireGuard protocols.
    It can perform local and remote installations using PowerShell Remoting.

.NOTES
    Name:        AutoSecure-VPN.psm1
    Author:      Jente
    Requires:    PowerShell 7.0+
#>

#Requires -Version 7.0
#endregion Module Header


[CmdletBinding()]
param()

# Determine Module Root (handles both dev/split and production/single file structures)
if ((Split-Path $PSScriptRoot -Leaf) -eq 'dev') {
    $Script:ModuleRoot = Split-Path $PSScriptRoot -Parent
} else {
    $Script:ModuleRoot = $PSScriptRoot
}

# Set base path logic
# When module is installed via Install-Module, use user's Documents folder for logs/output to avoid permission issues.
# When running from development folder (e.g. git clone), use the project root.
if ($Script:ModuleRoot -match 'Documents\\PowerShell\\Modules|Program Files\\WindowsPowerShell\\Modules') {
    # Module is installed in a standard library location - use user's Documents folder
    $Script:BasePath = [Environment]::GetFolderPath('MyDocuments')
}
else {
    # Module is in development/source mode - use the project root (parent of the module folder)
    $Script:BasePath = Split-Path (Split-Path $Script:ModuleRoot -Parent) -Parent
}


#region Core / Menu System
# =================================================================================================
# REGION: Core / Menu System
# =================================================================================================
# This section contains the main entry points and menu logic for the AutoSecure-VPN module.
# It handles the initial user selection for Server/Client modes, protocol selection (OpenVPN/WireGuard),
# and the choice between Local and Remote deployment strategies.
# Key Functions: Start-VPNSetup, Select-ServerMode, Select-ClientMode, Select-VPNProtocol.
# =================================================================================================

function Start-VPNSetup {
    <#
    .SYNOPSIS
        Displays the main menu for VPN setup selection.

    .DESCRIPTION
        This function shows a menu with options for server or client setup selection.
        It initializes the configuration settings by loading .psd1 files before displaying the menu.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    # Load settings here so messages are visible before menu clears console
    # Check if the global Settings hashtable is empty
    if ($Script:Settings.Count -eq 0) {
        try {
            # Determine config directory
            # Dev: ../config relative to module root
            # Prod: Same directory as module root (flat structure)
            $devConfigDir = Join-Path (Split-Path $Script:ModuleRoot -Parent) 'config'
            if (Test-Path $devConfigDir) {
                $configDir = $devConfigDir
            } else {
                $configDir = $Script:ModuleRoot
            }
            
            # Check for Stable.psd1 existence
            $stableConfigPath = Join-Path $configDir 'Stable.psd1'
            if (-not (Test-Path $stableConfigPath)) {
                Write-Host "Configuration file 'Stable.psd1' not found." -ForegroundColor Red
                $examplePath = Join-Path $configDir 'Stable.psd1.example'
                if (Test-Path $examplePath) {
                    Write-Host "Please copy 'Stable.psd1.example' to 'Stable.psd1' and customize it." -ForegroundColor Yellow
                }
                Write-Host "Location: $configDir" -ForegroundColor Cyan
                return
            }
            
            # Load stable settings first (defaults from module directory)
            $stableSettings = Import-PowerShellDataFile -Path $stableConfigPath -ErrorAction Stop
            if ($stableSettings) { $Script:Settings = $stableSettings.Clone() }
            
            # Check for Variable.psd1 existence
            $variableConfigPath = Join-Path $configDir 'Variable.psd1'
            if (-not (Test-Path $variableConfigPath)) {
                Write-Host "Configuration file 'Variable.psd1' not found." -ForegroundColor Red
                $examplePath = Join-Path $configDir 'Variable.psd1.example'
                if (Test-Path $examplePath) {
                    Write-Host "Please copy 'Variable.psd1.example' to 'Variable.psd1' and customize it." -ForegroundColor Yellow
                }
                Write-Host "Location: $configDir" -ForegroundColor Cyan
                return
            }
            
            # Load variable settings and merge (variable overrides stable defaults)
            $variableSettings = Import-PowerShellDataFile -Path $variableConfigPath -ErrorAction Stop
            if ($variableSettings) {
                # Loop through variable settings and update the main Settings hashtable
                foreach ($key in $variableSettings.Keys) {
                    $Script:Settings[$key] = $variableSettings[$key]
                }
            }
        }
        catch {
            # Handle any errors during configuration loading (e.g., syntax errors in PSD1)
            Write-Host "Could not load settings: $($_.Exception.Message)" -ForegroundColor Yellow
            exit 1
        }
    }
    
    Write-Log "=== AutoSecure-VPN Automatic Setup Started ===" -Level "INFO"
    
    # Display the main menu
    $choice = Show-Menu -Mode Menu -Title "AutoSecure-VPN Automatic Setup" -Options @("Server Setup", "Client Setup", "Exit") -HeaderColor Cyan -OptionColor Green -FooterColor Cyan -Prompt "Enter your choice (1-3)"
    
    # Process user choice
    switch ($choice) {
        1 {
            Write-Host "`n[*] Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Server Setup selected" -Level "INFO"
            Select-ServerMode
        }
        2 {
            Write-Host "`n[*] Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Client Setup selected" -Level "INFO"
            Select-ClientMode
        }
        3 {
            Write-Host "`n[*] Exiting setup..." -ForegroundColor Yellow
            Write-Log "Setup closed by user" -Level "INFO"
            exit 0
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Start-VPNSetup
        }
    }
}

function Select-ServerMode {
    <#
    .SYNOPSIS
        Displays submenu for server setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local or remote server setup.
        It routes the logic to the specific protocol handlers (OpenVPN/WireGuard).

    .EXAMPLE
        Select-ServerMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Server Setup Options" -Options @("Local (Install and configure VPN server on this machine)", "Remote (Install and configure VPN server remotely)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Server Setup selected" -Level "INFO"
            
            # Ask for protocol and execute corresponding local setup
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardServerSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Server Setup selected" -Level "INFO"
            
            # Ask for protocol and execute corresponding remote setup
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardServerSetup
            }
        }
        3 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ServerMode
        }
    }
}

function Select-ClientMode {
    <#
    .SYNOPSIS
        Displays submenu for client setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local, remote, or batch client setup.

    .EXAMPLE
        Select-ClientMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Client Setup Options" -Options @("Local (Install and connect VPN client on this machine)", "Remote (Install and connect VPN client remotely)", "Batch Remote (Install VPN client on multiple machines)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-4)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Client Setup selected" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardClientSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Client Setup selected" -Level "INFO"
             
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardClientSetup
            }
        }
        3 {
            Write-Host "`n[*] Batch Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Batch Remote Client Setup selected" -Level "INFO"
            # Batch setup handles protocol selection internally
            Invoke-BatchRemoteClientSetup
        }
        4 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}

function Select-VPNProtocol {
    <#
    .SYNOPSIS
        Asks the user to choose a VPN protocol.
    #>
    $choice = Show-Menu -Mode Menu -Title "Choose VPN Protocol" -Options @("OpenVPN", "WireGuard") -HeaderColor Magenta -OptionColor White -Prompt "Select protocol (1-2)"
    
    switch ($choice) {
        1 { return "OpenVPN" }
        2 { return "WireGuard" }
    }
}


#endregion Core / Menu System
#region Module Initialization & Configuration Loading

# =================================================================================================
# REGION: Module Initialization & Configuration Loading
# =================================================================================================
# This section handles the dynamic loading of configuration settings from .psd1 files
# upon module import. It establishes the global settings scope and base paths.
# =================================================================================================

# Load module settings from src/config/Stable.psd1 and Variable.psd1 (if present)
# Use $Script:ModuleRoot and $Script: scope so the module is import-safe in test runspaces.
$Script:Settings = @{}

# Only load config files if $Script:ModuleRoot is available (not available when loaded via Invoke-Expression)
if ($Script:ModuleRoot -and -not [string]::IsNullOrWhiteSpace($Script:ModuleRoot)) {
    try {
        # Load stable settings first
        $stableConfigPath = Join-Path $Script:ModuleRoot '..\config\Stable.psd1'
        if (Test-Path $stableConfigPath) {
            $stableSettings = Import-PowerShellDataFile -Path $stableConfigPath -ErrorAction Stop
            if ($stableSettings) { $Script:Settings = $stableSettings.Clone() }
        }
        
        # Load variable settings and merge (variable overrides stable)
        $variableConfigPath = Join-Path $Script:ModuleRoot '..\config\Variable.psd1'
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
        Write-Log "Could not load settings: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Set BasePath only if Script:ModuleRoot is available
if ($Script:ModuleRoot -and -not [string]::IsNullOrWhiteSpace($Script:ModuleRoot)) {
    $Script:BasePath = Split-Path (Split-Path $Script:ModuleRoot -Parent) -Parent
}
else {
    # Fallback for remote execution via Invoke-Expression where paths are volatile
    $Script:BasePath = "C:\Temp"
}



#endregion Module Initialization & Configuration Loading
#region Helper Functions & Utilities


# =================================================================================================
# REGION: Helper Functions & Utilities
# =================================================================================================
# This section contains shared utility functions used across the module.
# It includes UI helpers (Show-Menu), logging (Write-Log), system checks (Test-IsAdmin),
# network configuration (Set-Firewall, Enable-VPNNAT, Enable-IPForwarding), and 
# remote installation helpers (Install-RemoteServer, Install-OpenVPN).
# =================================================================================================

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

        # Ask for user input and validate the choice in a loop
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
            # Attempt to retrieve the last error from the global stack
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
        It is typically called inside a remote ScriptBlock to initialize the environment.

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
        This function checks if the current user has administrator privileges by verifying role membership.

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
        It handles log directory creation if needed.

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
        
        # Ensure logFileName setting exists
        if (-not $Script:Settings.logFileName) {
            $Script:Settings.logFileName = 'vpn-setup.log'
        }
        
        $LogFile = Join-Path $logsPath $Script:Settings.logFileName
    }
    
    # Verify LogFile is not a directory (safety check)
    if (Test-Path $LogFile -PathType Container) {
        Write-Warning "LogFile path is a directory, not a file: $LogFile"
        $LogFile = Join-Path $LogFile 'vpn-setup.log'
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
    
    # Note: Console output handling is commented out here as the caller usually handles visual output
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
        Configures the Windows Firewall for OpenVPN or WireGuard.

    .DESCRIPTION
        This function adds an inbound firewall rule for the specified port and protocol.
        It checks if the rule already exists to avoid duplication.

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
        # Define unique rule name
        $ruleName = "OpenVPN-Inbound-$Protocol-$Port"
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-Log "Firewall rule already exists: $ruleName" -Level "INFO"
            return $true
        }
        
        # Create new rule
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
        It prioritizes Internet Connection Sharing (ICS) as it handles DNS/DHCP correctly for VPNs.
        It uses COM objects (HNetCfg.HNetShare) for configuration and Registry tweaks for persistence.
        
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
        [Parameter(Mandatory = $false)][string]$InterfaceAlias,
        [Parameter(Mandatory = $false)][ValidateSet("OpenVPN", "WireGuard")][string]$VPNType
    )
    
    # Defaults logic for Subnet
    if ([string]::IsNullOrWhiteSpace($VPNSubnet)) {
        $base = $null
        if ($Script:Settings -and $Script:Settings.ContainsKey('wireGuardBaseSubnet')) {
            $base = $Script:Settings.wireGuardBaseSubnet
        }
        if (-not [string]::IsNullOrWhiteSpace($base)) {
            $VPNSubnet = "${base}.0/24"
        }
    }
    
    try {
        # 0. Enable IP Forwarding first (Prerequisite for any routing)
        if (-not (Enable-IPForwarding)) {
            Write-Log "Could not enable IP Forwarding" -Level "ERROR"
            return $false
        }
        
        # 1. Register DLL required for ICS COM objects
        Write-Log "Registering hnetcfg.dll..." -Level "INFO"
        Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s hnetcfg.dll" -Wait -NoNewWindow
        
        # 2. Identify Adapters (Network Adapter Objects)
        # We generally need these for the Registry logic later
        
        # A. Internet Adapter detection
        if (-not $InterfaceAlias) {
            # Try to find the adapter with the default route (internet facing)
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object { $_.NextHop -ne "0.0.0.0" } | 
            Sort-Object RouteMetric | Select-Object -First 1
            
            if ($defaultRoute) {
                $InterfaceAlias = (Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Log "Internet interface detected: $InterfaceAlias" -Level "INFO"
            }
            
            if (-not $InterfaceAlias) {
                # Fallback: find first Up non-VPN adapter
                $InterfaceAlias = (Get-NetAdapter | Where-Object { 
                        $_.Status -eq "Up" -and 
                        $_.Name -notlike "*WireGuard*" -and 
                        $_.Name -notlike "*VPN*" -and
                        $_.Name -notlike "*Loopback*"
                    } | Select-Object -First 1).Name
            }
            if (-not $InterfaceAlias) { throw "Could not detect any internet interface." }
        }
        $internetAdapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue

        # B. VPN Adapter detection (Strict Priority based on type)
        $vpnAdapter = $null
        if ($VPNType -eq "OpenVPN") {
            Write-Log "Looking for OpenVPN adapter (Priority: TAP-Windows)..." -Level "INFO"
            
            # Priority 1: TAP-Windows specifically (Name or Description)
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                $_.InterfaceDescription -like "*TAP-Windows*" -or $_.Name -like "*TAP-Windows*" 
            } | Select-Object -First 1
            
            # Priority 2: Generic TAP if specific TAP-Windows not found
            if (-not $vpnAdapter) {
                Write-Log "TAP-Windows specific match not found. checking generic TAP..." -Level "INFO"
                $vpnAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*TAP*" } | Select-Object -First 1
            }
            
            # Priority 3: Generic OpenVPN (Last resort, might catch Wintun)
            if (-not $vpnAdapter) {
                Write-Log "TAP adapter not found. Checking generic OpenVPN..." -Level "INFO"
                $vpnAdapter = Get-NetAdapter | Where-Object { $_.Name -like "*OpenVPN*" } | Select-Object -First 1
            }
        }
        elseif ($VPNType -eq "WireGuard") {
            Write-Log "Looking for WireGuard adapter..." -Level "INFO"
            # Look for WireGuard adapters, prefer 'Up' status
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                ($_.Name -like "*wg_server*" -or $_.Name -like "*WireGuard*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq 'Up'
            } | Sort-Object ifIndex | Select-Object -Last 1
            
            if (-not $vpnAdapter) {
                Start-Sleep -Seconds 3
                # Retry without 'Up' status requirement
                $vpnAdapter = Get-NetAdapter | Where-Object { 
                    ($_.Name -like "*wg_server*" -or $_.Name -like "*WireGuard*" -or $_.InterfaceDescription -like "*WireGuard*")
                } | Select-Object -First 1
            }
        }
        else {
            # Generic Fallback if type not specified
            $vpnAdapter = Get-NetAdapter | Where-Object { 
                ($_.Name -like "*wg*" -or $_.InterfaceDescription -like "*WireGuard*" -or $_.InterfaceDescription -like "*TAP-Windows*" -or $_.Name -like "*OpenVPN*")
            } | Select-Object -Last 1
        }
        
        if (-not $vpnAdapter) {
            $allAdapters = Get-NetAdapter | ForEach-Object { "  Name='$($_.Name)' Desc='$($_.InterfaceDescription)' Status='$($_.Status)'" }
            $msg = "Private VPN adapter not found. Available adapters:`n" + ($allAdapters -join "`n")
            Write-Warning $msg
            Write-Log $msg -Level "WARNING"
            return $false
        }

        Write-Log "Identified Adapters: Public='$($internetAdapter.Name)' <-> Private='$($vpnAdapter.Name)' ($($vpnAdapter.InterfaceDescription))" -Level "INFO"
        
        if ($internetAdapter.Name -eq $vpnAdapter.Name) {
            Write-Log "Source and Destination adapters are the same. Check detection logic." -Level "ERROR"
            return $false
        }

        # 3. PHASE 1: COM Cleanup & Enable
        # Use COM to clear existing sharing configs and set initial state
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            $connections = @($netShare.EnumEveryConnection)
            
            Write-Log "Cleaning up existing ICS configurations (COM)..." -Level "INFO"
            # Disable sharing on all connections first
            foreach ($conn in $connections) {
                try {
                    $conf = $netShare.INetSharingConfigurationForINetConnection($conn)
                    if ($conf.SharingEnabled) {
                        $conf.DisableSharing()
                    }
                }
                catch {}
            }
            Start-Sleep -Seconds 2
            
            # Enable via COM (Best effort)
            $pubConn = $connections | Where-Object { $netShare.NetConnectionProps($_).Name -eq $internetAdapter.Name } | Select-Object -First 1
            $privConn = $connections | Where-Object { $netShare.NetConnectionProps($_).Name -eq $vpnAdapter.Name } | Select-Object -First 1
            
            if ($pubConn -and $privConn) {
                Write-Log "Setting initial COM sharing..." -Level "INFO"
                # Enable Public sharing (0 = public)
                $netShare.INetSharingConfigurationForINetConnection($pubConn).EnableSharing(0)
                # Enable Private sharing (1 = private)
                $netShare.INetSharingConfigurationForINetConnection($privConn).EnableSharing(1)
            }
            else {
                Write-Log "Could not find COM connection objects for one or both adapters (PublicFound=$($null -ne $pubConn), PrivateFound=$($null -ne $privConn))" -Level "WARNING"
            }
            Start-Sleep -Seconds 1
        }
        catch {
            Write-Log "COM Phase warning: $_" -Level "WARNING"
        }

        # 4. PHASE 2: Registry Enforcement (Persistence)
        # This forces the bindings in the registry and restarts the service, ensuring internet access works reliably.
        Write-Log "Enforcing ICS via Registry..." -Level "INFO"
        
        if ($internetAdapter -and $vpnAdapter) {
            # Get Network Connection GUIDs from Registry
            $netCfgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            $internetGuid = $null
            $vpnGuid = $null
            
            Get-ChildItem $netCfgPath -ErrorAction SilentlyContinue | ForEach-Object {
                $connPath = Join-Path $_.PSPath "Connection"
                if (Test-Path $connPath) {
                    $name = (Get-ItemProperty $connPath -Name "Name" -ErrorAction SilentlyContinue).Name
                    if ($name -eq $internetAdapter.Name) { $internetGuid = $_.PSChildName }
                    if ($name -eq $vpnAdapter.Name) { $vpnGuid = $_.PSChildName }
                }
            }
            
            if ($internetGuid -and $vpnGuid) {
                # Stop Service before registry edit
                Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                # Registry Hacking for ICS Binding
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess"
                
                # Explicitly Enable Sharing by GUID
                Set-ItemProperty -Path $regPath -Name "SharingPublicInterface" -Value $internetGuid -Type String -Force
                Set-ItemProperty -Path $regPath -Name "SharingPrivateInterface" -Value $vpnGuid -Type String -Force
                
                # Ensure start mode is Manual (triggered by dependencies) or Auto
                Set-Service SharedAccess -StartupType Manual
                
                # Start Service to apply changes
                Write-Log "Restarting SharedAccess service..." -Level "INFO"
                Start-Service SharedAccess
                
                # Wait for service to settle
                Start-Sleep -Seconds 3
                
                if ((Get-Service SharedAccess).Status -eq 'Running') {
                    Write-Log "Registry Enforcement Applied. SharedAccess service is running." -Level "SUCCESS"
                }
                else {
                    Write-Log "SharedAccess service failed to start." -Level "ERROR"
                    return $false
                }
            }
            else {
                Write-Log "Could not determine Interface GUIDs for Registry." -Level "WARNING"
            }
        }

        # 5. PHASE 3: Verification (COM)
        Write-Log "Verifying final ICS status..." -Level "INFO"
        $icsVerified = $false
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction Stop
            $conns = $netShare.EnumEveryConnection
            
            $pubConn = $conns | Where-Object { $netShare.NetConnectionProps($_).Name -eq $internetAdapter.Name } | Select-Object -First 1
            $privConn = $conns | Where-Object { $netShare.NetConnectionProps($_).Name -eq $vpnAdapter.Name } | Select-Object -First 1
            
            if ($pubConn -and $privConn) {
                $pubConfig = $netShare.INetSharingConfigurationForINetConnection($pubConn)
                $privConfig = $netShare.INetSharingConfigurationForINetConnection($privConn)
                
                if ($pubConfig.SharingEnabled -and $privConfig.SharingEnabled) {
                    Write-Log "Verification SUCCESS: ICS is active on both adapters." -Level "SUCCESS"
                    $icsVerified = $true
                }
                else {
                    Write-Log "Verification FAILED: COM reports sharing is NOT fully enabled." -Level "WARNING"
                }
            }
        }
        catch {}

        if ($icsVerified) {
            # Extra Packet Forwarding check on interfaces
            Set-NetIPInterface -InterfaceIndex $internetAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
            Set-NetIPInterface -InterfaceIndex $vpnAdapter.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
            return $true
        }
        else {
            # Provide manual instructions if automation failed
            $manualMsg = "ICS configuration commands ran, but verification failed.`n" +
            "If internet access does not work for VPN clients, consider enabling Internet Connection Sharing MANUALLY on the server:`n" +
            "  1. Go to Control Panel > Network Connections`n" +
            "  2. Right-click '$($internetAdapter.Name)' (Internet) > Properties > Sharing`n" +
            "  3. Check 'Allow other network users to connect...'`n" +
            "  4. Select '$($vpnAdapter.Name)' as the Home Networking Connection`n" +
            "  5. Click OK."
             
            Write-Warning $manualMsg
            Write-Log $manualMsg -Level "WARNING"
            # Return false so the warning is shown in summary
            return $false
        }

    }
    catch {
        Write-Log "Critical error in Enable-VPNNAT: $_" -Level "ERROR"
        return $false
    }
}

function Enable-IPForwarding {
    <#
    .SYNOPSIS
        Enables IP Forwarding on Windows for VPN routing.
    
    .DESCRIPTION
        This function enables IP routing via the Windows registry (IPEnableRouter).
        This is required to forward VPN traffic to the internet.
        
    .OUTPUTS
        System.Boolean
        $true on success, otherwise $false.
        
    .EXAMPLE
        Enable-IPForwarding
        
    .NOTES
        Requires admin privileges. A restart may be required for activation on some systems.
    #>
    param()
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        $currentValue = Get-ItemProperty -Path $regPath -Name "IPEnableRouter" -ErrorAction SilentlyContinue
        
        # Check if already enabled
        if ($currentValue.IPEnableRouter -eq 1) {
            Write-Log "IP Forwarding is already enabled" -Level "INFO"
            return $true
        }
        
        # Enable it
        Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value 1 -Type DWord
        Write-Log "IP Forwarding enabled in registry. Restart may be required." -Level "SUCCESS"
        
        # Attempt to start RemoteAccess service to activate routing without reboot
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
        It is used to clean up the system state if an installation fails partway through.

    .PARAMETER SetupType
        Type of setup ('Server' or 'Client').

    .OUTPUTS
        None

    .EXAMPLE
        Invoke-Rollback -SetupType "Server"

    .NOTES
        This function tries to ignore errors and logs warnings on failures, as the system might already be in an inconsistent state.
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

                # Remove PKI directory (Certificates)
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
                # Stop VPN connection (Processes)
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

                # Remove imported configuration files from config directory
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


#endregion Helper Functions & Utilities
